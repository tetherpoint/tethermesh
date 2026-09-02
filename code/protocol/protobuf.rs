// SPDX-FileCopyrightText: 2026 Matthew Klapman
// SPDX-License-Identifier: Apache-2.0

//! Protobuf wire format — the primitives, hand-written.
//!
//! # Why hand-written
//!
//! Two reasons, both recorded in `docs/DISTRIBUTION.md` and `README.md`. There is
//! no code-generation dependency in the build; and generated output would
//! derive from a GPL-3.0 `.proto`, which would make this crate a derivative
//! work. Field numbers and wire layouts are facts about the wire and may be
//! read from the schema as specification. Generated code is expression.
//!
//! # What this module knows, and what it deliberately does not
//!
//! It understands tags, wire types and lengths. It does **not** know any
//! message, field name or type. That separation is not tidiness — a decoder
//! that understood the messages would be exactly the artefact that must not
//! be derived from their schema, and keeping the wire layer schema-free means
//! the message layer above it is small, readable, and obviously ours.
//!
//! # Conformance target
//!
//! `tests/captures/fromradio_corpus.json` holds messages produced by the
//! reference implementation's own encoder. Two properties were measured on
//! capture: every message re-emits bit-identically under minimal-varint
//! encoding, and every message carries its fields in ascending field-number
//! order. Their encoder is therefore canonical, which is what makes
//! bit-identical round-tripping an achievable requirement rather than an
//! impossible one. This module is written to preserve both properties.
//!
//! # No panics, and how that is achieved here
//!
//! Every length comes from untrusted input, so there is no slice indexing and
//! no bare arithmetic anywhere below — `get`, `checked_add` and `checked_shl`
//! throughout. Malformed input produces [`Error`], never a panic.

/// What went wrong decoding or encoding.
///
/// Deliberately coarse. A parser that reports precisely where an adversary's
/// input failed is a parser that tells the adversary how to do better.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Input ended inside a field.
    Truncated,
    /// A varint ran past ten bytes, or would overflow 64 bits.
    MalformedVarint,
    /// Wire type 3, 4 (deprecated groups) or 6, 7 (never assigned).
    UnsupportedWireType,
    /// Field number 0, which the wire format does not permit.
    ZeroFieldNumber,
    /// The caller's output buffer is too small.
    BufferTooSmall,
}

/// A decoded field value, borrowing from the input for length-delimited data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value<'a> {
    /// Wire type 0.
    Varint(u64),
    /// Wire type 1, kept as raw bytes because interpretation is the caller's.
    Fixed64([u8; 8]),
    /// Wire type 2. Strings, bytes and nested messages are all this.
    Len(&'a [u8]),
    /// Wire type 5, kept as raw bytes for the same reason as [`Value::Fixed64`].
    Fixed32([u8; 4]),
}

impl Value<'_> {
    /// The wire type this value encodes as.
    #[must_use]
    pub const fn wire_type(&self) -> u8 {
        match self {
            Value::Varint(_) => 0,
            Value::Fixed64(_) => 1,
            Value::Len(_) => 2,
            Value::Fixed32(_) => 5,
        }
    }
}

/// One field: its number and its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field<'a> {
    /// Field number from the tag.
    pub number: u32,
    /// The value.
    pub value: Value<'a>,
}

/// Reads fields from a protobuf message.
///
/// Borrows the input; nothing is copied and nothing is allocated.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Start reading `buf`.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes consumed so far.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// True once every byte has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let b = self.buf.get(self.pos).copied().ok_or(Error::Truncated)?;
        self.pos = self.pos.checked_add(1).ok_or(Error::Truncated)?;
        Ok(b)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(len).ok_or(Error::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Decode one varint.
    ///
    /// Rejects anything longer than ten bytes and any encoding whose
    /// continuation bits would shift past 64, rather than wrapping.
    fn varint(&mut self) -> Result<u64, Error> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.byte()?;
            let part = u64::from(byte & 0x7F)
                .checked_shl(shift)
                .ok_or(Error::MalformedVarint)?;
            value |= part;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift = shift.checked_add(7).ok_or(Error::MalformedVarint)?;
            if shift >= 64 {
                return Err(Error::MalformedVarint);
            }
        }
    }

    /// Read the next field, or `None` at the end of the message.
    ///
    /// # Errors
    ///
    /// [`Error`] on truncated, malformed or unsupported input. A reader that
    /// has returned an error must not be used again; its position is
    /// unspecified.
    pub fn next_field(&mut self) -> Result<Option<Field<'a>>, Error> {
        if self.is_empty() {
            return Ok(None);
        }
        let tag = self.varint()?;
        // Wire type is the low three bits; the field number is the rest.
        let wire_type = u8::try_from(tag & 0x07).map_err(|_| Error::UnsupportedWireType)?;
        let number_u64 = tag.checked_shr(3).ok_or(Error::MalformedVarint)?;
        let number = u32::try_from(number_u64).map_err(|_| Error::ZeroFieldNumber)?;
        if number == 0 {
            return Err(Error::ZeroFieldNumber);
        }
        let value = match wire_type {
            0 => Value::Varint(self.varint()?),
            1 => {
                let bytes = self.take(8)?;
                let mut out = [0u8; 8];
                for (d, s) in out.iter_mut().zip(bytes.iter()) {
                    *d = *s;
                }
                Value::Fixed64(out)
            }
            2 => {
                let len = usize::try_from(self.varint()?).map_err(|_| Error::Truncated)?;
                Value::Len(self.take(len)?)
            }
            5 => {
                let bytes = self.take(4)?;
                let mut out = [0u8; 4];
                for (d, s) in out.iter_mut().zip(bytes.iter()) {
                    *d = *s;
                }
                Value::Fixed32(out)
            }
            // 3 and 4 are the deprecated group encoding; 6 and 7 were never
            // assigned. Rejecting rather than skipping is deliberate: a
            // decoder that skips what it does not understand cannot tell a
            // new feature from a malformed frame.
            _ => return Err(Error::UnsupportedWireType),
        };
        Ok(Some(Field { number, value }))
    }
}

/// Writes fields into a caller-provided buffer.
///
/// Allocates nothing. The caller owns the buffer and its length, per the FFI
/// discipline in `docs/DISTRIBUTION.md`.
#[derive(Debug)]
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    /// Start writing into `buf`.
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes written so far.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.pos
    }

    /// True if nothing has been written.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pos == 0
    }

    fn put(&mut self, byte: u8) -> Result<(), Error> {
        let slot = self.buf.get_mut(self.pos).ok_or(Error::BufferTooSmall)?;
        *slot = byte;
        self.pos = self.pos.checked_add(1).ok_or(Error::BufferTooSmall)?;
        Ok(())
    }

    fn put_slice(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self.pos.checked_add(bytes.len()).ok_or(Error::BufferTooSmall)?;
        let dst = self.buf.get_mut(self.pos..end).ok_or(Error::BufferTooSmall)?;
        for (d, s) in dst.iter_mut().zip(bytes.iter()) {
            *d = *s;
        }
        self.pos = end;
        Ok(())
    }

    /// Write a varint in minimal form.
    ///
    /// Minimal encoding is required, not merely preferred: the corpus shows
    /// the reference encoder emits minimal varints, and a non-minimal one
    /// here would decode to the same value while failing a byte-identical
    /// comparison.
    fn varint(&mut self, mut value: u64) -> Result<(), Error> {
        loop {
            let low = u8::try_from(value & 0x7F).map_err(|_| Error::MalformedVarint)?;
            let rest = value.checked_shr(7).unwrap_or(0);
            if rest == 0 {
                return self.put(low);
            }
            self.put(low | 0x80)?;
            value = rest;
        }
    }

    /// Append one field.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] if the buffer cannot hold it,
    /// [`Error::ZeroFieldNumber`] if `number` is 0.
    pub fn field(&mut self, number: u32, value: &Value<'_>) -> Result<(), Error> {
        if number == 0 {
            return Err(Error::ZeroFieldNumber);
        }
        let tag = u64::from(number)
            .checked_shl(3)
            .ok_or(Error::MalformedVarint)?
            | u64::from(value.wire_type());
        self.varint(tag)?;
        match *value {
            Value::Varint(v) => self.varint(v),
            Value::Fixed64(bytes) => self.put_slice(&bytes),
            Value::Len(bytes) => {
                let len = u64::try_from(bytes.len()).map_err(|_| Error::BufferTooSmall)?;
                self.varint(len)?;
                self.put_slice(bytes)
            }
            Value::Fixed32(bytes) => self.put_slice(&bytes),
        }
    }
}
