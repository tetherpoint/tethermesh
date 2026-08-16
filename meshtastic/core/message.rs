//! Per-message wrappers.
//!
//! [`crate::protobuf`] handles the wire format and knows nothing about any
//! message. This module is the thin layer that does: it maps field numbers to
//! meanings for the messages this stack needs, and nothing more.
//!
//! # Unknown fields are dropped, and that has an architectural consequence
//!
//! These wrappers hold fixed fields and allocate nothing, so a field this
//! build does not know about is **discarded on decode**. That is unavoidable
//! without an allocator, and it is safe for interpretation — but it is not
//! safe for retransmission.
//!
//! **A relay path must never round-trip a frame through this layer.** The
//! wire format moves between firmware releases; a node that decodes to a
//! struct and re-encodes will silently strip any field it was built before,
//! and the packet it forwards will differ from the packet it received. Relay
//! through [`crate::protobuf`], which borrows and copies payloads verbatim
//! and preserves everything, or better, relay the frame bytes untouched.
//!
//! This layer is for reading what a frame says, and for building frames of
//! our own. It is not a pass-through.
//!
//! # Proto3 default omission
//!
//! Proto3 does not transmit scalar fields holding their default value, and
//! the reference encoder follows that. Encoding here does the same, because
//! emitting an explicit zero would decode to the same message while failing
//! the byte-identical comparison that `tests/captures/fromradio_corpus.json`
//! is checked against. Fields declared `optional` carry real presence and are
//! modelled as [`Option`].

use crate::protobuf::{Error, Reader, Value, Writer};

/// Application port, identifying what a payload means.
///
/// Kept as a plain number rather than an enumeration: the set is large, it
/// grows between firmware releases, and an unknown port must be ignored
/// rather than rejected. A closed enumeration here would turn a future port
/// into a decode failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PortNum(pub u32);

impl PortNum {
    /// Plain UTF-8 text.
    pub const TEXT_MESSAGE_APP: Self = Self(1);
    /// Position reports.
    pub const POSITION_APP: Self = Self(3);
    /// `User` records — the payload [`User`] describes.
    pub const NODEINFO_APP: Self = Self(4);
    /// Routing control.
    pub const ROUTING_APP: Self = Self(5);
    /// Administrative messages.
    pub const ADMIN_APP: Self = Self(6);
}

/// The decrypted payload of a mesh packet.
///
/// Borrows from the input; nothing is copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Data<'a> {
    /// What the payload means.
    pub portnum: u32,
    /// The payload itself, uninterpreted.
    pub payload: &'a [u8],
    /// Whether the sender wants a reply.
    pub want_response: bool,
    /// Destination node, when this is a reply routed to one node.
    pub dest: u32,
    /// Original source, when relayed on behalf of another node.
    pub source: u32,
    /// Identifier of the request this answers.
    pub request_id: u32,
    /// Identifier of the message this replies to.
    pub reply_id: u32,
    /// Emoji reaction marker.
    pub emoji: u32,
    /// Present only when the sender set it.
    pub bitfield: Option<u32>,
    /// XEdDSA signature, 64 bytes when present. Firmware 2.8.x and later.
    pub xeddsa_signature: &'a [u8],
}

impl<'a> Data<'a> {
    /// Decode from protobuf bytes.
    ///
    /// Unknown fields are ignored — see the module documentation for why that
    /// makes this unsuitable for a relay path.
    ///
    /// # Errors
    ///
    /// [`Error`] if the input is not well-formed protobuf.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut out = Self::default();
        let mut reader = Reader::new(bytes);
        while let Some(field) = reader.next_field()? {
            match (field.number, field.value) {
                (1, Value::Varint(v)) => out.portnum = truncate_u32(v),
                (2, Value::Len(b)) => out.payload = b,
                (3, Value::Varint(v)) => out.want_response = v != 0,
                (4, Value::Fixed32(b)) => out.dest = u32::from_le_bytes(b),
                (5, Value::Fixed32(b)) => out.source = u32::from_le_bytes(b),
                (6, Value::Fixed32(b)) => out.request_id = u32::from_le_bytes(b),
                (7, Value::Fixed32(b)) => out.reply_id = u32::from_le_bytes(b),
                (8, Value::Fixed32(b)) => out.emoji = u32::from_le_bytes(b),
                (9, Value::Varint(v)) => out.bitfield = Some(truncate_u32(v)),
                (10, Value::Len(b)) => out.xeddsa_signature = b,
                // A field we do not know, or a known field arriving with an
                // unexpected wire type. Both are ignored rather than
                // rejected: a stricter decoder would turn every future
                // protocol addition into an outage.
                _ => {}
            }
        }
        Ok(out)
    }

    /// Encode into `buf`, returning the number of bytes written.
    ///
    /// Fields are written in ascending number order with defaults omitted,
    /// matching the reference encoder.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] if `buf` cannot hold the result.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(buf);
        if self.portnum != 0 {
            w.field(1, &Value::Varint(u64::from(self.portnum)))?;
        }
        if !self.payload.is_empty() {
            w.field(2, &Value::Len(self.payload))?;
        }
        if self.want_response {
            w.field(3, &Value::Varint(1))?;
        }
        for (number, value) in [
            (4, self.dest),
            (5, self.source),
            (6, self.request_id),
            (7, self.reply_id),
            (8, self.emoji),
        ] {
            if value != 0 {
                w.field(number, &Value::Fixed32(value.to_le_bytes()))?;
            }
        }
        if let Some(bits) = self.bitfield {
            w.field(9, &Value::Varint(u64::from(bits)))?;
        }
        if !self.xeddsa_signature.is_empty() {
            w.field(10, &Value::Len(self.xeddsa_signature))?;
        }
        Ok(w.len())
    }
}

/// A node's identity record.
///
/// Strings are kept as raw bytes rather than `&str`. Proto3 requires UTF-8,
/// but this input arrives from a mesh whose participants are assumed to
/// include adversarial ones, and validating here would add a rejection path
/// for something no caller of this layer needs to be true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct User<'a> {
    /// Node identifier, conventionally `!` followed by the hex node number.
    pub id: &'a [u8],
    /// Full name.
    pub long_name: &'a [u8],
    /// Short name, conventionally four characters.
    pub short_name: &'a [u8],
    /// MAC address. **Deprecated in Meshtastic 2.1.x, and still emitted.**
    ///
    /// Carried because firmware 2.7.26 puts it on the wire — as six zero
    /// bytes in every `User` in the corpus — and a wrapper that dropped it
    /// would re-encode to something shorter than what the reference produced.
    /// Deprecated in the schema is not absent from the wire, and byte
    /// identity is decided by the wire.
    pub macaddr: &'a [u8],
    /// Hardware model.
    pub hw_model: u32,
    /// Whether the operator is licensed.
    pub is_licensed: bool,
    /// Device role.
    pub role: u32,
    /// X25519 public key.
    pub public_key: &'a [u8],
    /// Present only when the sender set it.
    pub is_unmessagable: Option<bool>,
}

impl<'a> User<'a> {
    /// Decode from protobuf bytes.
    ///
    /// # Errors
    ///
    /// [`Error`] if the input is not well-formed protobuf.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut out = Self::default();
        let mut reader = Reader::new(bytes);
        while let Some(field) = reader.next_field()? {
            match (field.number, field.value) {
                (1, Value::Len(b)) => out.id = b,
                (2, Value::Len(b)) => out.long_name = b,
                (3, Value::Len(b)) => out.short_name = b,
                (4, Value::Len(b)) => out.macaddr = b,
                (5, Value::Varint(v)) => out.hw_model = truncate_u32(v),
                (6, Value::Varint(v)) => out.is_licensed = v != 0,
                (7, Value::Varint(v)) => out.role = truncate_u32(v),
                (8, Value::Len(b)) => out.public_key = b,
                (9, Value::Varint(v)) => out.is_unmessagable = Some(v != 0),
                _ => {}
            }
        }
        Ok(out)
    }

    /// Encode into `buf`, returning the number of bytes written.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] if `buf` cannot hold the result.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(buf);
        for (number, bytes) in [
            (1, self.id),
            (2, self.long_name),
            (3, self.short_name),
            (4, self.macaddr),
        ] {
            if !bytes.is_empty() {
                w.field(number, &Value::Len(bytes))?;
            }
        }
        if self.hw_model != 0 {
            w.field(5, &Value::Varint(u64::from(self.hw_model)))?;
        }
        if self.is_licensed {
            w.field(6, &Value::Varint(1))?;
        }
        if self.role != 0 {
            w.field(7, &Value::Varint(u64::from(self.role)))?;
        }
        if !self.public_key.is_empty() {
            w.field(8, &Value::Len(self.public_key))?;
        }
        if let Some(flag) = self.is_unmessagable {
            w.field(9, &Value::Varint(u64::from(flag)))?;
        }
        Ok(w.len())
    }
}

/// One channel's settings.
///
/// Carries the two inputs [`crate::channel::channel_hash`] needs, which is
/// why this wrapper exists at all: without it the hash function has verified
/// behaviour and no way to get its arguments off the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChannelSettings<'a> {
    /// Pre-shared key.
    ///
    /// **May be a short index rather than a key.** A single byte `0x01`
    /// means "the default key", expanded at use; the reference logs
    /// `Expand short PSK #1` when it does so. Anything passed to
    /// [`crate::channel::channel_hash`] must be the expanded key, because the
    /// hash folds the key bytes and an index would fold to something else
    /// entirely.
    pub psk: &'a [u8],
    /// Channel name, folded into the channel hash.
    pub name: &'a [u8],
    /// Channel identifier.
    pub id: u32,
    /// Whether traffic is uplinked to MQTT.
    pub uplink_enabled: bool,
    /// Whether traffic is downlinked from MQTT.
    pub downlink_enabled: bool,
    /// Module settings, kept as raw bytes — this layer does not interpret them.
    pub module_settings: &'a [u8],
}

impl<'a> ChannelSettings<'a> {
    /// Decode from protobuf bytes.
    ///
    /// # Errors
    ///
    /// [`Error`] if the input is not well-formed protobuf.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut out = Self::default();
        let mut reader = Reader::new(bytes);
        while let Some(field) = reader.next_field()? {
            match (field.number, field.value) {
                // Field 1 was `channel_num`, removed upstream.
                (2, Value::Len(b)) => out.psk = b,
                (3, Value::Len(b)) => out.name = b,
                (4, Value::Fixed32(b)) => out.id = u32::from_le_bytes(b),
                (5, Value::Varint(v)) => out.uplink_enabled = v != 0,
                (6, Value::Varint(v)) => out.downlink_enabled = v != 0,
                (7, Value::Len(b)) => out.module_settings = b,
                _ => {}
            }
        }
        Ok(out)
    }

    /// Encode into `buf`, returning the number of bytes written.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] if `buf` cannot hold the result.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(buf);
        if !self.psk.is_empty() {
            w.field(2, &Value::Len(self.psk))?;
        }
        if !self.name.is_empty() {
            w.field(3, &Value::Len(self.name))?;
        }
        if self.id != 0 {
            w.field(4, &Value::Fixed32(self.id.to_le_bytes()))?;
        }
        if self.uplink_enabled {
            w.field(5, &Value::Varint(1))?;
        }
        if self.downlink_enabled {
            w.field(6, &Value::Varint(1))?;
        }
        if !self.module_settings.is_empty() {
            w.field(7, &Value::Len(self.module_settings))?;
        }
        Ok(w.len())
    }
}

/// Narrow a wire varint to 32 bits.
///
/// A `uint32` field arrives as a 64-bit varint and an oversized value is
/// malformed rather than meaningful. Truncating keeps the decode total, which
/// matters more here than distinguishing a case no honest sender produces —
/// and the alternative, an error, would let one bad field discard a whole
/// otherwise-readable message.
const fn truncate_u32(value: u64) -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    {
        value as u32
    }
}
