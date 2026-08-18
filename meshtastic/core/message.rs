// SPDX-FileCopyrightText: 2026 The tethermesh Authors
// SPDX-License-Identifier: Apache-2.0

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

/// A node's location, `POSITION_APP`.
///
/// # The wire types are the whole difficulty
///
/// `latitude_i` and `longitude_i` are **`sfixed32`** and `time` is `fixed32` —
/// **32-bit fields, not varints.** Varint is the obvious guess for an integer
/// and it is wrong here, exactly as it was for [`MeshPacket`]'s `from`, `to`
/// and `id`. An encoder built on the guess produces bytes a stock node cannot
/// read, and nothing about the mistake announces itself.
///
/// Coordinates are degrees scaled by 1e7, carried as raw little-endian
/// two's-complement in those four bytes.
///
/// # What is verified, and what is not
///
/// **Our encoder is checked against their decoder.** A `Position` built here
/// was carried by a stock node's radio and read by a second stock node, which
/// reported the payload length we produced and the exact `time` we sent —
/// `tests/captures/position_record.json`.
///
/// **Our decoder is NOT checked against their bytes**, because no node on the
/// bench emits a `Position`: none has GPS, and setting a fixed position needs
/// admin messages whose schema is not available locally. The round-trip test
/// below is self-consistency, and is labelled as such rather than counted as
/// interoperability.
///
/// # The SENDER quantises the coordinates, and says by how much
///
/// A stock node does not transmit the coordinate it was given. Handed
/// `latitude_i = 123456789` (`0x075BCD15`) it put `123469824` (`0x075C0000`) on
/// the air — **rounded**, not truncated, to eighteen trailing zero bits — and
/// stamped `precision_bits = 13` alongside. `time` and `altitude` went out
/// exactly as supplied.
///
/// **This happens on TRANSMIT, not on receipt**, which is only visible by
/// capturing the frame off the air; reading the receiver's log alone suggests
/// the opposite and that reading was wrong for an hour. Anyone comparing a
/// coordinate they supplied against one that arrives must expect the loss, and
/// `precision_bits` is how the sender declares it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Position {
    /// Degrees times 1e7. `sfixed32` on the wire.
    pub latitude_i: i32,
    /// Degrees times 1e7. `sfixed32` on the wire.
    pub longitude_i: i32,
    /// Metres. A varint, unlike the coordinates.
    pub altitude: i32,
    /// Seconds since the epoch. `fixed32` on the wire.
    pub time: u32,
    /// How many bits of coordinate precision the SENDER kept, field 23.
    ///
    /// Carried because a stock node puts it on the wire in every `Position` it
    /// sends, and a wrapper that dropped it would re-encode shorter than the
    /// reference produced — the same rule that keeps `User::macaddr`.
    pub precision_bits: u32,
}

impl Position {
    /// Decode from protobuf bytes.
    ///
    /// # Errors
    ///
    /// [`Error`] if the input is not well-formed protobuf.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut out = Self::default();
        let mut reader = Reader::new(bytes);
        while let Some(field) = reader.next_field()? {
            match (field.number, field.value) {
                (1, Value::Fixed32(b)) => out.latitude_i = i32::from_le_bytes(b),
                (2, Value::Fixed32(b)) => out.longitude_i = i32::from_le_bytes(b),
                (3, Value::Varint(v)) => out.altitude = truncate_u32(v) as i32,
                (4, Value::Fixed32(b)) => out.time = u32::from_le_bytes(b),
                (23, Value::Varint(v)) => out.precision_bits = truncate_u32(v),
                _ => {}
            }
        }
        Ok(out)
    }

    /// Encode into `buf`, returning the number of bytes written.
    ///
    /// Zero-valued fields are omitted, which is what proto3 does with a
    /// default — and note that a latitude of exactly zero is therefore absent
    /// rather than present-and-zero. That is the reference's own behaviour for
    /// scalar fields and is not a choice made here.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] if `buf` cannot hold the result.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(buf);
        if self.latitude_i != 0 {
            w.field(1, &Value::Fixed32(self.latitude_i.to_le_bytes()))?;
        }
        if self.longitude_i != 0 {
            w.field(2, &Value::Fixed32(self.longitude_i.to_le_bytes()))?;
        }
        if self.altitude != 0 {
            w.field(3, &Value::Varint(self.altitude as u32 as u64))?;
        }
        if self.time != 0 {
            w.field(4, &Value::Fixed32(self.time.to_le_bytes()))?;
        }
        if self.precision_bits != 0 {
            w.field(23, &Value::Varint(u64::from(self.precision_bits)))?;
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

/// The status a `Routing` message carries.
///
/// Kept as a number rather than an enum **on purpose**. Two values have been
/// observed on the wire: `0` on acceptance and `6` on one rejection. Naming `6`
/// would need the schema read as specification, and this project does not
/// promote an observed value to a named fact. A caller that must distinguish
/// specific rejections can compare the number and say where it got it from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RoutingStatus(pub u32);

impl RoutingStatus {
    /// The accepted status, `0`.
    pub const ACCEPTED: Self = Self(0);

    /// Whether this reports success.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        self.0 == 0
    }
}

/// A `Routing` message — the payload of a `ROUTING_APP` (portnum 5) frame.
///
/// # Only field 3 is decoded, and that is a statement about evidence
///
/// Field 3 is the status, established by capturing a stock node's replies:
/// `0` when it accepted a direct message and `6` when it rejected one. Fields 1
/// and 2 carry route discovery, which only appears when routing actually
/// discovers a route — something a two-node bench cannot produce. They are
/// **not decoded**, because this project does not implement field numbers it
/// has not established.
///
/// # Encoding writes the status even when it is zero
///
/// proto3 omits a zero varint and the rest of this module follows that rule.
/// This one does not, because a stock node does not: its acceptance carries the
/// two bytes `18 00` explicitly. An acknowledgement encoded the ordinary way
/// would be empty, and on the evidence would not be recognised. The deviation
/// is the measurement, not a mistake — see `tests/captures/routing_ack.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Routing {
    /// Field 3. Zero means accepted.
    pub status: RoutingStatus,
}

impl Routing {
    /// A `Routing` reporting acceptance.
    pub const ACCEPTED: Self = Self { status: RoutingStatus::ACCEPTED };

    /// Decode from the payload of a `ROUTING_APP` frame.
    ///
    /// Unknown fields — including the undecoded route-discovery ones — are
    /// skipped, as everywhere else in this module.
    ///
    /// # Errors
    ///
    /// [`Error`] if the payload is not well-formed protobuf.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut out = Self::default();
        let mut reader = Reader::new(bytes);
        while let Some(field) = reader.next_field()? {
            if let (3, Value::Varint(v)) = (field.number, field.value) {
                out.status = RoutingStatus(truncate_u32(v));
            }
        }
        Ok(out)
    }

    /// Encode into `buf`, returning the number of bytes written.
    ///
    /// **Always writes field 3**, including when the status is zero. See the
    /// type note.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] if `buf` cannot hold the result.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(buf);
        w.field(3, &Value::Varint(u64::from(self.status.0)))?;
        Ok(w.len())
    }
}

/// A node database entry, as the reference emits it.
///
/// # What is established, and what is not
///
/// The layout below is read off `tests/captures/fromradio_corpus.json`'s
/// `node_info` message — their encoder's bytes. It establishes that fields 1, 2,
/// 3 and 10 exist and their wire types. It does **not** establish field 10's
/// meaning: one capture showing a varint `1` names nothing, no primary document
/// here records it, and guessing from a remembered schema is the kind of
/// self-consistent invention this project exists to avoid. So it is carried
/// under a name that describes its position rather than a purpose it has not
/// been shown to have. Naming it costs a capture, not a rewrite.
///
/// Fields 4–9 do not appear in the corpus at all and are therefore **not
/// carried**. The consequence is worth stating plainly rather than discovering:
/// a `NodeInfo` that used them would lose them across decode-then-encode. That
/// is a real limitation, and the honest one — a field number invented here would
/// corrupt a neighbour's record rather than drop it.
///
/// # Why `position` is an `Option` of a possibly-empty slice
///
/// The captured message carries `1a 00` — field 3, present, zero bytes. A
/// wrapper that skipped empty submessages the way [`User`] skips empty byte
/// fields would drop those two bytes and fail to re-encode bit-identically.
/// `None` means absent and `Some(&[])` means present-and-empty, because the wire
/// distinguishes them. This is the same lesson as [`User::macaddr`]: the schema
/// says what a field means, not whether it is transmitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NodeInfo<'a> {
    /// Field 1. The node number — `0x021e81dd` in the corpus message, matching
    /// the `!021e81dd` in its own [`User::id`].
    pub num: u32,
    /// Field 2, undecoded. Feed to [`User::decode`]; kept as raw bytes so this
    /// type does not force that cost on a caller that only wants `num`.
    pub user: Option<&'a [u8]>,
    /// Field 3, undecoded. `Some(&[])` when present and empty — see the type
    /// note, that case is in the corpus and is load-bearing.
    pub position: Option<&'a [u8]>,
    /// Field 10, a varint flag, observed as `1`. **Its meaning is not
    /// established** — see the type note.
    pub flag_10: Option<bool>,
}

impl<'a> NodeInfo<'a> {
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
                (1, Value::Varint(v)) => out.num = truncate_u32(v),
                (2, Value::Len(b)) => out.user = Some(b),
                (3, Value::Len(b)) => out.position = Some(b),
                (10, Value::Varint(v)) => out.flag_10 = Some(v != 0),
                _ => {}
            }
        }
        Ok(out)
    }

    /// Encode into `buf`, returning the number of bytes written.
    ///
    /// Fields are written in ascending order, which is what the reference's own
    /// encoder does — `fromradio_corpus.json` records 43 of 43 messages in
    /// ascending order, and that is why a bit-identical re-encode is reachable
    /// at all rather than merely semantically equal.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] if `buf` cannot hold the result.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(buf);
        if self.num != 0 {
            w.field(1, &Value::Varint(u64::from(self.num)))?;
        }
        // Written whenever PRESENT, empty or not. Skipping an empty submessage
        // is what would break the round-trip; see the type note.
        if let Some(b) = self.user {
            w.field(2, &Value::Len(b))?;
        }
        if let Some(b) = self.position {
            w.field(3, &Value::Len(b))?;
        }
        if let Some(flag) = self.flag_10 {
            w.field(10, &Value::Varint(u64::from(flag)))?;
        }
        Ok(w.len())
    }
}

/// A packet in its **protobuf** form, as it travels over UDP multicast and the
/// device API.
///
/// # This is not the packed LoRa frame, and confusing the two is the hazard
///
/// [`crate::header`] handles the sixteen packed bytes that go on the air. This
/// is a different representation of an overlapping set of fields, and they
/// disagree about encoding in a way that is easy to get wrong: here `from`,
/// `to` and `id` are **`fixed32`** (wire type 5), where the packed header
/// carries them as raw little-endian words in fixed positions. A wrapper that
/// assumed varint — the obvious guess for an integer field — produces bytes
/// that parse as a different message entirely.
///
/// `tests/captures/udp_mesh_capture.json` records the boundary explicitly:
/// *"The payload is the protobuf MeshPacket, not the packed LoRa frame. Nothing
/// here settles wire layout."*
///
/// # What the capture establishes
///
/// Two datagrams from a stock node, fields in ascending order:
///
/// | field | wire type | meaning |
/// |---|---|---|
/// | 1 | fixed32 | `from` |
/// | 2 | fixed32 | `to` |
/// | 3 | varint | `channel` — the one-byte channel hash, 8 for LongFast |
/// | 5 | len | `encrypted` |
/// | 6 | fixed32 | `id` |
/// | 11 | varint | `priority` |
/// | 19 | varint | `relay_node` |
///
/// `relay_node` is corroborated rather than assumed: it is the low byte of the
/// sender's node number in both datagrams — `0x266cbc2b` → `0x2b` and
/// `0x2f7f90dc` → `0xdc` — which independently reproduces the same finding made
/// earlier from log output.
///
/// # What is carried, and what is deliberately left out
///
/// `WIRE_REFERENCE.md` § `MeshPacket` records the **whole** field set, read from
/// the schema as specification — `hop_limit = 9`, `want_ack = 10`,
/// `hop_start = 15`, `next_hop = 18` and the rest. Their numbers are not in
/// doubt. What is carried here is narrower on purpose: the fields **observed on
/// the wire**, so that every one of them is pinned by a byte-identical
/// round-trip rather than by a reading of the schema.
///
/// `hop_limit` and `hop_start` are absent from both datagrams, meaning zero. The
/// consequence is recorded in the capture's own findings and is worth repeating:
/// a packet with no hops left is not a rebroadcast candidate, so **this
/// transport never reaches the managed-flooding decision** — two nodes
/// exchanging over UDP demonstrate delivery, not relay.
///
/// Field 4 (`decoded`) never appears either; a packet carries one of decoded or
/// encrypted, and only the encrypted arm was observed.
///
/// Adding the rest is mechanical once traffic exercises them. Adding them *now*
/// would mean shipping fields whose encoding nothing has confirmed, in a type
/// whose entire value is that its bytes match the reference's.
///
/// **No field was observed carrying a zero**, so whether this encoder omits a
/// zero the way proto3 normally does is *unverified here*. Zeros are omitted
/// below, which is the proto3 rule and round-trips every captured datagram. Note
/// that [`Routing`] deviates from exactly that rule, and only capture revealed
/// it — so this is an assumption flagged as one, not a settled fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MeshPacket<'a> {
    /// Field 1, `fixed32`.
    pub from: u32,
    /// Field 2, `fixed32`.
    pub to: u32,
    /// Field 3. The one-byte channel hash.
    pub channel: u32,
    /// Field 5, undecoded ciphertext.
    pub encrypted: &'a [u8],
    /// Field 6, `fixed32`.
    pub id: u32,
    /// Field 11.
    pub priority: u32,
    /// Field 19. The low byte of the sending node's number.
    pub relay_node: u32,
}

impl<'a> MeshPacket<'a> {
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
                (1, Value::Fixed32(b)) => out.from = u32::from_le_bytes(b),
                (2, Value::Fixed32(b)) => out.to = u32::from_le_bytes(b),
                (3, Value::Varint(v)) => out.channel = truncate_u32(v),
                (5, Value::Len(b)) => out.encrypted = b,
                (6, Value::Fixed32(b)) => out.id = u32::from_le_bytes(b),
                (11, Value::Varint(v)) => out.priority = truncate_u32(v),
                (19, Value::Varint(v)) => out.relay_node = truncate_u32(v),
                _ => {}
            }
        }
        Ok(out)
    }

    /// Encode into `buf`, returning the number of bytes written.
    ///
    /// Fields ascend, which is what the captured datagrams do and what makes a
    /// bit-identical re-encode reachable rather than merely equivalent.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] if `buf` cannot hold the result.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut w = Writer::new(buf);
        if self.from != 0 {
            w.field(1, &Value::Fixed32(self.from.to_le_bytes()))?;
        }
        if self.to != 0 {
            w.field(2, &Value::Fixed32(self.to.to_le_bytes()))?;
        }
        if self.channel != 0 {
            w.field(3, &Value::Varint(u64::from(self.channel)))?;
        }
        if !self.encrypted.is_empty() {
            w.field(5, &Value::Len(self.encrypted))?;
        }
        if self.id != 0 {
            w.field(6, &Value::Fixed32(self.id.to_le_bytes()))?;
        }
        if self.priority != 0 {
            w.field(11, &Value::Varint(u64::from(self.priority)))?;
        }
        if self.relay_node != 0 {
            w.field(19, &Value::Varint(u64::from(self.relay_node)))?;
        }
        Ok(w.len())
    }
}
