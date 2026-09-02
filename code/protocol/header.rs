// SPDX-FileCopyrightText: 2026 Matthew Klapman
// SPDX-License-Identifier: Apache-2.0

//! The 16-byte unencrypted header that precedes every frame on the air.
//!
//! # Provenance
//!
//! **Verified 2026-08-16 by on-air capture.** A stock Meshtastic node
//! (`2.7.26.54e0d8d`) transmitted; a receiver running our own SX1262 driver
//! printed the PHY payload verbatim. Layout, field order, endianness and the
//! flag bit positions are all read off real frames rather than taken from any
//! secondary description. Frames in `tests/captures/on_air_frames.json`, full
//! record in `docs/WIRE_REFERENCE.md`.
//!
//! ```text
//! offset  size  field
//!    0     4    to          u32 little-endian
//!    4     4    from        u32 little-endian
//!    8     4    id          u32 little-endian
//!   12     1    flags       bits 0-2 hop_limit, bit 3 want_ack,
//!                           bit 4 via_mqtt, bits 5-7 hop_start
//!   13     1    channel     one-byte channel hash
//!   14     1    next_hop    low byte of node number, 0 = none
//!   15     1    relay_node  low byte of the relaying node's number
//! ```
//!
//! # Little-endian, and why that is worth a warning
//!
//! Every multi-byte field is little-endian. Readers arriving from the
//! protobuf side tend to expect otherwise, and getting it backwards produces a
//! header that is structurally valid, passes any round-trip test written
//! against itself, and is wrong on the air. The tests here compare against
//! captured bytes precisely so that self-consistency cannot masquerade as
//! correctness.
//!
//! # This header is not authenticated
//!
//! It travels in the clear and nothing covers it. Any relay can alter it and
//! any listener can forge one. `hop_limit`, `channel` and `relay_node` are
//! routing hints, never evidence. The extension suite's AEAD tag exists to
//! bind the header to the payload precisely because nothing here does.
//!
//! **It binds the invariant subset, not all sixteen bytes**, and the
//! distinction is load-bearing rather than pedantic. `hop_limit`, `next_hop`
//! and `relay_node` change legitimately in transit — every relay decrements
//! the first and stamps the last — so a tag covering them verifies only for a
//! packet nobody has relayed. Even with the suite, **hop fields stay
//! unauthenticated**: origin and content are covered, path is not. See
//! `code/groups/SPEC.md` § 3.1.

/// Bytes on the wire before the ciphertext begins.
pub const HEADER_LEN: usize = 16;

/// Broadcast destination.
pub const BROADCAST_ADDR: u32 = 0xFFFF_FFFF;

/// The unencrypted header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header {
    /// Destination node, or [`BROADCAST_ADDR`].
    pub to: u32,
    /// Originating node. Not the relaying node — see [`Header::relay_node`].
    pub from: u32,
    /// Packet identifier, unique per sender.
    ///
    /// Together with `from` this is the AES-CTR nonce input, so a repeat
    /// reproduces a keystream. See [`crate::packet_id`].
    pub id: u32,
    /// Hops remaining. Three bits, so 0..=7.
    pub hop_limit: u8,
    /// Sender requested an acknowledgement.
    pub want_ack: bool,
    /// Packet arrived via an MQTT gateway rather than over the air.
    pub via_mqtt: bool,
    /// Hops the packet started with. Three bits, so 0..=7.
    ///
    /// Firmware before 2.3.0 never set this, so `hop_start == 0` means
    /// "unknown", not "zero hops". Treating it as a direct-neighbour
    /// indicator without confirming the sender's bitfield is a mistake the
    /// proto comments call out explicitly.
    pub hop_start: u8,
    /// One-byte channel hash — see [`crate::channel::channel_hash`].
    ///
    /// A hint, and a colliding one: one byte collides about once in 256. It
    /// says "worth attempting", never "belongs to this channel".
    pub channel: u8,
    /// Low byte of the next hop's node number, 0 when unset.
    pub next_hop: u8,
    /// Low byte of the relaying node's number.
    pub relay_node: u8,
}

const HOP_LIMIT_MASK: u8 = 0b0000_0111;
const WANT_ACK_BIT: u8 = 0b0000_1000;
const VIA_MQTT_BIT: u8 = 0b0001_0000;
const HOP_START_MASK: u8 = 0b1110_0000;

impl Header {
    /// Decode a header from the first [`HEADER_LEN`] bytes of a frame.
    ///
    /// Returns `None` if the input is too short. Total over every 16-byte
    /// input otherwise: every bit pattern is a header, because the wire has
    /// no reserved values here and inventing a rejection would drop frames a
    /// stock node accepts.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let head = bytes.get(..HEADER_LEN)?;
        let u32_at = |i: usize| -> Option<u32> {
            let b = head.get(i..i.checked_add(4)?)?;
            Some(u32::from_le_bytes([
                *b.first()?,
                *b.get(1)?,
                *b.get(2)?,
                *b.get(3)?,
            ]))
        };
        let flags = *head.get(12)?;
        Some(Self {
            to: u32_at(0)?,
            from: u32_at(4)?,
            id: u32_at(8)?,
            hop_limit: flags & HOP_LIMIT_MASK,
            want_ack: flags & WANT_ACK_BIT != 0,
            via_mqtt: flags & VIA_MQTT_BIT != 0,
            hop_start: (flags & HOP_START_MASK) >> 5,
            channel: *head.get(13)?,
            next_hop: *head.get(14)?,
            relay_node: *head.get(15)?,
        })
    }

    /// The packed flags byte.
    ///
    /// `hop_limit` and `hop_start` are masked to three bits rather than
    /// rejected if oversized. The wire has three bits and no more; silently
    /// corrupting a neighbouring field would be worse than clamping, and an
    /// error return would put a failure path on an encode that cannot
    /// otherwise fail.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        let mut f = self.hop_limit & HOP_LIMIT_MASK;
        if self.want_ack {
            f |= WANT_ACK_BIT;
        }
        if self.via_mqtt {
            f |= VIA_MQTT_BIT;
        }
        f |= (self.hop_start << 5) & HOP_START_MASK;
        f
    }

    /// Encode to the 16 bytes that go on the air.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let to = self.to.to_le_bytes();
        let fr = self.from.to_le_bytes();
        let id = self.id.to_le_bytes();
        [
            to[0], to[1], to[2], to[3],
            fr[0], fr[1], fr[2], fr[3],
            id[0], id[1], id[2], id[3],
            self.flags(),
            self.channel,
            self.next_hop,
            self.relay_node,
        ]
    }

    /// Whether this frame is addressed to every node.
    #[must_use]
    pub const fn is_broadcast(&self) -> bool {
        self.to == BROADCAST_ADDR
    }

    /// The header a relay would emit: one hop spent, and our relay byte.
    ///
    /// Returns `None` when no hops remain, which is the caller's signal not
    /// to forward. Everything else is carried through untouched — in
    /// particular `channel`, which stays the ORIGINATOR's hash. That is
    /// observed behaviour, not a choice: a stock node relaying traffic it
    /// cannot decrypt was seen forwarding the sender's `0x08` rather than
    /// restamping it, and the extension suite depends on that carriage.
    #[must_use]
    pub fn relayed_by(&self, our_node_num: u32) -> Option<Self> {
        // checked_sub is the hop-exhaustion test: 0 - 1 is None, which is
        // exactly "do not forward".
        let remaining = self.hop_limit.checked_sub(1)?;
        let relay = our_node_num.to_le_bytes();
        Some(Self {
            hop_limit: remaining,
            relay_node: *relay.first().unwrap_or(&0),
            ..*self
        })
    }
}
