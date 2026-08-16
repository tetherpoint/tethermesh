// SPDX-FileCopyrightText: 2026 The tethermesh Authors
// SPDX-License-Identifier: Apache-2.0

//! Packet identifiers, and why they are a security concern rather than hygiene.
//!
//! # The problem
//!
//! Channel traffic is encrypted with AES-CTR, and the counter block is
//! derived from the packet identifier together with the sender. Reuse a
//! `(packet_id, sender)` pair and the same keystream is produced twice; the
//! XOR of the two ciphertexts is then the XOR of the two plaintexts, and the
//! key is not needed to compute it.
//!
//! `meshtastic/WIRE_REFERENCE.md` records that this is worse than a
//! confidentiality loss. The published documentation states that an attacker
//! who can deduce one plaintext can reuse the node number and packet
//! identifier to forge messages **without knowing the PSK**. So a repeated
//! identifier is not a privacy bug, it is a forgery primitive.
//!
//! The identifier is 32 bits. That is the entire budget.
//!
//! # Why a counter, and why persistence is the hard part
//!
//! Random identifiers collide by the birthday bound: at 32 bits, a node has
//! roughly a 50% chance of a collision after about 77,000 packets, which a
//! busy node reaches. A counter cannot collide at all until it wraps, so this
//! is a counter.
//!
//! The difficulty is restart. A counter held only in RAM restarts at its
//! seed and reissues every identifier it already used, which is the worst
//! case rather than an edge case. So the counter must persist — but writing
//! storage on every packet is not acceptable on a device whose flash has a
//! finite erase budget.
//!
//! The resolution is to persist a **high-water mark** ahead of use, in
//! blocks. Identifiers are only ever issued below a value already durably
//! stored, so a power loss at any instant can lose at most the unissued
//! remainder of a block — never an identifier that was actually used. The
//! cost is skipped identifiers, which are free, in exchange for one write per
//! block rather than one per packet.
//!
//! # Why this type does not own the storage or the entropy
//!
//! `DISTRIBUTION.md` puts all state in a caller-owned context and forbids
//! mutable global state, because `Send`/`Sync` do not cross an FFI boundary
//! that a foreign RTOS scheduler calls into. It also forbids allocation. A
//! library that opened a file or seeded itself from a global RNG would be
//! wrong on every one of those counts, and would be untestable besides.
//!
//! So the caller owns both, and the API makes the persistence obligation
//! impossible to skip by accident: [`PacketIdSource::issue`] returns
//! [`NextId::PersistFirst`] rather than an identifier when the high-water
//! mark must be written, and issues nothing until it is told the write
//! happened.

/// How many identifiers are reserved per durable write.
///
/// Larger means fewer writes and more identifiers skipped by an unclean
/// restart; smaller means the reverse. 256 spends about 1/16,777,216 of the
/// identifier space per restart, which is negligible against the 32-bit
/// budget, while reducing writes by more than two orders of magnitude.
pub const DEFAULT_BLOCK: u32 = 256;

/// What [`PacketIdSource::issue`] produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextId {
    /// An identifier safe to transmit.
    Ready(u32),
    /// Nothing was issued. Store `high_water` durably, call
    /// [`PacketIdSource::persisted`], then ask again.
    ///
    /// Returned rather than silently issuing, because an identifier handed
    /// out before its high-water mark is durable is exactly the identifier
    /// that gets reissued after an unclean restart.
    PersistFirst {
        /// The value to store.
        high_water: u32,
    },
    /// The 32-bit space is exhausted for this node.
    ///
    /// Reported rather than wrapped. Wrapping would silently reissue every
    /// identifier from the beginning, which is the failure this whole type
    /// exists to prevent — and a node that stops identifying packets is a
    /// visibly broken node, which is a better outcome than one that quietly
    /// starts leaking plaintext XORs.
    Exhausted,
}

/// Issues packet identifiers that never repeat, including across restarts.
///
/// Holds no storage and no entropy source; see the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketIdSource {
    next: u32,
    block_end: u32,
    block: u32,
}

impl PacketIdSource {
    /// Resume from a durably stored high-water mark.
    ///
    /// `high_water` is the last value passed to [`Self::persisted`] and
    /// actually written, or the seed on first ever start. Identifiers resume
    /// at that point, so anything below it is never reissued.
    ///
    /// On a genuinely first start the caller should seed `high_water` from
    /// entropy rather than zero. Not for collision resistance — a counter
    /// does not collide — but because a node whose identifiers begin at zero
    /// on every fresh install announces its restart to anyone listening, and
    /// makes the next identifier predictable to an attacker who wants a
    /// specific counter block.
    #[must_use]
    pub const fn resume(high_water: u32, block: u32) -> Self {
        Self {
            next: high_water,
            block_end: high_water,
            block: if block == 0 { DEFAULT_BLOCK } else { block },
        }
    }

    /// Resume with [`DEFAULT_BLOCK`].
    #[must_use]
    pub const fn resume_default(high_water: u32) -> Self {
        Self::resume(high_water, DEFAULT_BLOCK)
    }

    /// Issue the next identifier, or say what must happen before one can be.
    ///
    /// Named `issue` rather than `next` deliberately: it is not an iterator,
    /// it has a persistence protocol, and a caller who assumed iterator
    /// semantics would ignore the outcome that matters.
    pub fn issue(&mut self) -> NextId {
        if self.next < self.block_end {
            let id = self.next;
            // Cannot overflow: `next < block_end <= u32::MAX`.
            self.next = self.next.saturating_add(1);
            return NextId::Ready(id);
        }
        match self.next.checked_add(self.block) {
            Some(high_water) => NextId::PersistFirst { high_water },
            // A final short block rather than refusing early, so the whole
            // space is usable.
            None if self.next < u32::MAX => NextId::PersistFirst {
                high_water: u32::MAX,
            },
            None => NextId::Exhausted,
        }
    }

    /// Record that `high_water` has been durably stored.
    ///
    /// Ignores a value that is not ahead of what is already reserved, so a
    /// replayed or stale confirmation cannot move the mark backwards and
    /// re-open identifiers that were already issued.
    pub fn persisted(&mut self, high_water: u32) {
        if high_water > self.block_end {
            self.block_end = high_water;
        }
    }

    /// The identifier that would be issued next, for inspection and tests.
    #[must_use]
    pub const fn peek(&self) -> u32 {
        self.next
    }

    /// The reservation currently backed by durable storage.
    #[must_use]
    pub const fn reserved_until(&self) -> u32 {
        self.block_end
    }
}
