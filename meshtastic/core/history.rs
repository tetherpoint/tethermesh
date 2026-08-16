//! Duplicate suppression: remembering which packets have already been seen.
//!
//! Managed flooding rebroadcasts a packet that still has hops left, but only
//! if this node has not already handled it. Without that memory a packet
//! circulates until every node's hop limit is spent, and on a shared medium
//! with no collision detection that is how a mesh takes itself down.
//!
//! # The key is `(from, id)`, and both halves are load-bearing
//!
//! Packet identifiers are only unique per sender. Two nodes will hold the
//! same 32-bit identifier routinely, and keying on the identifier alone would
//! suppress a stranger's packet because a neighbour happened to use the same
//! number — silent, traffic-dependent, and indistinguishable from poor range.
//!
//! # Why a ring rather than a hash table
//!
//! Eviction has to be by age: the useful memory is "the most recent N
//! packets", and a hash table has no natural answer to which entry to drop.
//! A ring gives oldest-first eviction for free.
//!
//! The cost is a linear scan per lookup. At the default preset a frame
//! occupies the air for roughly 800 ms, so the packet rate a node can
//! physically face is on the order of one per second; scanning a few hundred
//! entries against that is nothing. Predictable memory and bounded worst-case
//! work matter more on an RTOS task with a small fixed stack than average
//! asymptotics do.
//!
//! # Capacity
//!
//! [`DEFAULT_CAPACITY`] is 400, which is what the reference implementation
//! was observed to use — it logs `Packet History - Invalid size -1, using
//! default 400` when its configured size is absent. Matching it is not
//! required for interoperability, since this is a local decision, but
//! differing without reason would make behaviour diverge under load for no
//! benefit.
//!
//! # What is deliberately *not* here
//!
//! The rebroadcast decision itself. Suppression is one input to it; the
//! others are the hop limit, the contention window, duty-cycle budget — and
//! whether a node relays traffic on channels it cannot decrypt, which
//! `meshtastic/WIRE_REFERENCE.md` still records as PLAUSIBLE, UNPROVEN.
//!
//! Writing a `should_relay` here would have to take a position on that
//! question, and doing so in code is how an assumption stops looking like
//! one. This module answers only "have I seen this before?", which is
//! answerable today.

/// Entries kept by default: what the reference implementation uses.
pub const DEFAULT_CAPACITY: usize = 400;

/// Whether a packet had been seen before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    /// Not seen within the remembered window. Now recorded.
    New,
    /// Already recorded. Do not rebroadcast.
    Duplicate,
}

/// A bounded, age-evicting memory of recently seen packets.
///
/// Fixed size, no allocation, and owned by the caller — `DISTRIBUTION.md`
/// forbids mutable global state because `Send`/`Sync` do not cross an FFI
/// boundary a foreign scheduler calls into.
#[derive(Debug, Clone)]
pub struct PacketHistory<const N: usize> {
    /// `(from, id)` pairs. Only the first `len` are meaningful, which avoids
    /// needing a sentinel — `(0, 0)` is a legitimate pair and must not be
    /// confused with an empty slot.
    entries: [(u32, u32); N],
    /// Where the next entry is written; wraps.
    cursor: usize,
    /// Populated slots, saturating at `N`.
    len: usize,
}

impl<const N: usize> Default for PacketHistory<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PacketHistory<N> {
    /// An empty history.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [(0, 0); N],
            cursor: 0,
            len: 0,
        }
    }

    /// How many packets are remembered.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing is remembered yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// How many packets can be remembered at once.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Whether this packet is already remembered, without recording it.
    #[must_use]
    pub fn contains(&self, from: u32, id: u32) -> bool {
        self.entries
            .iter()
            .take(self.len)
            .any(|&entry| entry == (from, id))
    }

    /// Record a packet, reporting whether it had been seen.
    ///
    /// A duplicate is **not** re-recorded. Eviction is by age of first
    /// sighting, and refreshing on every repeat would let one chattering
    /// node's retransmissions hold its own entry alive while pushing every
    /// other node's out — which is precisely the traffic pattern under which
    /// suppression needs to keep working.
    pub fn observe(&mut self, from: u32, id: u32) -> Seen {
        if self.contains(from, id) {
            return Seen::Duplicate;
        }
        if let Some(slot) = self.entries.get_mut(self.cursor) {
            *slot = (from, id);
        }
        self.cursor = match self.cursor.checked_add(1) {
            Some(next) if next < N => next,
            _ => 0,
        };
        if self.len < N {
            self.len = self.len.saturating_add(1);
        }
        Seen::New
    }

    /// Forget everything.
    pub fn clear(&mut self) {
        self.cursor = 0;
        self.len = 0;
    }
}
