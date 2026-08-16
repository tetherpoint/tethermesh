// SPDX-FileCopyrightText: 2026 The tethermesh Authors
// SPDX-License-Identifier: Apache-2.0

//! Acknowledgement and retransmission.
//!
//! # Why this is here and not above
//!
//! It is tempting to call delivery an application concern. It is not: `want_ack`
//! is a bit in the frame header this crate already parses, `ROUTING` is
//! portnum 5, and the reference's own routing description falls back *"to
//! flooding on the final retry"*. Delivery is part of the protocol.
//!
//! Nor does anything below supply it. LoRa gives forward error correction and a
//! CRC — it repairs some corrupted symbols and detects the rest — and **no ARQ
//! whatsoever**. A frame lost beyond FEC's reach is lost silently. Flood
//! routing raises the odds of arrival by redundancy; that is not delivery
//! confirmation, and treating it as one is the mistake this module exists to
//! prevent.
//!
//! # Everything here was measured, and the measurements are why
//!
//! `tests/captures/retry_behaviour.json` and `tests/captures/routing_ack.json`
//! hold the captures. Two of the findings would not have been reached by
//! reasoning:
//!
//! **Success is `Routing` field 3 = 0, encoded explicitly** — the two bytes
//! `18 00`. proto3 normally omits a zero varint, so an acknowledgement built
//! from first principles carries an *empty* payload. That is [`ACK_PAYLOAD`],
//! and it is a literal rather than something generated.
//!
//! **The acknowledgement is returned channel-encrypted even when the message it
//! acknowledges was PKI.** The reply does not inherit the request's encryption
//! mode. That is the caller's business, but it is the sort of thing that fails
//! looking like a radio fault.
//!
//! # Where our policy deliberately differs, and why each is safe
//!
//! `PLAN.md` fixes the rule: upstream's policy is a **ceiling, never a target**,
//! because retransmission spends *shared* airtime and on a flood mesh each retry
//! is rebroadcast by every neighbour that hears it, so the cost multiplies by
//! local node count. Less aggressive is always safe. More is antisocial.
//!
//! - **We resend the stored frame verbatim; upstream re-encrypts each attempt.**
//!   Safe: nonce reuse only endangers *different* plaintexts, and identical
//!   plaintext under an identical nonce simply reproduces the same ciphertext.
//!   It also costs less state, and a receiver cannot tell — it drops the
//!   repeated `(from, id)` as a duplicate either way.
//! - **We do not set `want_ack` on our own acknowledgements; upstream does.**
//!   Doing so means retransmitting acknowledgements that nobody acknowledges,
//!   which spends shared airtime for no delivery benefit.
//!
//! # What is deliberately not encoded here
//!
//! Whether retry behaviour changes across hops. The reference documents next-hop
//! routing falling back to flooding on the final retry, which implies the
//! routing *mode* varies by attempt. The measurement could not see it: the
//! header was byte-identical across all three attempts — but the bench has two
//! nodes, so there is no multi-hop path for next-hop routing to engage on.
//! **No position is taken until a third node settles it.**

use crate::frame::{self, MAX_FRAME};
use crate::header::{Header, HEADER_LEN};
use crate::message::{Data, PortNum, Routing, RoutingStatus};

/// The `Routing` payload for a successful acknowledgement: field 3, varint 0.
///
/// **A literal, because it must be.** Measured from a stock node on
/// 2026-08-16, which encodes the zero explicitly rather than omitting it as
/// proto3 would normally do. Generating this through the writer would produce
/// an empty payload and, on the evidence available, would not be recognised.
pub const ACK_PAYLOAD: [u8; 2] = [0x18, 0x00];

/// How many times to send, and how long to wait between attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total transmissions including the first. One means never retransmit.
    pub max_attempts: u8,
    /// Gap between attempts, in microseconds.
    pub interval_us: u32,
}

impl RetryPolicy {
    /// What a stock node was measured doing: three attempts, roughly seven
    /// seconds apart.
    ///
    /// **This is a ceiling, not a recommendation.** Observed intervals ranged
    /// 6.38–7.67 s over eight samples across four trials; whether that spread
    /// is deliberate randomisation or the contention window leaking into the
    /// retry timer was *not* established, so no jitter is reproduced here.
    /// A caller wanting to be a better neighbour should reduce
    /// [`Self::max_attempts`] or lengthen [`Self::interval_us`], never the
    /// reverse.
    pub const MEASURED_CEILING: Self = Self {
        max_attempts: 3,
        interval_us: 7_000_000,
    };

    /// Send once and do not retransmit. Useful for a node that must not add
    /// load, and the safe default for anything unsure.
    pub const SEND_ONCE: Self = Self {
        max_attempts: 1,
        interval_us: 0,
    };
}

/// Why an entry could not be queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// No free slot. The outbox is a fixed-capacity array by design; growing it
    /// would mean allocating.
    Full,
    /// The frame is too short to carry a header, or longer than [`MAX_FRAME`].
    BadFrame,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Free,
    Pending,
}

#[derive(Clone, Copy)]
struct Slot {
    state: State,
    from: u32,
    id: u32,
    attempts: u8,
    due_us: u64,
    len: u16,
    frame: [u8; MAX_FRAME],
}

impl Slot {
    const EMPTY: Self = Self {
        state: State::Free,
        from: 0,
        id: 0,
        attempts: 0,
        due_us: 0,
        len: 0,
        frame: [0; MAX_FRAME],
    };
}

/// A frame due for retransmission.
#[derive(Debug)]
pub struct Due<'a> {
    /// The stored frame, to put on the air unchanged.
    pub frame: &'a [u8],
    /// Which attempt this is, counting the original as one.
    pub attempt: u8,
}

/// Pending transmissions awaiting acknowledgement.
///
/// # Caller-owned, fixed capacity, and no clock
///
/// `N` slots, each holding a whole frame — roughly `N * 260` bytes — so the
/// caller chooses the cost. `DISTRIBUTION.md` forbids allocation and mutable
/// global state, and every time-dependent method takes `now_us` for the same
/// reason [`crate::airtime::DutyCycle`] does: a `no_std` library cannot
/// portably know the time, and a hidden clock would be untestable.
pub struct Outbox<const N: usize> {
    slots: [Slot; N],
    policy: RetryPolicy,
}

impl<const N: usize> Outbox<N> {
    /// An empty outbox using `policy`.
    #[must_use]
    pub const fn new(policy: RetryPolicy) -> Self {
        Self {
            slots: [Slot::EMPTY; N],
            policy,
        }
    }

    /// How many slots are in use.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.state == State::Pending).count()
    }

    /// Whether nothing is pending.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Track a frame that has **already been transmitted once**.
    ///
    /// The first transmission is the caller's, so its airtime is charged by the
    /// caller. This records the frame so later attempts can be made, and is a
    /// no-op beyond storage if the policy allows only one attempt.
    ///
    /// # Errors
    ///
    /// [`Error::BadFrame`] for a frame that cannot hold a header or exceeds
    /// [`MAX_FRAME`]; [`Error::Full`] when every slot is in use.
    pub fn track(&mut self, frame: &[u8], now_us: u64) -> Result<(), Error> {
        if frame.len() < HEADER_LEN || frame.len() > MAX_FRAME {
            return Err(Error::BadFrame);
        }
        let header = Header::decode(frame).ok_or(Error::BadFrame)?;
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.state == State::Free)
            .ok_or(Error::Full)?;

        slot.state = State::Pending;
        slot.from = header.from;
        slot.id = header.id;
        slot.attempts = 1;
        slot.due_us = now_us.saturating_add(u64::from(self.policy.interval_us));
        slot.len = u16::try_from(frame.len()).map_err(|_| Error::BadFrame)?;
        for (d, s) in slot.frame.iter_mut().zip(frame.iter()) {
            *d = *s;
        }
        Ok(())
    }

    /// Retire the entry an acknowledgement refers to.
    ///
    /// Returns whether anything matched. An unmatched acknowledgement is
    /// ordinary — it may be for a frame already retired, or for another node —
    /// and is not an error.
    pub fn acknowledge(&mut self, request_id: u32) -> bool {
        let mut hit = false;
        for s in &mut self.slots {
            if s.state == State::Pending && s.id == request_id {
                s.state = State::Free;
                hit = true;
            }
        }
        hit
    }

    /// Drop entries that have used every attempt and waited out the last
    /// interval, returning `(from, id)` for one of them.
    ///
    /// Call until it returns `None`. Reported rather than discarded silently,
    /// because "we gave up" is information the layer above usually wants.
    pub fn reap(&mut self, now_us: u64) -> Option<(u32, u32)> {
        for s in &mut self.slots {
            if s.state == State::Pending
                && s.attempts >= self.policy.max_attempts
                && now_us >= s.due_us
            {
                s.state = State::Free;
                return Some((s.from, s.id));
            }
        }
        None
    }

    /// The next frame due for retransmission, if the duty budget allows it.
    ///
    /// **Marks the attempt and schedules the next**, so a caller that takes a
    /// frame must transmit it. **Does not charge the duty budget** — the caller
    /// charges on actual transmission, matching
    /// [`crate::routing::should_relay`]. Charging here would bill a node for a
    /// frame it had not sent.
    ///
    /// Returns `None` when nothing is due, everything is exhausted (see
    /// [`Self::reap`]), or the budget would not permit the airtime.
    pub fn next_due(
        &mut self,
        now_us: u64,
        airtime_us: crate::airtime::Micros,
        duty: &mut crate::airtime::DutyCycle,
    ) -> Option<Due<'_>> {
        let interval = u64::from(self.policy.interval_us);
        let max = self.policy.max_attempts;

        let idx = self.slots.iter().position(|s| {
            s.state == State::Pending && s.attempts < max && now_us >= s.due_us
        })?;

        if !duty.would_permit(now_us, airtime_us) {
            return None;
        }

        let slot = self.slots.get_mut(idx)?;
        slot.attempts = slot.attempts.saturating_add(1);
        slot.due_us = now_us.saturating_add(interval);
        let len = usize::from(slot.len);
        Some(Due {
            frame: slot.frame.get(..len)?,
            attempt: slot.attempts,
        })
    }
}

/// Build the `Data` for a positive acknowledgement of `request_id`.
///
/// `want_ack` is deliberately **not** requested on it — see the module note.
/// The caller frames and encrypts this; measurement shows the reply travels
/// channel-encrypted even when acknowledging a PKI message.
#[must_use]
pub fn acknowledgement(request_id: u32) -> Data<'static> {
    Data {
        portnum: PortNum::ROUTING_APP.0,
        payload: &ACK_PAYLOAD,
        request_id,
        ..Data::default()
    }
}

/// What an incoming acknowledgement refers to, and what it says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Acknowledgement {
    /// The packet id being answered.
    pub request_id: u32,
    /// The status. **A rejection retires the pending entry exactly as an
    /// acceptance does** — either way no further retransmission will help — so
    /// this is for the caller to report, not for the outbox to act on.
    pub status: RoutingStatus,
}

/// Read an incoming message as an acknowledgement, if it is one.
///
/// **Matching needs only `portnum` and `request_id`**, both long since
/// verified. Reading the *status* additionally decodes [`Routing`], whose
/// field 3 this project established by capture; a payload that fails to decode
/// still matches, reported as accepted, because the identity of the frame
/// being answered does not depend on the body parsing.
#[must_use]
pub fn acknowledges(data: &Data<'_>) -> Option<Acknowledgement> {
    if data.portnum != PortNum::ROUTING_APP.0 || data.request_id == 0 {
        return None;
    }
    let status = Routing::decode(data.payload)
        .map(|r| r.status)
        .unwrap_or(RoutingStatus::ACCEPTED);
    Some(Acknowledgement { request_id: data.request_id, status })
}

/// Whether a received frame is addressed to us and asks to be acknowledged.
#[must_use]
pub fn wants_acknowledgement(frame: &[u8], our_node_num: u32) -> bool {
    frame::peek_header(frame).is_ok_and(|h| h.want_ack && h.to == our_node_num)
}
