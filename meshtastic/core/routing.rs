// SPDX-FileCopyrightText: 2026 The tethermesh Authors
// SPDX-License-Identifier: Apache-2.0

//! Managed flooding: the rebroadcast decision.
//!
//! `WIRE_REFERENCE.md` records what routing is: *"A node decrements
//! `hop_limit` and rebroadcasts if non-zero, but only after listening to see
//! whether someone else already did, suppressing itself if so."* Duplicate
//! suppression already lives in [`crate::history`]. This module is the rest of
//! the decision.
//!
//! # The assumption underneath, and that it is no longer an assumption
//!
//! All of this rests on stock nodes relaying traffic they cannot decrypt.
//! That was `PLAUSIBLE, UNPROVEN` for most of this project's life, and
//! `should_relay` was deliberately not written while it stood open — writing
//! it would have meant encoding a position on an open question.
//!
//! It was **settled on hardware on 2026-08-16**: two Heltec V3s, node B
//! holding a channel it could not decrypt A's traffic with, and B rebroadcast
//! anyway with `hop_limit` decremented and the originator's channel hash
//! preserved. Method and log evidence in `WIRE_REFERENCE.md`. So this module
//! now describes measured behaviour rather than a guess.
//!
//! # What is ours, and must not be mistaken for theirs
//!
//! **The mechanism is documented; the bounds were guessed, and the guess was
//! measured and found badly wrong.** The official documentation gives only the
//! direction — *"The CW size is small for a low SNR, such that nodes that are
//! further away are more likely to flood first"*.
//!
//! On 2026-08-16 a bench measurement established three things a single earlier
//! observation could not. Full record in
//! `tests/captures/contention_window.json`:
//!
//! 1. **The backoff is a random draw, not a fixed delay.** 33 relays at
//!    essentially constant SNR produced delays spread across 3332 ms. No
//!    deterministic mapping does that from a constant input. This is why
//!    [`Relay::After`] hands back a *window* rather than a wait.
//! 2. **Delays are quantised to the slot time.** All 33 were exact multiples
//!    of 28 ms, with no exceptions.
//! 3. **The window at ~6 dB SNR reaches at least 142 slots**, where this module
//!    originally guessed a maximum of 8 — wrong by more than an order of
//!    magnitude.
//!
//! **What is still ours: the low-SNR end.** The SNR axis could not be varied on
//! this bench — at ~3 m even −9 dBm leaves roughly 88 dB of margin over
//! sensitivity, so reported SNR stayed pegged across a 23 dB power sweep. So
//! `max_slots` is measured and `min_slots` is not, and the slope between them
//! is unconstrained. Measuring it needs real attenuation, not a power setting.
//!
//! A node using these values interoperates regardless — the frames are
//! identical and suppression still works — but its *timing* will not match a
//! stock node's until the low end is measured too.
//!
//! Per `DISTRIBUTION.md`, the answer to an unknown like this is our own design
//! plus a citation of the wire behaviour it implements — never a read of their
//! source.

use crate::airtime::{DutyCycle, Micros};

/// How a node participates in flooding.
///
/// `WIRE_REFERENCE.md`: *"ROUTER and REPEATER roles rebroadcast regardless of
/// hearing others."* That is the only role distinction this module needs, and
/// it is the one that changes the decision rather than merely the timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// An ordinary node. Defers to anyone already heard relaying the frame.
    Client,
    /// Infrastructure. Rebroadcasts even having heard another node do so.
    Router,
    /// Infrastructure, as [`Role::Router`] for this decision.
    Repeater,
}

impl Role {
    /// Whether hearing someone else relay the frame suppresses us.
    #[must_use]
    pub fn defers_to_others(self) -> bool {
        matches!(self, Self::Client)
    }
}

/// The SNR-scaled contention window.
///
/// Slots are counted, not milliseconds: slot duration is a modem-parameter
/// property (28 ms at LongFast, per `WIRE_REFERENCE.md`) and belongs to the
/// caller's radio layer, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentionWindow {
    /// Window at or below [`Self::snr_floor_quarter_db`], in slots.
    pub min_slots: u8,
    /// Window at or above [`Self::snr_ceil_quarter_db`], in slots.
    pub max_slots: u8,
    /// SNR at or below which the window is [`Self::min_slots`], quarter-dB.
    pub snr_floor_quarter_db: i16,
    /// SNR at or above which the window is [`Self::max_slots`], quarter-dB.
    pub snr_ceil_quarter_db: i16,
}

impl ContentionWindow {
    /// The documented shape, with the **high-SNR end now measured** and the
    /// low-SNR end still ours.
    ///
    /// # This was wrong, and measurement caught it
    ///
    /// The first version of this constant used `max_slots: 8`. On 2026-08-16 a
    /// bench measurement observed a stock node drawing **up to 142 slots** at
    /// roughly 6 dB SNR — wrong by more than an order of magnitude. The
    /// documented *direction* was right; the *scale* was a guess, and the guess
    /// was bad. Recorded rather than quietly corrected, because it is the
    /// clearest illustration in this crate of what an unmeasured parameter is
    /// worth.
    ///
    /// # What is measured and what is not
    ///
    /// 33 relays observed at 5.50–6.75 dB gave slot draws spanning 23–142,
    /// mean 79.8, consistent with a uniform draw over roughly 17–143 slots.
    /// `max_slots` is set from that. With 33 samples the true bound is likely a
    /// little above the largest draw, so 143 is a lower bound presented as a
    /// value.
    ///
    /// **`min_slots` is still not measured.** The SNR axis could not be varied:
    /// at ~3 m even −9 dBm leaves ~88 dB of margin over sensitivity, so
    /// reported SNR stayed pegged across a 23 dB power sweep. Measuring the
    /// low-SNR end needs real attenuation, not a power setting. See
    /// `tests/captures/contention_window.json`.
    pub const MESHTASTIC_SHAPE: Self = Self {
        // NOT MEASURED. The documented direction says the window is small for a
        // weak signal; how small is unknown.
        min_slots: 8,
        // Measured: largest observed draw at ~6 dB SNR, +1.
        max_slots: 143,
        snr_floor_quarter_db: -80,
        snr_ceil_quarter_db: 40,
    };

    /// Width of the contention window for a received frame's SNR, in slots.
    ///
    /// The caller draws uniformly in `[0, result)`. This is not a delay.
    ///
    /// **Small window for weak signal.** A distant node hears the originator
    /// faintly, draws a short backoff and relays early; a near node waits and
    /// usually hears the relay first, suppressing itself. The effect is that a
    /// frame travels outward rather than being re-sent by whoever is closest,
    /// which is what makes this managed flooding instead of a broadcast storm.
    ///
    /// Clamps outside the configured range rather than extrapolating, and is
    /// total: every SNR yields a window, and none panics.
    #[must_use]
    pub fn slots_for_snr(&self, snr_quarter_db: i16) -> u8 {
        let (lo, hi) = (self.min_slots, self.max_slots);
        if snr_quarter_db <= self.snr_floor_quarter_db {
            return lo;
        }
        if snr_quarter_db >= self.snr_ceil_quarter_db {
            return hi;
        }
        // Degenerate configuration: an inverted or empty SNR range. Return the
        // widest window rather than dividing by zero — the conservative
        // direction, since a large window defers.
        let span = self
            .snr_ceil_quarter_db
            .saturating_sub(self.snr_floor_quarter_db);
        if span <= 0 || hi < lo {
            return hi;
        }
        let offset = snr_quarter_db.saturating_sub(self.snr_floor_quarter_db);
        let slot_span = u32::from(hi.saturating_sub(lo));
        let scaled = u32::try_from(offset)
            .unwrap_or(0)
            .saturating_mul(slot_span)
            .checked_div(u32::try_from(span).unwrap_or(1))
            .unwrap_or(0);
        u8::try_from(u32::from(lo).saturating_add(scaled)).unwrap_or(hi)
    }
}

/// Why a frame will not be relayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suppressed {
    /// `hop_limit` reached zero. The frame has travelled as far as its
    /// originator allowed.
    HopLimitExhausted,
    /// This `(from, id)` has been seen before — [`crate::history`].
    Duplicate,
    /// Another node was already heard relaying it, and this role defers.
    AlreadyRelayedByAnother,
    /// Relaying would exceed the duty-cycle budget.
    ///
    /// **Distinct from the others on purpose.** The rest are properties of the
    /// frame and would suppress it on any node; this one is a property of
    /// *this* node's recent transmissions, and the same frame arriving a
    /// minute later may well be relayed. Conflating them would make a busy
    /// node look like a loop-suppressing one.
    DutyBudgetExhausted,
}

/// The outcome of the rebroadcast decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relay {
    /// Relay after a backoff drawn from this many contention slots.
    ///
    /// # This is a WINDOW, not a wait
    ///
    /// The caller must **draw uniformly in `[0, window_slots)`** and wait that
    /// many slots. It is not a delay to sit out verbatim.
    ///
    /// That distinction was a real defect here until 2026-08-16. This variant
    /// originally carried a field named `slots` documented as the number to
    /// wait, which is deterministic — and a deterministic backoff defeats the
    /// entire mechanism, because every node hearing a frame at similar SNR
    /// would transmit at the same instant and collide rather than suppress.
    /// Measurement settled it: 33 relays observed at essentially fixed SNR
    /// produced delays spread over 3332 ms, which no deterministic mapping can
    /// produce from a constant input.
    ///
    /// **The draw belongs to the caller because this crate has no entropy.**
    /// `DISTRIBUTION.md` forbids global state and this is `no_std` with no RNG;
    /// inventing one here would be worse than handing the caller a window.
    ///
    /// The caller converts slots to time using its own slot duration — measured
    /// at 28 ms for LongFast, and every observed delay was an exact multiple of
    /// it — and must re-check for another node's relay while waiting. The wait
    /// is what makes suppression possible, so skipping it defeats the point.
    After {
        /// Width of the contention window, in slots. Draw uniformly in
        /// `[0, window_slots)`; do not wait this value directly.
        window_slots: u8,
        /// `hop_limit` already decremented, to write into the relayed frame.
        hop_limit: u8,
    },
    /// Do not relay.
    No(Suppressed),
}

/// What the caller already knows about a received frame.
#[derive(Debug, Clone, Copy)]
pub struct Observed {
    /// `hop_limit` as received, before decrement.
    pub hop_limit: u8,
    /// Receive SNR in quarter-dB, as the radio reported it.
    pub snr_quarter_db: i16,
    /// Whether [`crate::history`] has seen this `(from, id)`.
    pub duplicate: bool,
    /// Whether another node has already been heard relaying this frame.
    pub heard_relayed: bool,
    /// Airtime relaying would cost, from [`crate::airtime`].
    pub airtime_us: Micros,
}

/// Decide whether to rebroadcast, and after how long.
///
/// **This does not charge the duty budget.** It checks it. The caller charges
/// on actual transmission via [`DutyCycle::charge`], because the wait may end
/// in suppression after hearing another node — and charging for a frame that
/// was never sent would throttle a node for staying quiet, which is precisely
/// backwards.
///
/// Checks run cheapest-first and in the order that yields the most accurate
/// reason: a duplicate is a duplicate whether or not the budget is full.
#[must_use]
pub fn should_relay(
    observed: &Observed,
    role: Role,
    window: &ContentionWindow,
    duty: &mut DutyCycle,
    now_us: u64,
) -> Relay {
    if observed.duplicate {
        return Relay::No(Suppressed::Duplicate);
    }
    let Some(hop_limit) = observed.hop_limit.checked_sub(1) else {
        return Relay::No(Suppressed::HopLimitExhausted);
    };
    if observed.hop_limit == 0 {
        return Relay::No(Suppressed::HopLimitExhausted);
    }
    if observed.heard_relayed && role.defers_to_others() {
        return Relay::No(Suppressed::AlreadyRelayedByAnother);
    }
    if !duty.would_permit(now_us, observed.airtime_us) {
        return Relay::No(Suppressed::DutyBudgetExhausted);
    }
    Relay::After {
        window_slots: window.slots_for_snr(observed.snr_quarter_db),
        hop_limit,
    }
}
