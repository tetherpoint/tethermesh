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
//! **The contention-window *mechanism* is documented; its *bounds* are not.**
//! The official documentation states the direction — *"The CW size is small
//! for a low SNR, such that nodes that are further away are more likely to
//! flood first"* — and that is all any primary source read so far provides.
//! The actual `CW_MIN`/`CW_MAX`, and the SNR range they map across, have
//! **never been observed**.
//!
//! So [`ContentionWindow::MESHTASTIC_SHAPE`] is **our** parameterisation. It
//! reproduces the documented direction and nothing more. Two consequences,
//! both stated rather than buried:
//!
//! - A node using these values interoperates — the frames are identical and
//!   suppression still works — but its *timing* will not match a stock node's,
//!   so it may win or lose races it would otherwise have lost or won.
//! - Nothing here may be cited as evidence of what upstream does. Settling it
//!   needs a capture of several nodes relaying one frame, timed. That is
//!   recorded as an open item in `WIRE_REFERENCE.md`.
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
    /// **Our** parameterisation of the documented shape. See the module note:
    /// the direction is upstream's, these numbers are not.
    ///
    /// SNR is quarter-dB signed, the unit `WIRE_REFERENCE.md` established from
    /// a traceroute reply carrying `snr_towards: [26]` for 6.5 dB. The range
    /// spans −20 dB (`-80`) to +10 dB (`40`), which covers the usable span of
    /// these spreading factors comfortably at both ends.
    pub const MESHTASTIC_SHAPE: Self = Self {
        min_slots: 2,
        max_slots: 8,
        snr_floor_quarter_db: -80,
        snr_ceil_quarter_db: 40,
    };

    /// Window size for a received frame's SNR, in slots.
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
    /// Relay after waiting this many contention slots.
    ///
    /// The caller converts slots to time using its own slot duration and must
    /// re-check for another node's relay while waiting — the wait is what
    /// makes suppression possible, so skipping it defeats the mechanism.
    After {
        /// Contention slots to wait before transmitting.
        slots: u8,
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
        slots: window.slots_for_snr(observed.snr_quarter_db),
        hop_limit,
    }
}
