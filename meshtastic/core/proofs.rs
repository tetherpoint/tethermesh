// SPDX-FileCopyrightText: 2026 The tethermesh Authors
// SPDX-License-Identifier: Apache-2.0

//! Machine-checked proofs, run by [Kani](https://model-checking.github.io/kani/).
//!
//! `DISTRIBUTION.md` promises that no path can panic on hostile input, and
//! `tools/check_rust_rules.sh` checks that promise by inspecting the built
//! artifact for panic machinery. That is evidence, not proof: it says the
//! compiler emitted no panic path it could see, on one target, at one
//! optimisation level.
//!
//! These harnesses prove the same property differently — **for every possible
//! input**, symbolically, rather than for the inputs a test happens to try.
//! Kani explores all of them at once, so a harness that passes has ruled out
//! panics, arithmetic overflow and out-of-bounds access on that path
//! altogether.
//!
//! Scope was originally the parse path alone. It now also covers the arithmetic
//! added for L5 — airtime, the duty budget and the contention window — because
//! those are total-function claims over wide numeric inputs, which is exactly
//! what a bounded test samples badly and a proof settles outright. The curve
//! arithmetic remains out of scope for the reason below.
//!
//! **Delivery joined that scope on 2026-08-17**, and for a different reason
//! than the rest. A retransmission defect corrupts nothing and panics nowhere —
//! it makes this node antisocial to an entire mesh. Retries spend *shared*
//! airtime, and on a flood mesh each one is rebroadcast by every neighbour that
//! hears it, so the cost multiplies by local node count and lands on nodes that
//! gain nothing. The symptom appears in somebody else's capture, not ours,
//! which is precisely the failure a bounded test is worst at catching and a
//! proof over arbitrary clocks settles.
//!
//! Scope, stated honestly. This proves things about the **parse path**, which
//! is where attacker-controlled bytes arrive and where a panic would be a
//! remote denial of service. It proves nothing about the curve arithmetic in
//! [`crate::x25519`]: proving that computes the right value is what
//! fiat-crypto and HACL* achieved with Coq and F*, at a scale this project has
//! no business reproducing. Those are separate properties, and conflating
//! them would overstate what is checked here.
//!
//! Run with `cargo kani`.
//!
//! Note there is no `#[allow]` here. The first draft carried one
//! defensively and `check_rust_rules.sh` rejected it, correctly: a proof
//! module that suspends the crate's rules is proving things about code the
//! crate would not accept.

use crate::airtime::{DutyCycle, ModemParams};
use crate::channel::channel_hash;
use crate::delivery::{Outbox, RetryPolicy};
use crate::routing::{should_relay, ContentionWindow, Observed, Relay, Role};
use crate::frame;
use crate::header::{Header, HEADER_LEN};
use crate::protobuf::Reader;

/// Decoding a header must not panic for **any** sixteen bytes.
#[kani::proof]
fn header_decode_never_panics() {
    let bytes: [u8; HEADER_LEN] = kani::any();
    let _ = Header::decode(&bytes);
}

/// A header decoded from any bytes must re-encode to exactly those bytes.
///
/// This is the round-trip gate, proven rather than sampled. It rules out an
/// endianness or bit-position error over the whole input space, not just the
/// captured frames — the class of bug that is self-consistent and only wrong
/// against the wire.
#[kani::proof]
fn header_roundtrip_is_the_identity() {
    let bytes: [u8; HEADER_LEN] = kani::any();
    if let Some(h) = Header::decode(&bytes) {
        assert!(h.encode() == bytes);
    }
}

/// Relaying either spends exactly one hop or refuses, and never alters
/// anything a relay has no business altering.
#[kani::proof]
fn relaying_spends_one_hop_and_preserves_the_rest() {
    let bytes: [u8; HEADER_LEN] = kani::any();
    let node: u32 = kani::any();
    if let Some(h) = Header::decode(&bytes) {
        match h.relayed_by(node) {
            Some(r) => {
                assert!(h.hop_limit > 0);
                assert!(r.hop_limit == h.hop_limit - 1);
                assert!(r.channel == h.channel);   // the originator's hash survives
                assert!(r.from == h.from);
                assert!(r.id == h.id);
                assert!(r.to == h.to);
                assert!(r.hop_start == h.hop_start);
            }
            None => assert!(h.hop_limit == 0),
        }
    }
}

/// A short frame is rejected rather than read past.
#[kani::proof]
#[kani::unwind(18)]
fn short_frames_are_rejected_not_read_past() {
    let len: usize = kani::any();
    kani::assume(len < HEADER_LEN);
    let bytes = [0u8; HEADER_LEN];
    if let Some(short) = bytes.get(..len) {
        assert!(Header::decode(short).is_none());
        assert!(frame::peek_header(short).is_err());
    }
}

/// The wire reader must not panic on any input, however malformed.
///
/// Bounded to eight bytes: the state machine's branches are all reachable
/// within that, and an unbounded proof would not terminate.
#[kani::proof]
#[kani::unwind(12)]
fn protobuf_reader_never_panics_on_arbitrary_bytes() {
    let bytes: [u8; 8] = kani::any();
    let mut r = Reader::new(&bytes);
    let mut steps = 0;
    while steps < 8 {
        match r.next_field() {
            Ok(Some(_)) => {}
            _ => break,
        }
        steps += 1;
    }
}

/// The channel hash is total: every input has a value and none panics.
#[kani::proof]
#[kani::unwind(10)]
fn channel_hash_is_total() {
    let name: [u8; 8] = kani::any();
    let psk: [u8; 8] = kani::any();
    let _ = channel_hash(&name, &psk);
}

// ── L5 arithmetic ──────────────────────────────────────────────────────────
// These are cheap to prove and awkward to test: the inputs are wide numeric
// ranges where a test picks a handful of values and a proof covers all of them.

/// Symbol time is total: no spreading factor or bandwidth panics it.
///
/// It refuses out-of-range inputs rather than returning a plausible wrong
/// number, and the refusal itself must not panic — this is the entry point
/// every other airtime figure is built on.
#[kani::proof]
fn symbol_time_never_panics_for_any_modem_parameters() {
    let p = ModemParams {
        spreading_factor: kani::any(),
        bandwidth_hz: kani::any(),
        coding_rate: kani::any(),
        preamble_symbols: kani::any(),
        crc: kani::any(),
        implicit_header: kani::any(),
        low_data_rate_optimize: kani::any(),
    };
    let _ = p.symbol_time_us();
}

/// Airtime is total over every payload length and every parameter set.
///
/// The payload symbol count is computed signed and clamped, because the
/// numerator goes negative for a short payload at a high spreading factor.
/// This proves that clamp holds for all of them rather than for the sizes a
/// test happened to try.
#[kani::proof]
fn airtime_never_panics_for_any_payload_or_parameters() {
    let p = ModemParams {
        spreading_factor: kani::any(),
        bandwidth_hz: kani::any(),
        coding_rate: kani::any(),
        preamble_symbols: kani::any(),
        crc: kani::any(),
        implicit_header: kani::any(),
        low_data_rate_optimize: kani::any(),
    };
    let len: u16 = kani::any();
    let _ = p.airtime_us(len);
}

/// **A charged duty cycle never exceeds its own budget.**
///
/// The property the type exists for: `charge` refuses rather than saturating,
/// so no accepted sequence can overrun.
///
/// # What is symbolic here, and what is not
///
/// The **charges are symbolic; the configuration is fixed.** An earlier version
/// left the window and permille symbolic too and did not terminate: `budget_us`
/// divides, and bit-vector division is expensive for the solver whatever the
/// operand size. Bounding the operands did not help, so the shape changed
/// rather than the bound.
///
/// That is a real narrowing and is stated rather than glossed. What remains
/// proven is the part that can actually be wrong — the guard logic in `charge`,
/// over **every** pair of charge values — at a representative 1% hourly budget.
/// The arithmetic in `budget_us` is a multiply and a divide covered by tests.
///
/// A proof that does not terminate proves nothing, and a narrower one that does
/// is worth more than an honest-looking one that hangs.
#[kani::proof]
fn a_duty_cycle_can_never_be_charged_beyond_its_budget() {
    // 1% of an hour — a real EU sub-band budget.
    let Some(mut d) = DutyCycle::new(10, 3_600_000, 0) else { return };
    let budget = d.budget_us();

    let a: u32 = kani::any();
    let b: u32 = kani::any();

    let _ = d.charge(0, a);
    assert!(d.used_us() <= budget, "one charge overran the budget");
    let _ = d.charge(0, b);
    assert!(d.used_us() <= budget, "two charges overran the budget");

    // And a refused charge must bill nothing.
    let before = d.used_us();
    let huge: u32 = kani::any();
    kani::assume(u64::from(huge) > budget);
    assert!(!d.charge(0, huge), "a charge larger than the whole budget must refuse");
    assert!(d.used_us() == before, "a refused charge must not bill airtime");
}

/// The contention window is total, and always inside its configured bounds.
///
/// Every SNR yields a window, none panics, and a degenerate configuration —
/// inverted or empty range — divides by nothing and still answers.
#[kani::proof]
fn the_contention_window_is_total_and_stays_within_its_bounds() {
    let cw = ContentionWindow {
        min_slots: kani::any(),
        max_slots: kani::any(),
        snr_floor_quarter_db: kani::any(),
        snr_ceil_quarter_db: kani::any(),
    };
    let snr: i16 = kani::any();
    let slots = cw.slots_for_snr(snr);
    if cw.min_slots <= cw.max_slots {
        assert!(slots >= cw.min_slots, "window fell below its own minimum");
        assert!(slots <= cw.max_slots, "window rose above its own maximum");
    }
}

/// The rebroadcast decision is total, and never spends a hop it did not have.
///
/// Relaying must decrement `hop_limit` by exactly one, and a frame with none
/// left must be refused — over every combination of inputs, not the handful a
/// test constructs.
#[kani::proof]
fn should_relay_is_total_and_spends_exactly_one_hop() {
    let o = Observed {
        hop_limit: kani::any(),
        snr_quarter_db: kani::any(),
        duplicate: kani::any(),
        heard_relayed: kani::any(),
        airtime_us: kani::any(),
    };
    let role = match kani::any::<u8>() % 3 {
        0 => Role::Client,
        1 => Role::Router,
        _ => Role::Repeater,
    };
    let Some(mut duty) = DutyCycle::new(1000, 60_000, 0) else { return };
    let cw = ContentionWindow::MESHTASTIC_SHAPE;

    if let Relay::After { hop_limit, .. } = should_relay(&o, role, &cw, &mut duty, 0) {
        assert!(o.hop_limit > 0, "relayed a frame with no hops left");
        assert!(hop_limit == o.hop_limit - 1, "hop limit not spent exactly once");
    }
}

/// Retransmission can never exceed the configured ceiling.
///
/// This is the airtime-safety property, and it is the one with a cost attached.
/// `PLAN.md` fixes upstream's retry behaviour as a **ceiling, never a target**,
/// because retransmission spends *shared* airtime: on a flood mesh every retry
/// is rebroadcast by every neighbour that hears it, so the cost multiplies by
/// local node count and is borne by nodes that gain nothing from it. A
/// scheduling bug here does not corrupt a frame — it makes this node antisocial
/// to an entire mesh, quietly, in a way only somebody else's capture would show.
///
/// [`Outbox::track`] records the caller's own first transmission as attempt one,
/// so [`Outbox::next_due`] may hand out at most `max_attempts - 1` further
/// frames. Proven over **arbitrary times**, including times that run backwards
/// or repeat, because nothing constrains a caller's clock and a monotonicity
/// assumption is exactly the kind a real system violates after a reboot.
#[kani::proof]
fn retransmission_never_exceeds_the_configured_ceiling() {
    let max: u8 = kani::any();
    kani::assume(max >= 1 && max <= 4);
    let interval: u32 = kani::any();

    let mut ob: Outbox<1> = Outbox::new(RetryPolicy {
        max_attempts: max,
        interval_us: interval,
    });
    // 100% of the window, so the duty budget never refuses. That is the HARDER
    // case: a budget that refused would only reduce the count and could hide a
    // ceiling defect behind an unrelated limit.
    let Some(mut duty) = DutyCycle::new(1000, 3_600_000, 0) else { return };

    let frame: [u8; HEADER_LEN] = kani::any();
    if ob.track(&frame, 0).is_err() {
        return;
    }

    // Ask more often than the ceiling could ever allow.
    let mut handed: u32 = 0;
    for _ in 0..5u8 {
        let now: u64 = kani::any();
        if ob.next_due(now, 1, &mut duty).is_some() {
            handed = handed.saturating_add(1);
        }
    }

    assert!(
        handed <= u32::from(max).saturating_sub(1),
        "the outbox handed out more transmissions than the policy allows, \
         counting the caller's own first send"
    );
}

/// An acknowledged entry is never retransmitted, and both are total.
///
/// The safety half of delivery: once an answer arrives the frame must stop, or
/// a node keeps spending shared airtime on a message that has already landed.
/// [`Outbox::acknowledge`] takes only a request id — **no status** — which is
/// what makes a rejection retire an entry exactly as an acceptance does. Proven
/// here for an arbitrary id rather than the one tracked, so an implementation
/// that retired the wrong slot, or every slot, fails.
///
/// [`Outbox::reap`] is exercised at an arbitrary time in the same harness to
/// establish it is total: it is called in a loop by callers until it answers
/// `None`, so a panic there is a hang or a crash in the retransmission path.
#[kani::proof]
fn an_acknowledged_entry_is_never_retransmitted() {
    let mut ob: Outbox<1> = Outbox::new(RetryPolicy::MEASURED_CEILING);
    let Some(mut duty) = DutyCycle::new(1000, 3_600_000, 0) else { return };

    let frame: [u8; HEADER_LEN] = kani::any();
    if ob.track(&frame, 0).is_err() {
        return;
    }
    let tracked = Header::decode(&frame).map(|h| h.id);

    // Total for ANY id, matched or not.
    let id: u32 = kani::any();
    let hit = ob.acknowledge(id);

    if hit {
        assert!(tracked == Some(id), "retired an entry the id did not name");
        assert!(ob.is_empty(), "an acknowledged outbox still holds something");
        let now: u64 = kani::any();
        assert!(
            ob.next_due(now, 1, &mut duty).is_none(),
            "retransmitted a frame that had already been acknowledged"
        );
    }

    // Total at any time, including one before the entry was tracked.
    let t: u64 = kani::any();
    let _ = ob.reap(t);
}
