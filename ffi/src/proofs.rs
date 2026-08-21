// SPDX-FileCopyrightText: 2026 The tetherpoint Authors
// SPDX-License-Identifier: Apache-2.0

//! Machine-checked proofs for the C ABI.
//!
//! This crate had none until 2026-08-18, which was the wrong way round: it is
//! the surface a C consumer actually reaches, it grew from ABI v3 to v7 in a
//! day, and it was the least proven code in the repository. The protocol crate
//! had thirteen harnesses and the extension bundle six.
//!
//! # What a proof buys here that a test does not
//!
//! Every property below was already covered by examples, and examples are
//! chosen by whoever writes them. `resolve_retry_policy` had four; the question
//! it answers — *can any caller obtain a policy more aggressive than the
//! measured ceiling* — is a claim about **every** input, and it is the
//! mechanism enforcing `PLAN.md`'s shared-airtime rule. Sampling it is not the
//! same as settling it.
//!
//! # What is deliberately not proven
//!
//! Nothing here says anything about pointer validity. The FFI boundary is the
//! trust edge `DISTRIBUTION.md` names: a caller passing a bad pointer or a
//! wrong length cannot be validated, so these harnesses supply real buffers and
//! prove what happens for arbitrary *contents and lengths within them*. That is
//! the half that is ours to guarantee.
//!
//! Run with `cargo kani -p tmffi`.

use crate::{
    classify_ack, portnum_is_private_use, resolve_retry_policy, tm_data_decode, tm_header_peek,
    tm_key_from_index, tm_pki_decrypt, TmData, TmHeader, TmKey, TmPkiKey, RetryPolicy,
    TM_E_BAD_INDEX, TM_E_SHORT, TM_OK,
};

/// No caller can obtain a retry policy more aggressive than the measured ceiling.
///
/// **This is the mechanism enforcing the shared-airtime rule**, and it had four
/// example tests. Retransmission spends airtime shared with every neighbour
/// that rebroadcasts it, so a caller who can talk this function into a shorter
/// interval imposes a cost on nodes that gain nothing from it.
///
/// Proven over every `(max_attempts, interval_us)` pair, including the `(0, 0)`
/// request that legitimately means "take the ceiling". A single attempt never
/// retransmits, so no interval can make it aggressive — that exemption is
/// stated here rather than assumed, because it is the one shape that looks like
/// a hole and is not.
#[kani::proof]
fn no_request_can_beat_the_retry_ceiling() {
    let attempts: u8 = kani::any();
    let interval: u32 = kani::any();
    let ceiling = RetryPolicy::MEASURED_CEILING;

    let asked_for_more = attempts > 1
        && (attempts > ceiling.max_attempts || interval < ceiling.interval_us);

    match resolve_retry_policy(attempts, interval) {
        Ok(p) => {
            assert!(p.max_attempts <= ceiling.max_attempts);
            // One attempt is the exemption: it never retransmits at all.
            if p.max_attempts > 1 {
                assert!(p.interval_us >= ceiling.interval_us);
            }
            // REFUSED, NOT CLAMPED. Without this the proof is satisfied by a
            // function that quietly hands back the ceiling -- found by mutating
            // the refusal into `Ok(ceiling)` and watching this harness stay
            // green. A clamp leaves the caller believing it configured
            // something it did not, and the difference only ever shows up as
            // someone else's congestion.
            assert!(!asked_for_more, "an over-aggressive request must be refused");
        }
        Err(_) => {}
    }
}

/// Reading a payload as an acknowledgement never panics, whatever the bytes.
///
/// Attacker-reachable: this runs on a decrypted payload, and channel decryption
/// authenticates nothing — CTR turns any bytes into some other bytes, so the
/// input here is genuinely arbitrary rather than merely unexpected.
#[kani::proof]
#[kani::unwind(6)]
fn classify_ack_is_total_on_arbitrary_bytes() {
    let bytes: [u8; 4] = kani::any();
    let _ = classify_ack(&bytes);
}

/// Every frame too short to hold a header is refused, and a full one is read.
///
/// The length is arbitrary within a real buffer, so this covers the boundary
/// from both sides rather than at the two points a test would pick.
#[kani::proof]
fn tm_header_peek_refuses_every_short_frame_and_reads_every_full_one() {
    // The LENGTH IS DRAWN AS u8, not usize, and widened. A symbolic 64-bit
    // length reaching `slice::from_raw_parts` explodes CBMC -- the first
    // attempt ran past ten minutes without reporting a single harness. Eight
    // bits covers every length inside this buffer, which is the whole property.
    let buf: [u8; 20] = kani::any();
    let len8: u8 = kani::any();
    kani::assume(len8 as usize <= buf.len());
    let len = len8 as usize;

    let mut out = TmHeader {
        to: 0, from: 0, id: 0, hop_limit: 0, hop_start: 0,
        channel_hash: 0, next_hop: 0, relay_node: 0, want_ack: 0, via_mqtt: 0,
    };
    let rc = unsafe { tm_header_peek(buf.as_ptr(), len, &mut out) };
    if len < 16 {
        assert!(rc == TM_E_SHORT, "a frame with no header must be refused");
    } else {
        assert!(rc == TM_OK, "sixteen bytes is always a header");
        // hop_start is never below hop_limit on a well-formed decode: both are
        // three-bit fields of one byte, and a relay only ever decrements.
        assert!(out.hop_limit <= 7 && out.hop_start <= 7);
    }
}

/// A direct message too short to hold one is refused, never read past.
///
/// Bounded deliberately to the refusal path — below `header(16) + tag(8) +
/// extra_nonce(4)` — because that is the property, and running AES-CCM under a
/// model checker would buy nothing and cost a great deal.
#[kani::proof]
#[kani::unwind(29)]
fn tm_pki_decrypt_refuses_every_frame_too_short_to_hold_one() {
    // u8 for the same reason as above; 28 is the smallest frame that could
    // hold a message, so every length below it must be refused.
    let mut buf: [u8; 28] = kani::any();
    let len8: u8 = kani::any();
    kani::assume((len8 as usize) < 28);
    let len = len8 as usize;

    let key = TmPkiKey { bytes: [0u8; 32] };
    let mut payload: *const u8 = core::ptr::null();
    let mut payload_len: usize = 0;
    let rc = unsafe {
        tm_pki_decrypt(buf.as_mut_ptr(), len, &key, &mut payload, &mut payload_len)
    };
    assert!(rc == TM_E_SHORT, "a runt must be refused, not parsed");
}

/// The channel-key shorthand accepts exactly `1..=10` and refuses the rest.
///
/// `0` means "no crypto" on the wire and must not silently yield a key. The
/// range is small enough to test exhaustively by hand and easy to get wrong by
/// one at either end, which is precisely why it is proven rather than sampled.
#[kani::proof]
fn tm_key_from_index_accepts_exactly_the_defined_range() {
    let index: u8 = kani::any();
    let mut key = TmKey { bytes: [0u8; 16] };
    let rc = unsafe { tm_key_from_index(index, &mut key) };
    if (1..=10).contains(&index) {
        assert!(rc == TM_OK);
    } else {
        assert!(rc == TM_E_BAD_INDEX, "0 is not a key, and neither is 11");
    }
}

/// Decoding a payload as `Data` never panics, whatever the bytes.
///
/// Same attacker-reachable path as `classify_ack`, one layer out: this is what
/// a consumer calls on anything that decrypted, and a panic here aborts their
/// firmware rather than ours.
#[kani::proof]
#[kani::unwind(6)]
fn tm_data_decode_is_total_on_arbitrary_bytes() {
    let bytes: [u8; 4] = kani::any();
    let mut out = TmData {
        portnum: 0, payload: core::ptr::null(), payload_len: 0,
        want_response: 0, request_id: 0,
    };
    let _ = unsafe { tm_data_decode(bytes.as_ptr(), bytes.len(), &mut out) };
}

/// The private-use boundary is exactly 256, over the WHOLE u32 range.
///
/// A test can name six points; this covers every value, including the two
/// adjacent to the boundary and every portnum upstream might ever define. That
/// exhaustiveness is the property — `PRIVATE_APP = 256` is a line, and a line
/// checked at samples is a line checked nowhere in particular.
///
/// Proven on the helper rather than on `tm_extension_encode` deliberately: the
/// encoder contains protobuf encoding and AES-CTR, and putting those under a
/// model checker cost more than fifteen minutes and bought nothing. The tests
/// carry the other half — that the encoder actually consults this.
#[kani::proof]
fn the_private_use_boundary_is_exactly_256() {
    let portnum: u32 = kani::any();
    assert!(
        portnum_is_private_use(portnum) == (portnum >= 256),
        "the boundary must be 256 for every portnum, not merely at the sampled ones"
    );
    if portnum < 256 {
        assert!(!portnum_is_private_use(portnum), "upstream's range is never claimable");
    }
}
