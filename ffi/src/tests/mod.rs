// SPDX-FileCopyrightText: 2026 The tetherpoint Authors
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the crate root.
//!
//! # Why these live in `src/tests/` rather than inline in `lib.rs`
//!
//! The crate denies `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`
//! and `arithmetic_side_effects`, and those denies apply to a `#[cfg(test)]`
//! module compiled inside `lib.rs` too. In a test that is the wrong rule: an
//! assertion IS a panic, and `expect()` on a value the test just constructed is
//! how a broken fixture announces itself instead of silently passing.
//!
//! `tools/check_rust_rules.sh` already says so in as many words — *"Tests may
//! panic; that is what an assertion is"* — and exempts any path containing
//! `tests/`. It refuses a local `#[allow]` anywhere else, deliberately, because
//! one would silently defeat a crate-level deny. So the fix is to put the tests
//! on the side of that line the project already drew, not to punch a hole in
//! the rule from inside `lib.rs`.
//!
//! **The guarantee is untouched.** Every deny still applies in full to all
//! shipped code, and the property that actually matters is checked on the built
//! object by that same script, which never sees a test binary.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::arithmetic_side_effects)]

use super::*;
use tethermesh::delivery::acknowledgement;
use tethermesh::message::PortNum;

#[test]
fn zero_zero_takes_the_measured_ceiling() {
    let p = resolve_retry_policy(0, 0).expect("(0,0) must resolve");
    assert_eq!(p, RetryPolicy::MEASURED_CEILING);
    assert_eq!(p.max_attempts, 3);
    assert_eq!(p.interval_us, 7_000_000);
}

/// The refusal that enforces the shared-airtime rule.
#[test]
fn a_policy_more_aggressive_than_the_ceiling_is_refused_not_clamped() {
    let ceiling = RetryPolicy::MEASURED_CEILING;

    // More attempts than measured.
    assert_eq!(
        resolve_retry_policy(200, ceiling.interval_us),
        Err(TM_E_TOO_AGGRESSIVE),
        "200 attempts must be refused"
    );
    assert_eq!(
        resolve_retry_policy(ceiling.max_attempts + 1, ceiling.interval_us),
        Err(TM_E_TOO_AGGRESSIVE),
        "one more than the ceiling must be refused"
    );

    // Same attempts, shorter gap -- the subtler abuse, and the one more
    // likely to be written by someone trying to be responsive.
    assert_eq!(
        resolve_retry_policy(ceiling.max_attempts, ceiling.interval_us - 1),
        Err(TM_E_TOO_AGGRESSIVE),
        "a shorter interval is more aggressive and must be refused"
    );
    assert_eq!(
        resolve_retry_policy(2, 100_000),
        Err(TM_E_TOO_AGGRESSIVE),
        "100 ms between retries must be refused"
    );

    // And it must REFUSE, not silently hand back the ceiling. A clamp would
    // leave the caller believing it configured something it did not.
    assert!(
        resolve_retry_policy(200, 1).is_err(),
        "clamping instead of refusing is the failure this guards"
    );
}

#[test]
fn less_aggressive_than_the_ceiling_is_allowed() {
    let ceiling = RetryPolicy::MEASURED_CEILING;
    assert!(resolve_retry_policy(2, ceiling.interval_us).is_ok(), "fewer attempts");
    assert!(resolve_retry_policy(3, 30_000_000).is_ok(), "a longer gap");
    assert!(
        resolve_retry_policy(1, 0).is_ok(),
        "one attempt never retransmits, so no interval can make it aggressive"
    );
    assert!(resolve_retry_policy(1, 1).is_ok(), "same, with a nonsense interval");
}

#[test]
fn zero_attempts_with_an_interval_is_a_malformed_request() {
    assert_eq!(
        resolve_retry_policy(0, 7_000_000),
        Err(TM_E_ARG),
        "zero attempts is not 'take the default' unless the interval is zero too"
    );
}

#[test]
fn an_acknowledgement_is_recognised_and_its_status_reported() {
    let mut buf = [0u8; 64];
    let n = acknowledgement(0x1234_5678).encode(&mut buf).unwrap();
    let (req, status) = classify_ack(&buf[..n]).expect("must be recognised");
    assert_eq!(req, 0x1234_5678);
    assert_eq!(status, 0, "an acceptance");
}

/// A NAK is still an answer, and must be reported rather than swallowed.
#[test]
fn a_rejection_is_recognised_too() {
    let nak = Data {
        portnum: PortNum::ROUTING_APP.0,
        payload: &[0x18, 0x06],
        request_id: 0x0bad_c0de,
        ..Data::default()
    };
    let mut buf = [0u8; 64];
    let n = nak.encode(&mut buf).unwrap();
    let (req, status) = classify_ack(&buf[..n]).expect("a NAK is still an answer");
    assert_eq!(req, 0x0bad_c0de);
    assert_eq!(status, 6, "the measured rejection value, reported not acted on");
}

#[test]
fn things_that_are_not_acknowledgements_are_rejected() {
    // Wrong portnum.
    let text = Data {
        portnum: PortNum::TEXT_MESSAGE_APP.0,
        request_id: 0x1234_5678,
        ..Data::default()
    };
    let mut buf = [0u8; 64];
    let n = text.encode(&mut buf).unwrap();
    assert!(classify_ack(&buf[..n]).is_none(), "portnum must match");

    // Right portnum, no request_id -- refers to nothing.
    let bare = Data { portnum: PortNum::ROUTING_APP.0, ..Data::default() };
    let n = bare.encode(&mut buf).unwrap();
    assert!(classify_ack(&buf[..n]).is_none(), "request_id 0 refers to nothing");

    // Not protobuf at all. Must not panic; this is attacker-reachable.
    assert!(classify_ack(&[0xff, 0xff, 0xff, 0xff]).is_none());
    assert!(classify_ack(&[]).is_none(), "empty is not an acknowledgement");
}

#[test]
fn a_full_outbox_and_a_bad_frame_map_to_different_codes() {
    assert_eq!(map_delivery_error(DeliveryError::Full), TM_E_SHORT);
    assert_eq!(map_delivery_error(DeliveryError::BadFrame), TM_E_ARG);
    assert_ne!(map_delivery_error(DeliveryError::Full), TM_OK, "never success");
    assert_ne!(map_delivery_error(DeliveryError::BadFrame), TM_OK);
}

/// Checked against RFC 7748's own answer, not against ours.
///
/// The library's ladder already has differential oracles; what this adds is
/// the *shim*, where a wrong length or a byte-order slip would produce a
/// plausible 32 bytes that agree with nothing. A self-consistency test
/// cannot see that, which is the failure the X25519 bug in this tree
/// actually had.
#[test]
fn tm_x25519_public_matches_the_rfc_7748_vector() {
    // RFC 7748 section 6.1, Alice's key pair.
    let private = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
        0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
        0x1d, 0xb9, 0x2c, 0x2a,
    ];
    let expected = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
        0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
        0xaa, 0x9b, 0x4e, 0x6a,
    ];
    let mut out = [0u8; 32];
    let rc = unsafe { tm_x25519_public(private.as_ptr(), private.len(), out.as_mut_ptr(), 32) };
    assert_eq!(rc, TM_OK);
    assert_eq!(out, expected, "shim disagrees with RFC 7748");
}

/// A key of the wrong length is refused, never truncated or zero-padded.
///
/// Truncating would derive a public key for a *different* private key and
/// report success, so the node would publish an identity it cannot use and
/// every direct message addressed to it would fail to decrypt — with
/// nothing anywhere reporting an error.
#[test]
fn tm_x25519_public_refuses_a_key_that_is_not_32_bytes() {
    let short = [0x11u8; 16];
    let mut out = [0u8; 32];
    assert_eq!(
        unsafe { tm_x25519_public(short.as_ptr(), short.len(), out.as_mut_ptr(), 32) },
        TM_E_BAD_KEY_LEN,
    );
    assert_eq!(out, [0u8; 32], "must not have written a partial answer");

    // And an output buffer too small is short, not a silent partial write.
    let full = [0x11u8; 32];
    assert_eq!(
        unsafe { tm_x25519_public(full.as_ptr(), full.len(), out.as_mut_ptr(), 31) },
        TM_E_SHORT,
    );
}

/// The published frame must survive the round trip carrying the key intact.
///
/// `public_key` is the whole point of the frame: a peer that does not
/// receive it refuses to originate a direct message to us at all, so a
/// dropped or mangled key looks exactly like a dead link.
#[test]
fn tm_nodeinfo_encode_round_trips_and_carries_the_public_key() {
    let mut key = TmKey { bytes: [0u8; 16] };
    assert_eq!(unsafe { tm_key_from_index(1, &mut key) }, TM_OK);

    let pubkey = [0xABu8; 32];
    let id = b"!7e5701a1";
    let long = b"tethermesh";
    let short = b"tm";
    let mac = [0u8; 6];
    let user = TmUser {
        id: id.as_ptr(),
        id_len: id.len(),
        long_name: long.as_ptr(),
        long_name_len: long.len(),
        short_name: short.as_ptr(),
        short_name_len: short.len(),
        public_key: pubkey.as_ptr(),
        public_key_len: pubkey.len(),
        macaddr: mac.as_ptr(),
        macaddr_len: mac.len(),
        hw_model: 0,
        role: 0,
    };

    let mut out = [0u8; 256];
    let n = unsafe {
        tm_nodeinfo_encode(
            0x7e57_01a1,
            0xFFFF_FFFF,
            0x0bad_c0de,
            3,
            0x08,
            0,
            &key,
            &user,
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert!(n > 0, "encode failed: {n}");
    let n = usize::try_from(n).expect("length");

    let buf = out.get_mut(..n).expect("frame");
    let (header, plain) = frame::decode_in_place(buf, &key.bytes, 0).expect("decode");
    assert_eq!(header.from, 0x7e57_01a1);
    assert_eq!(header.to, 0xFFFF_FFFF);
    assert_eq!(header.hop_start, header.hop_limit, "an originated frame");
    // The low byte of `from`, per WIRE_REFERENCE.md's relay_node rule.
    assert_eq!(header.relay_node, 0xa1);

    let data = Data::decode(plain).expect("Data");
    assert_eq!(data.portnum, PortNum::NODEINFO_APP.0);
    assert!(!data.want_response);

    let profile = User::decode(data.payload).expect("User");
    assert_eq!(profile.public_key, &pubkey, "the key must survive intact");
    assert_eq!(profile.id, id);
    assert_eq!(profile.long_name, long);
    assert_eq!(profile.short_name, short);
    // Deprecated since 2.1.x and still on the wire; dropping it would
    // re-encode shorter than the reference produces.
    assert_eq!(profile.macaddr, &mac);
}

/// A `User` with no key still encodes — and is unaddressable, on purpose.
///
/// This is a real and reachable state: visible, named, and impossible to send
/// a direct message to. Encoding must not invent a key to fill the gap.
#[test]
fn a_nodeinfo_without_a_public_key_omits_the_field_rather_than_faking_one() {
    let mut key = TmKey { bytes: [0u8; 16] };
    assert_eq!(unsafe { tm_key_from_index(1, &mut key) }, TM_OK);

    let id = b"!7e5701a1";
    let user = TmUser {
        id: id.as_ptr(),
        id_len: id.len(),
        long_name: core::ptr::null(),
        long_name_len: 0,
        short_name: core::ptr::null(),
        short_name_len: 0,
        public_key: core::ptr::null(),
        public_key_len: 0,
        macaddr: core::ptr::null(),
        macaddr_len: 0,
        hw_model: 0,
        role: 0,
    };
    let mut out = [0u8; 256];
    let n = unsafe {
        tm_nodeinfo_encode(
            0x7e57_01a1, 0xFFFF_FFFF, 1, 3, 0x08, 0,
            &key, &user, out.as_mut_ptr(), out.len(),
        )
    };
    assert!(n > 0, "a keyless NodeInfo is still a valid frame: {n}");
    let n = usize::try_from(n).expect("length");
    let buf = out.get_mut(..n).expect("frame");
    let (_, plain) = frame::decode_in_place(buf, &key.bytes, 0).expect("decode");
    let data = Data::decode(plain).expect("Data");
    let profile = User::decode(data.payload).expect("User");
    assert!(profile.public_key.is_empty(), "no key must mean no field");
}
