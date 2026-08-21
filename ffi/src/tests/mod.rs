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

// ── PKI direct messages ─────────────────────────────────────────────────────

/// The committed capture, read through the same fixture the protocol crate
/// uses. Deliberately not a copy: a second copy of a vector drifts from the
/// first, and then two tests disagree about what the reference actually did.
fn pki_record() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/captures/pki_dm_record.json"
    ))
    .expect("pki_dm_record.json")
}

fn field_hex(doc: &str, name: &str) -> Vec<u8> {
    let at = doc.find(&format!("\"{name}\"")).expect("field present");
    let rest = &doc[at..];
    let open = rest.find(':').expect("colon");
    let q1 = rest[open..].find('"').expect("open quote") + open + 1;
    let q2 = rest[q1..].find('"').expect("close quote") + q1;
    let hex = &rest[q1..q2];
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

/// The shared secret from the bench exchange whose both halves we held.
/// Recorded in `pki_dm_record.json`'s prose; the derived key it produces was
/// independently reported by the reference node's own log as `d8 85 d2 24 …`.
const BENCH_SHARED: &str = "b82315ffc2c374aba1ee1b290a7d4823a1837049920f9821b34a4dfd0a8f3d60";

fn bench_key() -> TmPkiKey {
    let shared: Vec<u8> = (0..BENCH_SHARED.len() / 2)
        .map(|i| u8::from_str_radix(&BENCH_SHARED[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    TmPkiKey { bytes: sha256(&shared) }
}

/// The ABI opens a direct message a real node actually sent.
///
/// This is the whole scheme at once: if it decrypts, the KDF, the key size, the
/// nonce layout, the tag length and the payload framing are simultaneously
/// right. Checked against their bytes, not against our encoder.
#[test]
fn tm_pki_decrypt_opens_a_real_captured_direct_message() {
    let doc = pki_record();
    let mut frame = field_hex(&doc, "frame_hex");
    let key = bench_key();
    // The reference node logged the first eight bytes of the key it derived.
    assert_eq!(
        &key.bytes[..8],
        &[0xd8, 0x85, 0xd2, 0x24, 0xe6, 0xcc, 0x3d, 0xe0],
        "our KDF must reproduce the key their firmware reported"
    );

    assert_eq!(unsafe { tm_is_pki(frame.as_ptr(), frame.len()) }, 1);

    let mut payload: *const u8 = core::ptr::null();
    let mut payload_len: usize = 0;
    let rc = unsafe {
        tm_pki_decrypt(frame.as_mut_ptr(), frame.len(), &key, &mut payload, &mut payload_len)
    };
    assert_eq!(rc, TM_OK, "a genuine message must open");

    let plain = unsafe { slice::from_raw_parts(payload, payload_len) };
    let data = Data::decode(plain).expect("plaintext parses as Data");
    assert_eq!(data.portnum, 1, "TEXT_MESSAGE_APP");
    assert_eq!(data.payload, b"pki-probe-B");
}

/// A forged message is refused, and refused with its own code.
///
/// The property channel encryption does not have. Every flipped byte must fail
/// the tag rather than yield plausible bytes — and it must not be reported as a
/// short buffer or a bad argument, because a caller distinguishing "someone is
/// lying to me" from "I passed the wrong length" is the entire point.
#[test]
fn tm_pki_decrypt_refuses_a_tampered_message() {
    let doc = pki_record();
    let key = bench_key();
    for flip in [0usize, 5, 16, 20] {
        let mut frame = field_hex(&doc, "frame_hex");
        frame[16 + flip] ^= 0x01;
        let mut payload: *const u8 = core::ptr::null();
        let mut payload_len: usize = 0;
        assert_eq!(
            unsafe {
                tm_pki_decrypt(frame.as_mut_ptr(), frame.len(), &key, &mut payload, &mut payload_len)
            },
            TM_E_UNAUTHENTIC,
            "flipping payload byte {flip} must fail the tag"
        );
    }
    // A wrong key must also fail the tag, not merely produce garbage.
    let mut frame = field_hex(&doc, "frame_hex");
    let wrong = TmPkiKey { bytes: [0u8; 32] };
    let mut payload: *const u8 = core::ptr::null();
    let mut payload_len: usize = 0;
    assert_eq!(
        unsafe {
            tm_pki_decrypt(frame.as_mut_ptr(), frame.len(), &wrong, &mut payload, &mut payload_len)
        },
        TM_E_UNAUTHENTIC,
    );
}

/// Agreement is symmetric, and it is the RFC's key pair on both sides.
#[test]
fn tm_pki_agree_is_symmetric_over_the_rfc_7748_pair() {
    // RFC 7748 section 6.1.
    let a_priv = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    let b_priv = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];
    let mut a_pub = [0u8; 32];
    let mut b_pub = [0u8; 32];
    assert_eq!(
        unsafe { tm_x25519_public(a_priv.as_ptr(), 32, a_pub.as_mut_ptr(), 32) }, TM_OK);
    assert_eq!(
        unsafe { tm_x25519_public(b_priv.as_ptr(), 32, b_pub.as_mut_ptr(), 32) }, TM_OK);

    let mut ka = TmPkiKey { bytes: [0u8; 32] };
    let mut kb = TmPkiKey { bytes: [0u8; 32] };
    assert_eq!(unsafe { tm_pki_agree(a_priv.as_ptr(), 32, b_pub.as_ptr(), 32, &mut ka) }, TM_OK);
    assert_eq!(unsafe { tm_pki_agree(b_priv.as_ptr(), 32, a_pub.as_ptr(), 32, &mut kb) }, TM_OK);
    assert_eq!(ka.bytes, kb.bytes, "both sides must agree the same key");

    // And it is SHA-256 of RFC 7748's published shared secret K, not of
    // something we invented -- so the KDF is pinned to an external answer.
    let k = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];
    assert_eq!(ka.bytes, sha256(&k));
}

/// A small-order peer key is refused with its own code, never agreed.
#[test]
fn tm_pki_agree_refuses_a_small_order_peer_key() {
    let priv_k = [0x11u8; 32];
    let mut out = TmPkiKey { bytes: [0xAAu8; 32] };
    // u = 0 drives the shared secret to zero regardless of the private key.
    let zero = [0u8; 32];
    assert_eq!(
        unsafe { tm_pki_agree(priv_k.as_ptr(), 32, zero.as_ptr(), 32, &mut out) },
        TM_E_SMALL_ORDER,
    );
    assert_eq!(out.bytes, [0xAAu8; 32], "must not have written a key");

    // A wrong length is a different failure and must not be conflated.
    assert_eq!(
        unsafe { tm_pki_agree(priv_k.as_ptr(), 16, zero.as_ptr(), 32, &mut out) },
        TM_E_BAD_KEY_LEN,
    );
}

/// Our encoder and our reader agree, and the frame looks like a PKI frame.
#[test]
fn tm_pki_encode_round_trips_through_tm_pki_decrypt() {
    let key = bench_key();
    let text = b"abi-round-trip";
    let mut out = [0u8; 256];
    let n = unsafe {
        tm_pki_encode(
            0x3280_70b9, 0x3369_e764, 0x0bad_1234, 3, 1, &key, 0x5200_0d21, 1,
            text.as_ptr(), text.len(), out.as_mut_ptr(), out.len(),
        )
    };
    assert!(n > 0, "encode failed: {n}");
    let n = usize::try_from(n).unwrap();

    // Channel byte 0x00 is what marks it, and it must be addressed.
    assert_eq!(unsafe { tm_is_pki(out.as_ptr(), n) }, 1);
    let h = frame::peek_header(&out[..n]).expect("header");
    assert_eq!(h.channel, 0x00);
    assert_eq!(h.relay_node, 0xb9, "low byte of `from`");
    assert!(h.want_ack);

    let mut payload: *const u8 = core::ptr::null();
    let mut payload_len: usize = 0;
    assert_eq!(
        unsafe {
            tm_pki_decrypt(out.as_mut_ptr(), n, &key, &mut payload, &mut payload_len)
        },
        TM_OK,
    );
    let plain = unsafe { slice::from_raw_parts(payload, payload_len) };
    let data = Data::decode(plain).expect("Data");
    assert_eq!(data.payload, text);
}

/// A broadcast on a real channel is not a PKI frame, and a runt is neither.
#[test]
fn tm_is_pki_and_tm_pki_decrypt_refuse_what_is_not_one() {
    let mut key = TmKey { bytes: [0u8; 16] };
    assert_eq!(unsafe { tm_key_from_index(1, &mut key) }, TM_OK);
    let mut out = [0u8; 128];
    let n = unsafe {
        tm_text_encode(1, 0xFFFF_FFFF, 2, 3, 0x08, 0, &key, b"hi".as_ptr(), 2,
                       out.as_mut_ptr(), out.len())
    };
    assert!(n > 0);
    assert_eq!(unsafe { tm_is_pki(out.as_ptr(), usize::try_from(n).unwrap()) }, 0,
               "a channel broadcast is not a direct message");

    // Hostile input: shorter than a header, and shorter than the overhead.
    let pki = bench_key();
    let mut payload: *const u8 = core::ptr::null();
    let mut payload_len: usize = 0;
    for len in [0usize, 1, 15, 16, 20, 27] {
        let mut runt = [0u8; 32];
        assert_eq!(
            unsafe {
                tm_pki_decrypt(runt.as_mut_ptr(), len, &pki, &mut payload, &mut payload_len)
            },
            TM_E_SHORT,
            "a {len}-byte frame must be refused, not parsed"
        );
    }
}

// ── Reading what arrived ────────────────────────────────────────────────────

/// A published NodeInfo must be readable back as a peer would read it.
///
/// This is the loop that makes a node addressable: we encode a `User` carrying
/// our key, a peer decodes it and keeps the key, and only then can it originate
/// a direct message to us. Testing the encoder alone leaves the half that
/// actually matters unchecked.
#[test]
fn a_published_nodeinfo_decodes_back_to_the_same_user() {
    let mut key = TmKey { bytes: [0u8; 16] };
    assert_eq!(unsafe { tm_key_from_index(1, &mut key) }, TM_OK);

    let pubkey = [0x5Au8; 32];
    let id = b"!328070b9";
    let long = b"tethermesh";
    let short = b"tm01";
    let mac = [0u8; 6];
    let user = TmUser {
        id: id.as_ptr(), id_len: id.len(),
        long_name: long.as_ptr(), long_name_len: long.len(),
        short_name: short.as_ptr(), short_name_len: short.len(),
        public_key: pubkey.as_ptr(), public_key_len: pubkey.len(),
        macaddr: mac.as_ptr(), macaddr_len: mac.len(),
        hw_model: 0, role: 0,
    };
    let mut out = [0u8; 256];
    let n = unsafe {
        tm_nodeinfo_encode(0x3280_70b9, 0xFFFF_FFFF, 7, 3, 0x08, 1, &key, &user,
                           out.as_mut_ptr(), out.len())
    };
    assert!(n > 0);
    let n = usize::try_from(n).unwrap();

    let (_, plain) = frame::decode_in_place(&mut out[..n], &key.bytes, 0).expect("decode");

    let mut data = TmData {
        portnum: 0, payload: core::ptr::null(), payload_len: 0,
        want_response: 0, request_id: 0,
    };
    assert_eq!(unsafe { tm_data_decode(plain.as_ptr(), plain.len(), &mut data) }, TM_OK);
    assert_eq!(data.portnum, 4, "NODEINFO_APP");
    assert_eq!(data.want_response, 1, "we asked, so a peer must see that we asked");

    let mut back = TmUser {
        id: core::ptr::null(), id_len: 0,
        long_name: core::ptr::null(), long_name_len: 0,
        short_name: core::ptr::null(), short_name_len: 0,
        public_key: core::ptr::null(), public_key_len: 0,
        macaddr: core::ptr::null(), macaddr_len: 0,
        hw_model: 0, role: 0,
    };
    assert_eq!(
        unsafe { tm_user_decode(data.payload, data.payload_len, &mut back) }, TM_OK);
    assert_eq!(back.public_key_len, 32, "the key is what makes us addressable");
    assert_eq!(unsafe { slice::from_raw_parts(back.public_key, 32) }, &pubkey);
    assert_eq!(unsafe { slice::from_raw_parts(back.id, back.id_len) }, id);
    assert_eq!(unsafe { slice::from_raw_parts(back.short_name, back.short_name_len) }, short);
}

/// A peer that published no key is a real state, not a decode failure.
#[test]
fn a_user_without_a_key_decodes_with_a_zero_length_key() {
    let id = b"!deadbeef";
    let mut ubuf = [0u8; 128];
    let ulen = User { id, ..Default::default() }.encode(&mut ubuf).unwrap();

    let mut back = TmUser {
        id: core::ptr::null(), id_len: 0,
        long_name: core::ptr::null(), long_name_len: 0,
        short_name: core::ptr::null(), short_name_len: 0,
        public_key: core::ptr::null(), public_key_len: 0,
        macaddr: core::ptr::null(), macaddr_len: 0,
        hw_model: 0, role: 0,
    };
    assert_eq!(unsafe { tm_user_decode(ubuf.as_ptr(), ulen, &mut back) }, TM_OK);
    assert_eq!(back.public_key_len, 0, "absent, and that is not an error");
    assert_eq!(back.id_len, 9);
}

/// Hostile input must be refused, never parsed into something plausible.
#[test]
fn the_decoders_refuse_rubbish_rather_than_inventing_a_peer() {
    let mut data = TmData {
        portnum: 0, payload: core::ptr::null(), payload_len: 0,
        want_response: 0, request_id: 0,
    };
    // Truncated length-delimited field: claims 0x7f bytes and supplies none.
    let truncated = [0x0au8, 0x7f];
    assert_eq!(
        unsafe { tm_data_decode(truncated.as_ptr(), truncated.len(), &mut data) },
        TM_E_ARG,
    );
    // A null payload is an argument error, not a crash.
    assert_eq!(unsafe { tm_data_decode(core::ptr::null(), 0, &mut data) }, TM_E_ARG);

    let mut back = TmUser {
        id: core::ptr::null(), id_len: 0,
        long_name: core::ptr::null(), long_name_len: 0,
        short_name: core::ptr::null(), short_name_len: 0,
        public_key: core::ptr::null(), public_key_len: 0,
        macaddr: core::ptr::null(), macaddr_len: 0,
        hw_model: 0, role: 0,
    };
    assert_eq!(
        unsafe { tm_user_decode(truncated.as_ptr(), truncated.len(), &mut back) },
        TM_E_ARG,
    );
}

/// Every originating encoder stamps `relay_node`, and they all agree.
///
/// The rule is measured, not inferred: all five frames in `on_air_frames.json`
/// are originated — `hop_limit == hop_start` — and every one carries
/// `relay_node = 0x64` for node `0x3369e764`. `WIRE_REFERENCE.md` corroborates
/// the truncation on two further nodes from captured traffic.
///
/// This exists because two encoders in this ABI disagreed with the other two
/// until 2026-08-18: `tm_text_encode` and `tm_ack_encode` wrote 0 while
/// `tm_nodeinfo_encode` and `tm_pki_encode` wrote the low byte. Stock nodes
/// tolerate the zero — our text was rendered — so nothing on the bench would
/// ever have reported it. A disagreement inside one ABI about what goes on the
/// wire is the kind of thing that is only ever found by looking.
#[test]
fn every_originating_encoder_stamps_relay_node_with_the_low_byte_of_from() {
    const FROM: u32 = 0x3280_70b9;
    const LOW: u8 = 0xb9;

    let mut key = TmKey { bytes: [0u8; 16] };
    assert_eq!(unsafe { tm_key_from_index(1, &mut key) }, TM_OK);
    let mut out = [0u8; 256];

    let n = unsafe {
        tm_text_encode(FROM, 0xFFFF_FFFF, 1, 3, 0x08, 0, &key, b"hi".as_ptr(), 2,
                       out.as_mut_ptr(), out.len())
    };
    assert!(n > 0);
    let h = frame::peek_header(&out[..usize::try_from(n).unwrap()]).expect("header");
    assert_eq!(h.relay_node, LOW, "tm_text_encode");
    assert_eq!(h.hop_limit, h.hop_start, "an originated frame");

    let n = unsafe {
        tm_ack_encode(FROM, 0x3369_e764, 2, 0xdead, 3, 0x08, &key,
                      out.as_mut_ptr(), out.len())
    };
    assert!(n > 0);
    let h = frame::peek_header(&out[..usize::try_from(n).unwrap()]).expect("header");
    assert_eq!(h.relay_node, LOW, "tm_ack_encode");

    let id = b"!328070b9";
    let mac = [0u8; 6];
    let user = TmUser {
        id: id.as_ptr(), id_len: id.len(),
        long_name: core::ptr::null(), long_name_len: 0,
        short_name: core::ptr::null(), short_name_len: 0,
        public_key: core::ptr::null(), public_key_len: 0,
        macaddr: mac.as_ptr(), macaddr_len: mac.len(),
        hw_model: 0, role: 0,
    };
    let n = unsafe {
        tm_nodeinfo_encode(FROM, 0xFFFF_FFFF, 3, 3, 0x08, 0, &key, &user,
                           out.as_mut_ptr(), out.len())
    };
    assert!(n > 0);
    let h = frame::peek_header(&out[..usize::try_from(n).unwrap()]).expect("header");
    assert_eq!(h.relay_node, LOW, "tm_nodeinfo_encode");

    let pki = bench_key();
    let n = unsafe {
        tm_pki_encode(FROM, 0x3369_e764, 4, 3, 0, &pki, 0x1234, 1,
                      b"x".as_ptr(), 1, out.as_mut_ptr(), out.len())
    };
    assert!(n > 0);
    let h = frame::peek_header(&out[..usize::try_from(n).unwrap()]).expect("header");
    assert_eq!(h.relay_node, LOW, "tm_pki_encode");
}

/// The header decode is pinned to real captured frames, field by field.
///
/// Not a round-trip against our own encoder — that would agree with itself. Each
/// frame in the on-air corpus carries the header values as the capture recorded
/// them, and this asserts the ABI reproduces every one.
///
/// **This test is the thing that keeps the wire layout in one place.** A
/// consumer that needed `from`, `id` and `relay_node` before it could call
/// anything else had been reading bytes 4..8, 8..12 and 15 out of the frame
/// itself, because the ABI offered no way to ask. That put these offsets in two
/// repositories with nothing comparing them.
#[test]
fn tm_header_peek_reproduces_every_captured_header() {
    let doc = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../tests/captures/on_air_frames.json"
    )).expect("on_air_frames.json");

    let num = |seg: &str, key: &str| -> u64 {
        let at = seg.find(&format!("\"{key}\"")).expect("key");
        let rest = &seg[at..];
        let colon = rest.find(':').expect("colon");
        rest[colon + 1..].trim_start()
            .split(|c: char| !c.is_ascii_digit()).next().expect("digits")
            .parse().expect("number")
    };

    // Only some frames carry a recorded header block, so each one is paired
    // with the nearest PRECEDING raw_hex rather than assuming one per frame.
    let mut checked = 0;
    for (hdr_at, _) in doc.match_indices("\"header\"") {
        let before = &doc[..hdr_at];
        let raw_at = before.rfind("\"raw_hex\"").expect("a frame precedes its header");
        let r = &doc[raw_at..];
        let colon = r.find(':').expect("colon");
        let q1 = r[colon..].find('"').expect("open") + colon + 1;
        let q2 = r[q1..].find('"').expect("close") + q1;
        let raw = &r[q1..q2];
        let bytes: Vec<u8> = (0..raw.len() / 2)
            .map(|i| u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).expect("hex"))
            .collect();
        let seg = &doc[hdr_at..];

        let mut h = TmHeader {
            to: 0, from: 0, id: 0, hop_limit: 0, hop_start: 0,
            channel_hash: 0, next_hop: 0, relay_node: 0, want_ack: 0, via_mqtt: 0,
        };
        assert_eq!(
            unsafe { tm_header_peek(bytes.as_ptr(), bytes.len(), &mut h) }, TM_OK);

        assert_eq!(u64::from(h.to), num(seg, "to"), "to");
        assert_eq!(u64::from(h.from), num(seg, "from"), "from");
        assert_eq!(u64::from(h.id), num(seg, "id"), "id");
        assert_eq!(u64::from(h.hop_limit), num(seg, "hop_limit"), "hop_limit");
        assert_eq!(u64::from(h.hop_start), num(seg, "hop_start"), "hop_start");
        assert_eq!(u64::from(h.channel_hash), num(seg, "channel"), "channel");
        assert_eq!(u64::from(h.next_hop), num(seg, "next_hop"), "next_hop");
        assert_eq!(u64::from(h.relay_node), num(seg, "relay_node"), "relay_node");
        checked += 1;
    }
    assert!(checked >= 3, "the corpus records at least three headers, saw {checked}");

    // THE CORPUS CANNOT PIN hop_start, and saying so is the point. Every
    // captured frame is originated, so hop_start == hop_limit in all of them
    // and reading one where the other belongs is invisible here -- found by
    // mutating this test and watching it stay green. A relayed frame would
    // separate them; the corpus contains none, so one is constructed.
    let relayed = Header {
        to: 0xFFFF_FFFF, from: 0x3369_e764, id: 0x0bad_c0de,
        hop_limit: 1, hop_start: 3, channel: 0x08, relay_node: 0x28,
        ..Header::default()
    }.encode();
    let mut h = TmHeader {
        to: 0, from: 0, id: 0, hop_limit: 0, hop_start: 0,
        channel_hash: 0, next_hop: 0, relay_node: 0, want_ack: 0, via_mqtt: 0,
    };
    assert_eq!(unsafe { tm_header_peek(relayed.as_ptr(), relayed.len(), &mut h) }, TM_OK);
    assert_eq!(h.hop_limit, 1, "hop_limit");
    assert_eq!(h.hop_start, 3, "hop_start must not read hop_limit");
    assert_ne!(h.hop_limit, h.hop_start, "a relayed frame is what separates them");
    assert_eq!(h.relay_node, 0x28, "stamped by the relay, not the originator");
}

/// A frame too short to hold a header is refused, not parsed.
#[test]
fn tm_header_peek_refuses_a_runt_rather_than_reading_past_it() {
    let mut h = TmHeader {
        to: 0, from: 0, id: 0, hop_limit: 0, hop_start: 0,
        channel_hash: 0, next_hop: 0, relay_node: 0, want_ack: 0, via_mqtt: 0,
    };
    let buf = [0xAAu8; 16];
    for len in 0..16usize {
        assert_eq!(
            unsafe { tm_header_peek(buf.as_ptr(), len, &mut h) }, TM_E_SHORT,
            "a {len}-byte frame has no header to read");
    }
    assert_eq!(unsafe { tm_header_peek(buf.as_ptr(), 16, &mut h) }, TM_OK,
               "exactly 16 bytes is a header");
    assert_eq!(unsafe { tm_header_peek(core::ptr::null(), 16, &mut h) }, TM_E_ARG);
}

/// The private-use boundary is refused, not clamped, and not reinterpreted.
///
/// 255 and 256 are one apart and mean entirely different things: below the line
/// the portnum is upstream's and this library constructs the body itself; at or
/// above it the body is the caller's. A clamp would silently move a caller from
/// one regime to the other.
#[test]
fn tm_extension_encode_refuses_a_portnum_below_the_private_range() {
    let mut key = TmKey { bytes: [0u8; 16] };
    assert_eq!(unsafe { tm_key_from_index(1, &mut key) }, TM_OK);
    let payload = b"x";
    let mut out = [0u8; 256];

    for portnum in [0u32, 1, 4, 5, 70, 255] {
        let rc = unsafe {
            tm_extension_encode(
                0x7e57_0042, 0xFFFF_FFFF, 1, 3, 0x08, 0, portnum, &key,
                payload.as_ptr(), payload.len(), out.as_mut_ptr(), out.len(),
            )
        };
        assert_eq!(
            rc, TM_E_RESERVED_PORTNUM,
            "portnum {portnum} is upstream's and must be refused, not encoded"
        );
    }
}

/// 256 and 511 both encode, and the frame is an ordinary channel packet whose
/// payload decodes back to the portnum and bytes that went in.
///
/// 256 is the boundary itself and 511 is `MAX` from WIRE_REFERENCE, so this
/// pins both ends of the sanctioned range rather than one interior value.
#[test]
fn tm_extension_encode_round_trips_across_the_private_range() {
    let mut key = TmKey { bytes: [0u8; 16] };
    assert_eq!(unsafe { tm_key_from_index(1, &mut key) }, TM_OK);
    let payload: [u8; 11] = *b"group-seal\x01";

    for portnum in [256u32, 300, 511] {
        let mut out = [0u8; 256];
        let n = unsafe {
            tm_extension_encode(
                0x7e57_0042, 0xFFFF_FFFF, 0x0bad_c0de, 3, 0x08, 0, portnum, &key,
                payload.as_ptr(), payload.len(), out.as_mut_ptr(), out.len(),
            )
        };
        assert!(n > 0, "portnum {portnum} must encode, got {n}");
        let n = n as usize;

        // Header first: the frame must look like any other originated packet.
        let mut hdr = TmHeader {
            to: 0, from: 0, id: 0, hop_limit: 0, hop_start: 0,
            channel_hash: 0, next_hop: 0, relay_node: 0, want_ack: 0, via_mqtt: 0,
        };
        assert_eq!(unsafe { tm_header_peek(out.as_ptr(), n, &mut hdr) }, TM_OK);
        assert_eq!(hdr.from, 0x7e57_0042);
        assert_eq!(hdr.hop_limit, 3);
        assert_eq!(hdr.hop_start, 3, "an originated frame has hop_start == hop_limit");
        assert_eq!(
            hdr.relay_node, 0x42,
            "relay_node is the low byte of `from`, as the other two encoders do"
        );

        // Then decrypt and decode, which is what a receiver actually does.
        let mut work = out;
        let mut pl: *const u8 = core::ptr::null();
        let mut pl_len: usize = 0;
        assert_eq!(
            unsafe { tm_frame_decrypt(work.as_mut_ptr(), n, &key, &mut pl, &mut pl_len) },
            TM_OK
        );
        let mut data = TmData {
            portnum: 0, payload: core::ptr::null(), payload_len: 0,
            want_response: 0, request_id: 0,
        };
        assert_eq!(unsafe { tm_data_decode(pl, pl_len, &mut data) }, TM_OK);
        assert_eq!(data.portnum, portnum, "the portnum must survive the round trip");
        assert_eq!(data.payload_len, payload.len());
        let got = unsafe { slice::from_raw_parts(data.payload, data.payload_len) };
        assert_eq!(got, &payload[..], "the caller's bytes must be carried verbatim");
    }
}

/// A null pointer is an argument error, and it is a DIFFERENT code from the
/// portnum refusal -- a caller must be able to tell "you passed nothing" from
/// "you used a portnum that is not yours".
#[test]
fn tm_extension_encode_separates_a_bad_pointer_from_a_bad_portnum() {
    let mut key = TmKey { bytes: [0u8; 16] };
    assert_eq!(unsafe { tm_key_from_index(1, &mut key) }, TM_OK);
    let mut out = [0u8; 256];
    let rc = unsafe {
        tm_extension_encode(
            1, 2, 3, 3, 0x08, 0, 256, &key,
            core::ptr::null(), 0, out.as_mut_ptr(), out.len(),
        )
    };
    assert_eq!(rc, TM_E_ARG);
    assert_ne!(TM_E_ARG, TM_E_RESERVED_PORTNUM);
}
