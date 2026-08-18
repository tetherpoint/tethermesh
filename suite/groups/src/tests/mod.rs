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

extern crate std;
use super::*;

const GK: [u8; 32] = [7u8; 32];
const HDR: [u8; HEADER_LEN] = [
    0xff, 0xff, 0xff, 0xff, // to
    0x01, 0x00, 0x57, 0x7e, // from
    0xde, 0xc0, 0xad, 0x0b, // id
    0x63, // flags: hop_limit 3, want_ack 0, hop_start 3
    0x08, // channel
    0x00, // next_hop
    0x00, // relay_node
];

fn seal_probe(buf: &mut [u8], pt: &[u8]) -> usize {
    seal(&GK, 0xCAFE, 0, MsgType::Data, &HDR, 0x7e57_0001, 0x0bad_c0de, pt, buf)
        .expect("seal")
}

#[test]
fn a_sealed_message_opens_to_what_went_in() {
    let pt = b"groups-round-trip";
    let mut buf = [0u8; 128];
    let n = seal_probe(&mut buf, pt);
    assert_eq!(n, pt.len() + OVERHEAD, "overhead is 15 bytes and fixed");

    let e = parse(&buf[..n]).expect("parse");
    assert_eq!(e.version, VERSION);
    assert_eq!(e.msg_type, MsgType::Data);
    assert_eq!(e.group_id, 0xCAFE);
    assert_eq!(e.epoch, 0);

    let len = open_in_place(&GK, &HDR, 0x7e57_0001, 0x0bad_c0de, &mut buf[..n]).expect("open");
    assert_eq!(&buf[HEADER_BYTES..HEADER_BYTES + len], pt);
}

/// The gate's forged-sender case, forged the way an attacker would.
///
/// SPEC.md § 10 warns about exactly this: forging by corrupting a tag at
/// random proves nothing, because any AEAD rejects that. A real forgery
/// keeps a valid-looking frame and changes who it claims to be from -- which
/// is free under plain Meshtastic, since `from` is an unauthenticated field
/// in a cleartext header.
#[test]
fn a_forged_sender_fails_the_tag() {
    let mut buf = [0u8; 128];
    let n = seal_probe(&mut buf, b"who sent this?");

    // Same bytes, same key, same epoch -- only `from` in the header differs.
    let mut forged = HDR;
    forged[4] = 0x99;
    assert_eq!(
        open_in_place(&GK, &forged, 0x7e57_0001, 0x0bad_c0de, &mut buf[..n]),
        Err(Error::Unauthentic),
        "a rewritten sender must not verify -- this is the property the \
         whole bundle exists for"
    );
}

/// A relay decrementing hop_limit must NOT break verification.
///
/// The counterpart to the test above, and the reason the AAD is a subset.
/// Binding all sixteen header bytes would fail here -- on every multi-hop
/// delivery, on a mesh larger than a bench.
#[test]
fn a_relayed_frame_still_verifies() {
    let mut buf = [0u8; 128];
    let n = seal_probe(&mut buf, b"relayed once");

    let mut relayed = HDR;
    relayed[12] = (HDR[12] & 0xF8) | 2; // hop_limit 3 -> 2
    relayed[15] = 0x64; // a relay stamped its low byte
    relayed[14] = 0x28; // and routing set next_hop

    let len = open_in_place(&GK, &relayed, 0x7e57_0001, 0x0bad_c0de, &mut buf[..n])
        .expect("a relayed frame must still verify");
    assert_eq!(&buf[HEADER_BYTES..HEADER_BYTES + len], b"relayed once");
}

#[test]
fn a_later_epoch_cannot_be_read_with_an_earlier_key() {
    let mut a = [0u8; 64];
    let na = seal(&GK, 1, 0, MsgType::Data, &HDR, 1, 2, b"epoch zero", &mut a).expect("seal");
    let mut b = [0u8; 64];
    let nb = seal(&GK, 1, 1, MsgType::Data, &HDR, 1, 3, b"epoch one", &mut b).expect("seal");

    assert_ne!(epoch_key(&GK, 0), epoch_key(&GK, 1), "epochs must derive different keys");

    // Each opens under its own epoch, which travels in the clear.
    assert!(open_in_place(&GK, &HDR, 1, 2, &mut a[..na]).is_ok());
    assert!(open_in_place(&GK, &HDR, 1, 3, &mut b[..nb]).is_ok());

    // A revoked member holds the OLD group key. Rekeying is what stops them,
    // and it stops them only for traffic sent afterwards -- see SPEC 6.4.
    let old = [9u8; 32];
    let mut c = [0u8; 64];
    let nc = seal(&GK, 1, 1, MsgType::Data, &HDR, 1, 4, b"after rekey", &mut c).expect("seal");
    assert_eq!(
        open_in_place(&old, &HDR, 1, 4, &mut c[..nc]),
        Err(Error::Unauthentic),
        "a stale group key must not open later traffic"
    );
}

#[test]
fn the_aad_is_the_invariant_subset_and_nothing_more() {
    let aad = aad_from_header(&HDR);
    assert_eq!(aad.len(), AAD_LEN);
    assert_eq!(&aad[..12], &HDR[..12], "to, from and id are covered verbatim");
    assert_eq!(aad[12], HDR[12] & 0xF8, "hop_limit is masked out");
    assert_eq!(aad[13], HDR[13], "channel is covered");

    // hop_limit varying must not change the AAD; the rest of byte 12 must.
    let mut hopped = HDR;
    hopped[12] = (HDR[12] & 0xF8) | 7;
    assert_eq!(aad_from_header(&hopped), aad, "hop_limit must not reach the tag");
    let mut acked = HDR;
    acked[12] = HDR[12] ^ 0x08; // want_ack
    assert_ne!(aad_from_header(&acked), aad, "want_ack must reach the tag");
}

#[test]
fn malformed_input_is_refused_rather_than_trusted() {
    assert_eq!(parse(&[]).unwrap_err(), Error::Malformed);
    assert_eq!(parse(&[0u8; OVERHEAD - 1]).unwrap_err(), Error::Malformed);

    let mut buf = [0u8; 64];
    let n = seal_probe(&mut buf, b"x");
    // Wrong version.
    let mut v = buf;
    v[0] = 99;
    assert_eq!(parse(&v[..n]).unwrap_err(), Error::UnsupportedVersion);
    // Zero group names nothing.
    let mut g = buf;
    g[2] = 0; g[3] = 0; g[4] = 0; g[5] = 0;
    assert_eq!(parse(&g[..n]).unwrap_err(), Error::BadGroupId);
    // Unknown message type.
    let mut t = buf;
    t[1] = 0x7f;
    assert_eq!(parse(&t[..n]).unwrap_err(), Error::Malformed);

    assert_eq!(
        seal(&GK, 0, 0, MsgType::Data, &HDR, 1, 2, b"x", &mut buf),
        Err(Error::BadGroupId)
    );
    let mut tiny = [0u8; 4];
    assert_eq!(
        seal(&GK, 1, 0, MsgType::Data, &HDR, 1, 2, b"x", &mut tiny),
        Err(Error::BufferTooSmall)
    );
}

#[test]
fn only_the_owner_may_change_membership() {
    let mut r: Roster<4> = Roster::new(0x1111);
    assert_eq!(r.add(0x2222, 0x3333, &[1u8; 32]), Err(Error::NotOwner));
    assert_eq!(r.remove(0x2222, 0x3333), Err(Error::NotOwner));
    assert_eq!(r.bump_epoch(0x2222), Err(Error::NotOwner));

    r.add(0x1111, 0x3333, &[1u8; 32]).expect("owner may add");
    assert!(r.contains(0x3333));
    assert_eq!(r.len(), 1);
    assert_eq!(r.remove(0x1111, 0x3333), Ok(true));
    assert!(!r.contains(0x3333));
    assert_eq!(r.remove(0x1111, 0x3333), Ok(false), "removing twice is not an error");
}

#[test]
fn a_full_roster_refuses_rather_than_dropping_someone() {
    let mut r: Roster<2> = Roster::new(1);
    r.add(1, 10, &[0u8; 32]).expect("first");
    r.add(1, 11, &[0u8; 32]).expect("second");
    assert_eq!(r.add(1, 12, &[0u8; 32]), Err(Error::RosterFull));
    assert!(r.contains(10) && r.contains(11), "neither existing member was displaced");
    // Re-adding an existing member updates the key without needing a slot.
    r.add(1, 10, &[5u8; 32]).expect("update in place");
    assert_eq!(r.len(), 2);
}

/// The epoch must refuse to wrap, because a wrap is not a rekey.
#[test]
fn the_epoch_refuses_to_wrap() {
    let mut r: Roster<2> = Roster::new(1);
    for _ in 0..255 {
        r.bump_epoch(1).expect("within range");
    }
    assert_eq!(r.epoch(), 255);
    assert_eq!(
        r.bump_epoch(1),
        Err(Error::EpochExhausted),
        "wrapping to 0 would reproduce epoch 0's key and reuse every nonce under it"
    );
}

