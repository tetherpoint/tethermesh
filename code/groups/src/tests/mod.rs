// SPDX-FileCopyrightText: 2026 Matthew Klapman
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
//! `gates/check_rust_rules.sh` already says so in as many words — *"Tests may
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
    let group = GroupEpoch { group_key: &GK, group_id: 0xCAFE, epoch: 0 };
    let binding = Binding { header: &HDR, from: 0x7e57_0001, id: 0x0bad_c0de };
    seal(&group, &binding, MsgType::Data, pt, buf).expect("seal")
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

    let binding = Binding { header: &HDR, from: 0x7e57_0001, id: 0x0bad_c0de };
    let len = open_in_place(&GK, &binding, &mut buf[..n]).expect("open");
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
        open_in_place(
            &GK,
            &Binding { header: &forged, from: 0x7e57_0001, id: 0x0bad_c0de },
            &mut buf[..n],
        ),
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

    let binding = Binding { header: &relayed, from: 0x7e57_0001, id: 0x0bad_c0de };
    let len = open_in_place(&GK, &binding, &mut buf[..n])
        .expect("a relayed frame must still verify");
    assert_eq!(&buf[HEADER_BYTES..HEADER_BYTES + len], b"relayed once");
}

#[test]
fn a_later_epoch_cannot_be_read_with_an_earlier_key() {
    let mut a = [0u8; 64];
    let e0 = GroupEpoch { group_key: &GK, group_id: 1, epoch: 0 };
    let e1 = GroupEpoch { group_key: &GK, group_id: 1, epoch: 1 };
    let b2 = Binding { header: &HDR, from: 1, id: 2 };
    let b3 = Binding { header: &HDR, from: 1, id: 3 };
    let na = seal(&e0, &b2, MsgType::Data, b"epoch zero", &mut a).expect("seal");
    let mut b = [0u8; 64];
    let nb = seal(&e1, &b3, MsgType::Data, b"epoch one", &mut b).expect("seal");

    assert_ne!(epoch_key(&GK, 0), epoch_key(&GK, 1), "epochs must derive different keys");

    // Each opens under its own epoch, which travels in the clear.
    assert!(open_in_place(&GK, &b2, &mut a[..na]).is_ok());
    assert!(open_in_place(&GK, &b3, &mut b[..nb]).is_ok());

    // A revoked member holds the OLD group key. Rekeying is what stops them,
    // and it stops them only for traffic sent afterwards -- see SPEC 6.4.
    let old = [9u8; 32];
    let mut c = [0u8; 64];
    let b4 = Binding { header: &HDR, from: 1, id: 4 };
    let nc = seal(&e1, &b4, MsgType::Data, b"after rekey", &mut c).expect("seal");
    assert_eq!(
        open_in_place(&old, &b4, &mut c[..nc]),
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
        seal(
            &GroupEpoch { group_key: &GK, group_id: 0, epoch: 0 },
            &Binding { header: &HDR, from: 1, id: 2 },
            MsgType::Data,
            b"x",
            &mut buf,
        ),
        Err(Error::BadGroupId)
    );
    let mut tiny = [0u8; 4];
    assert_eq!(
        seal(
            &GroupEpoch { group_key: &GK, group_id: 1, epoch: 0 },
            &Binding { header: &HDR, from: 1, id: 2 },
            MsgType::Data,
            b"x",
            &mut tiny,
        ),
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

/// The nonce layout, pinned to SPEC.md § 3.2 rather than to our own round trip.
///
/// # Why a round trip cannot settle this
///
/// Transpose `from` and `id` in *both* `seal` and `open_in_place` and every
/// test in this file still passes: the two ends make the same swap, the nonces
/// agree, and the tag verifies. It was found exactly that way — a mutation that
/// changed both call sites survived the whole suite on 2026-08-21.
///
/// **That is the `hop_start`/`hop_limit` defect again.** This project shipped a
/// self-consistent transposition of two header fields that passed 102 host
/// tests, 24 ABI tests and every Kani harness, because nothing anywhere pinned
/// the byte positions and every captured frame had the two fields equal. It was
/// caught only by a frame from someone else's radio.
///
/// There is no second implementation of this envelope to capture, so the
/// external answer is the **written specification**, and this asserts against
/// it. The Kani harness `nonce_construction_is_total_and_carries_the_epoch`
/// pins the length and the epoch's position; it deliberately says nothing about
/// the order of the two 32-bit fields, which is the gap this closes.
#[test]
fn the_nonce_layout_matches_the_spec_not_only_itself() {
    // Chosen so that every byte is distinct and no rotation of the input
    // produces the same output: a lazy fixture of 1 and 2 would not notice a
    // swap of two equal-looking words.
    let n = nonce(0x0403_0201, 0x0807_0605, 0x5a);
    assert_eq!(
        n,
        [
            0x01, 0x02, 0x03, 0x04, // from, little-endian
            0x05, 0x06, 0x07, 0x08, // id, little-endian
            0x5a, // epoch
            0x00, 0x00, 0x00, 0x00, // padding to 13
        ],
        "SPEC.md § 3.2: nonce = from[4,LE] || id[4,LE] || epoch[1] || 0x00 x 4"
    );
}

/// Sealing must **use** the epoch it was handed, not merely carry it.
///
/// Also found by mutation on 2026-08-21: making `seal` ignore
/// `GroupEpoch::epoch` and derive everything under epoch 0 passed every test in
/// this file. It stamps zero into the envelope as well, so the two ends still
/// agree and the round trip still works — a node would simply transmit under an
/// epoch nobody asked for, and the only symptom would be traffic a peer on the
/// current epoch cannot read.
#[test]
fn seal_uses_the_epoch_it_was_given_and_not_a_default() {
    let group = GroupEpoch { group_key: &GK, group_id: 0xCAFE, epoch: 3 };
    let binding = Binding { header: &HDR, from: 0x7e57_0001, id: 0x0bad_c0de };

    let mut buf = [0u8; 64];
    let n = seal(&group, &binding, MsgType::Data, b"epoch three", &mut buf).expect("seal");

    // It travels in the clear, so a receiver can pick the key before verifying.
    assert_eq!(parse(&buf[..n]).expect("parse").epoch, 3, "the envelope must declare epoch 3");

    // And the ciphertext really is under epoch 3's key: rewriting the declared
    // epoch makes the receiver derive a different key, which must not verify.
    let mut tampered = buf;
    tampered[6] = 0;
    assert_eq!(
        open_in_place(&GK, &binding, &mut tampered[..n]),
        Err(Error::Unauthentic),
        "the epoch is authenticated through the key, not merely carried"
    );

    // The honest positive: it opens under the epoch it claims.
    let len = open_in_place(&GK, &binding, &mut buf[..n]).expect("open");
    assert_eq!(&buf[HEADER_BYTES..HEADER_BYTES + len], b"epoch three");
}

/// `seal` must feed the nonce in the order the SPEC gives, not merely in an
/// order it agrees with itself about.
///
/// # The gap this closes, and why the obvious tests miss it
///
/// Transposing `binding.from` and `binding.id` at the `nonce(..)` call inside
/// **both** `seal` and `open_in_place` survived every other test in this file,
/// including `the_nonce_layout_matches_the_spec_not_only_itself` — that one
/// pins what `nonce()` does with its arguments, and says nothing about which
/// arguments `seal` hands it. Both ends swap, the nonces agree, the tag
/// verifies. Round-tripping cannot see it and neither can a differential
/// against ourselves.
///
/// So this test does not round-trip. It **re-derives the construction from
/// SPEC.md § 3** — epoch key, nonce in the specified field order, AAD from the
/// invariant header — encrypts the same plaintext with the same primitive, and
/// asserts `seal` produced those exact bytes.
///
/// **Be honest about the strength of this.** It is not checked against an
/// independent implementation; there is no second implementation of this
/// envelope to check against, and SPEC.md publishes no envelope vectors. What
/// it is: an assertion that the composition matches the written specification,
/// resting on primitives pinned elsewhere — `nonce`'s byte layout by the test
/// above, and CCM itself by `ccm_aad_vectors.json`, which WAS generated by an
/// independent Python implementation. That is a real chain, and it stops short
/// of a second implementation of the whole.
#[test]
fn seal_composes_the_nonce_and_aad_the_way_the_spec_says() {
    const PT: &[u8] = b"composition, not round trip";
    let group = GroupEpoch { group_key: &GK, group_id: 0xCAFE, epoch: 2 };
    let binding = Binding { header: &HDR, from: 0x7e57_0001, id: 0x0bad_c0de };

    let mut sealed = [0u8; 96];
    let n = seal(&group, &binding, MsgType::Data, PT, &mut sealed).expect("seal");

    // Re-derive, naming each input in the order SPEC.md § 3.2 gives it. If
    // `seal` swapped these two arguments, this nonce differs from the one it
    // used and the bytes below cannot match.
    let key = epoch_key(&GK, 2);
    let expect_nonce = nonce(binding.from, binding.id, 2);
    let aad = aad_from_header(binding.header);

    let mut body = [0u8; 96];
    body[..PT.len()].copy_from_slice(PT);
    let written =
        ccm_encrypt_in_place_aad(&key, &expect_nonce, &aad, &mut body, PT.len(), CCM_TAG_LEN)
            .expect("reference encrypt");

    assert_eq!(
        &sealed[HEADER_BYTES..n],
        &body[..written],
        "seal must encrypt under the SPEC's nonce and AAD, not merely under one \
         it agrees with itself about"
    );
}
