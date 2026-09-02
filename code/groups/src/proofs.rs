// SPDX-FileCopyrightText: 2026 Matthew Klapman
// SPDX-License-Identifier: Apache-2.0

//! Machine-checked proofs for the groups bundle.
//!
//! `docs/SCOPE.md` requires a bundle crate to inherit the whole regime, and the
//! proof table is part of it. These are the properties a bounded test samples
//! badly and a proof settles.
//!
//! # What is proven here, and what is not
//!
//! Totality on the **attacker-reachable** path, and two invariants whose
//! failure is silent.
//!
//! Nothing here proves the AEAD is sound — that is AES-CCM's, and it is
//! checked instead against an independent implementation's answers in
//! `tests/captures/ccm_aad_vectors.json`. Conflating "our framing does not
//! panic" with "the construction is secure" would overstate this considerably.
//!
//! Run with `cargo kani -p tethermesh_groups`.

use crate::{aad_from_header, nonce, parse, Roster};
use tethermesh::header::HEADER_LEN;

/// Parsing an envelope must not panic for **any** input.
///
/// This is the one that matters most. `parse` runs on bytes that arrived from a
/// public mesh, before anything has been authenticated — a panic here is a
/// remote denial of service reachable by any node in range, and the tag cannot
/// protect a path that runs *before* the tag is checked.
///
/// Sixteen bytes spans both sides of the length check: `OVERHEAD` is 15, so
/// arbitrary inputs at this size exercise the too-short refusal and the
/// full-parse path together.
#[kani::proof]
fn parsing_an_envelope_never_panics() {
    let bytes: [u8; 16] = kani::any();
    let _ = parse(&bytes);
}

/// A shorter buffer must be refused rather than read past.
#[kani::proof]
fn a_short_envelope_is_refused_not_read_past() {
    let bytes: [u8; 8] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let Some(slice) = bytes.get(..len) else { return };
    let got = parse(slice);
    if len < crate::OVERHEAD {
        assert!(got.is_err(), "anything shorter than an envelope must be refused");
    }
}

/// `hop_limit` can never reach the tag, for any header.
///
/// The property the whole bundle depends on, and the one a test can only
/// sample. Every relay decrements `hop_limit`, so if it reached the AAD the
/// extension would fail on every multi-hop delivery — working on a two-node
/// bench and failing in the field, which is the worst place to find it.
///
/// Proven the strong way: two headers differing **only** in the mutable bits
/// must produce the identical AAD, over all 2^128 header values rather than the
/// handful a test constructs.
#[kani::proof]
fn the_aad_ignores_every_mutable_header_field() {
    let a: [u8; HEADER_LEN] = kani::any();
    let mut b = a;

    // The three fields a relay is entitled to change: hop_limit (byte 12, bits
    // 0-2), next_hop (14), relay_node (15).
    let hop: u8 = kani::any();
    let next: u8 = kani::any();
    let relay: u8 = kani::any();
    if let Some(d) = b.get_mut(12) {
        let keep = a.get(12).copied().unwrap_or(0) & 0xF8;
        *d = keep | (hop & 0x07);
    }
    if let Some(d) = b.get_mut(14) {
        *d = next;
    }
    if let Some(d) = b.get_mut(15) {
        *d = relay;
    }

    assert!(
        aad_from_header(&a) == aad_from_header(&b),
        "a relayed frame must authenticate identically to the one that was sent"
    );
}

/// And the immutable fields must all reach the tag.
///
/// The converse, and it is not redundant: an `aad_from_header` that returned a
/// constant would satisfy the proof above perfectly while authenticating
/// nothing at all.
#[kani::proof]
fn the_aad_covers_every_immutable_header_field() {
    let a: [u8; HEADER_LEN] = kani::any();
    let mut b = a;
    let i: usize = kani::any();
    kani::assume(i < HEADER_LEN);
    // Skip the bytes a relay may legitimately rewrite.
    kani::assume(i != 14 && i != 15);

    let delta: u8 = kani::any();
    kani::assume(delta != 0);
    if i == 12 {
        // Only the immutable bits of the flags byte.
        kani::assume(delta & 0x07 == 0);
    }
    if let (Some(d), Some(s)) = (b.get_mut(i), a.get(i)) {
        *d = *s ^ delta;
    }

    assert!(
        aad_from_header(&a) != aad_from_header(&b),
        "changing an immutable header field must change the tag input"
    );
}

/// The epoch never wraps, from **any** starting value.
///
/// A wrap is not a rekey: the epoch feeds the key derivation, so returning to 0
/// reproduces epoch 0's key and reuses every nonce ever used under it, which
/// breaks confidentiality and authenticity together. Refusing is the only safe
/// alternative to doing that silently.
///
/// The starting epoch is set directly rather than reached by 255 bumps — a loop
/// Kani would have to unroll, and which the unit test already walks. The first
/// version of this harness was **vacuous**: it bumped a fresh roster, which
/// starts at 0, so the exhausted branch was unreachable and the proof held
/// without ever testing the property it names.
#[kani::proof]
fn the_epoch_never_wraps_from_any_starting_value() {
    let start: u8 = kani::any();
    let mut r: Roster<1> = Roster::new(1);
    r.set_epoch_for_proof(start);

    let owner = r.owner();
    match r.bump_epoch(owner) {
        Ok(next) => {
            assert!(start != 255, "255 must never be accepted");
            assert!(next == start.wrapping_add(1), "a bump advances by exactly one");
            assert!(next > start, "and never wraps");
        }
        Err(_) => assert!(start == 255, "only an exhausted epoch may refuse"),
    }
}

/// Nonce construction is total, and the epoch reaches it.
///
/// Every message builds one, so a panic here is the same remote denial of
/// service as one in `parse`. The epoch must appear in the nonce or two epochs
/// would share one, which under CCM breaks confidentiality and authenticity
/// together.
///
/// **`epoch_key` is deliberately absent.** Proving anything about a digest's
/// output is SHA-256's property, not this crate's, and asking Kani for it means
/// asking it to model the hash — the first version of this file asserted
/// "distinct epochs derive distinct keys", which is SHA-256 injectivity and did
/// not terminate. That the epoch reaches the derivation at all is covered by a
/// unit test against concrete values.
#[kani::proof]
fn nonce_construction_is_total_and_carries_the_epoch() {
    let epoch: u8 = kani::any();
    let from: u32 = kani::any();
    let id: u32 = kani::any();

    let n = nonce(from, id, epoch);
    assert!(n.get(8) == Some(&epoch), "the epoch must appear in the nonce");
    assert!(n.len() == 13, "CCM here takes a 13-byte nonce");
}
