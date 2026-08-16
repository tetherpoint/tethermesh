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

use crate::channel::channel_hash;
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
