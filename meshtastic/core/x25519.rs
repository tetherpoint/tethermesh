//! X25519 key agreement, for direct messages.
//!
//! `WIRE_REFERENCE.md` records the direct-message construction as
//! `AES-256-CCM` keyed by `SHA-256` over a raw X25519 shared secret. This
//! produces that secret. RFC 7748 specifies the function completely and
//! publishes vectors for it; the bench supplied one more, from a real
//! exchange with a stock node.
//!
//! # What is proven and what is not — read before editing the ladder
//!
//! The **field arithmetic is not ours**. Multiplication, squaring, addition,
//! subtraction, carrying, the 121666 scalar multiply, serialisation and the
//! constant-time select all come from `fiat-crypto`, generated from Coq
//! proofs and called unmodified from the pinned submodule.
//!
//! Note the algorithm names, which are easy to conflate: this file implements
//! the Montgomery **ladder**, the scalar-multiplication loop. It contains no
//! Montgomery **multiplication** — the linked code is `unsaturated_solinas`,
//! and REDC appears nowhere in it.
//!
//! **Their proof is not weakened by our calling it, but it does not extend to
//! our composition.** Two things sit outside it:
//!
//! 1. *Sequencing* — that [`scalarmult`] and [`invert`] compose those
//!    operations into the right group operation. Checked against RFC 7748
//!    vectors and against two independent implementations, not proven.
//! 2. *Preconditions* — and this is the one that can bite silently. Each fiat
//!    operation is proven correct **given inputs within stated magnitude
//!    bounds**. Supply a value outside them and the proof simply does not
//!    apply; the result may be wrong with nothing to signal it.
//!
//! What makes (2) safe here is structural rather than careful: fiat's
//! `tight`/`loose` types *are* those bounds, expressed in the type system.
//!
//! ```text
//! add(tight, tight) -> loose        mul(loose, loose) -> tight
//! sub(tight, tight) -> loose        relax(tight)      -> loose
//! ```
//!
//! Two additions cannot be chained without an intervening carry, because
//! `add` requires `tight` and produces `loose`. The misuse that would void the
//! proof is a **compile error**, so this file compiling is itself evidence
//! that every call site respects the preconditions.
//!
//! If you edit the ladder, keep every field value flowing through the
//! wrappers below. Reaching into `.0` to do arithmetic by hand discards
//! exactly the protection described above.
//!
//! # Representation
//!
//! Field elements are five 51-bit limbs over `2^255 - 19` — fiat's
//! representation, which happens to be the one the hand-written version used
//! too, because it is the standard choice at 64-bit word size.
//!
//! # Constant time, and what that does and does not mean here
//!
//! The ladder does the same work for every scalar: no branch and no memory
//! access depends on a secret bit. Conditional swaps are arithmetic masks
//! rather than `if`, and the final inversion is a fixed addition chain rather
//! than a loop over the exponent's bits.
//!
//! What this cannot promise is what the *compiler* emits. Rust has no way to
//! state "do not turn this mask into a branch", so on a hostile target with
//! an aggressive optimiser the property is a strong expectation rather than a
//! guarantee. It is worth saying plainly rather than implying more rigour
//! than the language supports.

/// Length of a scalar, a public key, and a shared secret.
pub const KEY_LEN: usize = 32;

use fiat_crypto::curve25519_64 as f;

/// A reduced field element. The tight/loose distinction is fiat's, and it
/// encodes the bounds its proof relies on: multiplication consumes loose
/// operands and produces tight ones, addition the reverse. Following it is
/// not bureaucracy — it is how the verified preconditions are respected.
type Tight = f::fiat_25519_tight_field_element;
type Loose = f::fiat_25519_loose_field_element;

const fn tight_zero() -> Tight {
    f::fiat_25519_tight_field_element([0, 0, 0, 0, 0])
}

const fn tight_one() -> Tight {
    f::fiat_25519_tight_field_element([1, 0, 0, 0, 0])
}

fn relax(a: &Tight) -> Loose {
    let mut o = f::fiat_25519_loose_field_element([0; 5]);
    f::fiat_25519_relax(&mut o, a);
    o
}

fn add(a: &Tight, b: &Tight) -> Loose {
    let mut o = f::fiat_25519_loose_field_element([0; 5]);
    f::fiat_25519_add(&mut o, a, b);
    o
}

fn sub(a: &Tight, b: &Tight) -> Loose {
    let mut o = f::fiat_25519_loose_field_element([0; 5]);
    f::fiat_25519_sub(&mut o, a, b);
    o
}

fn mul(a: &Loose, b: &Loose) -> Tight {
    let mut o = tight_zero();
    f::fiat_25519_carry_mul(&mut o, a, b);
    o
}

fn sq(a: &Loose) -> Tight {
    let mut o = tight_zero();
    f::fiat_25519_carry_square(&mut o, a);
    o
}

fn mul121666(a: &Loose) -> Tight {
    let mut o = tight_zero();
    f::fiat_25519_carry_scmul_121666(&mut o, a);
    o
}

fn sq_t(a: &Tight) -> Tight {
    sq(&relax(a))
}

fn mul_t(a: &Tight, b: &Tight) -> Tight {
    mul(&relax(a), &relax(b))
}

/// Constant-time conditional swap, via fiat's `selectznz`.
fn cswap(swap: u64, a: &mut Tight, b: &mut Tight) {
    let c = if swap == 0 { 0u8 } else { 1u8 };
    let (x, y) = (a.0, b.0);
    let mut na = [0u64; 5];
    let mut nb = [0u64; 5];
    f::fiat_25519_selectznz(&mut na, c, &x, &y);
    f::fiat_25519_selectznz(&mut nb, c, &y, &x);
    a.0 = na;
    b.0 = nb;
}

/// `a^(p-2)`, i.e. the inverse for non-zero `a`.
///
/// A fixed addition chain: the exponent is public, so the work is identical
/// whatever is being inverted.
fn invert(a: &Tight) -> Tight {
    let z2 = sq_t(a);
    let z8 = sq_t(&sq_t(&z2));
    let z9 = mul_t(&z8, a);
    let z11 = mul_t(&z9, &z2);
    let z22 = sq_t(&z11);
    let z5 = mul_t(&z22, &z9);

    let mut t = sq_t(&z5);
    for _ in 0..4 {
        t = sq_t(&t);
    }
    let z10 = mul_t(&t, &z5);

    let mut t = sq_t(&z10);
    for _ in 0..9 {
        t = sq_t(&t);
    }
    let z20 = mul_t(&t, &z10);

    let mut t = sq_t(&z20);
    for _ in 0..19 {
        t = sq_t(&t);
    }
    let z40 = mul_t(&t, &z20);

    let mut t = sq_t(&z40);
    for _ in 0..9 {
        t = sq_t(&t);
    }
    let z50 = mul_t(&t, &z10);

    let mut t = sq_t(&z50);
    for _ in 0..49 {
        t = sq_t(&t);
    }
    let z100 = mul_t(&t, &z50);

    let mut t = sq_t(&z100);
    for _ in 0..99 {
        t = sq_t(&t);
    }
    let z200 = mul_t(&t, &z100);

    let mut t = sq_t(&z200);
    for _ in 0..49 {
        t = sq_t(&t);
    }
    let z250 = mul_t(&t, &z50);

    let mut t = sq_t(&z250);
    for _ in 0..4 {
        t = sq_t(&t);
    }
    mul_t(&t, &z11)
}

fn from_bytes(b: &[u8; KEY_LEN]) -> Tight {
    let mut o = tight_zero();
    // The top bit is masked off before decoding, as RFC 7748 requires.
    let mut m = *b;
    if let Some(p) = m.get_mut(31) {
        *p &= 0x7F;
    }
    f::fiat_25519_from_bytes(&mut o, &m);
    o
}

fn to_bytes(a: &Tight) -> [u8; KEY_LEN] {
    let mut o = [0u8; KEY_LEN];
    f::fiat_25519_to_bytes(&mut o, a);
    o
}

/// Clamp a scalar as RFC 7748 requires.
///
/// Clearing the low three bits puts the scalar in the prime-order subgroup;
/// setting bit 254 and clearing bit 255 fixes its length so the ladder runs
/// the same number of iterations for every key. Skipping this does not merely
/// weaken the result, it produces a different function.
#[must_use]
pub fn clamp(scalar: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut k = *scalar;
    if let Some(p) = k.get_mut(0) {
        *p &= 248;
    }
    if let Some(p) = k.get_mut(31) {
        *p &= 127;
        *p |= 64;
    }
    k
}

/// Montgomery ladder: `scalar * point` on Curve25519.
///
/// Returns the shared secret. Per RFC 7748 the caller **must** reject an
/// all-zero result, which indicates a small-order input point; that check is
/// left to [`x25519`] so this stays a pure ladder.
fn scalarmult(scalar: &[u8; KEY_LEN], point: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let k = clamp(scalar);
    let x1 = from_bytes(point);

    let mut x2 = tight_one();
    let mut z2 = tight_zero();
    let mut x3 = x1;
    let mut z3 = tight_one();
    let mut swap = 0u64;

    let mut pos: i32 = 254;
    while pos >= 0 {
        let byte = k.get((pos as usize) >> 3).copied().unwrap_or(0);
        let bit = u64::from((byte >> ((pos as u32) & 7)) & 1);
        swap ^= bit;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = bit;

        let a = add(&x2, &z2);
        let b = sub(&x2, &z2);
        let aa = sq(&a);
        let bb = sq(&b);
        let e = sub(&aa, &bb);
        let c = add(&x3, &z3);
        let d = sub(&x3, &z3);
        let da = mul(&d, &a);
        let cb = mul(&c, &b);

        x3 = sq(&add(&da, &cb));
        z3 = mul(&relax(&x1), &relax(&sq(&sub(&da, &cb))));
        x2 = mul(&relax(&aa), &relax(&bb));
        z2 = mul(&e, &add(&bb, &mul121666(&e)));

        pos = pos.saturating_sub(1);
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);

    to_bytes(&mul_t(&x2, &invert(&z2)))
}

/// The Curve25519 base point, u = 9.
pub const BASE_POINT: [u8; KEY_LEN] = {
    let mut b = [0u8; KEY_LEN];
    b[0] = 9;
    b
};

/// Derive the public key for a private key.
///
#[must_use]
pub fn public_key(private: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    scalarmult(private, &BASE_POINT)
}

/// Compute the shared secret from our private key and a peer's public key.
///
/// Returns `None` when the result is all zeros. RFC 7748 requires that check:
/// a small-order public key drives the output to zero regardless of the
/// private key, so accepting it would agree a "shared" secret with an
/// attacker who knows it in advance.
///
/// The raw output is **not** the message key. `WIRE_REFERENCE.md` records that
/// Meshtastic hashes it with SHA-256 first; see [`crate::sha256`].
#[must_use]
pub fn x25519(private: &[u8; KEY_LEN], peer_public: &[u8; KEY_LEN]) -> Option<[u8; KEY_LEN]> {
    let shared = scalarmult(private, peer_public);
    let mut acc = 0u8;
    for b in &shared {
        acc |= *b;
    }
    if acc == 0 {
        return None;
    }
    Some(shared)
}
