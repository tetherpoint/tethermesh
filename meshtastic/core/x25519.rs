//! X25519 key agreement, for direct messages.
//!
//! `WIRE_REFERENCE.md` records the direct-message construction as
//! `AES-256-CCM` keyed by `SHA-256` over a raw X25519 shared secret. This
//! produces that secret. RFC 7748 specifies the function completely and
//! publishes vectors for it; the bench supplied one more, from a real
//! exchange with a stock node.
//!
//! # Representation
//!
//! Field elements are five 51-bit limbs over `2^255 - 19`. That leaves
//! headroom in a `u64` for several additions before a carry pass is needed,
//! and keeps multiplication to twenty-five 64×64 products.
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

type Fe = [u64; 5];

const MASK51: u64 = (1u64 << 51) - 1;

const fn fe_zero() -> Fe {
    [0, 0, 0, 0, 0]
}

const fn fe_one() -> Fe {
    [1, 0, 0, 0, 0]
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    [
        a[0].wrapping_add(b[0]),
        a[1].wrapping_add(b[1]),
        a[2].wrapping_add(b[2]),
        a[3].wrapping_add(b[3]),
        a[4].wrapping_add(b[4]),
    ]
}

/// `a - b`, biased by 2p so no limb underflows.
fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    // 2p in limb form. p's limbs are [2^51-19, 2^51-1, 2^51-1, 2^51-1, 2^51-1],
    // so these are twice that. Biasing by p alone is not enough: limbs can
    // exceed 2^51 between carry passes, and a single-p bias then underflows.
    let t = [
        a[0].wrapping_add(0x000F_FFFF_FFFF_FFDA),
        a[1].wrapping_add(0x000F_FFFF_FFFF_FFFE),
        a[2].wrapping_add(0x000F_FFFF_FFFF_FFFE),
        a[3].wrapping_add(0x000F_FFFF_FFFF_FFFE),
        a[4].wrapping_add(0x000F_FFFF_FFFF_FFFE),
    ];
    [
        t[0].wrapping_sub(b[0]),
        t[1].wrapping_sub(b[1]),
        t[2].wrapping_sub(b[2]),
        t[3].wrapping_sub(b[3]),
        t[4].wrapping_sub(b[4]),
    ]
}

fn fe_carry(mut c0: u128, mut c1: u128, mut c2: u128, mut c3: u128, mut c4: u128) -> Fe {
    let m = u128::from(MASK51);
    c1 = c1.wrapping_add(c0 >> 51);
    c0 &= m;
    c2 = c2.wrapping_add(c1 >> 51);
    c1 &= m;
    c3 = c3.wrapping_add(c2 >> 51);
    c2 &= m;
    c4 = c4.wrapping_add(c3 >> 51);
    c3 &= m;
    // The top limb folds back into the bottom, times 19.
    c0 = c0.wrapping_add((c4 >> 51).wrapping_mul(19));
    c4 &= m;
    c1 = c1.wrapping_add(c0 >> 51);
    c0 &= m;
    [c0 as u64, c1 as u64, c2 as u64, c3 as u64, c4 as u64]
}

fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let p = |x: u64, y: u64| -> u128 { u128::from(x).wrapping_mul(u128::from(y)) };
    let b1_19 = b[1].wrapping_mul(19);
    let b2_19 = b[2].wrapping_mul(19);
    let b3_19 = b[3].wrapping_mul(19);
    let b4_19 = b[4].wrapping_mul(19);

    let c0 = p(a[0], b[0])
        .wrapping_add(p(a[1], b4_19))
        .wrapping_add(p(a[2], b3_19))
        .wrapping_add(p(a[3], b2_19))
        .wrapping_add(p(a[4], b1_19));
    let c1 = p(a[0], b[1])
        .wrapping_add(p(a[1], b[0]))
        .wrapping_add(p(a[2], b4_19))
        .wrapping_add(p(a[3], b3_19))
        .wrapping_add(p(a[4], b2_19));
    let c2 = p(a[0], b[2])
        .wrapping_add(p(a[1], b[1]))
        .wrapping_add(p(a[2], b[0]))
        .wrapping_add(p(a[3], b4_19))
        .wrapping_add(p(a[4], b3_19));
    let c3 = p(a[0], b[3])
        .wrapping_add(p(a[1], b[2]))
        .wrapping_add(p(a[2], b[1]))
        .wrapping_add(p(a[3], b[0]))
        .wrapping_add(p(a[4], b4_19));
    let c4 = p(a[0], b[4])
        .wrapping_add(p(a[1], b[3]))
        .wrapping_add(p(a[2], b[2]))
        .wrapping_add(p(a[3], b[1]))
        .wrapping_add(p(a[4], b[0]));
    fe_carry(c0, c1, c2, c3, c4)
}

fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

fn fe_mul121666(a: &Fe) -> Fe {
    let p = |x: u64| -> u128 { u128::from(x).wrapping_mul(121_666) };
    fe_carry(p(a[0]), p(a[1]), p(a[2]), p(a[3]), p(a[4]))
}

/// Swap `a` and `b` when `swap` is 1, leave them when it is 0.
///
/// Arithmetic rather than a branch: the scalar bit driving this is secret, and
/// a branch on it is exactly what a timing attack reads.
fn fe_cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..5usize {
        let ai = a.get(i).copied().unwrap_or(0);
        let bi = b.get(i).copied().unwrap_or(0);
        let t = mask & (ai ^ bi);
        if let Some(p) = a.get_mut(i) {
            *p = ai ^ t;
        }
        if let Some(p) = b.get_mut(i) {
            *p = bi ^ t;
        }
    }
}

/// `a^(p-2)`, which is `a^-1` for non-zero `a`.
///
/// A fixed addition chain: the exponent is public, so this is the same work
/// every time regardless of the value being inverted.
fn fe_invert(a: &Fe) -> Fe {
    let z2 = fe_sq(a);
    let z8 = fe_sq(&fe_sq(&z2));
    let z9 = fe_mul(&z8, a);
    let z11 = fe_mul(&z9, &z2);
    let z22 = fe_sq(&z11);
    let z5 = fe_mul(&z22, &z9);

    let mut t = fe_sq(&z5);
    for _ in 0..4 {
        t = fe_sq(&t);
    }
    let z10 = fe_mul(&t, &z5);

    let mut t = fe_sq(&z10);
    for _ in 0..9 {
        t = fe_sq(&t);
    }
    let z20 = fe_mul(&t, &z10);

    let mut t = fe_sq(&z20);
    for _ in 0..19 {
        t = fe_sq(&t);
    }
    let z40 = fe_mul(&t, &z20);

    let mut t = fe_sq(&z40);
    for _ in 0..9 {
        t = fe_sq(&t);
    }
    let z50 = fe_mul(&t, &z10);

    let mut t = fe_sq(&z50);
    for _ in 0..49 {
        t = fe_sq(&t);
    }
    let z100 = fe_mul(&t, &z50);

    let mut t = fe_sq(&z100);
    for _ in 0..99 {
        t = fe_sq(&t);
    }
    let z200 = fe_mul(&t, &z100);

    let mut t = fe_sq(&z200);
    for _ in 0..49 {
        t = fe_sq(&t);
    }
    let z250 = fe_mul(&t, &z50);

    let mut t = fe_sq(&z250);
    for _ in 0..4 {
        t = fe_sq(&t);
    }
    fe_mul(&t, &z11)
}

fn fe_from_bytes(b: &[u8; KEY_LEN]) -> Fe {
    let ld = |i: usize| -> u64 {
        let mut v = 0u64;
        for k in 0..8usize {
            let idx = i.wrapping_add(k);
            let byte = b.get(idx).copied().unwrap_or(0);
            v |= u64::from(byte) << (k.wrapping_mul(8));
        }
        v
    };
    [
        ld(0) & MASK51,
        (ld(6) >> 3) & MASK51,
        (ld(12) >> 6) & MASK51,
        (ld(19) >> 1) & MASK51,
        (ld(24) >> 12) & MASK51,
    ]
}

fn fe_to_bytes(a: &Fe) -> [u8; KEY_LEN] {
    let get = |t: &Fe, i: usize| -> u64 { t.get(i).copied().unwrap_or(0) };
    let put = |t: &mut Fe, i: usize, v: u64| {
        if let Some(p) = t.get_mut(i) {
            *p = v;
        }
    };

    // Normalise: limbs can exceed 2^51 on the way in, so carry until they do
    // not. Twice is enough because each pass folds at most a small multiple.
    let mut t = *a;
    for _ in 0..2 {
        let mut carry = 0u64;
        for i in 0..5usize {
            let v = get(&t, i).wrapping_add(carry);
            put(&mut t, i, v & MASK51);
            carry = v >> 51;
        }
        let v0 = get(&t, 0).wrapping_add(carry.wrapping_mul(19));
        put(&mut t, 0, v0);
    }

    // Is the value >= p? Adding 19 and watching the top carry answers it
    // without a comparison, so the result does not branch on the value.
    let mut q = get(&t, 0).wrapping_add(19) >> 51;
    for i in 1..5usize {
        q = get(&t, i).wrapping_add(q) >> 51;
    }
    let v0 = get(&t, 0).wrapping_add(q.wrapping_mul(19));
    put(&mut t, 0, v0);

    let mut carry = 0u64;
    for i in 0..5usize {
        let v = get(&t, i).wrapping_add(carry);
        put(&mut t, i, v & MASK51);
        carry = v >> 51;
    }
    // Dropping the final carry is the subtraction of 2^255.

    // Serialise with 64-bit shifts only. A u128 shift pulls in the
    // compiler-rt intrinsic __ashlti3, which is an outside reference the
    // panic-free artifact check flags — and nothing here needs 128 bits: a
    // limb is 51 bits and at most 7 bits of carry-over sit above it.
    let mut out = [0u8; KEY_LEN];
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    let mut li = 0usize;
    for idx in 0..KEY_LEN {
        if bits < 8 {
            acc |= get(&t, li) << bits;      // bits < 8, limb < 2^51, so < 2^59
            bits = bits.wrapping_add(51);
            li = li.wrapping_add(1);
        }
        if let Some(p) = out.get_mut(idx) {
            *p = (acc & 0xFF) as u8;
        }
        acc >>= 8;
        bits = bits.wrapping_sub(8);
    }
    out
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
    let x1 = fe_from_bytes(point);

    let mut x2 = fe_one();
    let mut z2 = fe_zero();
    let mut x3 = x1;
    let mut z3 = fe_one();
    let mut swap = 0u64;

    let mut pos: i32 = 254;
    while pos >= 0 {
        let byte = k.get((pos as usize) >> 3).copied().unwrap_or(0);
        let bit = u64::from((byte >> ((pos as u32) & 7)) & 1);
        swap ^= bit;
        fe_cswap(swap, &mut x2, &mut x3);
        fe_cswap(swap, &mut z2, &mut z3);
        swap = bit;

        let a = fe_add(&x2, &z2);
        let b = fe_sub(&x2, &z2);
        let c = fe_add(&x3, &z3);
        let d = fe_sub(&x3, &z3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);
        let aa = fe_sq(&a);
        let bb = fe_sq(&b);
        let e = fe_sub(&aa, &bb);

        x3 = fe_sq(&fe_add(&da, &cb));
        z3 = fe_mul(&x1, &fe_sq(&fe_sub(&da, &cb)));
        x2 = fe_mul(&aa, &bb);
        z2 = fe_mul(&e, &fe_add(&bb, &fe_mul121666(&e)));

        pos = pos.saturating_sub(1);
    }
    fe_cswap(swap, &mut x2, &mut x3);
    fe_cswap(swap, &mut z2, &mut z3);

    fe_to_bytes(&fe_mul(&x2, &fe_invert(&z2)))
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
