//! AES-128 and the CTR construction the wire uses.
//!
//! # Provenance
//!
//! The nonce construction was **verified 2026-08-16** by decrypting frames
//! captured off the air to their known plaintext. See
//! `meshtastic/WIRE_REFERENCE.md`; the frames are in
//! `tests/captures/on_air_frames.json` and are used as this module's
//! known-answer vectors.
//!
//! # Encryption only, and why that is not a limitation
//!
//! CTR turns a block cipher into a stream cipher by encrypting a counter and
//! XORing the result with the data. The inverse cipher is never invoked, in
//! either direction — decrypting is the same operation as encrypting. So only
//! the forward direction is implemented. Half the code, half the tables, and
//! half the surface to get wrong.
//!
//! # Why this is hand-written
//!
//! `Cargo.toml` records that a dependency has to clear two bars: no
//! code-generation in the build, and nothing derived from a copyleft input.
//! AES is also small, fully specified by FIPS-197, and testable against
//! published vectors — so a dependency would buy little and cost the
//! `no_std`, no-allocation, panic-free guarantees this crate makes.
//!
//! # The security property this module cannot provide
//!
//! **CTR gives confidentiality and nothing else.** There is no authentication
//! here, and `WIRE_REFERENCE.md` records the consequence: an attacker who can
//! deduce one plaintext can reuse the `(packet_id, sender)` pair to forge
//! messages *without the key*. Nothing in this module detects that. The
//! extension suite's AEAD tag exists precisely because this layer cannot.
//!
//! And because the nonce is a pure function of `packet_id` and `from` — with
//! `extra_nonce` observed as zero on every captured frame — reusing that pair
//! reproduces the keystream exactly. See [`crate::packet_id`].

/// AES block size, and the CTR counter width.
pub const BLOCK: usize = 16;

/// The published default channel key, used when a PSK is the short index `1`.
pub const DEFAULT_KEY: [u8; 16] = [
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59,
    0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
];

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// S-box lookup, written as a total function.
///
/// The index is a `u8` and the table has 256 entries, so the fallback is
/// unreachable. It exists because `clippy::indexing_slicing` is denied at
/// crate level and a proof the compiler cannot see is not a proof it will
/// accept — and an unreachable `0` is a better failure than a panic on a
/// device parsing hostile input.
fn sbox(b: u8) -> u8 {
    at(&SBOX, b as usize)
}

/// Multiply by x in GF(2^8) with the AES reduction polynomial.
fn xtime(b: u8) -> u8 {
    let shifted = b.wrapping_shl(1);
    if b & 0x80 != 0 {
        shifted ^ 0x1B
    } else {
        shifted
    }
}


// ── total accessors ────────────────────────────────────────────────────────
// `clippy::indexing_slicing` and `clippy::arithmetic_side_effects` are denied
// at crate level, and AES is nothing but variable indexing and index
// arithmetic. Rather than suppress the lints for this file — which would
// defeat the point of having them — every access goes through these, and
// every index is computed with wrapping arithmetic.
//
// The fallbacks are unreachable: each index is derived from a `u8` or a bound
// under 16 into a table of exactly that size. They exist so the compiler can
// see totality without being handed a proof it cannot check. An unreachable
// zero is also a better outcome on a device parsing hostile input than a
// panic would be.
#[inline]
fn at(a: &[u8], i: usize) -> u8 {
    match a.get(i) {
        Some(v) => *v,
        None => 0,
    }
}

#[inline]
fn set(a: &mut [u8], i: usize, v: u8) {
    if let Some(p) = a.get_mut(i) {
        *p = v;
    }
}

#[inline]
const fn idx(col: usize, row: usize) -> usize {
    col.wrapping_mul(4).wrapping_add(row)
}

/// An expanded AES-128 key schedule.
#[derive(Clone)]
pub struct Aes128 {
    round_keys: [[u8; BLOCK]; 11],
}

impl Aes128 {
    /// Expand a 128-bit key.
    #[must_use]
    pub fn new(key: &[u8; BLOCK]) -> Self {
        let mut rk = [[0u8; BLOCK]; 11];
        if let Some(first) = rk.first_mut() {
            *first = *key;
        }
        let mut rcon: u8 = 1;
        for r in 1..11usize {
            let prev = match rk.get(r.wrapping_sub(1)) {
                Some(p) => *p,
                None => [0u8; BLOCK],
            };
            // RotWord, SubWord, then XOR the round constant into byte 0.
            let mut t = [
                sbox(at(&prev, 13)),
                sbox(at(&prev, 14)),
                sbox(at(&prev, 15)),
                sbox(at(&prev, 12)),
            ];
            let t0 = at(&t, 0) ^ rcon;
            set(&mut t, 0, t0);

            let mut cur = [0u8; BLOCK];
            for j in 0..4usize {
                set(&mut cur, j, at(&prev, j) ^ at(&t, j));
            }
            for col in 1..4usize {
                for j in 0..4usize {
                    let i = idx(col, j);
                    let v = at(&prev, i) ^ at(&cur, i.wrapping_sub(4));
                    set(&mut cur, i, v);
                }
            }
            if let Some(slot) = rk.get_mut(r) {
                *slot = cur;
            }
            rcon = xtime(rcon);
        }
        Self { round_keys: rk }
    }

    pub(crate) fn add_round_key(state: &mut [u8; BLOCK], rk: &[u8; BLOCK]) {
        for (s, k) in state.iter_mut().zip(rk.iter()) {
            *s ^= *k;
        }
    }

    fn sub_bytes(state: &mut [u8; BLOCK]) {
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
    }

    fn shift_rows(state: &mut [u8; BLOCK]) {
        // Column-major: byte (row r, col c) lives at index c*4 + r. Row r is
        // rotated left by r.
        let src = *state;
        for c in 0..4usize {
            for r in 0..4usize {
                let from = idx(c.wrapping_add(r) % 4, r);
                set(state, idx(c, r), at(&src, from));
            }
        }
    }

    fn mix_columns(state: &mut [u8; BLOCK]) {
        for c in 0..4usize {
            let a0 = at(state, idx(c, 0));
            let a1 = at(state, idx(c, 1));
            let a2 = at(state, idx(c, 2));
            let a3 = at(state, idx(c, 3));
            let t = a0 ^ a1 ^ a2 ^ a3;
            set(state, idx(c, 0), a0 ^ t ^ xtime(a0 ^ a1));
            set(state, idx(c, 1), a1 ^ t ^ xtime(a1 ^ a2));
            set(state, idx(c, 2), a2 ^ t ^ xtime(a2 ^ a3));
            set(state, idx(c, 3), a3 ^ t ^ xtime(a3 ^ a0));
        }
    }

    /// Encrypt one block in place. The only direction CTR needs.
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK]) {
        const ZERO: [u8; BLOCK] = [0u8; BLOCK];
        let rk = |i: usize| -> &[u8; BLOCK] { self.round_keys.get(i).unwrap_or(&ZERO) };

        Self::add_round_key(block, rk(0));
        for round in 1..10usize {
            Self::sub_bytes(block);
            Self::shift_rows(block);
            Self::mix_columns(block);
            Self::add_round_key(block, rk(round));
        }
        Self::sub_bytes(block);
        Self::shift_rows(block);
        Self::add_round_key(block, rk(10));
    }
}

/// Build the CTR nonce for a packet.
///
/// ```text
/// packet_id (u64 little-endian) || from (u32 little-endian) || extra_nonce (u32 little-endian)
/// ```
///
/// Verified against captured traffic. `extra_nonce` was zero in every frame
/// observed, which is what makes `(packet_id, from)` the whole of the nonce
/// in practice — and a repeat of that pair a keystream reuse.
#[must_use]
pub fn nonce(packet_id: u32, from: u32, extra_nonce: u32) -> [u8; BLOCK] {
    let mut n = [0u8; BLOCK];
    let id = u64::from(packet_id).to_le_bytes();
    let f = from.to_le_bytes();
    let e = extra_nonce.to_le_bytes();
    for i in 0..8usize {
        set(&mut n, i, at(&id, i));
    }
    for i in 0..4usize {
        set(&mut n, i.wrapping_add(8), at(&f, i));
        set(&mut n, i.wrapping_add(12), at(&e, i));
    }
    n
}

/// Apply AES-CTR in place.
///
/// Encryption and decryption are the same call. The counter block starts at
/// `nonce` and increments as a **128-bit big-endian integer**, which is the
/// behaviour confirmed by decrypting captured frames that span two blocks.
pub fn ctr_apply(key: &[u8; BLOCK], nonce: &[u8; BLOCK], data: &mut [u8]) {
    let aes = Aes128::new(key);
    let mut counter = *nonce;
    for chunk in data.chunks_mut(BLOCK) {
        let mut ks = counter;
        aes.encrypt_block(&mut ks);
        for (d, k) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= *k;
        }
        // Increment the counter big-endian, from the last byte back.
        for slot in counter.iter_mut().rev() {
            let (v, carry) = slot.overflowing_add(1);
            *slot = v;
            if !carry {
                break;
            }
        }
    }
}

/// What a stored PSK turned out to mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Psk {
    /// No encryption on this channel.
    None,
    /// A 128-bit key.
    Aes128([u8; 16]),
    /// A 256-bit key. Key expansion for it is not implemented here.
    Aes256([u8; 32]),
}

/// Expand a stored PSK into the key actually used.
///
/// A single byte is an index, not a key: `0` means no encryption, `1` means
/// the default channel key, and `2..=10` mean that key with `n - 1` added to
/// its **last byte**. The reference logs `Expand short PSK #1` when it does
/// this, and the default channel stores exactly one byte — so an
/// implementation that fed the stored bytes straight to AES would compute a
/// completely different key for the most common channel on the network, and
/// would do so silently.
///
/// Returns `None` for a length the wire does not define.
#[must_use]
pub fn expand_psk(stored: &[u8]) -> Option<Psk> {
    match stored.len() {
        0 => Some(Psk::None),
        1 => {
            let idx = *stored.first()?;
            if idx == 0 {
                return Some(Psk::None);
            }
            if idx > 10 {
                return None;
            }
            let mut key = DEFAULT_KEY;
            let last = key.last_mut()?;
            *last = last.wrapping_add(idx.checked_sub(1)?);
            Some(Psk::Aes128(key))
        }
        16 => {
            let mut key = [0u8; 16];
            for (d, s) in key.iter_mut().zip(stored.iter()) {
                *d = *s;
            }
            Some(Psk::Aes128(key))
        }
        32 => {
            let mut key = [0u8; 32];
            for (d, s) in key.iter_mut().zip(stored.iter()) {
                *d = *s;
            }
            Some(Psk::Aes256(key))
        }
        _ => None,
    }
}


/// An expanded AES-256 key schedule.
///
/// Direct messages use AES-256-CCM with the **full** 32-byte SHA-256 output as
/// the key — measured, not assumed. Truncating it to 128 bits is the obvious
/// wrong guess and produces a tag that never verifies.
#[derive(Clone)]
pub struct Aes256 {
    round_keys: [[u8; BLOCK]; 15],
}

impl Aes256 {
    /// Expand a 256-bit key.
    ///
    /// AES-256 differs from AES-128 in more than round count: the schedule
    /// applies an extra `SubWord` every eighth word, which is easy to omit and
    /// produces a cipher that is self-consistent and wrong.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let mut w = [0u8; 240];                      // 60 words of 4 bytes
        for (i, b) in key.iter().enumerate() {
            set(&mut w, i, *b);
        }
        let mut rcon: u8 = 1;
        for i in 8..60usize {
            let p = i.wrapping_sub(1).wrapping_mul(4);
            let mut t = [at(&w, p), at(&w, p.wrapping_add(1)),
                         at(&w, p.wrapping_add(2)), at(&w, p.wrapping_add(3))];
            if i % 8 == 0 {
                t = [sbox(at(&t, 1)) ^ rcon, sbox(at(&t, 2)), sbox(at(&t, 3)), sbox(at(&t, 0))];
                rcon = xtime(rcon);
            } else if i % 8 == 4 {
                t = [sbox(at(&t, 0)), sbox(at(&t, 1)), sbox(at(&t, 2)), sbox(at(&t, 3))];
            }
            let q = i.wrapping_sub(8).wrapping_mul(4);
            let d = i.wrapping_mul(4);
            for j in 0..4usize {
                let v = at(&w, q.wrapping_add(j)) ^ at(&t, j);
                set(&mut w, d.wrapping_add(j), v);
            }
        }
        let mut rk = [[0u8; BLOCK]; 15];
        for r in 0..15usize {
            let base = r.wrapping_mul(BLOCK);
            let mut block = [0u8; BLOCK];
            for j in 0..BLOCK {
                set(&mut block, j, at(&w, base.wrapping_add(j)));
            }
            if let Some(slot) = rk.get_mut(r) {
                *slot = block;
            }
        }
        Self { round_keys: rk }
    }

    /// Encrypt one block in place. CCM never needs the inverse cipher.
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK]) {
        const ZERO: [u8; BLOCK] = [0u8; BLOCK];
        let rk = |i: usize| -> &[u8; BLOCK] { self.round_keys.get(i).unwrap_or(&ZERO) };
        Aes128::add_round_key(block, rk(0));
        for round in 1..14usize {
            Aes128::sub_bytes(block);
            Aes128::shift_rows(block);
            Aes128::mix_columns(block);
            Aes128::add_round_key(block, rk(round));
        }
        Aes128::sub_bytes(block);
        Aes128::shift_rows(block);
        Aes128::add_round_key(block, rk(14));
    }
}

/// What went wrong in an authenticated decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CcmError {
    /// The buffer is smaller than the tag it is supposed to carry.
    TooShort,
    /// **The tag did not verify.** The message is forged, corrupted, or
    /// addressed to a different key. The plaintext must not be used.
    Unauthentic,
    /// Nonce length outside what this construction supports.
    BadNonce,
}

/// Tag length used by Meshtastic direct messages, in bytes.
pub const CCM_TAG_LEN: usize = 8;

/// Nonce length used by Meshtastic direct messages, in bytes.
pub const CCM_NONCE_LEN: usize = 13;

fn ccm_blocks(nonce: &[u8], msg_len: usize, tag_len: usize) -> Result<([u8; BLOCK], [u8; BLOCK]), CcmError> {
    if nonce.len() != CCM_NONCE_LEN {
        return Err(CcmError::BadNonce);
    }
    // L = 15 - nonce_len. With a 13-byte nonce, L = 2, so the length field is
    // two bytes and messages are limited to 65535 bytes — far above the 233
    // the wire allows anyway.
    let l: usize = 2;
    let mut b0 = [0u8; BLOCK];
    // flags = 64*has_aad + 8*((t-2)/2) + (L-1); no additional data here.
    let t_field = tag_len.saturating_sub(2) / 2;
    set(&mut b0, 0, ((t_field as u8) << 3) | ((l as u8).saturating_sub(1)));
    for (i, b) in nonce.iter().enumerate() {
        set(&mut b0, i.wrapping_add(1), *b);
    }
    set(&mut b0, 14, ((msg_len >> 8) & 0xFF) as u8);
    set(&mut b0, 15, (msg_len & 0xFF) as u8);

    let mut a0 = [0u8; BLOCK];
    set(&mut a0, 0, (l as u8).saturating_sub(1));
    for (i, b) in nonce.iter().enumerate() {
        set(&mut a0, i.wrapping_add(1), *b);
    }
    Ok((b0, a0))
}

fn cbc_mac(aes: &Aes256, b0: &[u8; BLOCK], plaintext: &[u8]) -> [u8; BLOCK] {
    let mut x = *b0;
    aes.encrypt_block(&mut x);
    for chunk in plaintext.chunks(BLOCK) {
        for (i, b) in chunk.iter().enumerate() {
            let cur = at(&x, i);
            set(&mut x, i, cur ^ *b);
        }
        aes.encrypt_block(&mut x);
    }
    x
}

fn ctr_xor(aes: &Aes256, a0: &[u8; BLOCK], data: &mut [u8]) {
    let mut counter: u16 = 1;
    for chunk in data.chunks_mut(BLOCK) {
        let mut ks = *a0;
        set(&mut ks, 14, ((counter >> 8) & 0xFF) as u8);
        set(&mut ks, 15, (counter & 0xFF) as u8);
        aes.encrypt_block(&mut ks);
        for (d, k) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= *k;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Decrypt and authenticate in place. `buf` is `ciphertext || tag`.
///
/// Returns the plaintext length, which is `buf.len() - tag_len`.
///
/// **The tag is checked before the plaintext is offered.** On
/// [`CcmError::Unauthentic`] the buffer holds whatever the keystream produced
/// and must be discarded — a forged direct message decrypts to *something*,
/// and the tag is the only thing that says it is not real.
///
/// # Errors
///
/// [`CcmError`] on a short buffer, a bad nonce, or a tag mismatch.
pub fn ccm_decrypt_in_place(
    key: &[u8; 32],
    nonce: &[u8],
    buf: &mut [u8],
    tag_len: usize,
) -> Result<usize, CcmError> {
    let msg_len = buf.len().checked_sub(tag_len).ok_or(CcmError::TooShort)?;
    let (b0, a0) = ccm_blocks(nonce, msg_len, tag_len)?;
    let aes = Aes256::new(key);

    // Recover the tag first: it is encrypted with counter 0.
    let mut received = [0u8; BLOCK];
    for (i, b) in buf.iter().skip(msg_len).take(tag_len).enumerate() {
        set(&mut received, i, *b);
    }
    let mut s0 = a0;
    aes.encrypt_block(&mut s0);
    for i in 0..tag_len {
        let v = at(&received, i) ^ at(&s0, i);
        set(&mut received, i, v);
    }

    let body = buf.get_mut(..msg_len).ok_or(CcmError::TooShort)?;
    ctr_xor(&aes, &a0, body);

    let expect = cbc_mac(&aes, &b0, body);
    // Constant-time-ish comparison: no early exit on the first differing byte.
    let mut diff = 0u8;
    for i in 0..tag_len {
        diff |= at(&expect, i) ^ at(&received, i);
    }
    if diff != 0 {
        return Err(CcmError::Unauthentic);
    }
    Ok(msg_len)
}

/// Encrypt and authenticate in place.
///
/// `buf` holds the plaintext in its first `msg_len` bytes and must have room
/// for `tag_len` more. Returns the total length written.
///
/// # Errors
///
/// [`CcmError`] on a short buffer or a bad nonce.
pub fn ccm_encrypt_in_place(
    key: &[u8; 32],
    nonce: &[u8],
    buf: &mut [u8],
    msg_len: usize,
    tag_len: usize,
) -> Result<usize, CcmError> {
    let total = msg_len.checked_add(tag_len).ok_or(CcmError::TooShort)?;
    if buf.len() < total {
        return Err(CcmError::TooShort);
    }
    let (b0, a0) = ccm_blocks(nonce, msg_len, tag_len)?;
    let aes = Aes256::new(key);

    let body = buf.get_mut(..msg_len).ok_or(CcmError::TooShort)?;
    let tag = cbc_mac(&aes, &b0, body);
    ctr_xor(&aes, &a0, body);

    let mut s0 = a0;
    aes.encrypt_block(&mut s0);
    for i in 0..tag_len {
        let v = at(&tag, i) ^ at(&s0, i);
        set(buf, msg_len.wrapping_add(i), v);
    }
    Ok(total)
}
