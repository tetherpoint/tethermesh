// SPDX-FileCopyrightText: 2026 Matthew Klapman
// SPDX-License-Identifier: Apache-2.0

//! Channel identification.
//!
//! The unencrypted header carries a one-byte hash of the channel. A receiver
//! uses it to decide, without decrypting anything, whether a frame is
//! plausibly for a channel it holds.
//!
//! # Provenance
//!
//! **Verified 2026-08-15** by observing a pinned oracle
//! (`meshtastic/meshtasticd` tag `2.7.26.54e0d8d`), not taken from a
//! secondary description. Two data points:
//!
//! | channel name | PSK | predicted | observed |
//! |---|---|---|---|
//! | `LongFast` | default PSK #1 | `0x08` | `0x08` |
//! | `TetherTest` | `00..0f` (XOR-fold `0x00`) | `0x0c` | `0x0c` |
//!
//! The second case is the one that carries the weight: the PSK was supplied
//! by us, so the result does not depend on the commonly-asserted default-PSK
//! value being correct, and a second match rules out the one-in-256
//! coincidence the first case alone would leave open. A third, independent
//! confirmation came from captured UDP traffic, where the `channel` field of
//! a `MeshPacket` on the default channel reads `8`.
//!
//! Vectors in `tests/captures/channel_hash.json`; the full record in
//! `docs/WIRE_REFERENCE.md`.
//!
//! # Two traps in the arguments
//!
//! Neither is visible from this function's signature, and both produce a
//! silently wrong hash rather than an error.
//!
//! **The name may be absent from the message.** Proto3 omits defaults, so the
//! default primary channel carries no `name` at all. The name to hash is then
//! the modem preset name — `LongFast` — not the empty string. Folding the
//! empty string gives `0x08 ^ 0x0a = 0x02` instead of the observed `0x08`,
//! and would be wrong for the most common channel on the network.
//!
//! **The PSK may be an index rather than a key.** A single byte `0x01` means
//! "the default key", which the reference expands at use. Pass the expanded
//! key; folding the index byte folds something else entirely.
//!
//! # This is identification, not authentication
//!
//! A one-byte hash collides roughly one time in 256, so a match means
//! "worth attempting", never "belongs to this channel". Nothing may treat a
//! hash match as evidence of anything. `WIRE_REFERENCE.md` records that
//! channel traffic has no authentication at all and that forgery does not
//! even require the PSK — the hash is a routing hint, and the extension
//! suite's AEAD tag exists precisely because there is nothing better here.

/// Fold a byte string into one byte by XOR.
///
/// Order-independent and collision-prone by construction; see the module
/// documentation for why that is acceptable for this use and for nothing
/// else.
fn xor_fold(bytes: &[u8]) -> u8 {
    let mut acc: u8 = 0;
    // Iterate rather than index: `clippy::indexing_slicing` is denied at
    // crate level because a slice index is a panic site, and this function
    // runs on attacker-supplied lengths.
    for byte in bytes {
        acc ^= *byte;
    }
    acc
}

/// Compute the one-byte channel hash carried in the unencrypted header.
///
/// `name` is the channel name as its raw bytes, and `psk` the pre-shared key
/// as stored — expanded, not a short index. Both are folded with XOR and the
/// results combined with XOR.
///
/// Total over all inputs: every byte string has a hash, there is no error
/// case, and an empty name or key is meaningful rather than invalid — an
/// empty input simply contributes nothing to the fold.
///
/// ```
/// use tethermesh::channel::channel_hash;
/// // Verified against the reference implementation; the PSK here is ours,
/// // so this case depends on nothing that has only been asserted.
/// let psk: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
/// assert_eq!(channel_hash(b"TetherTest", &psk), 0x0c);
/// ```
#[must_use]
pub fn channel_hash(name: &[u8], psk: &[u8]) -> u8 {
    xor_fold(name) ^ xor_fold(psk)
}
