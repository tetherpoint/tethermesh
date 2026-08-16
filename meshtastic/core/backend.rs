//! Where a hardware crypto accelerator plugs in.
//!
//! `README.md` says of radios: *"A radio driver is deliberately not included —
//! implementers have their own, and tying the stack to one part would narrow
//! it for no benefit."* Crypto accelerators are the same argument, and this is
//! the seam that keeps it true.
//!
//! # Why this matters more than speed
//!
//! Throughput is the least interesting reason to use an accelerator here. A
//! frame is 233 bytes at most and the radio takes the better part of a second
//! to send it, so software crypto is never the bottleneck.
//!
//! The reason is **side-channel resistance**. [`crate::x25519`] states plainly
//! that its constant-time property is a strong expectation rather than a
//! guarantee, because Rust cannot express "do not turn this mask into a
//! branch" and nothing here verifies the emitted code. Hardware designed
//! against timing and power analysis can make a promise software on a
//! general-purpose core cannot. On a device an attacker can hold, that is the
//! difference that matters.
//!
//! The secondary reason is key custody: an accelerator with key storage can
//! use a private key without it ever appearing in addressable memory.
//!
//! # Coverage is patchy, so this is per-primitive
//!
//! Every method has a software default, and a backend overrides only what its
//! silicon actually covers. That is not a stylistic choice — parts differ
//! sharply in what they accelerate, and an all-or-nothing trait would force
//! implementers to either reimplement everything or use none of it.
//!
//! The bench hardware for this project illustrates it: an ESP32-S3 has
//! dedicated AES and SHA accelerators, while its ECC unit covers the NIST
//! prime curves rather than Curve25519 — so on that part `sha256` and the AES
//! paths are worth overriding and [`Crypto::x25519`] is not. Check the
//! reference manual for the specific part rather than trusting a summary;
//! this is exactly the kind of claim that is stale as often as not.
//!
//! # Shape
//!
//! The backend is passed by reference, never stored in a global.
//! `DISTRIBUTION.md` forbids mutable global state because `Send`/`Sync` do not
//! cross an FFI boundary a foreign scheduler calls into, and an accelerator is
//! a shared peripheral — precisely the resource where that would bite.

use crate::crypto::{self, CcmError};
use crate::sha256;
use crate::x25519;

/// The cryptographic primitives this stack needs.
///
/// Implement it to route any subset onto hardware. Everything not overridden
/// falls back to the portable software implementation, so a backend that
/// accelerates only SHA-256 is a three-line type.
pub trait Crypto {
    /// X25519 agreement. `None` for a small-order peer key.
    fn x25519(&self, secret: &[u8; 32], peer: &[u8; 32]) -> Option<[u8; 32]> {
        x25519::x25519(secret, peer)
    }

    /// The public key for a secret key.
    fn public_key(&self, secret: &[u8; 32]) -> [u8; 32] {
        x25519::public_key(secret)
    }

    /// SHA-256, used for the direct-message key derivation.
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        sha256::sha256(data)
    }

    /// AES-CTR over channel traffic, in place.
    fn aes_ctr(&self, key: &[u8; 16], nonce: &[u8; 16], data: &mut [u8]) {
        crypto::ctr_apply(key, nonce, data);
    }

    /// AES-256-CCM open, in place. `buf` is `ciphertext || tag`.
    ///
    /// # Errors
    ///
    /// [`CcmError::Unauthentic`] if the tag does not verify — and a backend
    /// **must** preserve that: returning plaintext for a bad tag turns the one
    /// authenticated path in this stack into an unauthenticated one.
    fn ccm_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        buf: &mut [u8],
        tag_len: usize,
    ) -> Result<usize, CcmError> {
        crypto::ccm_decrypt_in_place(key, nonce, buf, tag_len)
    }

    /// AES-256-CCM seal, in place.
    ///
    /// # Errors
    ///
    /// [`CcmError`] on a short buffer or an unsupported nonce length.
    fn ccm_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        buf: &mut [u8],
        msg_len: usize,
        tag_len: usize,
    ) -> Result<usize, CcmError> {
        crypto::ccm_encrypt_in_place(key, nonce, buf, msg_len, tag_len)
    }
}

/// The portable implementation, used when no accelerator is supplied.
///
/// Every method is the trait default, so this type exists to be named rather
/// than to add behaviour — and to make "no backend" an explicit choice at a
/// call site rather than an implicit one.
#[derive(Debug, Clone, Copy, Default)]
pub struct Software;

impl Crypto for Software {}
