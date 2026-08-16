// SPDX-FileCopyrightText: 2026 The tethermesh Authors
// SPDX-License-Identifier: Apache-2.0

//! Where a hardware crypto accelerator plugs in.
//!
//! `README.md` says of radios: *"A radio driver is deliberately not included —
//! implementers have their own, and tying the stack to one part would narrow
//! it for no benefit."* Crypto accelerators are the same argument, and this is
//! the seam that keeps it true.
//!
//! `docs/HARDWARE-BACKENDS.md` records what specific parts actually accelerate,
//! how confident each entry is, and which document would settle it. Read that
//! before assuming a part covers a primitive.
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
//! The secondary reason is **key custody**: a part with key storage can use a
//! private key without it ever appearing in addressable memory. That is what
//! [`SecretKey`] exists for — see below, because a seam that takes the scalar
//! as bytes cannot express it at all.
//!
//! # Coverage is patchy, so this is per-primitive
//!
//! Every method has a software default, and a backend overrides only what its
//! silicon actually covers. That is not a stylistic choice — parts differ
//! sharply in what they accelerate, and an all-or-nothing trait would force
//! implementers to either reimplement everything or use none of it.
//!
//! Of the nine parts surveyed in `docs/HARDWARE-BACKENDS.md`, **exactly one
//! accelerates this stack's curve** — and several that advertise an "ECC
//! accelerator" cannot touch Curve25519, because their unit is NIST-prime only.
//! Check the reference manual for the specific part rather than trusting a
//! summary; this is exactly the kind of claim that is stale as often as not,
//! and the 2026-08-16 survey found one entry in that document confidently
//! wrong for precisely this reason.
//!
//! # Two things this seam learned from real parts
//!
//! The first version of this trait was written against an on-chip accelerator
//! and was wrong for two of the parts surveyed. Both corrections are worth
//! stating, because both are invisible until an implementer hits them.
//!
//! **Hardware fails, and failure is not an answer.** An off-chip companion such
//! as the ATECC608B is reached over I²C: it can NAK, time out, arrive with a
//! bad CRC, or report a self-test failure. An on-chip engine can be busy or
//! wedged. A method returning `[u8; 32]` leaves such a backend two options,
//! both unacceptable — panic, which `DISTRIBUTION.md` forbids, or return
//! plausible garbage, which is worse than either. So every method returns
//! [`Result`].
//!
//! That also separates two things the old signature conflated. `x25519`
//! previously returned `Option`, where `None` meant a small-order peer key. A
//! hardware backend with no other channel would have reported an I²C timeout
//! the same way, making a loose connector indistinguishable from an active
//! attack. [`Error::Hardware`] and [`Error::SmallOrderPeer`] are now distinct,
//! and the distinction is load-bearing: one is retryable and the other must
//! never be.
//!
//! **A key that never leaves the part cannot be passed as bytes.** The custody
//! argument above is void if the signature demands the scalar, so the caller
//! names the key instead — [`SecretKey::Bytes`] for software, or
//! [`SecretKey::Slot`] for a key the accelerator holds and will not surrender.
//!
//! # Shape
//!
//! The backend is passed by reference, never stored in a global.
//! `DISTRIBUTION.md` forbids mutable global state because `Send`/`Sync` do not
//! cross an FFI boundary a foreign scheduler calls into, and an accelerator is
//! a shared peripheral — precisely the resource where that would bite.
//!
//! Methods take `&self` rather than `&mut self`, so one backend can be shared
//! by reference across call sites. A peripheral is stateful, so a real driver
//! will need a critical section or interior mutability of its own; that
//! synchronisation is the implementer's, because only they know what else on
//! the part contends for it.

use crate::crypto::{self, CcmError};
use crate::sha256;
use crate::x25519::{self, KEY_LEN};

/// Why a backend could not complete an operation.
///
/// Marked `#[non_exhaustive]`: new failure modes are expected as backends are
/// written, and adding one should not break a downstream `match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The hardware did not complete the operation — bus fault, NAK, timeout,
    /// peripheral busy, failed self-test.
    ///
    /// **This says nothing about the input.** It is the one error here that may
    /// be worth retrying, and it must never be reported for a result that is
    /// merely cryptographically unfavourable.
    Hardware,
    /// This backend cannot perform this operation as asked.
    ///
    /// The ordinary cause is a [`SecretKey::Slot`] given to a backend with no
    /// key storage, or a slot provisioned for a different algorithm. It is a
    /// statement about the request, not about the hardware's health.
    Unsupported,
    /// The peer's public key is small-order, driving the shared secret to zero
    /// whatever our private key is.
    ///
    /// RFC 7748 requires rejecting this. Accepting it would agree a "shared"
    /// secret with an attacker who knew it in advance, so this is a real
    /// finding about a real peer — never a transient condition.
    SmallOrderPeer,
    /// A CCM failure, including [`CcmError::Unauthentic`] for a tag that did
    /// not verify.
    Ccm(CcmError),
}

impl From<CcmError> for Error {
    fn from(e: CcmError) -> Self {
        Self::Ccm(e)
    }
}

/// How the caller names the private key for an X25519 operation.
///
/// Deliberately **not** `#[non_exhaustive]`, unlike [`Error`]. A backend must
/// handle every way a key can be named, and `#[non_exhaustive]` would push
/// implementers toward a wildcard arm — which would silently mishandle a new
/// variant instead of failing to compile. Adding a variant here should break
/// every backend on purpose.
#[derive(Debug, Clone, Copy)]
pub enum SecretKey<'a> {
    /// The scalar itself, in memory.
    ///
    /// The only option a software implementation has, and the only one that
    /// forfeits key custody: the bytes are addressable, so anything that can
    /// read memory can read the key.
    Bytes(&'a [u8; KEY_LEN]),
    /// A key held inside the accelerator, named by slot.
    ///
    /// The scalar is never returned, and on most parts cannot be. Backends
    /// without key storage return [`Error::Unsupported`], which is what every
    /// software default below does.
    Slot(u16),
}

/// The cryptographic primitives this stack needs.
///
/// Implement it to route any subset onto hardware. Everything not overridden
/// falls back to the portable software implementation, so a backend that
/// accelerates only SHA-256 really is a short `impl` with one method.
pub trait Crypto {
    /// X25519 agreement.
    ///
    /// # Errors
    ///
    /// [`Error::SmallOrderPeer`] for a small-order `peer`,
    /// [`Error::Unsupported`] for a [`SecretKey::Slot`] this backend does not
    /// hold, [`Error::Hardware`] for a peripheral or bus failure.
    fn x25519(&self, secret: SecretKey<'_>, peer: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN], Error> {
        match secret {
            SecretKey::Bytes(s) => x25519::x25519(s, peer).ok_or(Error::SmallOrderPeer),
            SecretKey::Slot(_) => Err(Error::Unsupported),
        }
    }

    /// The public key for a secret key.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] for a [`SecretKey::Slot`] this backend does not
    /// hold, [`Error::Hardware`] for a peripheral or bus failure.
    fn public_key(&self, secret: SecretKey<'_>) -> Result<[u8; KEY_LEN], Error> {
        match secret {
            SecretKey::Bytes(s) => Ok(x25519::public_key(s)),
            SecretKey::Slot(_) => Err(Error::Unsupported),
        }
    }

    /// SHA-256, used for the direct-message key derivation.
    ///
    /// One-shot rather than streaming, because the only use in this stack
    /// hashes a 32-byte shared secret. [`crate::sha256::Sha256`] remains
    /// available directly for anything that needs to absorb in pieces; a
    /// streaming hardware digest is a poor fit for a seam that must also be
    /// implementable by a companion chip over a bus.
    ///
    /// # Errors
    ///
    /// [`Error::Hardware`] for a peripheral or bus failure.
    fn sha256(&self, data: &[u8]) -> Result<[u8; sha256::DIGEST_LEN], Error> {
        Ok(sha256::sha256(data))
    }

    /// AES-CTR over channel traffic, in place.
    ///
    /// # Errors
    ///
    /// [`Error::Hardware`] for a peripheral or bus failure.
    fn aes_ctr(&self, key: &[u8; 16], nonce: &[u8; 16], data: &mut [u8]) -> Result<(), Error> {
        crypto::ctr_apply(key, nonce, data);
        Ok(())
    }

    /// AES-256-CCM open, in place. `buf` is `ciphertext || tag`.
    ///
    /// # Errors
    ///
    /// [`CcmError::Unauthentic`] if the tag does not verify — and a backend
    /// **must** preserve that: returning plaintext for a bad tag turns the one
    /// authenticated path in this stack into an unauthenticated one. A tag
    /// failure is also never [`Error::Hardware`]; reporting it as a retryable
    /// fault invites a caller to retry its way past authentication.
    fn ccm_open(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        buf: &mut [u8],
        tag_len: usize,
    ) -> Result<usize, Error> {
        crypto::ccm_decrypt_in_place(key, nonce, buf, tag_len).map_err(Error::Ccm)
    }

    /// AES-256-CCM seal, in place.
    ///
    /// # Errors
    ///
    /// [`Error::Ccm`] on a short buffer or an unsupported nonce length,
    /// [`Error::Hardware`] for a peripheral or bus failure.
    fn ccm_seal(
        &self,
        key: &[u8; 32],
        nonce: &[u8],
        buf: &mut [u8],
        msg_len: usize,
        tag_len: usize,
    ) -> Result<usize, Error> {
        crypto::ccm_encrypt_in_place(key, nonce, buf, msg_len, tag_len).map_err(Error::Ccm)
    }
}

/// The portable implementation, used when no accelerator is supplied.
///
/// Every method is the trait default, so this type exists to be named rather
/// than to add behaviour — and to make "no backend" an explicit choice at a
/// call site rather than an implicit one.
///
/// It has no key storage, so [`SecretKey::Slot`] is [`Error::Unsupported`] on
/// every path. Software cannot offer custody it does not have, and pretending
/// otherwise by accepting a slot number would be the worst outcome available.
#[derive(Debug, Clone, Copy, Default)]
pub struct Software;

impl Crypto for Software {}
