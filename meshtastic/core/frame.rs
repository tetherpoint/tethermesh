//! Whole frames: the header and the encrypted payload, together.
//!
//! [`crate::header`] packs the sixteen unencrypted bytes and
//! [`crate::crypto`] turns a payload into ciphertext. This joins them into
//! the thing that actually goes on the air, and takes it apart again.
//!
//! ```text
//! +----------------------------+---------------------------+
//! | 16-byte header, cleartext  | AES-CTR ciphertext         |
//! +----------------------------+---------------------------+
//! ```
//!
//! # Encrypt and decrypt happen in the caller's buffer
//!
//! No allocation, so there is nowhere to put a second copy. Both directions
//! work in place on a buffer the caller owns and sized. That is not only a
//! `no_std` concession: a frame that is decrypted into a fresh buffer tends
//! to leave the ciphertext lying around as well, and on a device with no
//! memory protection the fewer copies of anything the better.
//!
//! # The header is not covered by the encryption
//!
//! It cannot be — relays must read and rewrite `hop_limit` without the key,
//! which is the property the whole mesh depends on and which this project
//! measured directly. The consequence is that **nothing authenticates the
//! header**, and CTR authenticates nothing at all. A decode that succeeds
//! means "the keystream produced these bytes", never "this frame is genuine".
//!
//! `WIRE_REFERENCE.md` records that forging does not even require the key: an
//! attacker who deduces one plaintext can reuse the `(packet_id, sender)`
//! pair. Treat a decoded frame as attacker-controlled input all the way up.

use crate::crypto::{ctr_apply, nonce, BLOCK};
use crate::header::{Header, HEADER_LEN};

/// Largest payload the wire carries, per `Constants.DATA_PAYLOAD_LEN`.
///
/// 233, not the 237 usually quoted — any budget computed at 237 is four bytes
/// optimistic.
pub const MAX_PAYLOAD: usize = 233;

/// Largest whole frame.
pub const MAX_FRAME: usize = HEADER_LEN + MAX_PAYLOAD;

/// What went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Fewer than [`HEADER_LEN`] bytes: not a frame at all.
    TooShort,
    /// Payload exceeds [`MAX_PAYLOAD`].
    PayloadTooLong,
    /// The caller's output buffer cannot hold the result.
    BufferTooSmall,
}

/// Build a frame into `out`, returning its length.
///
/// The payload is copied in and then encrypted in place, so `plaintext` is
/// left untouched.
///
/// # Errors
///
/// [`Error::PayloadTooLong`] above [`MAX_PAYLOAD`], [`Error::BufferTooSmall`]
/// if `out` cannot hold header plus payload.
pub fn encode(
    header: &Header,
    plaintext: &[u8],
    key: &[u8; BLOCK],
    extra_nonce: u32,
    out: &mut [u8],
) -> Result<usize, Error> {
    if plaintext.len() > MAX_PAYLOAD {
        return Err(Error::PayloadTooLong);
    }
    let total = HEADER_LEN.checked_add(plaintext.len()).ok_or(Error::PayloadTooLong)?;
    let buf = out.get_mut(..total).ok_or(Error::BufferTooSmall)?;

    let head = header.encode();
    let (head_dst, body_dst) = buf.split_at_mut(HEADER_LEN);
    // zip rather than copy_from_slice: the latter panics on a length
    // mismatch and the optimiser cannot prove these equal, so the panic path
    // survives into the artifact and breaks the crate's central promise.
    // Lengths here are equal by construction.
    for (d, s) in head_dst.iter_mut().zip(head.iter()) {
        *d = *s;
    }
    for (d, s) in body_dst.iter_mut().zip(plaintext.iter()) {
        *d = *s;
    }

    ctr_apply(key, &nonce(header.id, header.from, extra_nonce), body_dst);
    Ok(total)
}

/// Take a frame apart, decrypting the payload in place.
///
/// Returns the header and the plaintext, which borrows the caller's buffer.
///
/// **A successful return is not an authenticity claim.** CTR will decrypt any
/// bytes at all into some other bytes; whether they mean anything is for the
/// layer above to decide, and it should decide sceptically.
///
/// # Errors
///
/// [`Error::TooShort`] if the input cannot hold a header.
pub fn decode_in_place<'a>(
    frame: &'a mut [u8],
    key: &[u8; BLOCK],
    extra_nonce: u32,
) -> Result<(Header, &'a [u8]), Error> {
    let header = Header::decode(frame).ok_or(Error::TooShort)?;
    let body = frame.get_mut(HEADER_LEN..).ok_or(Error::TooShort)?;
    ctr_apply(key, &nonce(header.id, header.from, extra_nonce), body);
    Ok((header, body))
}

/// Read the header without touching the payload.
///
/// This is the relay path, and the reason it exists separately is the
/// measured behaviour of stock nodes: they forward frames on channels they
/// cannot decrypt. Routing needs the header and nothing else, so a relay must
/// never need the key — and calling a decrypt function with a key that cannot
/// work would be a strange way to express that.
///
/// # Errors
///
/// [`Error::TooShort`] if the input cannot hold a header.
pub fn peek_header(frame: &[u8]) -> Result<Header, Error> {
    Header::decode(frame).ok_or(Error::TooShort)
}

/// The ciphertext, unmodified.
///
/// # Errors
///
/// [`Error::TooShort`] if the input cannot hold a header.
pub fn payload(frame: &[u8]) -> Result<&[u8], Error> {
    frame.get(HEADER_LEN..).ok_or(Error::TooShort)
}
