// SPDX-FileCopyrightText: 2026 Matthew Klapman
// SPDX-License-Identifier: Apache-2.0

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
/// **This is the Meshtastic-compatible path and its ceiling is
/// [`MAX_PAYLOAD`].** Anything larger needs [`encode_bounded`], and needs to
/// have read why that is a different function.
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
    encode_bounded(header, plaintext, key, extra_nonce, MAX_PAYLOAD, out)
}

/// Build a frame with an explicit payload ceiling.
///
/// **[`encode`] is this with `max_payload = MAX_PAYLOAD`, and on any
/// Meshtastic carrier that is the only correct value.** A frame carrying more
/// than 233 bytes is not a Meshtastic frame: a stock node cannot parse it, and
/// emitting one on a shared channel spends airtime that reaches nobody.
///
/// # Why this exists at all
///
/// Nothing about the frame *layout* is 233-specific. The header is 16 bytes,
/// the payload is CTR-encrypted in place, and [`decode_in_place`] already
/// carries no payload bound whatever — it decrypts what it is given. The 233
/// is `Constants.DATA_PAYLOAD_LEN`, an upstream constant, and it was the only
/// thing in this module that assumed a carrier.
///
/// A carrier that is not LoRa may carry more. FLRC's frame is 511 bytes, and a
/// consumer fragmenting above this module to stay inside 233 pays about **13%**
/// extra airtime for frames it did not need to split. This lets that consumer
/// decide, without a fork and without this module knowing what FLRC is.
///
/// # This does not weaken the compatibility claim, and the reason is structural
///
/// The default is unchanged, [`encode`] is byte-identical to what it was, and
/// no code that does not pass a larger ceiling can produce a frame that differs
/// by one bit. **A caller that passes a larger ceiling has left Meshtastic
/// deliberately and knows it** — which is a different thing from a library that
/// drifts.
///
/// # Errors
///
/// [`Error::PayloadTooLong`] above `max_payload`, [`Error::BufferTooSmall`]
/// if `out` cannot hold header plus payload.
pub fn encode_bounded(
    header: &Header,
    plaintext: &[u8],
    key: &[u8; BLOCK],
    extra_nonce: u32,
    max_payload: usize,
    out: &mut [u8],
) -> Result<usize, Error> {
    if plaintext.len() > max_payload {
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
