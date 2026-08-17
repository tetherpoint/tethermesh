// SPDX-FileCopyrightText: 2026 The tethermesh Authors
// SPDX-License-Identifier: Apache-2.0

//! `groups` — authenticated channels with membership.
//!
//! Implements `suite/groups/SPEC.md`. Read that first: it argues the design and
//! records what the construction does *not* protect, which matters more here
//! than in most modules because the words "revocation" and "authenticated"
//! both promise more than this delivers.
//!
//! # The one-paragraph version
//!
//! Meshtastic channel traffic is AES-CTR under a shared key with **no
//! authentication**, so anyone holding the key can send as any node — and
//! because CTR is a stream cipher with no tag, an attacker who can guess a
//! plaintext can forge without holding the key at all. This adds an AES-CCM tag
//! bound to the invariant part of the cleartext header, plus an owner, a roster
//! and an epoch, all inside the payload of a private portnum so stock nodes
//! relay it and ignore it.
//!
//! # What is authenticated, and what cannot be
//!
//! Origin and content. **Not path.** `hop_limit`, `next_hop` and `relay_node`
//! change legitimately in transit, so a tag covering them would fail on every
//! multi-hop delivery — see [`aad_from_header`]. Anyone describing this as
//! "authenticating the header" should be corrected.
//!
//! # What revocation is not
//!
//! It protects *future* traffic only. A revoked member keeps everything they
//! already held and heard. **This is not forward secrecy** and must never be
//! described as such; that would need per-message ephemeral keys, which is not
//! viable at 233 bytes and sub-kilobit airtime.

#![no_std]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::arithmetic_side_effects)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(unsafe_code)]
#![deny(missing_docs)]

use tethermesh::crypto::{
    ccm_decrypt_in_place_aad, ccm_encrypt_in_place_aad, CcmError, CCM_NONCE_LEN, CCM_TAG_LEN,
};
use tethermesh::header::HEADER_LEN;
use tethermesh::sha256::sha256;

/// Envelope format version. Bumped when the layout below changes.
pub const VERSION: u8 = 1;

/// The private PortNum this bundle rides on.
///
/// **Provisional and unregistered.** Upstream reserves `>= 256` for private
/// use, which makes the *range* safe and this specific value nobody's to claim.
/// Two suites picking 256 would each see the other's traffic as malformed —
/// which is survivable only because a failed parse is a silent drop.
pub const PORTNUM: u32 = 256;

/// Bytes of envelope before the ciphertext: version, type, group, epoch.
pub const HEADER_BYTES: usize = 7;

/// Fixed cost of the extension: envelope header plus tag.
///
/// Fifteen bytes, roughly 116 ms of airtime at LongFast. That is 37% of a
/// 40-byte message and 7.5% of a 200-byte one — well suited to carrying
/// meaningful payloads and poorly suited to chatter.
pub const OVERHEAD: usize = HEADER_BYTES + CCM_TAG_LEN;

/// Length of the additional authenticated data: the invariant header subset.
pub const AAD_LEN: usize = 14;

/// Domain separation for the epoch key derivation.
const KDF_LABEL: &[u8] = b"tethermesh-groups-v1";

/// What an envelope carries.
///
/// Values are wire values and must not be renumbered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    /// Application payload from any member.
    Data = 1,
    /// Owner to one member: the wrapped epoch key.
    Invite = 2,
    /// Owner to the group: an epoch bump happened.
    Revoke = 3,
    /// Owner to the group: current membership.
    Roster = 4,
    /// Member to owner: voluntary departure.
    Leave = 5,
}

impl MsgType {
    /// Read a wire value, or `None` if it names nothing.
    ///
    /// An unknown type is **not** an error to escalate — a future version may
    /// define one, and a node that refused to relay what it cannot parse would
    /// break the property the whole suite rests on.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Data),
            2 => Some(Self::Invite),
            3 => Some(Self::Revoke),
            4 => Some(Self::Roster),
            5 => Some(Self::Leave),
            _ => None,
        }
    }
}

/// Why an envelope could not be produced or accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The buffer cannot hold the result.
    BufferTooSmall,
    /// Fewer bytes than an envelope can occupy, or a truncated body.
    Malformed,
    /// Envelope version this build does not implement.
    UnsupportedVersion,
    /// **The tag did not verify.** Forged, corrupted, addressed to another
    /// group, or sent under a different epoch. The plaintext must not be used.
    Unauthentic,
    /// A group identifier of zero, which names no group.
    BadGroupId,
    /// No room left in a fixed-capacity roster.
    RosterFull,
    /// The operation requires the owner and the caller is not it.
    NotOwner,
    /// The epoch byte would wrap, which would reuse nonces. See
    /// [`Roster::bump_epoch`].
    EpochExhausted,
}

impl From<CcmError> for Error {
    fn from(e: CcmError) -> Self {
        match e {
            CcmError::Unauthentic => Self::Unauthentic,
            // TooShort and BadNonce both mean the caller handed us something
            // the construction cannot express. Neither is ever a tag failure,
            // and collapsing them into Unauthentic would tell an attacker
            // nothing but would tell US the wrong thing while debugging.
            _ => Self::Malformed,
        }
    }
}

/// The additional authenticated data for a frame: the **invariant** subset of
/// the cleartext header.
///
/// # Why not all sixteen bytes
///
/// `hop_limit` (byte 12, bits 0–2), `next_hop` (14) and `relay_node` (15)
/// change legitimately in transit — every relay decrements the first and stamps
/// the last. A tag covering them verifies only for a packet nobody has relayed,
/// so on a flood mesh it would fail on **every multi-hop delivery**, presenting
/// as "works on the bench, not in the field".
///
/// The mask keeps `want_ack`, `via_mqtt` and `hop_start`, and clears
/// `hop_limit`.
#[must_use]
pub fn aad_from_header(header: &[u8; HEADER_LEN]) -> [u8; AAD_LEN] {
    let mut out = [0u8; AAD_LEN];
    for (d, s) in out.iter_mut().zip(header.iter()) {
        *d = *s;
    }
    // Byte 12 keeps only the bits that do not move. `get`/`get_mut`, not
    // indexing: bare indexing compiles to a panic path and the crate rules
    // forbid one reaching a linked artifact.
    if let (Some(d), Some(s)) = (out.get_mut(12), header.get(12)) {
        *d = *s & 0xF8;
    }
    out
}

/// Derive the AES-256 key for an epoch.
///
/// `SHA-256(group_key ‖ "tethermesh-groups-v1" ‖ epoch)`. The digest is exactly
/// an AES-256 key, so there is no truncation step and no opportunity to
/// truncate inconsistently at the two ends.
#[must_use]
pub fn epoch_key(group_key: &[u8; 32], epoch: u8) -> [u8; 32] {
    let mut input = [0u8; 32 + 20 + 1];
    let mut n: usize = 0;
    for (d, s) in input.iter_mut().zip(group_key.iter()) {
        *d = *s;
        n = n.wrapping_add(1);
    }
    for (i, s) in KDF_LABEL.iter().enumerate() {
        if let Some(d) = input.get_mut(n.wrapping_add(i)) {
            *d = *s;
        }
    }
    n = n.wrapping_add(KDF_LABEL.len());
    if let Some(d) = input.get_mut(n) {
        *d = epoch;
    }
    n = n.wrapping_add(1);
    match input.get(..n) {
        Some(slice) => sha256(slice),
        // Unreachable: the array is sized for exactly this. Returning a hash of
        // the whole buffer rather than panicking, because the crate rules
        // forbid a panic path and a wrong key fails loudly at the tag anyway.
        None => sha256(&input),
    }
}

/// The CCM nonce for a frame.
///
/// `from ‖ id ‖ epoch ‖ zero padding`, little-endian, 13 bytes.
///
/// **Uniqueness rests on a sender never reusing a packet id under one key.** A
/// repeated `(from, id)` within an epoch is a nonce reuse, and under CCM that
/// breaks confidentiality and authenticity together — worse than the same
/// mistake costs the plain CTR layer.
#[must_use]
pub fn nonce(from: u32, id: u32, epoch: u8) -> [u8; CCM_NONCE_LEN] {
    let mut out = [0u8; CCM_NONCE_LEN];
    for (i, b) in from.to_le_bytes().iter().enumerate() {
        if let Some(d) = out.get_mut(i) {
            *d = *b;
        }
    }
    for (i, b) in id.to_le_bytes().iter().enumerate() {
        if let Some(d) = out.get_mut(i.wrapping_add(4)) {
            *d = *b;
        }
    }
    if let Some(d) = out.get_mut(8) {
        *d = epoch;
    }
    out
}

/// A sealed extension message, as it sits in `Data.payload`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Envelope<'a> {
    /// Envelope format version.
    pub version: u8,
    /// What the body means.
    pub msg_type: MsgType,
    /// Which group. Never zero.
    pub group_id: u32,
    /// Which epoch key sealed it.
    pub epoch: u8,
    /// Ciphertext followed by the tag, undecrypted.
    pub sealed: &'a [u8],
}

/// Seal a message into `out`, returning the number of bytes written.
///
/// `plaintext` is copied in and encrypted in place, so `out` needs
/// `plaintext.len() + OVERHEAD` bytes.
///
/// # Errors
///
/// [`Error::BadGroupId`] for a zero group, [`Error::BufferTooSmall`] if `out`
/// cannot hold the result.
pub fn seal(
    group_key: &[u8; 32],
    group_id: u32,
    epoch: u8,
    msg_type: MsgType,
    header: &[u8; HEADER_LEN],
    from: u32,
    id: u32,
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    if group_id == 0 {
        return Err(Error::BadGroupId);
    }
    let total = plaintext
        .len()
        .checked_add(OVERHEAD)
        .ok_or(Error::BufferTooSmall)?;
    if out.len() < total {
        return Err(Error::BufferTooSmall);
    }

    if let Some(d) = out.get_mut(0) {
        *d = VERSION;
    }
    if let Some(d) = out.get_mut(1) {
        *d = msg_type as u8;
    }
    for (i, b) in group_id.to_le_bytes().iter().enumerate() {
        if let Some(d) = out.get_mut(i.wrapping_add(2)) {
            *d = *b;
        }
    }
    if let Some(d) = out.get_mut(6) {
        *d = epoch;
    }

    let body = out
        .get_mut(HEADER_BYTES..total)
        .ok_or(Error::BufferTooSmall)?;
    for (d, s) in body.iter_mut().zip(plaintext.iter()) {
        *d = *s;
    }

    let key = epoch_key(group_key, epoch);
    let n = nonce(from, id, epoch);
    let aad = aad_from_header(header);
    let written = ccm_encrypt_in_place_aad(&key, &n, &aad, body, plaintext.len(), CCM_TAG_LEN)?;
    HEADER_BYTES.checked_add(written).ok_or(Error::BufferTooSmall)
}

/// Parse an envelope without decrypting it.
///
/// Cheap, and it is what a node uses to decide whether a message is even for a
/// group it belongs to before spending a CCM verification on it.
///
/// # Errors
///
/// [`Error::Malformed`] if it is too short, [`Error::UnsupportedVersion`] for a
/// version this build does not implement, [`Error::BadGroupId`] for a zero
/// group.
pub fn parse(payload: &[u8]) -> Result<Envelope<'_>, Error> {
    if payload.len() < OVERHEAD {
        return Err(Error::Malformed);
    }
    let version = *payload.first().ok_or(Error::Malformed)?;
    if version != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let raw_type = *payload.get(1).ok_or(Error::Malformed)?;
    let msg_type = MsgType::from_u8(raw_type).ok_or(Error::Malformed)?;

    let mut gid = [0u8; 4];
    for (i, d) in gid.iter_mut().enumerate() {
        *d = *payload.get(i.wrapping_add(2)).ok_or(Error::Malformed)?;
    }
    let group_id = u32::from_le_bytes(gid);
    if group_id == 0 {
        return Err(Error::BadGroupId);
    }
    let epoch = *payload.get(6).ok_or(Error::Malformed)?;
    let sealed = payload.get(HEADER_BYTES..).ok_or(Error::Malformed)?;

    Ok(Envelope { version, msg_type, group_id, epoch, sealed })
}

/// Verify and decrypt in place, returning the plaintext length.
///
/// `buf` must hold the envelope exactly as received; the plaintext ends up in
/// `buf[HEADER_BYTES..HEADER_BYTES + n]`.
///
/// # Errors
///
/// [`Error::Unauthentic`] when the tag does not verify — **the plaintext must
/// not be used**, and a node should drop the frame *silently*, because
/// answering "your tag was wrong" confirms group membership to anyone probing
/// for it.
pub fn open_in_place(
    group_key: &[u8; 32],
    header: &[u8; HEADER_LEN],
    from: u32,
    id: u32,
    buf: &mut [u8],
) -> Result<usize, Error> {
    let (epoch, group_id) = {
        let e = parse(buf)?;
        (e.epoch, e.group_id)
    };
    if group_id == 0 {
        return Err(Error::BadGroupId);
    }

    let key = epoch_key(group_key, epoch);
    let n = nonce(from, id, epoch);
    let aad = aad_from_header(header);
    let body = buf.get_mut(HEADER_BYTES..).ok_or(Error::Malformed)?;
    let len = ccm_decrypt_in_place_aad(&key, &n, &aad, body, CCM_TAG_LEN)?;
    Ok(len)
}

/// One member: a node number and the public key an invite is wrapped to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Member {
    /// Node number. Zero means an empty slot.
    pub node: u32,
    /// X25519 public key.
    pub public_key: [u8; 32],
}

/// Membership, in caller-provided fixed capacity.
///
/// `N` is the integrator's decision. Nothing here allocates — the same shape
/// `history::PacketHistory` and `delivery::Outbox` already use, so a full
/// roster is a refusal rather than a reallocation.
///
/// # One owner, and what that costs
///
/// **If the owner is lost the group can never be changed again**, only
/// abandoned. Multi-owner consensus over a lossy mesh with no ordering
/// guarantees is a distributed-systems problem this bundle declines to solve at
/// 233 bytes per message. Create groups from a node unlikely to vanish, and
/// treat them as cheap to recreate.
#[derive(Debug, Clone, Copy)]
pub struct Roster<const N: usize> {
    owner: u32,
    epoch: u8,
    members: [Member; N],
}

impl<const N: usize> Roster<N> {
    /// A new roster owned by `owner`, at epoch 0.
    #[must_use]
    pub const fn new(owner: u32) -> Self {
        Self {
            owner,
            epoch: 0,
            members: [Member { node: 0, public_key: [0u8; 32] }; N],
        }
    }

    /// The owning node.
    #[must_use]
    pub const fn owner(&self) -> u32 {
        self.owner
    }

    /// The current epoch.
    #[must_use]
    pub const fn epoch(&self) -> u8 {
        self.epoch
    }

    /// How many members are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.iter().filter(|m| m.node != 0).count()
    }

    /// Whether the roster holds nobody.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether `node` is a member.
    #[must_use]
    pub fn contains(&self, node: u32) -> bool {
        node != 0 && self.members.iter().any(|m| m.node == node)
    }

    /// Add a member, or replace the key of one already present.
    ///
    /// # Errors
    ///
    /// [`Error::NotOwner`] unless `actor` owns the group, [`Error::RosterFull`]
    /// when there is no free slot.
    pub fn add(&mut self, actor: u32, node: u32, public_key: &[u8; 32]) -> Result<(), Error> {
        if actor != self.owner {
            return Err(Error::NotOwner);
        }
        if node == 0 {
            return Err(Error::Malformed);
        }
        if let Some(slot) = self.members.iter_mut().find(|m| m.node == node) {
            slot.public_key = *public_key;
            return Ok(());
        }
        let slot = self
            .members
            .iter_mut()
            .find(|m| m.node == 0)
            .ok_or(Error::RosterFull)?;
        slot.node = node;
        slot.public_key = *public_key;
        Ok(())
    }

    /// Remove a member. Returns whether one was present.
    ///
    /// **Removing does not revoke.** The epoch must be bumped and the key
    /// re-wrapped to everyone remaining, or the removed member can still read
    /// everything sent — see [`Self::bump_epoch`].
    ///
    /// # Errors
    ///
    /// [`Error::NotOwner`] unless `actor` owns the group.
    pub fn remove(&mut self, actor: u32, node: u32) -> Result<bool, Error> {
        if actor != self.owner {
            return Err(Error::NotOwner);
        }
        match self.members.iter_mut().find(|m| m.node == node && node != 0) {
            Some(slot) => {
                *slot = Member { node: 0, public_key: [0u8; 32] };
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Advance the epoch, which is what actually revokes.
    ///
    /// # Errors
    ///
    /// [`Error::NotOwner`] unless `actor` owns the group.
    ///
    /// [`Error::EpochExhausted`] at 255 rather than wrapping to 0. **A wrap is
    /// not a rekey**: the epoch feeds the key derivation, so returning to 0
    /// reproduces an earlier key and reuses every nonce under it, which breaks
    /// confidentiality and authenticity at once. The group key itself must be
    /// rotated before this point; refusing is the only safe alternative to
    /// doing it silently.
    pub fn bump_epoch(&mut self, actor: u32) -> Result<u8, Error> {
        if actor != self.owner {
            return Err(Error::NotOwner);
        }
        let next = self.epoch.checked_add(1).ok_or(Error::EpochExhausted)?;
        self.epoch = next;
        Ok(next)
    }

    /// Iterate the members currently held.
    pub fn members(&self) -> impl Iterator<Item = &Member> {
        self.members.iter().filter(|m| m.node != 0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    const GK: [u8; 32] = [7u8; 32];
    const HDR: [u8; HEADER_LEN] = [
        0xff, 0xff, 0xff, 0xff, // to
        0x01, 0x00, 0x57, 0x7e, // from
        0xde, 0xc0, 0xad, 0x0b, // id
        0x63, // flags: hop_limit 3, want_ack 0, hop_start 3
        0x08, // channel
        0x00, // next_hop
        0x00, // relay_node
    ];

    fn seal_probe(buf: &mut [u8], pt: &[u8]) -> usize {
        seal(&GK, 0xCAFE, 0, MsgType::Data, &HDR, 0x7e57_0001, 0x0bad_c0de, pt, buf)
            .expect("seal")
    }

    #[test]
    fn a_sealed_message_opens_to_what_went_in() {
        let pt = b"groups-round-trip";
        let mut buf = [0u8; 128];
        let n = seal_probe(&mut buf, pt);
        assert_eq!(n, pt.len() + OVERHEAD, "overhead is 15 bytes and fixed");

        let e = parse(&buf[..n]).expect("parse");
        assert_eq!(e.version, VERSION);
        assert_eq!(e.msg_type, MsgType::Data);
        assert_eq!(e.group_id, 0xCAFE);
        assert_eq!(e.epoch, 0);

        let len = open_in_place(&GK, &HDR, 0x7e57_0001, 0x0bad_c0de, &mut buf[..n]).expect("open");
        assert_eq!(&buf[HEADER_BYTES..HEADER_BYTES + len], pt);
    }

    /// The gate's forged-sender case, forged the way an attacker would.
    ///
    /// SPEC.md § 10 warns about exactly this: forging by corrupting a tag at
    /// random proves nothing, because any AEAD rejects that. A real forgery
    /// keeps a valid-looking frame and changes who it claims to be from -- which
    /// is free under plain Meshtastic, since `from` is an unauthenticated field
    /// in a cleartext header.
    #[test]
    fn a_forged_sender_fails_the_tag() {
        let mut buf = [0u8; 128];
        let n = seal_probe(&mut buf, b"who sent this?");

        // Same bytes, same key, same epoch -- only `from` in the header differs.
        let mut forged = HDR;
        forged[4] = 0x99;
        assert_eq!(
            open_in_place(&GK, &forged, 0x7e57_0001, 0x0bad_c0de, &mut buf[..n]),
            Err(Error::Unauthentic),
            "a rewritten sender must not verify -- this is the property the \
             whole bundle exists for"
        );
    }

    /// A relay decrementing hop_limit must NOT break verification.
    ///
    /// The counterpart to the test above, and the reason the AAD is a subset.
    /// Binding all sixteen header bytes would fail here -- on every multi-hop
    /// delivery, on a mesh larger than a bench.
    #[test]
    fn a_relayed_frame_still_verifies() {
        let mut buf = [0u8; 128];
        let n = seal_probe(&mut buf, b"relayed once");

        let mut relayed = HDR;
        relayed[12] = (HDR[12] & 0xF8) | 2; // hop_limit 3 -> 2
        relayed[15] = 0x64; // a relay stamped its low byte
        relayed[14] = 0x28; // and routing set next_hop

        let len = open_in_place(&GK, &relayed, 0x7e57_0001, 0x0bad_c0de, &mut buf[..n])
            .expect("a relayed frame must still verify");
        assert_eq!(&buf[HEADER_BYTES..HEADER_BYTES + len], b"relayed once");
    }

    #[test]
    fn a_later_epoch_cannot_be_read_with_an_earlier_key() {
        let mut a = [0u8; 64];
        let na = seal(&GK, 1, 0, MsgType::Data, &HDR, 1, 2, b"epoch zero", &mut a).expect("seal");
        let mut b = [0u8; 64];
        let nb = seal(&GK, 1, 1, MsgType::Data, &HDR, 1, 3, b"epoch one", &mut b).expect("seal");

        assert_ne!(epoch_key(&GK, 0), epoch_key(&GK, 1), "epochs must derive different keys");

        // Each opens under its own epoch, which travels in the clear.
        assert!(open_in_place(&GK, &HDR, 1, 2, &mut a[..na]).is_ok());
        assert!(open_in_place(&GK, &HDR, 1, 3, &mut b[..nb]).is_ok());

        // A revoked member holds the OLD group key. Rekeying is what stops them,
        // and it stops them only for traffic sent afterwards -- see SPEC 6.4.
        let old = [9u8; 32];
        let mut c = [0u8; 64];
        let nc = seal(&GK, 1, 1, MsgType::Data, &HDR, 1, 4, b"after rekey", &mut c).expect("seal");
        assert_eq!(
            open_in_place(&old, &HDR, 1, 4, &mut c[..nc]),
            Err(Error::Unauthentic),
            "a stale group key must not open later traffic"
        );
    }

    #[test]
    fn the_aad_is_the_invariant_subset_and_nothing_more() {
        let aad = aad_from_header(&HDR);
        assert_eq!(aad.len(), AAD_LEN);
        assert_eq!(&aad[..12], &HDR[..12], "to, from and id are covered verbatim");
        assert_eq!(aad[12], HDR[12] & 0xF8, "hop_limit is masked out");
        assert_eq!(aad[13], HDR[13], "channel is covered");

        // hop_limit varying must not change the AAD; the rest of byte 12 must.
        let mut hopped = HDR;
        hopped[12] = (HDR[12] & 0xF8) | 7;
        assert_eq!(aad_from_header(&hopped), aad, "hop_limit must not reach the tag");
        let mut acked = HDR;
        acked[12] = HDR[12] ^ 0x08; // want_ack
        assert_ne!(aad_from_header(&acked), aad, "want_ack must reach the tag");
    }

    #[test]
    fn malformed_input_is_refused_rather_than_trusted() {
        assert_eq!(parse(&[]).unwrap_err(), Error::Malformed);
        assert_eq!(parse(&[0u8; OVERHEAD - 1]).unwrap_err(), Error::Malformed);

        let mut buf = [0u8; 64];
        let n = seal_probe(&mut buf, b"x");
        // Wrong version.
        let mut v = buf;
        v[0] = 99;
        assert_eq!(parse(&v[..n]).unwrap_err(), Error::UnsupportedVersion);
        // Zero group names nothing.
        let mut g = buf;
        g[2] = 0; g[3] = 0; g[4] = 0; g[5] = 0;
        assert_eq!(parse(&g[..n]).unwrap_err(), Error::BadGroupId);
        // Unknown message type.
        let mut t = buf;
        t[1] = 0x7f;
        assert_eq!(parse(&t[..n]).unwrap_err(), Error::Malformed);

        assert_eq!(
            seal(&GK, 0, 0, MsgType::Data, &HDR, 1, 2, b"x", &mut buf),
            Err(Error::BadGroupId)
        );
        let mut tiny = [0u8; 4];
        assert_eq!(
            seal(&GK, 1, 0, MsgType::Data, &HDR, 1, 2, b"x", &mut tiny),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn only_the_owner_may_change_membership() {
        let mut r: Roster<4> = Roster::new(0x1111);
        assert_eq!(r.add(0x2222, 0x3333, &[1u8; 32]), Err(Error::NotOwner));
        assert_eq!(r.remove(0x2222, 0x3333), Err(Error::NotOwner));
        assert_eq!(r.bump_epoch(0x2222), Err(Error::NotOwner));

        r.add(0x1111, 0x3333, &[1u8; 32]).expect("owner may add");
        assert!(r.contains(0x3333));
        assert_eq!(r.len(), 1);
        assert_eq!(r.remove(0x1111, 0x3333), Ok(true));
        assert!(!r.contains(0x3333));
        assert_eq!(r.remove(0x1111, 0x3333), Ok(false), "removing twice is not an error");
    }

    #[test]
    fn a_full_roster_refuses_rather_than_dropping_someone() {
        let mut r: Roster<2> = Roster::new(1);
        r.add(1, 10, &[0u8; 32]).expect("first");
        r.add(1, 11, &[0u8; 32]).expect("second");
        assert_eq!(r.add(1, 12, &[0u8; 32]), Err(Error::RosterFull));
        assert!(r.contains(10) && r.contains(11), "neither existing member was displaced");
        // Re-adding an existing member updates the key without needing a slot.
        r.add(1, 10, &[5u8; 32]).expect("update in place");
        assert_eq!(r.len(), 2);
    }

    /// The epoch must refuse to wrap, because a wrap is not a rekey.
    #[test]
    fn the_epoch_refuses_to_wrap() {
        let mut r: Roster<2> = Roster::new(1);
        for _ in 0..255 {
            r.bump_epoch(1).expect("within range");
        }
        assert_eq!(r.epoch(), 255);
        assert_eq!(
            r.bump_epoch(1),
            Err(Error::EpochExhausted),
            "wrapping to 0 would reproduce epoch 0's key and reuse every nonce under it"
        );
    }
}
