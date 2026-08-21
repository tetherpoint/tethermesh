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

#[cfg(kani)]
mod proofs;

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

/// Which group, at which epoch, and the group's long-term key.
///
/// # Why these three travel together
///
/// They are the entire input to key selection: [`epoch_key`] takes `group_key`
/// and `epoch`, and `group_id` is what a receiver checks before spending a CCM
/// verification at all. Bundling them is not tidying — it removes a real
/// hazard. `seal` used to take `group_id: u32` and `epoch: u8` as bare
/// positional arguments immediately before `from: u32` and `id: u32`, four
/// adjacent integers in which a transposition compiles, round-trips and passes
/// every test, because seal and open would make the same swap. That is exactly
/// the shape of the `hop_start`/`hop_limit` transposition this project has
/// already shipped once and caught only by capturing a frame from someone
/// else's radio. Named fields do not make a swap impossible; they make it
/// visible at the call site, which is the difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupEpoch<'a> {
    /// The group's long-term key. [`epoch_key`] derives the working key from it.
    pub group_key: &'a [u8; 32],
    /// Which group. Never zero — [`Error::BadGroupId`] otherwise.
    pub group_id: u32,
    /// Which epoch of that group's key schedule.
    pub epoch: u8,
}

/// What the AEAD is bound to: the carrying frame's invariant identity.
///
/// # Why this is one type and not three arguments
///
/// These three values are the whole of the nonce and the AAD — [`nonce`] takes
/// `from` and `id`, [`aad_from_header`] takes `header` — and **the sealing and
/// opening ends must supply identical values or the tag does not verify.** That
/// is a property of a pair of calls, and until it had a name there was nowhere
/// to write it down. It is also why `open_in_place` takes this rather than the
/// loose triple: a reader can now see that the two sides are being handed the
/// same thing.
///
/// `header` is the cleartext Meshtastic header of the frame this message rides
/// in. Only its invariant subset is authenticated; see [`aad_from_header`] for
/// which bytes move in transit and why covering them would fail on every
/// multi-hop delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding<'a> {
    /// The carrying frame's 16-byte cleartext header.
    pub header: &'a [u8; HEADER_LEN],
    /// The originating node number, as it appears in that header.
    pub from: u32,
    /// The packet id, as it appears in that header. Never reuse one within an
    /// epoch: see [`nonce`].
    pub id: u32,
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
    group: &GroupEpoch<'_>,
    binding: &Binding<'_>,
    msg_type: MsgType,
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let GroupEpoch { group_key, group_id, epoch } = *group;
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
    let n = nonce(binding.from, binding.id, epoch);
    let aad = aad_from_header(binding.header);
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
    binding: &Binding<'_>,
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
    let n = nonce(binding.from, binding.id, epoch);
    let aad = aad_from_header(binding.header);
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

    /// Set the epoch directly. **Proof harnesses only.**
    ///
    /// Reaching an arbitrary epoch by bumping needs 255 iterations, which a
    /// model checker must unroll. This lets the wrap proof start anywhere. It is
    /// `#[cfg(kani)]`, so a shipped build cannot reach it and the only way to
    /// move the epoch there is through `bump_epoch`'s owner check.
    #[cfg(kani)]
    pub fn set_epoch_for_proof(&mut self, epoch: u8) {
        self.epoch = epoch;
    }

    /// Iterate the members currently held.
    pub fn members(&self) -> impl Iterator<Item = &Member> {
        self.members.iter().filter(|m| m.node != 0)
    }
}

#[cfg(test)]
mod tests;

