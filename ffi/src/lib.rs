// SPDX-FileCopyrightText: 2026 The tetherpoint Authors
// SPDX-License-Identifier: Apache-2.0

//! tmffi — the C ABI for the tethermesh protocol library.
//!
//! # Why this crate exists separately
//!
//! tethermesh is an `rlib` on purpose. A crate defining `#[panic_handler]`
//! forces it on every consumer and only one may exist in a linked program, so
//! the handler lives here, at the edge, where a firmware image can have exactly
//! one. `tools/check_artifact_link.sh` in that repository proves the shape
//! links panic-free into a real Cortex-M33 image.
//!
//! # Where the tests are, and a claim that was wrong
//!
//! This section used to say the crate "cannot host a `#[test]` at all", because
//! `cargo test` links std and brings a `#[panic_handler]` of its own — and that
//! decisions therefore lived in a second `tmffi_core` rlib. **The premise was
//! false.** `#![cfg_attr(not(test), no_std)]` with `#[cfg(not(test))]` on the
//! handler lets a staticlib host its own tests directly; the split was
//! unnecessary and was merged back on 2026-08-17. It is recorded rather than
//! quietly overwritten because the reasoning is worth seeing wrong: the shape
//! was asserted around instead of being tried.
//!
//! So the decisions are tested here, in this crate: the retry-policy cap that
//! enforces the shared-airtime rule, acknowledgement recognition, error
//! mapping, the status codes themselves, and the identity surface below —
//! checked against RFC 7748's published vector rather than against ourselves.
//!
//! **What is still untested is honest about itself.** The pointer handling —
//! null checks, `slice::from_raw_parts`, the raw writes — is untestable in
//! isolation and no arrangement of crates would change that: a null check is
//! only meaningful against a caller that passes null, which is a property of
//! the C side. It remains covered by the artifact gate on the linked image.
//!
//! # The hazard this ABI is designed around
//!
//! Meshtastic's PSK field is polymorphic on the wire: 0 bytes means no crypto,
//! 16 or 32 bytes is a key, and **1 byte is a shorthand index** where `1` names
//! the default channel key and `2..10` name that key with 1..9 added to its last
//! byte. All of those are legitimate protocol inputs.
//!
//! A C function taking `(const uint8_t *psk, size_t len)` cannot distinguish
//! them, and the failure is silent. Writing the harness for the link check, the
//! first C consumer passed the index `{1}` where the expanded key was wanted and
//! got channel hash `0x0b` instead of `0x08` — a wrong hash on the single most
//! common channel on the network, with nothing to indicate it.
//!
//! So the raw form is not exposed. A key is constructed through one of two
//! explicitly-named functions and thereafter carried as `tm_key_t`, which is a
//! distinct type. The confusion is unrepresentable rather than documented.
//!
//! # State
//!
//! Nothing is allocated and nothing is global. The caller owns a context sized
//! by [`tm_ctx_size`] and placed wherever it likes — `.bss` is the usual answer,
//! because that way the linker checks the budget instead of a task stack
//! silently overflowing at runtime.
//!
//! One task per context needs no locking. Sharing one across tasks needs the
//! caller's, and nothing here can enforce that: `Send`/`Sync` do not cross an
//! FFI boundary a foreign scheduler calls into.
//!
//! **Stack: budget ~1 KB for this library's own call depth**, measured at 696
//! bytes worst case in `ccm_decrypt_in_place` on Cortex-M33. A task sized at
//! FreeRTOS's `configMINIMAL_STACK_SIZE` (512 bytes) is smaller than a single
//! CCM decrypt.

#![cfg_attr(not(any(test, kani)), no_std)]
// The same crate rules the protocol library lives by. An FFI shim is where they
// matter most: it is the surface a C consumer reaches, and a panic here aborts
// their firmware rather than ours.
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::arithmetic_side_effects)]
// Not `deny(unsafe_code)` -- an FFI boundary cannot exist without unsafe. This
// requires every unsafe OPERATION to sit in an explicit `unsafe {}` block even
// inside an `unsafe fn`, so that a signature does not blanket-authorise a body.
//
// HONEST LIMITATION, 2026-08-17: the blocks below were applied by `cargo fix`,
// which satisfies the lint by wrapping WHOLE FUNCTION BODIES -- `fn f(..) {
// unsafe { .. } }`. That is exactly the blanket authorisation the attribute
// exists to prevent, so for this crate the lint is currently satisfied without
// being earned. Nothing regressed -- the bodies were `unsafe fn` bodies before
// -- but nobody should read the attribute here as evidence that each unsafe
// operation has been individually justified. Narrowing them to the specific
// operations is real work and is recorded as such rather than claimed.
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]

use core::slice;

use tethermesh::channel;
use tethermesh::crypto;
use tethermesh::header;
use tethermesh::sha256::sha256;
use tethermesh::delivery::{self, Error as DeliveryError, Outbox, RetryPolicy};
use tethermesh::frame;
use tethermesh::message::{Data, PortNum, User};
use tethermesh::header::Header;
use tethermesh::history::PacketHistory;
use tethermesh::airtime::DutyCycle;
use tethermesh::history::Seen;
use tethermesh::routing::{self, ContentionWindow, Observed, Relay, Role};
use tethermesh::x25519;

// Not under `test` OR `kani`: both link a harness that brings its own handler,
// and only one may exist per program. `cargo kani --workspace` failed with
// E0152 (duplicate lang item) until this covered kani too -- which meant the
// documented verification command could not include this crate at all.
//
// Neither predicate can reach a shipped build.
#[cfg(not(any(test, kani)))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // Unreachable by construction -- the crate rules forbid panicking paths and
    // check_rust_rules.sh inspects the built object to confirm none survive.
    // Present because the language requires it, and a loop rather than a reset
    // so that if the impossible happens it is observable on a debugger instead
    // of presenting as a spontaneously rebooting radio.
    loop {}
}

/// Bumped on any change to a signature, struct layout, or enum value here.
///
/// Checked at init by the C side. A stale header against a rebuilt library is
/// otherwise silent and produces symptoms attributable to anything at all;
/// four bytes to make it impossible is a trade worth taking every time.
pub const TM_ABI_VERSION: u32 = 5;

#[no_mangle]
pub extern "C" fn tm_abi_version() -> u32 {
    TM_ABI_VERSION
}

/// Verify the C header's view of struct layout matches this crate's.
///
/// cbindgen is not available in this environment, so `tethermesh.h` is written
/// by hand -- and a hand-written header against a changing Rust crate drifts
/// silently, producing field reads at the wrong offsets that look like protocol
/// bugs. The C side passes its own `sizeof`s and a mismatch fails loudly at
/// init instead.
///
/// This is weaker than generating the header: equal sizes do not prove equal
/// field order. It catches the common case (a field added, removed, or resized)
/// and not the rare one (two fields swapped at the same width). Stated plainly
/// so nobody reads it as more than it is.
#[no_mangle]
pub extern "C" fn tm_check_layout(
    sizeof_rx: usize,
    sizeof_key: usize,
    sizeof_user: usize,
    sizeof_pki_key: usize,
) -> i32 {
    if sizeof_rx != core::mem::size_of::<TmRx>() {
        return TM_E_ABI;
    }
    if sizeof_key != core::mem::size_of::<TmKey>() {
        return TM_E_ABI;
    }
    if sizeof_user != core::mem::size_of::<TmUser>() {
        return TM_E_ABI;
    }
    if sizeof_pki_key != core::mem::size_of::<TmPkiKey>() {
        return TM_E_ABI;
    }
    TM_OK
}

// ── Status ──────────────────────────────────────────────────────────────────

/// Status codes, defined once so the ABI and its tests cannot disagree.
///
/// These are the values `tethermesh.h` publishes. A second definition in the
/// shim would be a place for the two to drift apart silently.
pub const TM_OK: i32 = 0;
/// A null pointer, a malformed input, or a value outside its documented range.
pub const TM_E_ARG: i32 = -1;
/// The caller's header disagrees with the linked library about the ABI.
pub const TM_E_ABI: i32 = -2;
/// A buffer too small, or no free slot.
pub const TM_E_SHORT: i32 = -3;
/// Key material of a length the protocol does not define.
pub const TM_E_BAD_KEY_LEN: i32 = -4;
/// A channel index outside the range the shorthand defines.
pub const TM_E_BAD_INDEX: i32 = -5;
/// A retry policy more aggressive than the measured ceiling.
pub const TM_E_TOO_AGGRESSIVE: i32 = -6;
/// A direct message whose authentication tag does not verify.
///
/// Its own code, because it is the one failure here that means someone may be
/// lying to you rather than that something is misconfigured. Never retry it and
/// never use the buffer: a forged message decrypts to *something*.
pub const TM_E_UNAUTHENTIC: i32 = -7;
/// A peer public key that drives the shared secret to zero.
///
/// Distinct from [`TM_E_UNAUTHENTIC`] and from a hardware fault because the
/// three call for opposite responses. This one is chosen deliberately by an
/// attacker and is never retryable.
pub const TM_E_SMALL_ORDER: i32 = -8;

/// Resolve a caller's requested retry policy, or refuse it.
///
/// **This function is the mechanism enforcing `PLAN.md`'s shared-airtime rule,**
/// and it is the specific thing T13 was opened about: it had no test, so the
/// rule was enforced by a line of code nobody exercised.
///
/// `PLAN.md` fixes upstream's retry behaviour as a **ceiling, never a target**.
/// The reason is not politeness. Retransmission spends *shared* airtime, and on
/// a flood mesh every retry is rebroadcast by every neighbour that hears it — so
/// the cost multiplies by local node count and is borne by nodes that gain
/// nothing from it. An ABI accepting `max_attempts = 200` invites exactly that
/// from a caller with no way to know better.
///
/// `(0, 0)` means "take the measured ceiling". Anything more aggressive is
/// **refused rather than clamped**: a clamp leaves the caller believing it
/// configured something it did not, and the difference only shows up as
/// someone else's congestion.
///
/// A single attempt never retransmits, so no interval can make it aggressive —
/// it is accepted whatever the interval says.
pub fn resolve_retry_policy(max_attempts: u8, interval_us: u32) -> Result<RetryPolicy, i32> {
    let ceiling = RetryPolicy::MEASURED_CEILING;

    if max_attempts == 0 && interval_us == 0 {
        return Ok(ceiling);
    }
    if max_attempts == 0 {
        return Err(TM_E_ARG);
    }
    if max_attempts > 1
        && (max_attempts > ceiling.max_attempts || interval_us < ceiling.interval_us)
    {
        return Err(TM_E_TOO_AGGRESSIVE);
    }
    Ok(RetryPolicy { max_attempts, interval_us })
}

/// Read a decrypted payload as an acknowledgement, if it is one.
///
/// Returns `(request_id, status)`. **Status is reported, never acted on here:**
/// a rejection retires a pending entry exactly as an acceptance does, because no
/// further retransmission will help either way.
#[must_use]
pub fn classify_ack(payload: &[u8]) -> Option<(u32, u32)> {
    let data = Data::decode(payload).ok()?;
    let ack = tethermesh::delivery::acknowledges(&data)?;
    Some((ack.request_id, ack.status.0))
}

/// Map a delivery error onto the ABI's status codes.
///
/// `delivery::Error` is `#[non_exhaustive]`, so a variant added upstream must
/// land somewhere. It lands on a refusal rather than on [`TM_OK`]: a new failure
/// mode silently reported as success is the shape of bug this ABI is least able
/// to recover from.
#[must_use]
pub fn map_delivery_error(e: DeliveryError) -> i32 {
    match e {
        DeliveryError::Full => TM_E_SHORT,
        DeliveryError::BadFrame => TM_E_ARG,
        _ => TM_E_ARG,
    }
}

#[cfg(test)]
mod tests;



// ── Keys ────────────────────────────────────────────────────────────────────

/// An expanded channel key. Always 16 bytes, always ready to use.
///
/// The point of the type is that it cannot be confused with the 1-byte
/// shorthand: there is no way to obtain one except through a constructor that
/// names which form it was given.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TmKey {
    pub bytes: [u8; 16],
}

/// The default channel key, from which every `1..10` shorthand is derived.
const DEFAULT_PSK: [u8; 16] = [
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
];

/// Expand the 1-byte shorthand: `1` is the default key, `2..=10` add 1..9 to its
/// last byte. `0` means no crypto and is rejected here rather than silently
/// producing a key, because a caller asking for a key when there is none is
/// making a mistake worth surfacing.
/// # Safety
///
/// `out` must be null or a valid, aligned, writable `TmKey`.
///
/// **This is `unsafe` because it writes through `out`, and it was not always.**
/// It was declared safe while dereferencing a raw pointer, which is unsound:
/// the null check covers null and nothing covers a dangling or misaligned
/// pointer, so a Rust caller could reach undefined behaviour with no `unsafe`
/// at the call site. Every other pointer-taking function in this ABI was
/// already `unsafe`; this one was the exception. **The C ABI is unchanged** —
/// `unsafe` is a Rust-side obligation and does not affect the symbol, the
/// calling convention or the header — so no version bump is owed for it.
#[no_mangle]
pub unsafe extern "C" fn tm_key_from_index(index: u8, out: *mut TmKey) -> i32 { unsafe {
    if out.is_null() {
        return TM_E_ARG;
    }
    if !(1..=10).contains(&index) {
        return TM_E_BAD_INDEX;
    }
    let mut k = DEFAULT_PSK;
    // Index 15 of a [u8; 16] is a compile-time-known constant into a
    // fixed-size array: bounds are provable and no panic path is emitted.
    //
    // BOTH operations are checked, not just the visible one. This line read
    // `wrapping_add(index - 1)` with a comment explaining the `wrapping_add` --
    // while the `index - 1` beside it was bare subtraction, which is exactly the
    // panic path the comment claimed to have avoided. The range check above
    // makes underflow unreachable in practice, and "unreachable in practice" is
    // the argument this crate does not accept: the rule is that no panic path
    // is emitted, and a proof by surrounding context is not that.
    k[15] = k[15].wrapping_add(index.wrapping_sub(1));
    (*out).bytes = k;
    TM_OK
}}

/// Take an explicit key. 16 bytes is used as-is; 32 bytes is accepted because
/// the protocol allows AES-256 channels, and its first 16 bytes are what this
/// path needs. Any other length is an error rather than a truncation.
#[no_mangle]
pub unsafe extern "C" fn tm_key_from_bytes(psk: *const u8, len: usize, out: *mut TmKey) -> i32 { unsafe {
    if psk.is_null() || out.is_null() {
        return TM_E_ARG;
    }
    if len != 16 && len != 32 {
        return TM_E_BAD_KEY_LEN;
    }
    let src = slice::from_raw_parts(psk, 16);
    let mut k = [0u8; 16];
    for (d, s) in k.iter_mut().zip(src) {
        *d = *s;
    }
    (*out).bytes = k;
    TM_OK
}}

/// Channel hash over a name and an already-expanded key.
///
/// Note the name: the *modem preset* name is what gets hashed, not whatever the
/// config message carries. Proto3 omits defaults, so the primary channel's name
/// is absent on the wire, and folding the empty string yields `0x02` where real
/// traffic shows `0x08`. Passing "LongFast" is correct for the default channel.
#[no_mangle]
pub unsafe extern "C" fn tm_channel_hash(name: *const u8, name_len: usize, key: *const TmKey) -> u8 { unsafe {
    if name.is_null() || key.is_null() {
        return 0;
    }
    channel::channel_hash(slice::from_raw_parts(name, name_len), &(*key).bytes)
}}

// ── Context ─────────────────────────────────────────────────────────────────

/// History depth. 400 is what the reference was observed using; at 8 bytes an
/// entry that is 3,216 bytes, which is the dominant term in the context and the
/// reason `tm_ctx_size` exists rather than a header constant.
const HISTORY: usize = 400;

#[repr(C)]
pub struct TmCtx {
    history: PacketHistory<HISTORY>,
    duty: DutyCycle,
    window: ContentionWindow,
    node_num: u32,
    role: Role,
}

#[no_mangle]
pub extern "C" fn tm_ctx_size() -> usize {
    core::mem::size_of::<TmCtx>()
}

#[no_mangle]
pub extern "C" fn tm_ctx_align() -> usize {
    core::mem::align_of::<TmCtx>()
}

/// Initialise a caller-provided context.
///
/// `abi` must be `tm_abi_version()` as the *header* saw it; a mismatch fails
/// here rather than misbehaving later.
#[no_mangle]
pub unsafe extern "C" fn tm_ctx_init(ctx: *mut TmCtx, abi: u32, node_num: u32) -> i32 { unsafe {
    if ctx.is_null() {
        return TM_E_ARG;
    }
    if abi != TM_ABI_VERSION {
        return TM_E_ABI;
    }
    ctx.write(TmCtx {
        history: PacketHistory::new(),
        // 100% of a 1-hour window: a duty budget the caller has not chosen to
        // constrain. Regulatory limits are a deployment decision and belong to
        // whoever knows the region, not to a default buried in an ABI.
        duty: match DutyCycle::new(1000, 3_600_000, 0) {
            Some(d) => d,
            None => return TM_E_ARG,
        },
        window: ContentionWindow::MESHTASTIC_SHAPE,
        node_num,
        role: Role::Client,
    });
    TM_OK
}}

// ── Receive ─────────────────────────────────────────────────────────────────

/// What a received frame turned out to be.
///
/// The shape mirrors the radio driver's callback deliberately: a frame and an
/// SNR go in, and nothing here knows what a chirp is. That keeps this library
/// usable over any PHY that can carry the bytes.
#[repr(C)]
pub struct TmRx {
    pub from: u32,
    pub to: u32,
    pub id: u32,
    pub hop_limit: u8,
    pub want_ack: u8,
    pub channel_hash: u8,
    pub duplicate: u8,
    /// 1 if the caller should rebroadcast after waiting.
    pub relay: u8,
    /// Draw uniformly in `[0, relay_window_slots)` and wait that many slots.
    /// Deterministic waiting is what makes a mesh collide with itself.
    pub relay_window_slots: u8,
    /// `hop_limit` already decremented, for the frame to rebroadcast.
    pub relay_hop_limit: u8,
    /// Reason when `relay` is 0, for diagnostics.
    pub suppressed: u8,
}

pub const TM_SUPPRESSED_NONE: u8 = 0;
pub const TM_SUPPRESSED_DUPLICATE: u8 = 1;
pub const TM_SUPPRESSED_HOP_LIMIT: u8 = 2;
pub const TM_SUPPRESSED_RELAYED_BY_OTHER: u8 = 3;
pub const TM_SUPPRESSED_DUTY_BUDGET: u8 = 4;

/// Observe a received frame: parse its header, note it in history, and decide
/// whether to relay.
///
/// `snr_q4` is signed quarter-dB — the unit the radio reports and the unit the
/// protocol carries, so nothing rescales it anywhere.
///
/// `heard_relayed` is the caller's to determine and cannot be inferred here:
/// it means "I already have this frame queued for relay and have now heard
/// somebody else send it." The library holds no pending-transmission set,
/// because it has neither a clock nor a radio -- `DISTRIBUTION.md` puts
/// scheduling firmly on the caller's side. `should_relay`'s contract says as
/// much: *wait a backoff drawn from this window, then transmit **if nobody else
/// did***. Passing 0 always makes that clause unenforceable and the
/// `AlreadyRelayedByAnother` suppression unreachable.
///
/// This does **not** decrypt. Relaying does not require the key, and stock nodes
/// are observed forwarding frames on channels they cannot read; a function that
/// demanded a key to make a routing decision would misdescribe the protocol.
#[no_mangle]
pub unsafe extern "C" fn tm_rx_observe(
    ctx: *mut TmCtx,
    frame_ptr: *const u8,
    frame_len: usize,
    snr_q4: i16,
    airtime_us: u32,
    now_us: u64,
    heard_relayed: u8,
    out: *mut TmRx,
) -> i32 { unsafe {
    if ctx.is_null() || frame_ptr.is_null() || out.is_null() {
        return TM_E_ARG;
    }
    let ctx = &mut *ctx;
    let bytes = slice::from_raw_parts(frame_ptr, frame_len);

    let Some(h) = Header::decode(bytes) else {
        return TM_E_SHORT;
    };

    let duplicate = ctx.history.observe(h.from, h.id) == Seen::Duplicate;
    let observed = Observed {
        hop_limit: h.hop_limit,
        snr_quarter_db: snr_q4,
        duplicate,
        heard_relayed: heard_relayed != 0,
        airtime_us,
    };
    let decision = routing::should_relay(&observed, ctx.role, &ctx.window, &mut ctx.duty, now_us);

    let mut r = TmRx {
        from: h.from,
        to: h.to,
        id: h.id,
        hop_limit: h.hop_limit,
        want_ack: u8::from(h.want_ack),
        channel_hash: h.channel,
        duplicate: u8::from(duplicate),
        relay: 0,
        relay_window_slots: 0,
        relay_hop_limit: 0,
        suppressed: TM_SUPPRESSED_NONE,
    };
    match decision {
        Relay::After {
            window_slots,
            hop_limit,
        } => {
            r.relay = 1;
            r.relay_window_slots = window_slots;
            r.relay_hop_limit = hop_limit;
        }
        Relay::No(reason) => {
            r.suppressed = match reason {
                routing::Suppressed::Duplicate => TM_SUPPRESSED_DUPLICATE,
                routing::Suppressed::HopLimitExhausted => TM_SUPPRESSED_HOP_LIMIT,
                routing::Suppressed::AlreadyRelayedByAnother => TM_SUPPRESSED_RELAYED_BY_OTHER,
                routing::Suppressed::DutyBudgetExhausted => TM_SUPPRESSED_DUTY_BUDGET,
            };
        }
    }
    out.write(r);
    TM_OK
}}

/// Decrypt a frame in place and hand back the plaintext payload.
///
/// Separate from `tm_rx_observe` because the two answer different questions and
/// need different inputs: routing needs the header alone, decryption needs a
/// key. Keeping them apart is what lets a relay work without one.
#[no_mangle]
pub unsafe extern "C" fn tm_frame_decrypt(
    frame_ptr: *mut u8,
    frame_len: usize,
    key: *const TmKey,
    payload_out: *mut *const u8,
    payload_len_out: *mut usize,
) -> i32 { unsafe {
    if frame_ptr.is_null() || key.is_null() || payload_out.is_null() || payload_len_out.is_null() {
        return TM_E_ARG;
    }
    let buf = slice::from_raw_parts_mut(frame_ptr, frame_len);
    match frame::decode_in_place(buf, &(*key).bytes, 0) {
        Ok((_h, payload)) => {
            *payload_out = payload.as_ptr();
            *payload_len_out = payload.len();
            TM_OK
        }
        Err(_) => TM_E_SHORT,
    }
}}

// ── Transmit ────────────────────────────────────────────────────────────────

/// Encode a broadcast text message into a ready-to-transmit frame.
///
/// Text is portnum 1 (TEXT_MESSAGE_APP). `to` is normally 0xFFFFFFFF, which is
/// how a stock node recognises a broadcast.
///
/// `id` is the caller's to choose and must not repeat: every receiver on the
/// mesh keys duplicate suppression on `(from, id)`, so a reused identifier is
/// silently dropped by everyone who saw the first one. tethermesh's
/// `packet_id::PacketIdSource` exists for this and refuses to issue past a
/// durable high-water mark, because an identifier handed out before it is
/// persisted is exactly the one reissued after an unclean restart.
///
/// `hop_start` is set equal to `hop_limit`, which is what a node originating a
/// packet does -- the pair is how receivers compute how far a frame has
/// travelled.
///
/// Returns the frame length, or negative on error.
#[no_mangle]
pub unsafe extern "C" fn tm_text_encode(
    from: u32,
    to: u32,
    id: u32,
    hop_limit: u8,
    channel_hash: u8,
    want_ack: u8,
    key: *const TmKey,
    text: *const u8,
    text_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> i32 { unsafe {
    if key.is_null() || text.is_null() || out.is_null() {
        return TM_E_ARG;
    }
    let txt = slice::from_raw_parts(text, text_len);

    // Data -> protobuf, then that plaintext into the frame body.
    let data = Data {
        portnum: 1,
        payload: txt,
        ..Default::default()
    };
    let mut plain = [0u8; 240];
    let Ok(plain_len) = data.encode(&mut plain) else {
        return TM_E_ARG;
    };

    let header = Header {
        to,
        from,
        id,
        hop_limit,
        want_ack: want_ack != 0,
        via_mqtt: false,
        hop_start: hop_limit,
        channel: channel_hash,
        next_hop: 0,
        relay_node: 0,
    };

    let dst = slice::from_raw_parts_mut(out, out_cap);
    // get(), not plain[..plain_len]. Bare slice indexing compiles to a panic
    // path, and one reaching a linked image is a crate-rule violation --
    // check_rust_rules.sh inspects the built object precisely because source
    // review misses these. This exact line put slice_index_fail into the
    // firmware and went unnoticed because panic symbols were not re-checked
    // after the function was added.
    let Some(body) = plain.get(..plain_len) else {
        return TM_E_ARG;
    };
    match frame::encode(&header, body, &(*key).bytes, 0, dst) {
        Ok(n) => n as i32,
        Err(_) => TM_E_ARG,
    }
}}

/// Patch a received frame in place so it can be rebroadcast.
///
/// Two fields change and nothing else: `hop_limit` takes the decremented value
/// from [`tm_rx_observe`], and `relay_node` becomes the low byte of this node's
/// number. Everything else -- id, from, the encrypted body -- is carried
/// verbatim, which is what makes it the *same* packet rather than a new one.
/// Rewriting `from` or `id` would defeat duplicate suppression across the whole
/// mesh and multiply the frame instead of forwarding it.
///
/// `relay_node` being a one-byte truncation of the node number is recorded in
/// WIRE_REFERENCE.md from captured traffic, and confirmed here: a stock node
/// relaying our packet stamped 0x64, the low byte of its own 0x3369e764.
#[no_mangle]
pub unsafe extern "C" fn tm_relay_prepare(
    frame_ptr: *mut u8,
    frame_len: usize,
    relay_hop_limit: u8,
    our_node_num: u32,
) -> i32 { unsafe {
    if frame_ptr.is_null() {
        return TM_E_ARG;
    }
    let buf = slice::from_raw_parts_mut(frame_ptr, frame_len);
    let Some(mut h) = Header::decode(buf) else {
        return TM_E_SHORT;
    };
    h.hop_limit = relay_hop_limit;
    h.relay_node = (our_node_num & 0xFF) as u8;
    let head = h.encode();
    for (d, s) in buf.iter_mut().zip(head.iter()) {
        *d = *s;
    }
    TM_OK
}}

/// Record a packet we originated, so it is suppressed if it comes back.
///
/// Transmitting records nothing in history, so a node's own packet returning
/// from someone else's relay reports `duplicate = 0`. The only thing preventing
/// a loop is then the caller comparing `from` against its own node number --
/// one check deep, for a failure that multiplies traffic across an entire mesh.
///
/// Calling this after transmitting makes the ordinary duplicate machinery cover
/// the case too, which is a second mechanism rather than a louder version of
/// the first.
#[no_mangle]
pub unsafe extern "C" fn tm_note_originated(ctx: *mut TmCtx, from: u32, id: u32) -> i32 { unsafe {
    if ctx.is_null() {
        return TM_E_ARG;
    }
    let ctx = &mut *ctx;
    let _ = ctx.history.observe(from, id);
    TM_OK
}}

// ── Delivery: acknowledgement and retransmission ─────────────────────────────
//
// tethermesh's `delivery` module is complete and Kani-verified, and until now
// had never been exercised on hardware because nothing here exposed it. That is
// the worst position for code to be in: proven correct against its own model and
// never once confronted with a radio.
//
// # Why the policy is capped rather than merely defaulted
//
// `PLAN.md` fixes the rule that upstream's retry behaviour is a CEILING and
// never a target, and the reason is not politeness. Retransmission spends
// SHARED airtime, and on a flood mesh every retry is rebroadcast by every
// neighbour that hears it -- so the cost multiplies by local node count, and it
// is borne by nodes that get no benefit from it. Less aggressive is always safe.
// More is antisocial, and an ABI that accepts `max_attempts = 200` invites it
// from a caller who has no way to know that.
//
// So `tm_outbox_init` REFUSES a policy more aggressive than the measured
// ceiling. The rule was written down; this makes it mechanical.

/// Frames awaiting acknowledgement at once.
///
/// Four, and it is a policy choice rather than a protocol fact. A slot stores
/// the frame verbatim -- `MAX_FRAME` is 249 bytes -- so the array dominates this
/// struct at roughly 1.1 KB, which is why `tm_outbox_size()` exists instead of a
/// constant in the header. Raising it costs RAM linearly and buys nothing unless
/// the application actually keeps that many `want_ack` messages in flight.
const OUTBOX_SLOTS: usize = 4;

/// Caller-owned retransmission state. Opaque to C; size it with
/// [`tm_outbox_size`] and align it with [`tm_outbox_align`].
#[repr(C)]
pub struct TmOutbox {
    inner: Outbox<OUTBOX_SLOTS>,
}

#[no_mangle]
pub extern "C" fn tm_outbox_size() -> usize {
    core::mem::size_of::<TmOutbox>()
}

#[no_mangle]
pub extern "C" fn tm_outbox_align() -> usize {
    core::mem::align_of::<TmOutbox>()
}

/// Initialise a caller-provided outbox.
///
/// Pass `max_attempts = 0` and `interval_us = 0` to take the measured ceiling
/// (3 attempts, 7 s). Any explicit policy must be no more aggressive than that:
/// more attempts, or a shorter interval, returns [`TM_E_TOO_AGGRESSIVE`] rather
/// than being quietly clamped -- a clamp would leave the caller believing it had
/// configured something it had not.
#[no_mangle]
pub unsafe extern "C" fn tm_outbox_init(
    ob: *mut TmOutbox,
    abi: u32,
    max_attempts: u8,
    interval_us: u32,
) -> i32 { unsafe {
    if ob.is_null() {
        return TM_E_ARG;
    }
    if abi != TM_ABI_VERSION {
        return TM_E_ABI;
    }

    // The decision lives in resolve_retry_policy, where it is tested. This
    // function keeps only what a test cannot reach: the null check and the raw
    // write.
    let policy = match resolve_retry_policy(max_attempts, interval_us) {
        Ok(p) => p,
        Err(code) => return code,
    };

    ob.write(TmOutbox { inner: Outbox::new(policy) });
    TM_OK
}}

/// Track a frame that has **already been transmitted once**.
///
/// The first transmission is the caller's and its airtime is the caller's to
/// charge; this records the frame so later attempts can be made from it.
///
/// Returns [`TM_OK`], or [`TM_E_SHORT`] when every slot is in use.
#[no_mangle]
pub unsafe extern "C" fn tm_outbox_track(
    ob: *mut TmOutbox,
    frame_ptr: *const u8,
    frame_len: usize,
    now_us: u64,
) -> i32 { unsafe {
    if ob.is_null() || frame_ptr.is_null() {
        return TM_E_ARG;
    }
    let f = slice::from_raw_parts(frame_ptr, frame_len);
    match (*ob).inner.track(f, now_us) {
        Ok(()) => TM_OK,
        Err(e) => map_delivery_error(e),
    }
}}

/// Retire the entry an acknowledgement refers to.
///
/// Returns 1 if something matched, 0 if nothing did. **Zero is ordinary, not an
/// error** -- the acknowledgement may be for a frame already retired, or for
/// another node entirely.
#[no_mangle]
pub unsafe extern "C" fn tm_outbox_acknowledge(ob: *mut TmOutbox, request_id: u32) -> i32 { unsafe {
    if ob.is_null() {
        return TM_E_ARG;
    }
    i32::from((*ob).inner.acknowledge(request_id))
}}

/// How many frames are still awaiting acknowledgement.
#[no_mangle]
pub unsafe extern "C" fn tm_outbox_pending(ob: *const TmOutbox) -> i32 { unsafe {
    if ob.is_null() {
        return TM_E_ARG;
    }
    i32::try_from((*ob).inner.len()).unwrap_or(i32::MAX)
}}

/// Drop one entry that has exhausted every attempt, reporting what it was.
///
/// Returns 1 and fills `out_from`/`out_id` when something was given up on, 0
/// when nothing has. Call until it returns 0.
///
/// Giving up is reported rather than discarded because "this was never
/// acknowledged" is the single most useful thing this module produces -- it is
/// the only evidence available that a frame did not arrive.
#[no_mangle]
pub unsafe extern "C" fn tm_outbox_reap(
    ob: *mut TmOutbox,
    now_us: u64,
    out_from: *mut u32,
    out_id: *mut u32,
) -> i32 { unsafe {
    if ob.is_null() || out_from.is_null() || out_id.is_null() {
        return TM_E_ARG;
    }
    match (*ob).inner.reap(now_us) {
        Some((from, id)) => {
            out_from.write(from);
            out_id.write(id);
            1
        }
        None => 0,
    }
}}

/// The next frame due for retransmission, copied into `out`.
///
/// Returns its length and writes the attempt number to `out_attempt`, or 0 when
/// nothing is due, everything is exhausted, or the duty budget would not permit
/// the airtime.
///
/// **A caller that takes a frame must transmit it.** The attempt is marked and
/// the next one scheduled by this call, so discarding the result silently
/// consumes a retry. The duty budget is deliberately NOT charged here -- the
/// caller charges on actual transmission, matching `should_relay`, because
/// charging here would bill a node for a frame it had not sent.
#[no_mangle]
pub unsafe extern "C" fn tm_outbox_next_due(
    ob: *mut TmOutbox,
    ctx: *mut TmCtx,
    now_us: u64,
    airtime_us: u32,
    out: *mut u8,
    out_cap: usize,
    out_attempt: *mut u8,
) -> i32 { unsafe {
    if ob.is_null() || ctx.is_null() || out.is_null() {
        return TM_E_ARG;
    }
    let ctx = &mut *ctx;
    let Some(due) = (*ob).inner.next_due(now_us, airtime_us, &mut ctx.duty) else {
        return 0;
    };
    let n = due.frame.len();
    if n > out_cap {
        // The attempt has already been marked, and there is no way to unmark it
        // without reaching into the outbox. Report it loudly: a caller whose
        // buffer cannot hold MAX_FRAME has a bug, not a transient condition.
        return TM_E_SHORT;
    }
    let dst = slice::from_raw_parts_mut(out, out_cap);
    for (d, s) in dst.iter_mut().zip(due.frame.iter()) {
        *d = *s;
    }
    if !out_attempt.is_null() {
        out_attempt.write(due.attempt);
    }
    match i32::try_from(n) {
        Ok(v) => v,
        Err(_) => TM_E_SHORT,
    }
}}

/// Read a decrypted payload as an acknowledgement, if it is one.
///
/// Returns 1 and fills the outputs when it is, 0 when it is not.
///
/// `out_status` is the `Routing` status: 0 is acceptance. **A rejection retires
/// the pending entry exactly as an acceptance does** -- either way no further
/// retransmission will help -- so it is reported for the caller to log, not for
/// the outbox to act on differently.
#[no_mangle]
pub unsafe extern "C" fn tm_acknowledges(
    payload: *const u8,
    payload_len: usize,
    out_request_id: *mut u32,
    out_status: *mut u32,
) -> i32 { unsafe {
    if payload.is_null() || out_request_id.is_null() {
        return TM_E_ARG;
    }
    let bytes = slice::from_raw_parts(payload, payload_len);
    match classify_ack(bytes) {
        Some((request_id, status)) => {
            out_request_id.write(request_id);
            if !out_status.is_null() {
                out_status.write(status);
            }
            1
        }
        None => 0,
    }
}}

/// Whether a received frame is addressed to us and asks to be acknowledged.
///
/// Reads the header only; the body does not need decrypting to answer it.
#[no_mangle]
pub unsafe extern "C" fn tm_wants_ack(
    frame_ptr: *const u8,
    frame_len: usize,
    our_node_num: u32,
) -> i32 { unsafe {
    if frame_ptr.is_null() {
        return TM_E_ARG;
    }
    let f = slice::from_raw_parts(frame_ptr, frame_len);
    i32::from(delivery::wants_acknowledgement(f, our_node_num))
}}

/// Build and encrypt an acknowledgement of `request_id`, addressed to `to`.
///
/// Returns the frame length, or negative on error.
///
/// Two measured facts are baked in and neither is obvious. The success payload
/// is the two bytes `18 00` -- `Routing` field 3 encoded EXPLICITLY, where
/// proto3 would normally omit a zero varint, so an acknowledgement built from
/// first principles carries an empty payload and on the evidence would not be
/// recognised. And the reply travels CHANNEL-encrypted even when acknowledging a
/// PKI message: the acknowledgement does not inherit the request's encryption
/// mode, which is the sort of thing that fails looking like a radio fault.
///
/// `want_ack` is deliberately not set on it. Acknowledging an acknowledgement
/// spends shared airtime for no delivery benefit.
#[no_mangle]
pub unsafe extern "C" fn tm_ack_encode(
    from: u32,
    to: u32,
    id: u32,
    request_id: u32,
    hop_limit: u8,
    channel_hash: u8,
    key: *const TmKey,
    out: *mut u8,
    out_cap: usize,
) -> i32 { unsafe {
    if key.is_null() || out.is_null() {
        return TM_E_ARG;
    }
    let data = delivery::acknowledgement(request_id);
    let mut plain = [0u8; 64];
    let Ok(plain_len) = data.encode(&mut plain) else {
        return TM_E_ARG;
    };
    let header = Header {
        to,
        from,
        id,
        hop_limit,
        want_ack: false,
        via_mqtt: false,
        hop_start: hop_limit,
        channel: channel_hash,
        next_hop: 0,
        relay_node: 0,
    };
    let dst = slice::from_raw_parts_mut(out, out_cap);
    // get(), not plain[..plain_len]: bare slice indexing compiles to a panic
    // path, and one reaching a linked image is a crate-rule violation.
    let Some(body) = plain.get(..plain_len) else {
        return TM_E_ARG;
    };
    match frame::encode(&header, body, &(*key).bytes, 0, dst) {
        Ok(n) => match i32::try_from(n) {
            Ok(v) => v,
            Err(_) => TM_E_SHORT,
        },
        Err(_) => TM_E_ARG,
    }
}}

// ── Identity: publishing a public key ───────────────────────────────────────

/// Derive the X25519 public key a peer needs in order to address this node.
///
/// **A node that publishes no public key cannot be sent a direct message at
/// all.** The sender refuses to fall back to channel encryption for a
/// destination whose key it does not hold, and NAKs the packet locally — so
/// the failure never reaches the air and presents as a dead link rather than
/// as a missing key. `tests/captures/pki_dm_record.json` records that
/// behaviour observed from the far side.
///
/// `private_len` must be 32. The scalar is clamped internally per RFC 7748, so
/// a caller may store the raw 32 bytes it drew: clamping is idempotent, and
/// *not* clamping computes a different function rather than a weaker one.
///
/// # This derives. It does not generate.
///
/// Where the private key comes from, and where it is kept, is the caller's
/// decision and deliberately outside this library. A portable `no_std` crate
/// has no entropy source and no storage, and offering a `tm_keygen` that
/// quietly used a weak one would put a security-critical choice behind an
/// interface that cannot honour it. [`crate::TmUser::public_key`] is where the
/// result belongs; `backend::SecretKey::Slot` is the seam for a private key
/// that never becomes addressable at all.
#[no_mangle]
pub unsafe extern "C" fn tm_x25519_public(
    private_key: *const u8,
    private_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> i32 { unsafe {
    if private_key.is_null() || out.is_null() {
        return TM_E_ARG;
    }
    if private_len != x25519::KEY_LEN {
        return TM_E_BAD_KEY_LEN;
    }
    if out_cap < x25519::KEY_LEN {
        return TM_E_SHORT;
    }
    let src = slice::from_raw_parts(private_key, private_len);
    let mut scalar = [0u8; x25519::KEY_LEN];
    // zip, never copy_from_slice: that call compiles to a length-mismatch panic
    // path, and check_rust_rules.sh reads the built object for exactly that
    // symbol. It has caught one here before.
    for (d, s) in scalar.iter_mut().zip(src.iter()) {
        *d = *s;
    }
    let public = x25519::public_key(&scalar);
    let dst = slice::from_raw_parts_mut(out, out_cap);
    for (d, s) in dst.iter_mut().zip(public.iter()) {
        *d = *s;
    }
    TM_OK
}}

/// What a node publishes about itself: the fields of a `User`.
///
/// Pointer/length pairs rather than fixed arrays, because every one of these is
/// variable-length on the wire and a fixed array would force this header to
/// invent a maximum the protocol does not define.
///
/// A null pointer or a zero length omits the field, which is what proto3 does
/// with a default. **`macaddr` is the trap.** It has been deprecated since
/// 2.1.x and firmware 2.7.26 still puts it on the wire as six zero bytes in
/// every `User` in the corpus, so a `User` that drops it re-encodes shorter
/// than the reference produced. Pass the six zero bytes to match what is
/// actually emitted; deprecated in the schema is not absent from the wire.
#[repr(C)]
pub struct TmUser {
    /// Conventionally `!` followed by the node number in lowercase hex.
    pub id: *const u8,
    pub id_len: usize,
    pub long_name: *const u8,
    pub long_name_len: usize,
    /// Conventionally four characters.
    pub short_name: *const u8,
    pub short_name_len: usize,
    /// 32 bytes from [`tm_x25519_public`]. Omitted when absent, and a peer that
    /// does not receive it cannot address this node by direct message.
    pub public_key: *const u8,
    pub public_key_len: usize,
    /// Six bytes. See the note above before deciding to leave it out.
    pub macaddr: *const u8,
    pub macaddr_len: usize,
    pub hw_model: u32,
    pub role: u32,
}

/// Borrow a pointer/length pair, treating null or empty as an absent field.
///
/// # Safety
///
/// `p` must be valid for `len` bytes when both are non-trivial, and outlive the
/// returned slice. That is the FFI trust edge `DISTRIBUTION.md` names: a caller
/// passing a bad pointer or a wrong length cannot be validated here.
unsafe fn borrow<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        return &[];
    }
    unsafe { slice::from_raw_parts(p, len) }
}

/// Build and encrypt a `NODEINFO_APP` frame announcing this node.
///
/// Returns the frame length, or negative on error. The on-air payload for this
/// port is a bare `User` — not a `NodeInfo` wrapping one — which is the shape
/// the corpus shows and the shape a stock node parses.
///
/// Broadcast it with `to = 0xFFFFFFFF`. When answering another node's request,
/// address it to the asker instead and leave `want_response` clear, so that two
/// nodes cannot ask each other in a loop.
///
/// `relay_node` is stamped with the low byte of `from`, which is what an
/// originating node does: `WIRE_REFERENCE.md` records the field as a one-byte
/// truncation of the relaying node's number, corroborated on captured traffic
/// for three separate nodes.
#[no_mangle]
pub unsafe extern "C" fn tm_nodeinfo_encode(
    from: u32,
    to: u32,
    id: u32,
    hop_limit: u8,
    channel_hash: u8,
    want_response: u8,
    key: *const TmKey,
    user: *const TmUser,
    out: *mut u8,
    out_cap: usize,
) -> i32 { unsafe {
    if key.is_null() || user.is_null() || out.is_null() {
        return TM_E_ARG;
    }
    let u = &*user;
    let profile = User {
        id: borrow(u.id, u.id_len),
        long_name: borrow(u.long_name, u.long_name_len),
        short_name: borrow(u.short_name, u.short_name_len),
        macaddr: borrow(u.macaddr, u.macaddr_len),
        public_key: borrow(u.public_key, u.public_key_len),
        hw_model: u.hw_model,
        role: u.role,
        ..Default::default()
    };
    let mut ubuf = [0u8; 160];
    let Ok(ulen) = profile.encode(&mut ubuf) else {
        return TM_E_SHORT;
    };
    let Some(ubody) = ubuf.get(..ulen) else {
        return TM_E_SHORT;
    };

    let data = Data {
        portnum: PortNum::NODEINFO_APP.0,
        payload: ubody,
        want_response: want_response != 0,
        ..Default::default()
    };
    let mut plain = [0u8; 240];
    let Ok(plain_len) = data.encode(&mut plain) else {
        return TM_E_SHORT;
    };
    // get(), not plain[..plain_len]: bare slice indexing compiles to a panic
    // path, and one reaching a linked image is a crate-rule violation.
    let Some(body) = plain.get(..plain_len) else {
        return TM_E_SHORT;
    };

    let header = Header {
        to,
        from,
        id,
        hop_limit,
        want_ack: false,
        via_mqtt: false,
        hop_start: hop_limit,
        channel: channel_hash,
        next_hop: 0,
        relay_node: (from & 0xFF) as u8,
    };
    let dst = slice::from_raw_parts_mut(out, out_cap);
    match frame::encode(&header, body, &(*key).bytes, 0, dst) {
        Ok(n) => match i32::try_from(n) {
            Ok(v) => v,
            Err(_) => TM_E_SHORT,
        },
        Err(_) => TM_E_ARG,
    }
}}

// ── PKI direct messages ─────────────────────────────────────────────────────

/// A message key agreed with one peer: SHA-256 over the raw X25519 secret.
///
/// A distinct type for the same reason [`TmKey`] is one — it is not
/// interchangeable with a channel key, and the two are the same shape in C. A
/// channel key is 16 bytes of AES-128 shared by everyone on the channel; this
/// is 32 bytes of AES-256 shared with exactly one peer, and passing one where
/// the other belongs would fail as "the radio is broken".
///
/// **The full SHA-256 output, not truncated to 128 bits.** That is measured, in
/// `tests/captures/pki_dm_record.json`, and it is the sort of parameter that is
/// guessed wrong and then produces garbage with nothing to say why.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TmPkiKey {
    pub bytes: [u8; 32],
}

/// The 13-byte CCM nonce for a direct message.
///
/// `packet_id(LE) || extra_nonce(LE) || from(LE) || 0x00`, measured and recorded
/// in `WIRE_REFERENCE.md`. One function rather than one per direction, because
/// a sealer and an opener that disagree about nonce layout produce a frame that
/// only its author can read -- and the two constructions sat six lines apart,
/// which is exactly how that disagreement gets introduced later.
fn pki_nonce(id: u32, extra_nonce: [u8; 4], from: u32) -> [u8; crypto::CCM_NONCE_LEN] {
    let mut n = [0u8; crypto::CCM_NONCE_LEN];
    for (d, s) in n.iter_mut().zip(id.to_le_bytes()) {
        *d = s;
    }
    for (d, s) in n.iter_mut().skip(4).zip(extra_nonce) {
        *d = s;
    }
    for (d, s) in n.iter_mut().skip(8).zip(from.to_le_bytes()) {
        *d = s;
    }
    // n[12] stays 0.
    n
}

/// Agree the message key for one peer.
///
/// Returns [`TM_E_SMALL_ORDER`] when the peer's public key drives the shared
/// secret to zero. **That is never retryable and must never be treated as a
/// transient failure** — a small-order key is chosen deliberately, and it makes
/// the "shared" secret one the attacker knew in advance. It is a separate code
/// from every other failure precisely so a caller cannot lump it in with a
/// wrong length and retry.
///
/// Agreement is the expensive half of this scheme — a scalar multiplication —
/// while opening a frame is cheap. Keeping them apart lets a caller agree once
/// per peer and keep the result, rather than paying for a ladder per frame.
#[no_mangle]
pub unsafe extern "C" fn tm_pki_agree(
    private_key: *const u8,
    private_len: usize,
    peer_public: *const u8,
    peer_public_len: usize,
    out: *mut TmPkiKey,
) -> i32 { unsafe {
    if private_key.is_null() || peer_public.is_null() || out.is_null() {
        return TM_E_ARG;
    }
    if private_len != x25519::KEY_LEN || peer_public_len != x25519::KEY_LEN {
        return TM_E_BAD_KEY_LEN;
    }
    let mut priv_k = [0u8; x25519::KEY_LEN];
    let mut peer_k = [0u8; x25519::KEY_LEN];
    for (d, s) in priv_k.iter_mut().zip(slice::from_raw_parts(private_key, private_len)) {
        *d = *s;
    }
    for (d, s) in peer_k.iter_mut().zip(slice::from_raw_parts(peer_public, peer_public_len)) {
        *d = *s;
    }
    let Some(shared) = x25519::x25519(&priv_k, &peer_k) else {
        return TM_E_SMALL_ORDER;
    };
    (*out).bytes = sha256(&shared);
    TM_OK
}}

/// Is this frame a PKI direct message?
///
/// Returns 1 if so, 0 if not, negative on a malformed input. **A channel hash
/// of `0x00` is what marks one on the wire** — measured, not inferred — and a
/// direct message is addressed rather than broadcast. A caller that guesses
/// wrong runs the frame through the channel path, which does not fail: CTR
/// decrypts anything into something.
#[no_mangle]
pub unsafe extern "C" fn tm_is_pki(frame: *const u8, frame_len: usize) -> i32 { unsafe {
    if frame.is_null() {
        return TM_E_ARG;
    }
    let f = slice::from_raw_parts(frame, frame_len);
    let Ok(h) = frame::peek_header(f) else {
        return TM_E_SHORT;
    };
    i32::from(h.channel == 0 && !h.is_broadcast())
}}

/// Bytes a PKI frame carries beyond its plaintext: the 8-byte tag and the
/// 4-byte `extra_nonce`. Both are on the wire; neither is the message.
const PKI_OVERHEAD: usize = 12;

/// Open a PKI direct message in place, leaving the plaintext borrowed from the
/// caller's buffer.
///
/// On success `payload` points into `frame` and `payload_len` is its length.
///
/// **A failed tag is reported, never returned as data.** This is the property
/// channel encryption does not have and the reason [`TM_E_UNAUTHENTIC`] exists
/// as its own code: a forged message decrypts to *something*, and only the tag
/// distinguishes it from a real one. On that error the buffer holds whatever
/// the keystream produced and must be discarded.
///
/// Layout, measured: `header(16) || ciphertext || tag(8) || extra_nonce(4)`,
/// with the nonce built as `packet_id(LE) || extra_nonce || from(LE) || 0x00`.
/// `extra_nonce` travels at the *end* of the payload, not with the header.
#[no_mangle]
pub unsafe extern "C" fn tm_pki_decrypt(
    frame: *mut u8,
    frame_len: usize,
    key: *const TmPkiKey,
    payload: *mut *const u8,
    payload_len: *mut usize,
) -> i32 { unsafe {
    if frame.is_null() || key.is_null() || payload.is_null() || payload_len.is_null() {
        return TM_E_ARG;
    }
    let f = slice::from_raw_parts_mut(frame, frame_len);
    let Ok(h) = frame::peek_header(f) else {
        return TM_E_SHORT;
    };
    let Some(body) = f.get_mut(header::HEADER_LEN..) else {
        return TM_E_SHORT;
    };
    // checked_sub, not `-`: a frame shorter than the overhead is exactly the
    // hostile input this crate refuses to panic on.
    if body.len() < PKI_OVERHEAD {
        return TM_E_SHORT;
    }
    let Some(sealed_len) = body.len().checked_sub(4) else {
        return TM_E_SHORT;
    };
    let mut extra = [0u8; 4];
    for (d, s) in extra.iter_mut().zip(body.iter().skip(sealed_len)) {
        *d = *s;
    }
    let nonce = pki_nonce(h.id, extra, h.from);
    let Some(sealed) = body.get_mut(..sealed_len) else {
        return TM_E_SHORT;
    };
    match crypto::ccm_decrypt_in_place(&(*key).bytes, &nonce, sealed, crypto::CCM_TAG_LEN) {
        Ok(n) => {
            *payload = sealed.as_ptr();
            *payload_len = n;
            TM_OK
        }
        Err(crypto::CcmError::Unauthentic) => TM_E_UNAUTHENTIC,
        Err(_) => TM_E_SHORT,
    }
}}

/// Build and seal a PKI direct message. Returns the frame length.
///
/// `extra_nonce` must not repeat for a given `(from, id)` — it is nonce input,
/// and a repeat under the same key reproduces a keystream. Draw it from the
/// same source as any other nonce material.
///
/// The channel hash is forced to `0x00`, which is what marks the frame as PKI
/// on the wire; there is no channel key involved and no channel to name.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn tm_pki_encode(
    from: u32,
    to: u32,
    id: u32,
    hop_limit: u8,
    want_ack: u8,
    key: *const TmPkiKey,
    extra_nonce: u32,
    portnum: u32,
    payload: *const u8,
    payload_len: usize,
    out: *mut u8,
    out_cap: usize,
) -> i32 { unsafe {
    if key.is_null() || payload.is_null() || out.is_null() {
        return TM_E_ARG;
    }
    let data = Data {
        portnum,
        payload: slice::from_raw_parts(payload, payload_len),
        ..Default::default()
    };
    let mut work = [0u8; 240];
    let Ok(plain_len) = data.encode(&mut work) else {
        return TM_E_SHORT;
    };

    let nonce = pki_nonce(id, extra_nonce.to_le_bytes(), from);
    let Ok(sealed) = crypto::ccm_encrypt_in_place(
        &(*key).bytes, &nonce, &mut work, plain_len, crypto::CCM_TAG_LEN,
    ) else {
        return TM_E_SHORT;
    };

    let header = Header {
        to,
        from,
        id,
        hop_limit,
        want_ack: want_ack != 0,
        via_mqtt: false,
        hop_start: hop_limit,
        channel: 0x00,
        next_hop: 0,
        relay_node: (from & 0xFF) as u8,
    };
    let hdr = header.encode();

    let Some(total) = sealed.checked_add(header::HEADER_LEN).and_then(|v| v.checked_add(4)) else {
        return TM_E_SHORT;
    };
    if out_cap < total {
        return TM_E_SHORT;
    }
    let dst = slice::from_raw_parts_mut(out, out_cap);
    for (d, s) in dst.iter_mut().zip(hdr.iter()) {
        *d = *s;
    }
    let Some(after_hdr) = dst.get_mut(header::HEADER_LEN..) else {
        return TM_E_SHORT;
    };
    for (d, s) in after_hdr.iter_mut().zip(work.iter().take(sealed)) {
        *d = *s;
    }
    let Some(after_body) = after_hdr.get_mut(sealed..) else {
        return TM_E_SHORT;
    };
    for (d, s) in after_body.iter_mut().zip(extra_nonce.to_le_bytes()) {
        *d = s;
    }
    match i32::try_from(total) {
        Ok(v) => v,
        Err(_) => TM_E_SHORT,
    }
}}
