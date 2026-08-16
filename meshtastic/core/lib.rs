//! tethermesh — a clean-room Meshtastic-compatible stack.
//!
//! Read `meshtastic/WIRE_REFERENCE.md` before adding anything to this crate.
//! It separates what has been verified from what has only been asserted, and
//! nothing in here may depend on the second category.
//!
//! # What the crate-level attributes below are for
//!
//! This library parses untrusted frames from a public mesh whose participants
//! are assumed to include adversarial ones. `DISTRIBUTION.md` promises three
//! properties, and each is enforced by the compiler here rather than by
//! review, because a promise no mechanism enforces decays silently:
//!
//! 1. **No panics on hostile input.** Rust turns a memory error into a panic,
//!    and under `panic = "abort"` a panic halts the node — so an unchecked
//!    panic path converts remote code execution into remote denial of
//!    service. That is a better bug, not an acceptable one. Hence no
//!    `unwrap`, no `expect`, no `panic!`, no slice indexing, and no bare
//!    integer arithmetic anywhere in the parse path.
//! 2. **No allocation.** Buffers are caller-provided with explicit lengths.
//!    An allocator on an embedded target is a failure mode, not a
//!    convenience.
//! 3. **No mutable global state.** `Send`/`Sync` do not cross an FFI boundary
//!    that a foreign RTOS scheduler calls into, so concurrency safety here is
//!    a property of API shape — state in a caller-owned context — and not of
//!    the language.
//!
//! `tools/check_rust_rules.sh` checks all three independently of the lints,
//! because a local `#[allow]` silently defeats a crate-level `deny`.

#![no_std]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::indexing_slicing)]
// Formerly `clippy::integer_arithmetic`, which clippy renamed. The old name
// still resolved and still enforced, so this is not a fix for a broken rule —
// it is a move off a deprecated spelling before it becomes a broken rule.
// Renamed is not removed: when clippy drops the old name, a `deny` on it
// becomes inert, arithmetic checking stops, and nothing goes red because the
// attribute is still sitting there looking correct. That is the exact decay
// this crate's rules exist to prevent, so it is not something to carry.
// tools/check_rust_rules.sh requires this spelling; the two move together.
#![deny(clippy::arithmetic_side_effects)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(unsafe_code)]


pub mod backend;
pub mod channel;
pub mod crypto;
pub mod frame;
pub mod header;
pub mod history;
pub mod message;
pub mod packet_id;
pub mod protobuf;

#[cfg(kani)]
mod proofs;
pub mod sha256;
pub mod x25519;
