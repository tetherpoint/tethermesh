#!/usr/bin/env bash
#
# check_rust_rules.sh — enforce the crate-level rules DISTRIBUTION.md commits to.
#
# WHY THESE ARE CHECKED AND NOT TRUSTED
# -------------------------------------
# DISTRIBUTION.md promises three properties that are only worth promising if
# they are mechanically true:
#
#   1. NO PANICS ON HOSTILE INPUT. This library parses untrusted frames from a
#      public mesh. Rust converts a memory error into a panic, and with
#      panic=abort a panic halts the device — so an unchecked panic path turns
#      remote code execution into remote denial of service. That is a better
#      bug, not an acceptable one. The parse path must have no panicking
#      construct at all.
#   2. NO ALLOCATION. Buffers are caller-provided. An allocator on an embedded
#      target is a failure mode, not a convenience.
#   3. NO MUTABLE GLOBAL STATE. Rust's Send/Sync guarantees do NOT cross an FFI
#      boundary where a foreign RTOS scheduler calls in. Concurrency safety
#      here is a property of the API shape — state in a caller-owned context —
#      not of the language.
#
# Each is verifiable, so each is verified. A promise in a document that no
# script enforces is a promise that decays silently.
#
# USAGE
#   tools/check_rust_rules.sh            source-level checks
#   tools/check_rust_rules.sh --binary <lib.a>   also check for panic machinery
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
say()  { printf '\033[36m[rust-rules]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[rust-rules] VIOLATION: %s\033[0m\n' "$*" >&2; violations=$((violations+1)); }
violations=0

# Required crate-level attributes. These are the mechanism by which rules 1-3
# are enforced by the compiler rather than by review.
REQUIRED_ATTRS=(
    'no_std'
    'deny(clippy::unwrap_used)'
    'deny(clippy::expect_used)'
    'deny(clippy::panic)'
    'deny(clippy::indexing_slicing)'
    'deny(clippy::integer_arithmetic)'
    'forbid(unsafe_op_in_unsafe_fn)'
)

rs_files=$(find "$ROOT" -name '*.rs' -not -path '*/target/*' 2>/dev/null || true)

if [ -z "$rs_files" ]; then
    # No silent no-op: a checker that passes because there is nothing to check
    # reads as a pass, and a pass that never ran is worse than a failure.
    printf '\033[33m[rust-rules] NOTHING TO CHECK — no .rs files yet\033[0m\n' >&2
    printf '        This is expected before the crate exists. It is reported as\n' >&2
    printf '        non-zero deliberately so it cannot be mistaken for a pass.\n' >&2
    printf '        The first lib.rs must carry:\n' >&2
    for a in "${REQUIRED_ATTRS[@]}"; do printf '            #![%s]\n' "$a" >&2; done
    exit 3
fi

# ── crate-level attributes present? ────────────────────────────────────────
LIB=$(echo "$rs_files" | grep -E '/lib\.rs$' | head -1 || true)
if [ -z "$LIB" ]; then
    fail "no lib.rs found — cannot verify crate-level attributes"
else
    for a in "${REQUIRED_ATTRS[@]}"; do
        grep -qF "#![$a]" "$LIB" || fail "lib.rs is missing #![$a]"
    done
fi

# ── forbidden constructs in source ─────────────────────────────────────────
# Checked as well as denied by lint, because a local #[allow] silently defeats
# a crate-level deny and would not otherwise be visible.
while IFS= read -r f; do
    [ -n "$f" ] || continue
    base=$(basename "$f")
    # Tests may panic; that is what an assertion is.
    case "$f" in */tests/*|*/benches/*) continue ;; esac
    grep -nE '^\s*[^/]*\ballow\(clippy::(unwrap_used|panic|indexing_slicing|integer_arithmetic)\)' "$f" 2>/dev/null \
        && fail "$base — local #[allow] defeats a crate-level deny"
    grep -nE '\bstatic\s+mut\b' "$f" 2>/dev/null \
        && fail "$base — 'static mut': mutable global state. State belongs in a caller-owned context; Send/Sync does not cross the FFI boundary."
    grep -nE '^\s*extern\s+crate\s+alloc' "$f" 2>/dev/null \
        && fail "$base — pulls in alloc. Buffers are caller-provided."
done <<< "$rs_files"

# ── binary check: panic machinery must not be linked ───────────────────────
if [ "${1:-}" = "--binary" ]; then
    LIBA="${2:-}"
    [ -f "$LIBA" ] || { printf '\033[31m[rust-rules] --binary given but %s not found\033[0m\n' "$LIBA" >&2; exit 1; }
    NM=$(command -v llvm-nm || command -v nm)
    # If no panic path exists, the panic formatting machinery is never
    # referenced and does not survive into the archive. Its presence is
    # evidence that some path can panic.
    n=$("$NM" "$LIBA" 2>/dev/null | grep -cE 'core\.\.panicking|rust_begin_unwind|panic_fmt' || true)
    if [ "$n" -gt 0 ]; then
        fail "$LIBA links panic machinery ($n symbols) — some path can still panic on input"
    else
        say "binary carries no panic machinery"
    fi
fi

if [ "$violations" -gt 0 ]; then
    printf '\033[31m[rust-rules] %d violation(s). REFUSING.\033[0m\n' "$violations" >&2
    exit 1
fi
say "OK — crate rules hold"
