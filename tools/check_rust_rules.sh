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
#   tools/check_rust_rules.sh --binary <obj.o>   also check for panic machinery
#       (an ELF object, NOT an .rlib and NOT bitcode — see the note below)
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
    # Was 'deny(clippy::integer_arithmetic)'. Clippy renamed that lint, and a
    # renamed lint still enforces — so this is not a repair, it is a move off a
    # deprecated spelling before it turns into a silent hole. Renamed is not
    # removed: once clippy drops the old name, denying it becomes inert and
    # arithmetic checking stops while the attribute still reads as present and
    # this script still finds the string. Requiring the current name is what
    # keeps the check honest.
    'deny(clippy::arithmetic_side_effects)'
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
    # Both spellings of the arithmetic lint are listed. The crate denies the
    # current name, but an #[allow] of either would read as intentional and
    # neither must pass: the old name still resolves today, so allowing it
    # would defeat the deny just as effectively.
    grep -nE '^\s*[^/]*\ballow\(clippy::(unwrap_used|expect_used|panic|indexing_slicing|integer_arithmetic|arithmetic_side_effects)\)' "$f" 2>/dev/null \
        && fail "$base — local #[allow] defeats a crate-level deny"
    grep -nE '\bstatic\s+mut\b' "$f" 2>/dev/null \
        && fail "$base — 'static mut': mutable global state. State belongs in a caller-owned context; Send/Sync does not cross the FFI boundary."
    grep -nE '^\s*extern\s+crate\s+alloc' "$f" 2>/dev/null \
        && fail "$base — pulls in alloc. Buffers are caller-provided."
done <<< "$rs_files"

# ── binary check: no panic path may survive into the artifact ──────────────
# THIS CHECK WAS SILENTLY VACUOUS UNTIL 2026-08-16, IN THREE SEPARATE WAYS.
# Recorded here because each one passed while proving nothing, which is worse
# than failing:
#
#   1. Pointed at an .rlib it saw 4 symbols, none of them ours. An rlib is
#      mostly metadata, not linked object code.
#   2. `--emit=obj` under this crate's release profile emits LLVM BITCODE
#      (magic 42 43 c0 de), which nm reads as an empty symbol table. LTO must
#      be off to get an ELF object.
#   3. The patterns below were written for LEGACY symbol mangling. This
#      toolchain uses v0, where `core..panicking` never appears — and panic
#      paths frequently surface as specialised symbols such as
#      `len_mismatch_fail` or `panic_bounds_check` that do not contain the
#      word "panicking" at all.
#
# So the real test is UNDEFINED REFERENCES. A crate that cannot panic and does
# not allocate should need nothing from outside itself except compiler
# intrinsics. Anything else undefined is a call into machinery that can fail.
#
# Produce a checkable artifact with:
#   CARGO_PROFILE_RELEASE_LTO=false \
#     cargo rustc --release --lib -- --emit=obj -o target/objcheck/tm.o
if [ "${1:-}" = "--binary" ]; then
    LIBA="${2:-}"
    [ -f "$LIBA" ] || { printf '\033[31m[rust-rules] --binary given but %s not found\033[0m\n' "$LIBA" >&2; exit 1; }

    magic=$(head -c 4 "$LIBA" | od -An -tx1 | tr -d ' \n')
    case "$magic" in
        7f454c46) : ;;                       # ELF
        213c6172) : ;;                       # "!<ar" archive
        4243c0de)
            printf '\033[31m[rust-rules] REFUSING: %s is LLVM bitcode, not object code.\033[0m\n' "$LIBA" >&2
            printf '        LTO is on, so nm sees an empty symbol table and this check\n' >&2
            printf '        would pass without inspecting anything. Rebuild with\n' >&2
            printf '        CARGO_PROFILE_RELEASE_LTO=false.\n' >&2
            exit 1 ;;
        *)
            printf '\033[31m[rust-rules] REFUSING: %s is not an object file (magic %s)\033[0m\n' "$LIBA" "$magic" >&2
            exit 1 ;;
    esac

    NM=$(command -v llvm-nm || command -v nm)
    total=$("$NM" "$LIBA" 2>/dev/null | grep -c . || true)
    if [ "$total" -lt 5 ]; then
        printf '\033[31m[rust-rules] REFUSING: only %s symbol(s) in %s\033[0m\n' "$total" "$LIBA" >&2
        printf '        An artifact this bare cannot demonstrate anything. A check that\n' >&2
        printf '        passes because there is nothing to look at is not a check.\n' >&2
        exit 1
    fi

    # Compiler intrinsics are the only outside references a no_std, no-alloc,
    # panic-free crate legitimately needs.
    undef=$("$NM" -u "$LIBA" 2>/dev/null | awk '{print $NF}' | grep -vE '^(memcpy|memset|memmove|memcmp|bcmp|__aeabi_[a-z0-9_]+)$' || true)
    if [ -n "$undef" ]; then
        fail "$LIBA references machinery outside the crate — every one of these is a
              path that can fail, and several panic entry points are named things
              like len_mismatch_fail rather than anything containing 'panic':"
        printf '%s\n' "$undef" | sed 's/^/                /' >&2
    else
        say "binary carries no panic machinery ($total symbols inspected, no outside references)"
    fi
fi

if [ "$violations" -gt 0 ]; then
    printf '\033[31m[rust-rules] %d violation(s). REFUSING.\033[0m\n' "$violations" >&2
    exit 1
fi
say "OK — crate rules hold"
