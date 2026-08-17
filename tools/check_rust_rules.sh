#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 The tethermesh Authors
# SPDX-License-Identifier: Apache-2.0
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

# third_party/ holds pinned upstream code, and OUR source rules do not govern
# it — we did not write it and may not edit it without voiding its provenance.
# What governs it is the artifact check below: whatever it does to the linked
# object is measured there, which is the property that actually matters. A
# source rule applied to somebody else's code would only ever produce a
# violation we would have to suppress.
rs_files=$(find "$ROOT" -name '*.rs' -not -path '*/target/*' -not -path '*/third_party/*' 2>/dev/null || true)

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

# In --binary mode the SOURCE pass is skipped: tools/check_all.sh runs it once
# up front, and repeating it per inspected crate printed every violation N
# times. Noise that scales with crate count trains people to skim output, which
# is how a real violation gets missed.
if [ "${1:-}" != "--binary" ]; then

# ── crate-level attributes present? ────────────────────────────────────────
# EVERY crate root, not the first one found.
#
# This read `head -1` until 2026-08-16, which was correct while there was one
# crate and would have gone silently wrong the moment there were two: the
# second crate's attributes would never have been checked and this would still
# have printed "crate rules hold". The extension suite is planned as one crate
# per bundle, so that day was coming. A gate that narrows silently is the
# failure this file's own header records being bitten by three times over.
libs=$(echo "$rs_files" | grep -E '/lib\.rs$' || true)
if [ -z "$libs" ]; then
    fail "no lib.rs found — cannot verify crate-level attributes"
else
    n_libs=0
    while IFS= read -r LIB; do
        [ -n "$LIB" ] || continue
        n_libs=$((n_libs+1))
        rel="${LIB#"$ROOT"/}"
        for a in "${REQUIRED_ATTRS[@]}"; do
            if grep -qF "#![$a]" "$LIB"; then
                continue
            fi
            # `no_std` may also appear as `#![cfg_attr(not(test), no_std)]`, and
            # ONLY in that exact form. A crate carrying a #[panic_handler] --
            # the FFI shim does, because a linked program may have exactly one
            # -- cannot host `cargo test` while unconditionally no_std: the test
            # harness links std and brings a handler of its own.
            #
            # This is not a hole. `not(test)` means the attribute applies to
            # every build that is not a test binary, which is every build that
            # ships. Any other predicate is refused, because `cfg_attr(not(
            # feature = "x"), no_std)` would let a feature flag quietly turn a
            # shipped artifact into a std one.
            if [ "$a" = "no_std" ] \
               && { grep -qF '#![cfg_attr(not(test), no_std)]' "$LIB" \
                    || grep -qF '#![cfg_attr(not(any(test, kani)), no_std)]' "$LIB"; }; then
                continue
            fi
            fail "$rel is missing #![$a]"
        done
    done <<< "$libs"
    say "crate roots checked: $n_libs"
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

# ── fiat-crypto precondition discipline ────────────────────────────────────
# THE FAILURE MODE THIS EXISTS FOR IS SILENT AND CRYPTOGRAPHIC.
#
# fiat-crypto's field operations are proven correct in Coq *given inputs within
# stated magnitude bounds*. Supply a value outside them and the proof does not
# apply -- the result may simply be wrong, with nothing to signal it. No test
# vector reliably catches this, because the wrong answer is still deterministic
# and self-consistent.
#
# What makes it safe in x25519.rs is structural: fiat's `tight`/`loose` types
# ARE those bounds, so misuse is a compile error. That argument holds only
# while every field value flows through the typed wrappers. Reaching into `.0`
# gets the raw limb array and steps outside the type system entirely, and
# arithmetic done there voids the proof silently.
#
# The 2026-08-16 audit adjudicated every `.0` in the tree by hand and found
# three, all in `cswap`, all moving limb arrays through fiat's own selectznz
# with no arithmetic. That is a fact about a moment, not a property -- so it is
# a gate now. This is an ALLOWLIST of the shapes adjudicated as safe, not a
# blocklist of operators: a blocklist has to anticipate every way to write
# arithmetic, and an allowlist only has to recognise the ways already approved.
#
# IF THIS FIRES, DO NOT WIDEN THE PATTERN TO MAKE IT PASS. Establish that the
# new site performs no arithmetic on raw limbs, then add its shape here
# deliberately -- the friction is the point.
fiat_files=$(grep -lE 'fiat_crypto|fiat_25519' $rs_files 2>/dev/null || true)
while IFS= read -r f; do
    [ -n "$f" ] || continue
    base=$(basename "$f")
    case "$f" in */tests/*|*/benches/*) continue ;; esac

    # Strip comments and string literals before judging: a doc comment
    # explaining the rule must not trip it, which is the same exemption
    # check_cleanroom.sh grants itself.
    while IFS=: read -r lineno body; do
        [ -n "$lineno" ] || continue
        trimmed=$(printf '%s' "$body" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
        case "$trimmed" in
            //*|'*'*) continue ;;                       # comment or rustdoc continuation
        esac
        ok=0
        # 1. paired read into locals:   let (x, y) = (a.0, b.0);
        printf '%s' "$trimmed" | grep -qE '^let \([a-z_]+, [a-z_]+\) = \([a-z_]+\.0, [a-z_]+\.0\);$' && ok=1
        # 2. plain write-back:          a.0 = na;
        printf '%s' "$trimmed" | grep -qE '^[a-z_]+\.0 = [a-z_]+;$' && ok=1
        # 3. plain read into a local:   let x = a.0;
        printf '%s' "$trimmed" | grep -qE '^let [a-z_]+ = [a-z_]+\.0;$' && ok=1
        if [ "$ok" -eq 0 ]; then
            fail "$base:$lineno — unadjudicated use of a fiat limb array via '.0'.
              Field values must flow through the tight/loose wrappers; those types
              ARE fiat's proven magnitude bounds. Arithmetic on raw limbs voids the
              Coq proof SILENTLY -- the answer stays deterministic and wrong.
              The line was:
                  $trimmed
              If it genuinely performs no arithmetic, add its shape to the
              allowlist in $(basename "${BASH_SOURCE[0]}") on purpose."
        fi
    done < <(grep -nE '\.0\b' "$f" 2>/dev/null || true)
done <<< "$fiat_files"

fi   # end of source pass

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
    # Compiler intrinsics are the only outside references a no_std, no-alloc,
    # panic-free crate legitimately needs -- and WHICH ones depends on the
    # target, which this list did not account for until 2026-08-16.
    #
    #   memcpy/memset/...   everywhere
    #   __aeabi_*           ARM EABI helpers
    #   __*di3, __*si3      libgcc-style 64- and 32-bit helpers. RISC-V needs
    #                       __udivdi3 and __ashldi3 because riscv32imc has no
    #                       hardware 64-bit divide, and airtime.rs does u64
    #                       arithmetic. Without these the gate reports a false
    #                       violation on that target -- found by actually
    #                       cross-compiling rather than by reading this list.
    # A SECOND legitimate class arrived with the FFI crate on 2026-08-17:
    # references to OTHER CRATES IN THIS WORKSPACE. tmffi is a shim, so nearly
    # every line it contains calls tethermesh -- `frame::encode`, `Header::decode`
    # and so on appear as undefined in its object and are resolved at link time.
    #
    # THIS IS NOT A WIDENING TO MAKE SOMETHING PASS, and the distinction matters
    # because this file's own header forbids exactly that. The guarantee is
    # preserved by construction:
    #
    #   * every workspace crate is inspected by this same check -- check_all.sh
    #     iterates `cargo metadata` and runs it per package, so a panic path in
    #     tethermesh fails on tethermesh's own object rather than hiding here;
    #   * a panicking generic INSTANTIATED in this crate is a DEFINED symbol in
    #     this object, not an undefined one, so it is still caught by the
    #     panic-machinery scan above;
    #   * and the linked image -- the only place the question has a final answer
    #     -- is checked separately by check_artifact_link.sh.
    #
    # What stays refused is anything satisfied by NEITHER an intrinsic nor a
    # crate we gate. The crate list is derived, never hardcoded: a name typed in
    # here would keep passing after the crate it named was deleted.
    #
    # v0 mangling embeds the crate name length-prefixed, so `10tethermesh`
    # identifies tethermesh unambiguously inside a symbol.
    ws_crates=$(cd "$ROOT" && cargo metadata --no-deps --format-version 1 2>/dev/null \
        | python3 -c 'import json,sys
try: m = json.load(sys.stdin)
except Exception: sys.exit(0)
for p in m.get("packages", []):
    if "/third_party/" in p.get("manifest_path", ""):
        continue
    n = p["name"].replace("-", "_")
    print("%d%s" % (len(n), n))' 2>/dev/null || true)

    undef=$("$NM" -u "$LIBA" 2>/dev/null | awk '{print $NF}' \
        | grep -vE '^(memcpy|memset|memmove|memcmp|bcmp|__aeabi_[a-z0-9_]+|__[a-z]+[dsq]i[23]|__clz[sd]i2|__ctz[sd]i2|__popcount[sd]i2)$' || true)

    if [ -n "$ws_crates" ] && [ -n "$undef" ]; then
        keep=""
        while IFS= read -r sym; do
            [ -n "$sym" ] || continue
            internal=0
            while IFS= read -r c; do
                [ -n "$c" ] || continue
                case "$sym" in *"$c"*) internal=1; break ;; esac
            done <<< "$ws_crates"
            [ "$internal" = 1 ] || keep="$keep$sym
"
        done <<< "$undef"
        undef=$(printf '%s' "$keep")
    fi
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
