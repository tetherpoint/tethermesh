#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Matthew Klapman
# SPDX-License-Identifier: Apache-2.0
#
# check_rust_rules_selftest.sh — prove that check_rust_rules.sh --binary still
# says NO, on synthetic archives built to make it say NO.
#
# WHY THIS EXISTS
# ---------------
# A18. `check_rust_rules.sh` listed `!<ar` as a supported input from the day it
# was written and REFUSED every archive on every architecture — 1219 flagged
# "symbols" on the shipped riscv32imc artifact, none of them symbols. The bug is
# unremarkable. WHAT IT SURVIVED ON IS THE POINT: check_all.sh only ever fed the
# gate a single .o, so the archive path was documented, believed, and never once
# executed. Nothing was wrong with the reasoning about archives; nothing had run
# it.
#
# So the fix is not only "read archives correctly". It is "make the archive path
# impossible to leave unexercised again", and that takes two things:
#
#   * check_all.sh now builds and inspects the staticlib for every declared
#     target, so the real artifact goes through the real gate on every run; and
#   * this script, which asserts the gate REFUSES what it must refuse. A gate
#     that only ever sees clean inputs cannot tell you it still works — the
#     four archives check_all inspects all pass, and would all pass just as
#     happily if the check were `exit 0`.
#
# THE FLOOR IS ASSERTED AND THEN BROKEN DELIBERATELY, which is this tree's rule:
# a test that has never been seen red is not yet a test. Several cases below run
# a MUTATED COPY of the gate and require that the mutant fails where the real one
# passes. That is what pins the fix in place: revert either half of the archive
# handling and this script goes red naming the half.
#
# The fixtures are host objects. The property under test is how the gate reads an
# archive — member headers, cross-member resolution, magic — and none of that is
# architecture-specific. Cross-compiled coverage comes from check_all.sh feeding
# it the four real staticlibs.
#
# The synthetic symbols are deliberately NOT workspace-mangled names, so no case
# turns on the `cargo metadata` whitelist: a fixture passes or fails on the
# archive semantics alone. The one place the crate list DOES matter is the
# defined-panic scan, whose fixture is named the way rustc names our members.
#
# USAGE
#   gates/check_rust_rules_selftest.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$ROOT/gates/check_rust_rules.sh"
say()  { printf '\033[36m[selftest]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[selftest]\033[0m %s\n' "$*" >&2; }

for t in cc ar nm; do
    command -v "$t" >/dev/null 2>&1 || {
        warn "SKIPPED — no '$t' on PATH. Not a pass."
        exit 2
    }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
MUT=""

cases=0
failed=0
pass_case() { cases=$((cases+1)); say "OK   $*"; }
fail_case() { cases=$((cases+1)); failed=$((failed+1)); printf '\033[31m[selftest] FAIL %s\033[0m\n' "$*" >&2; }

# $1 gate to run, $2 archive, $3 description
expect_accept() {
    if "$1" --binary "$2" >"$WORK/out.txt" 2>&1; then
        pass_case "$3"
    else
        fail_case "$3 — the gate REFUSED a clean archive:"
        sed 's/^/         /' "$WORK/out.txt" >&2
    fi
}
# $1 gate, $2 archive, $3 description, $4 substring the refusal must contain
expect_refuse() {
    if "$1" --binary "$2" >"$WORK/out.txt" 2>&1; then
        fail_case "$3 — the gate ACCEPTED it:"
        sed 's/^/         /' "$WORK/out.txt" >&2
    elif grep -qF "$4" "$WORK/out.txt"; then
        pass_case "$3"
    else
        fail_case "$3 — refused, but not for the stated reason (wanted '$4'):"
        sed 's/^/         /' "$WORK/out.txt" >&2
    fi
}

obj() { # $1 = output name, $2... = C source lines on stdin
    printf '%s\n' "$(cat)" > "$WORK/src.c"
    cc -c -O2 -ffreestanding -o "$WORK/$1" "$WORK/src.c"
}

# ── fixtures ───────────────────────────────────────────────────────────────
# Enough symbols per object to clear the gate's five-symbol floor, which is
# itself one of the cases below.
obj a.o <<'EOF'
int tmst_a1(int x){return x+1;}
int tmst_a2(int x){return x+2;}
int tmst_a3(int x){return x+3;}
EOF
obj b.o <<'EOF'
int tmst_b1(int x){return x*2;}
int tmst_b2(int x){return x*3;}
int tmst_b3(int x){return x*4;}
EOF
# One member calls a helper that ANOTHER MEMBER defines. A linker resolves this
# inside the archive; the gate must too.
obj user.o <<'EOF'
int tmst_helper(int);
int tmst_use1(int x){return tmst_helper(x);}
int tmst_use2(int x){return tmst_helper(x)+1;}
EOF
obj helper.o <<'EOF'
int tmst_helper(int x){return x*7;}
int tmst_filler1(int x){return x-1;}
int tmst_filler2(int x){return x-2;}
EOF
# A reference NOTHING defines and no intrinsic covers. This is the case the
# whole check exists for, and it must still fail after the archive work.
obj outside.o <<'EOF'
int tmst_not_defined_anywhere(int);
int tmst_calls_out1(int x){return tmst_not_defined_anywhere(x);}
int tmst_calls_out2(int x){return tmst_not_defined_anywhere(x)+1;}
EOF
obj tiny.o <<'EOF'
int tmst_only_one(void){return 1;}
EOF
# A Rust panic entry point as a plain C identifier — every character in the v0
# mangled name is legal in one, so this needs no Rust toolchain to build. The
# MEMBER NAME is what matters: the defined-symbol scan is scoped to members
# belonging to workspace crates, so this is named the way rustc names ours.
obj panicdef_src.o <<'EOF'
int _ZN4core9panicking18panic_bounds_check17hdeadbeefcafef00dE(void){return 0;}
int tmst_p1(int x){return x+11;}
int tmst_p2(int x){return x+12;}
EOF
cp "$WORK/panicdef_src.o" "$WORK/tethermesh-0123456789abcdef.tethermesh.0-cgu.0.rcgu.o"

mk() { rm -f "$WORK/$1"; ( cd "$WORK" && ar rcs "$1" "${@:2}" ); }

mk clean.a a.o b.o
mk cross.a user.o helper.o
mk outside.a a.o outside.o
mk tiny.a tiny.o
mk panic.a a.o "tethermesh-0123456789abcdef.tethermesh.0-cgu.0.rcgu.o"

# A member nm cannot read. Fabricated from the four magic bytes rather than
# emitted by LLVM: the gate reads exactly those four, so this is the honest
# stimulus for the detector and needs no llvm-as.
printf 'BC\300\336padding-so-it-is-not-empty' > "$WORK/bitcode_member.o"
mk mixed.a a.o b.o bitcode_member.o

# ── mutants ────────────────────────────────────────────────────────────────
# Each removes ONE half of the archive handling. A mutant that still passes the
# clean archive would mean that half is doing nothing.
#
# A MUTANT RUNS FROM THE REAL gates/ DIRECTORY, and both alternatives were tried
# before this one, each producing a refusal that had nothing to do with the
# mutation:
#
#   * from /tmp, `cargo metadata` finds no workspace, so the gate refuses on the
#     missing crate list;
#   * from a tree of symlinks to the real one, the gate's source-level scan finds
#     no .rs files at all, because a glob does not traverse a symlinked
#     directory, so it refuses with "NOTHING TO CHECK".
#
# Both look like the mutation being caught while proving nothing about it. The
# gate resolves everything relative to its own location, so the only place a
# mutant behaves like the original is beside the original. Dot-prefixed because
# every glob in this tree is `gates/*.sh`, and removed by the trap below.
MUTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # the gates dir this script lives in
trap 'rm -rf "$WORK"; rm -f "$MUTDIR"/.tm-selftest-mutant-*.sh' EXIT

mutant() { # $1 = name, $2 = sed program
    local m="$MUTDIR/.tm-selftest-mutant-$1.sh"
    sed "$2" "$GATE" > "$m"
    chmod +x "$m"
    if cmp -s "$GATE" "$m"; then
        fail_case "mutant '$1' is IDENTICAL to the gate — its anchor no longer matches, so it tests nothing"
        return 1
    fi
    # A mutant must still agree with the original everywhere the mutation does
    # not reach. If it refuses the CLEAN archive, its verdict on the fixture
    # below would be unattributable.
    if ! "$m" --binary "$WORK/clean.a" >"$WORK/probe.txt" 2>&1; then
        case "$1" in
            no_dash_A) : ;;   # this one is SUPPOSED to fail on the clean archive
            *)
                fail_case "mutant '$1' refuses the clean archive, so its verdict means nothing:"
                sed 's/^/         /' "$WORK/probe.txt" >&2
                return 1 ;;
        esac
    fi
    MUT="$m"
    return 0
}

# ── the cases ──────────────────────────────────────────────────────────────
say "gate under test: $GATE"

expect_accept "$GATE" "$WORK/clean.a" \
    "a clean multi-member archive is accepted (member header lines are not symbols)"
expect_accept "$GATE" "$WORK/cross.a" \
    "a cross-member reference resolves inside the archive, as a linker would"
expect_refuse "$GATE" "$WORK/outside.a" \
    "a genuine outside reference is still refused" \
    "references machinery outside the crate"
expect_refuse "$GATE" "$WORK/tiny.a" \
    "an archive too bare to demonstrate anything is refused" \
    "REFUSING: only"
expect_refuse "$GATE" "$WORK/mixed.a" \
    "a bitcode member is refused rather than silently uninspected" \
    "is LLVM bitcode"
expect_refuse "$GATE" "$WORK/panic.a" \
    "a panic entry point DEFINED in one of our members is refused" \
    "DEFINES panic machinery"

# MUTATION 1 — drop -A from the undefined-symbol read. This is cause (1) of A18
# exactly: nm falls back to emitting bare "member.o:" header lines and the gate
# reads those filenames as symbol names.
if mutant no_dash_A 's|"\$NM" -A -u "\$LIBA"|"$NM" -u "$LIBA"|'; then
    expect_refuse "$MUT" "$WORK/clean.a" \
        "MUTANT (no -A): the clean archive goes red, so -A is what makes it pass" \
        "references machinery outside the crate"
fi

# MUTATION 2 — remove the linker-style resolution. This is cause (2): a member's
# reference to another member's symbol reads as an outside reference.
if mutant no_resolve 's|^    if \[ "\$is_archive" = 1 \] && \[ -n "\$undef" \]; then|    if false; then|'; then
    expect_refuse "$MUT" "$WORK/cross.a" \
        "MUTANT (no intra-archive resolution): the cross-member archive goes red" \
        "references machinery outside the crate"
fi

# MUTATION 3 — disable the defined-symbol panic scan. Without it the resolution
# added by MUTATION 2's target would hide panic machinery bundled INTO the
# archive, which is the hole the scan exists to close.
if mutant no_panic_scan 's|^    if \[ "\$is_archive" = 1 \]; then$|    if false; then|'; then
    expect_accept "$MUT" "$WORK/panic.a" \
        "MUTANT (no defined-panic scan): the panic archive passes, so the scan is what caught it"
fi

# ── verdict ────────────────────────────────────────────────────────────────
# An absent counter must not read as zero: if no case ran, this is not a pass.
if [ "$cases" -lt 9 ]; then
    printf '\033[31m[selftest] only %s case(s) ran; expected at least 9\033[0m\n' "$cases" >&2
    printf '        A harness that stopped running its own cases reports green\n' >&2
    printf '        while proving nothing, which is the failure it was written for.\n' >&2
    exit 1
fi

if [ "$failed" -gt 0 ]; then
    printf '\033[31m[selftest] %s of %s case(s) FAILED. REFUSING.\033[0m\n' "$failed" "$cases" >&2
    exit 1
fi
say "OK — $cases case(s), the gate accepts what it must and refuses what it must"
