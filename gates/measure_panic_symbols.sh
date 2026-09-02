#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Matthew Klapman
# SPDX-License-Identifier: Apache-2.0
#
# measure_panic_symbols.sh — reproduce the dependency measurements in
# docs/CRYPTO-DEPENDENCY.md.
#
# WHY THIS SCRIPT EXISTS
# ----------------------
# docs/CRYPTO-DEPENDENCY.md decides which curve implementation this crate
# links, and it decides it by measurement rather than by argument. That is the
# right way to settle it — but a measurement nobody can re-run is a claim.
#
# The audit on 2026-08-16 found the table did not reproduce: the doc reported
# a baseline of 2038 total / 48 panic-related symbols, and re-measuring on the
# SAME toolchain it names (rustc 1.97.1, pinned in docs/DEPS.md) gave 2037 / 58.
# The totals matched closely enough to show the artifact was built the same
# way, so the gap was the symbol-matching pattern — which the document never
# recorded. Neither the harness source nor the grep pattern was written down,
# so the numbers could not be defended or refuted.
#
# This script IS the methodology. The document cites it instead of describing
# it in prose, so the figures stay checkable as toolchains move.
#
# WHAT IS MEASURED, AND WHY THIS SHAPE
# ------------------------------------
# Each candidate is built as a STATICLIB, no_std, panic = "abort", LTO OFF,
# against a baseline crate with no dependency at all. Every part of that
# matters:
#
#   - staticlib, not rlib: an rlib is mostly metadata. check_rust_rules.sh
#     records that pointing the check at one saw 4 symbols and proved nothing.
#   - LTO off: with LTO on, `--emit=obj` produces LLVM bitcode and nm reads an
#     empty symbol table. A check that inspects nothing passes.
#   - against a baseline: `core` contributes panic symbols regardless of what
#     is linked. Counting them absolutely makes every crate look bad, so only
#     the delta above an empty no_std crate says anything.
#
# Two counts are reported because they answer different questions:
#
#   raw    — lines in the archive symbol table matching the pattern. Sensitive
#            to the same symbol appearing in several object files.
#   unique — distinct symbol NAMES. This is the honest one for "does this
#            dependency introduce a panic path that was not already there".
#
# USAGE
#   gates/measure_panic_symbols.sh            measure all candidates
#   gates/measure_panic_symbols.sh --keep     leave the scratch crates on disk
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
say()  { printf '\033[36m[panic-measure]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[panic-measure] %s\033[0m\n' "$*" >&2; }

# The pattern, recorded because its absence is what made the original figures
# unreproducible. Panic entry points are NOT all spelled "panic": under v0
# mangling they surface as len_mismatch_fail, panic_bounds_check and friends,
# which is the same trap check_rust_rules.sh documents.
PANIC_RE='panic|unwrap|expect|assert|bounds_check|len_mismatch|slice_index|begin_unwind|slice_start_index|slice_end_index'

WORK="${TMPDIR:-/tmp}/tm-panic-measure.$$"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1
cleanup() { [ "$KEEP" -eq 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
mkdir -p "$WORK"

NM=$(command -v llvm-nm || command -v nm)
[ -n "$NM" ] || { warn "no nm found"; exit 1; }

say "toolchain: $(rustc --version)"
say "docs/DEPS.md pins rustc 1.97.1 — a different version here means the absolute"
say "numbers may move. The DELTA above baseline is the figure that matters."
echo

# $1 = crate name, $2 = dependency line (may be empty), $3 = body appended to lib.rs
mkcrate() {
    mkdir -p "$WORK/$1/src"
    cat > "$WORK/$1/Cargo.toml" <<EOF
[package]
name = "$1"
version = "0.0.0"
edition = "2021"
[lib]
crate-type = ["staticlib"]
[dependencies]
$2
[profile.release]
panic = "abort"
lto = false
codegen-units = 1
opt-level = "z"
EOF
    cat > "$WORK/$1/src/lib.rs" <<'EOF'
#![no_std]
#[panic_handler]
fn ph(_: &core::panic::PanicInfo) -> ! { loop {} }
EOF
    printf '%s\n' "$3" >> "$WORK/$1/src/lib.rs"
}

# A dependency that is never CALLED may be dropped entirely by the linker, so
# every candidate exports one extern "C" entry point that performs a real
# agreement. Measuring an unreferenced dependency would report zero and mean
# nothing.
mkcrate baseline "" ''

mkcrate dalek \
    'x25519-dalek = { version = "2", default-features = false, features = ["static_secrets"] }' \
'#[no_mangle]
pub extern "C" fn dh(sk: &[u8; 32], pk: &[u8; 32], out: &mut [u8; 32]) {
    let s = x25519_dalek::StaticSecret::from(*sk);
    let p = x25519_dalek::PublicKey::from(*pk);
    *out = *s.diffie_hellman(&p).as_bytes();
}'

mkcrate libcrux \
    'libcrux-curve25519 = { version = "0.0.8", default-features = false }' \
'#[no_mangle]
pub extern "C" fn dh(sk: &[u8; 32], pk: &[u8; 32], out: &mut [u8; 32]) -> bool {
    libcrux_curve25519::ecdh(out, pk, sk).is_ok()
}'

# fiat-crypto is measured through THIS crate rather than a scratch one: it is
# what actually ships, and the field arithmetic is only exercised via our
# ladder. A scratch crate calling fiat directly would measure a different
# thing from the artifact the promise is about.

base_raw=0; base_uniq=0
printf '%-26s %8s %10s %8s %8s\n' "staticlib" "total" "panic(raw)" "uniq" "delta"
printf '%-26s %8s %10s %8s %8s\n' "--------------------------" "--------" "----------" "--------" "--------"

for c in baseline dalek libcrux; do
    if ! (cd "$WORK/$c" && cargo build --release --offline >"$WORK/$c.log" 2>&1); then
        # A build failure is a RESULT here, not an error. Record it rather than
        # aborting the run.
        #
        # READ THE LABEL CAREFULLY -- IT COST A MISDIAGNOSIS ON 2026-08-18.
        # This row builds the WHOLE `libcrux-curve25519` crate. The allocator it
        # requires comes from the crate around the curve code, NOT from the curve
        # code. Verified by building it both ways:
        #
        #   curve path only (fstar + lowstar + bignum25519_51 + curve25519_51)
        #       builds no_std for thumbv8m with NO allocator, zero allocator
        #       symbols, and +3 panic symbols (panic_bounds_check, panic_fmt,
        #       slice_index_fail).
        #   the libcrux-hacl-rs CRATE, calling only that same curve path
        #       FAILS with "no global memory allocator", because lib.rs declares
        #       `pub mod prelude { extern crate alloc; }`.
        #
        # So THE ALLOCATOR REQUIREMENT IS A CRATE-LEVEL PROPERTY, NOT A
        # CALL-GRAPH ONE, and "we only call the allocation-free part" does not
        # help. Saying "libcrux requires an allocator" unqualified reads as a
        # statement about the curve code and is wrong about it; the honest
        # summary is that the curve code is disqualified by the PANIC rule and
        # the crate additionally by the allocation rule.
        # docs/UPSTREAM-HACL-PANIC-FREEDOM.md carries the full analysis.
        if grep -q 'no global memory allocator' "$WORK/$c.log"; then
            printf '%-26s %8s %10s %8s %8s   <- WHOLE CRATE NEEDS AN ALLOCATOR (its prelude, not its curve code)\n' "$c" "n/a" "n/a" "n/a" "n/a"
            continue
        fi
        warn "$c failed to build for a reason other than the allocator:"
        tail -5 "$WORK/$c.log" >&2
        continue
    fi

    a="$WORK/$c/target/release/lib$c.a"
    [ -f "$a" ] || { warn "$c built but produced no archive"; continue; }

    total=$("$NM" "$a" 2>/dev/null | grep -c . || true)
    raw=$("$NM" "$a" 2>/dev/null | grep -icE "$PANIC_RE" || true)
    uniq=$("$NM" "$a" 2>/dev/null | grep -iE "$PANIC_RE" | awk '{print $NF}' | sort -u | grep -c . || true)

    if [ "$c" = "baseline" ]; then
        base_raw=$raw; base_uniq=$uniq
        printf '%-26s %8s %10s %8s %8s\n' "$c" "$total" "$raw" "$uniq" "—"
    else
        printf '%-26s %8s %10s %8s %+8s\n' "$c" "$total" "$raw" "$uniq" "$((uniq - base_uniq))"
        added=$(comm -13 \
            <("$NM" "$WORK/baseline/target/release/libbaseline.a" 2>/dev/null | grep -iE "$PANIC_RE" | awk '{print $NF}' | sort -u) \
            <("$NM" "$a" 2>/dev/null | grep -iE "$PANIC_RE" | awk '{print $NF}' | sort -u))
        if [ -n "$added" ]; then
            printf '%s\n' "$added" | sed 's/^/      + /'
        fi
    fi
done

echo
say "the figure that actually governs: undefined references in the shipped object"
say "  that is gates/check_rust_rules.sh --binary, run by gates/check_all.sh."
say "  A staticlib archive bundles compiler_builtins and is too noisy to read"
say "  that way, which is why the artifact check inspects the crate object."
