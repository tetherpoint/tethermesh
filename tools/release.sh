#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 The tethermesh Authors
# SPDX-License-Identifier: Apache-2.0
#
# release.sh — build the shippable artifacts and name them so the name is true.
#
# tethermesh ships two things: the Rust crate, and a BINARY ARCHIVE WITH A C API
# so a consumer can link it from a C build with no Rust toolchain at all. This
# produces the second, for every target in targets.conf.
#
# WHY THE NAME CARRIES THE TARGET TRIPLE AND NOT A CHIP
# -----------------------------------------------------
# The obvious naming is `tethermesh_arm_rp2350_v1.0.0_<hash>`, and it would be
# WRONG in a way that costs someone a day.
#
# This is a static library, not firmware. What decides whether it links is the
# TARGET TRIPLE -- instruction set plus float ABI. thumbv8m.main-none-eabi and
# thumbv8m.main-none-eabihf are genuinely incompatible; mixing float ABIs is a
# link error. But the SAME soft-float archive links into any Cortex-M33 program:
# RP2350, nRF5340, STM32L5. This library touches no MCU peripheral at all --
# that is the whole point of the no-radio, no-HAL design.
#
# So a chip in the filename would claim specificity the bytes do not have.
# Someone on an nRF5340 would conclude no build exists for them, or would ask
# for one that would be byte-identical to the RP2350 file already published.
#
# The triple is unambiguous, it is what the consumer already passes to their own
# toolchain, and it is what actually decides compatibility. The MANIFEST carries
# the friendly mapping, so a reader searching for "RP2350" still finds it
# without the filename asserting something false.
#
# WHY THE COMMIT HASH, AND WHY -dirty MATTERS MORE THAN IT LOOKS
# ---------------------------------------------------------------
# The hash is what makes "rebuild it yourself and compare" checkable, which
# DISTRIBUTION.md calls the only thing that makes shipping a crypto binary
# defensible. A hash that does not describe the bytes destroys exactly that.
#
# So a dirty tree is marked in the FILENAME, not merely warned about. This bench
# already has the failure on record from the other direction: a firmware build
# reported `fw=79ddfa9` with no -dirty suffix because the hash was captured at
# CMake configure time and the tree had been edited since. The image genuinely
# contained the new code and its self-reported revision was wrong.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="$ROOT/targets.conf"
OUT="${1:-$ROOT/dist}"

say()  { printf '\033[36m[release]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[release] %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31m[release] %s\033[0m\n' "$*" >&2; exit 1; }

[ -f "$CONF" ] || die "no targets.conf"

VERSION="${TM_VERSION:-0.1.0}"
HASH="$(git -C "$ROOT" rev-parse --short=7 HEAD 2>/dev/null || echo nogit)"
if ! git -C "$ROOT" diff --quiet HEAD 2>/dev/null; then
    HASH="${HASH}-dirty"
    warn "TREE IS DIRTY — artifacts are tagged -dirty."
    warn "A -dirty blob is for testing. Its commit does not describe its"
    warn "contents, so nobody can reproduce it, which is the property the"
    warn "hash exists to provide. Do not publish one."
fi

# Friendly names for the manifest. NOT for the filename -- see the header.
# Deliberately a non-exhaustive list of PARTS KNOWN TO WORK, phrased so, because
# "compatible with" a chip nobody has tried is a claim this cannot support.
triple_note() {
    case "$1" in
      thumbv8m.main-none-eabi)     echo "Cortex-M33, soft float — e.g. RP2350, nRF5340, STM32L5" ;;
      thumbv8m.main-none-eabihf)   echo "Cortex-M33, hard float — same parts, hard-float ABI" ;;
      thumbv7em-none-eabihf)       echo "Cortex-M4F / M7 — e.g. nRF52840, STM32F4" ;;
      riscv32imc-unknown-none-elf) echo "RISC-V RV32IMC — e.g. ESP32-C3, ESP32-C6" ;;
      *)                           echo "no friendly name recorded for this triple" ;;
    esac
}

mkdir -p "$OUT"
MANIFEST="$OUT/MANIFEST.txt"
: > "$MANIFEST"
{
    echo "tethermesh release artifacts"
    echo "version   : v$VERSION"
    echo "commit    : $HASH"
    echo "built     : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "Each .a is the protocol library with a C API. Link it from a C build;"
    echo "no Rust toolchain is required. The header is the same for every target."
    echo
    # DISTRIBUTION.md requires this caveat in THREE places -- the release notes,
    # the archive, and the generated header -- and says why: "the person who
    # hits the problem is unlikely to have read this". It was in the header and
    # missing here until 2026-08-18, which is exactly the reader it was written
    # for: someone holding the artifact and not the repository.
    echo "THE PREBUILT LIBRARIES ARE A CONVENIENCE ONLY."
    echo "IF YOU ENCOUNTER ABI BOUNDARY ISSUES, REBUILD FROM SOURCE."
    echo
    echo "That is not a disclaimer of quality. Float ABI variants, toolchain"
    echo "versions, calling-convention flags and linker expectations differ"
    echo "between build environments in ways a published artifact cannot"
    echo "anticipate. Rebuilding resolves them definitively, and the source is"
    echo "the commit named above -- every archive here rebuilds bit-identically"
    echo "from it, which is what makes \"build your own and compare\" a real"
    echo "option rather than a slogan."
    echo
    echo "THE FILENAME CARRIES THE TARGET TRIPLE, NOT A CHIP, and that is"
    echo "deliberate: the triple is what decides whether the archive links. One"
    echo "soft-float Cortex-M33 archive serves every Cortex-M33 soft-float part,"
    echo "because this library touches no MCU peripheral."
    echo
} >> "$MANIFEST"

installed="$(rustup target list --installed 2>/dev/null || true)"
built=0
skipped=0
seen_triples=""

while read -r target crate ceiling measured note; do
    case "$target" in ''|'#'*) continue ;; esac
    [ "${crate:-}" = "tmffi" ] || continue      # the C-API archive is the artifact

    case " $seen_triples " in *" $target "*) continue ;; esac
    seen_triples="$seen_triples $target"

    if ! printf '%s\n' "$installed" | grep -qx "$target"; then
        warn "SKIPPED $target — toolchain not installed. Absent from this release, not silently missing."
        printf 'SKIPPED   %s (toolchain not installed)\n' "$target" >> "$MANIFEST"
        skipped=$((skipped+1))
        continue
    fi

    say "building $target"
    ( cd "$ROOT" && cargo build --release -p tmffi --target "$target" ) >/dev/null 2>&1 \
        || die "$target failed to build — a declared target that does not compile cannot be released"

    src="$ROOT/target/$target/release/libtmffi.a"
    [ -f "$src" ] || die "$target produced no archive"

    base="tethermesh_${target}_v${VERSION}_${HASH}"
    cp "$src" "$OUT/${base}.a"
    # ONE header for the whole release, not one per target. It is byte-identical
    # across triples, and emitting per-target copies would imply a per-target
    # header that does not exist -- inviting someone to hunt for the difference.
    HDR="tethermesh_v${VERSION}_${HASH}.h"
    cp "$ROOT/ffi/include/tethermesh.h" "$OUT/$HDR"

    sha=$(sha256sum "$OUT/${base}.a" | awk '{print $1}')
    sz=$(stat -c%s "$OUT/${base}.a")
    {
        printf '%s\n' "${base}.a"
        printf '  triple : %s\n' "$target"
        printf '  parts  : %s\n' "$(triple_note "$target")"
        printf '  size   : %s bytes\n' "$sz"
        printf '  sha256 : %s\n' "$sha"
        printf '  header : %s (shared by every target)\n' "$HDR"
        printf '\n'
    } >> "$MANIFEST"
    built=$((built+1))
done < "$CONF"

[ "$built" -gt 0 ] || die "nothing was built — a release with no artifacts is not a release"

say "$built artifact(s) in $OUT"
[ "$skipped" -gt 0 ] && warn "$skipped target(s) skipped; this release does not cover the whole declared set"
say "manifest: $MANIFEST"
case "$HASH" in
    *-dirty) warn "REMINDER: these are -dirty and must not be published." ;;
esac
