#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Matthew Klapman
# SPDX-License-Identifier: Apache-2.0
#
# check_reproducible.sh — build the artifact twice and prove the bytes match.
#
# docs/DISTRIBUTION.md: "Anyone can rebuild them bit-identically ... This matters
# more than usual here — a security-relevant binary for a cryptographic library,
# offered to an audience that reasonably prefers to build its own, is only
# acceptable if 'build your own and compare' is a real option rather than a
# slogan."
#
# It was a slogan until 2026-08-17. Nothing had ever built it twice.
#
# WHY THE SECOND BUILD USES A DIFFERENT SOURCE PATH
# --------------------------------------------------
# Building twice in place proves almost nothing: cargo caches, and even a clean
# rebuild in the same directory shares every path that could have been embedded.
# The failure this is actually looking for is a build that bakes in WHERE it was
# built -- an absolute path in a panic message, a debug section, a symbol -- so
# that a user rebuilding under their own home directory gets different bytes and
# cannot tell a benign difference from a backdoored one.
#
# So the second build happens from a COPY AT A DIFFERENT PATH, with its own
# target directory. That is the shape of what a third party actually does.
#
# WHAT IT STILL DOES NOT PROVE
# ----------------------------
# Same machine, same toolchain, same filesystem, same environment. A genuine
# reproducibility claim needs a different machine and a pinned toolchain, which
# is a release-pipeline property rather than a script's. This catches the
# embedded-path and build-ordering classes, which are the ones that bite first,
# and it is stated here so nobody reads a pass as more than that.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-thumbv8m.main-none-eabi}"

say()  { printf '\033[36m[repro]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[repro] %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31m[repro] %s\033[0m\n' "$*" >&2; exit 1; }

if ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET"; then
    warn "SKIPPED — $TARGET not installed. Not a pass."
    exit 0
fi

WORK="${TMPDIR:-/tmp}/tm-repro.$$"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/src" "$WORK/t1" "$WORK/t2"

say "build 1: from $ROOT"
( cd "$ROOT" && CARGO_TARGET_DIR="$WORK/t1" \
    cargo build --release -p tmffi --target "$TARGET" ) >/dev/null 2>&1 \
    || die "first build failed"

# A copy at a different path, without target/ or .git -- neither belongs in a
# source distribution, and carrying target/ would smuggle the first build's
# artifacts into the second.
say "copying the tree to a different path"
( cd "$ROOT" && tar -cf - --exclude=./target --exclude=./.git --exclude=./dist . ) \
    | ( cd "$WORK/src" && tar -xf - ) || die "could not copy the tree"

say "build 2: from $WORK/src"
( cd "$WORK/src" && CARGO_TARGET_DIR="$WORK/t2" \
    cargo build --release -p tmffi --target "$TARGET" ) >/dev/null 2>&1 \
    || die "second build failed from a copied tree — the build depends on its own location, which defeats 'rebuild it yourself'"

A="$WORK/t1/$TARGET/release/libtmffi.a"
B="$WORK/t2/$TARGET/release/libtmffi.a"
[ -f "$A" ] && [ -f "$B" ] || die "an archive is missing; nothing was compared"

ha=$(sha256sum "$A" | awk '{print $1}')
hb=$(sha256sum "$B" | awk '{print $1}')

if [ "$ha" != "$hb" ]; then
    printf '\033[31m[repro] VIOLATION: the two builds differ.\033[0m\n' >&2
    printf '        %s  (from %s)\n' "$ha" "$ROOT" >&2
    printf '        %s  (from a copy at another path)\n' "$hb" >&2
    printf '        "Build your own and compare" does not work, so a published\n' >&2
    printf '        binary cannot be checked against its source. Likely an\n' >&2
    printf '        absolute path embedded in the artifact -- try\n' >&2
    printf '        --remap-path-prefix, which docs/DISTRIBUTION.md already commits to.\n' >&2
    exit 1
fi

say "identical across source paths: $ha"
say "OK — $TARGET rebuilds bit-identically"
