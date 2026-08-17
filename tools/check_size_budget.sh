#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 The tethermesh Authors
# SPDX-License-Identifier: Apache-2.0
#
# check_size_budget.sh — build every declared target and gate the code size.
#
# DISTRIBUTION.md promises "a declared target set" and "a size budget ... gated
# in CI [so] a regression fails the build, rather than being discovered on a
# device with 256 KB of flash". Both were prose until 2026-08-17. This reads
# targets.conf and enforces them.
#
# It does TWO things, and the first matters as much as the second:
#
#   1. Every declared target must BUILD. A target listed and never compiled is
#      a promise nobody checks -- and this repository has already been bitten by
#      exactly that: the crate was described as portable no_std while only one
#      target was ever installed, and cross-compiling for the first time found a
#      gate whose allowlist was ARM-centric.
#
#   2. Crate-object .text must stay under its ceiling. See targets.conf for why
#      that measure and not the archive or the linked image.
#
# Skips cleanly when a toolchain is missing rather than passing quietly: an
# uninstalled target is REPORTED, because "we could not check" and "it is fine"
# must never print the same way.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="$ROOT/targets.conf"

say()  { printf '\033[36m[size]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[size] %s\033[0m\n' "$*" >&2; }
fail() { printf '\033[31m[size] VIOLATION: %s\033[0m\n' "$*" >&2; bad=$((bad+1)); }
bad=0
skipped=0
checked=0

[ -f "$CONF" ] || { printf '\033[31m[size] no targets.conf\033[0m\n' >&2; exit 1; }

# A size tool that understands the object. GNU size is format-agnostic across
# ELF, so the ARM one reads a RISC-V object fine; llvm-size is the fallback.
SIZE=""
for c in arm-none-eabi-size llvm-size size; do
    command -v "$c" >/dev/null 2>&1 && { SIZE="$c"; break; }
done
[ -n "$SIZE" ] || { printf '\033[31m[size] no size tool on PATH\033[0m\n' >&2; exit 1; }

installed="$(rustup target list --installed 2>/dev/null || true)"

while read -r target crate ceiling measured note; do
    case "$target" in ''|'#'*) continue ;; esac
    [ -n "${crate:-}" ] && [ -n "${ceiling:-}" ] || continue

    if ! printf '%s\n' "$installed" | grep -qx "$target"; then
        warn "SKIPPED $target ($crate) — target not installed. Not a pass."
        skipped=$((skipped+1))
        continue
    fi

    d="$ROOT/target/sizecheck/$target/$crate"
    rm -rf "$d"; mkdir -p "$d"
    # LTO off: under LTO `--emit=obj` produces bitcode, which reads as an empty
    # symbol table and would measure nothing. Same trap check_rust_rules.sh
    # records being caught by.
    if ! ( cd "$ROOT" && CARGO_PROFILE_RELEASE_LTO=false \
            cargo rustc --release -p "$crate" --lib --target "$target" \
            -- --emit=obj -o "$d/o.o" ) >/dev/null 2>&1; then
        fail "$target ($crate) DID NOT BUILD. A declared target that does not compile is a promise this repository is not keeping."
        continue
    fi

    # A glob, not `ls | head -1`: rustc names the object with a hash suffix, and
    # this script defines its own helpers that a pipe into `head` would hit.
    obj=""
    for f in "$d"/*.o; do [ -f "$f" ] && obj="$f" && break; done
    if [ -z "$obj" ]; then
        fail "$target ($crate): no object emitted, so nothing was measured"
        continue
    fi

    text=$("$SIZE" "$obj" 2>/dev/null | tail -1 | awk '{print $1}')
    if ! printf '%s' "$text" | grep -qE '^[0-9]+$'; then
        fail "$target ($crate): could not read .text from $obj"
        continue
    fi

    checked=$((checked+1))
    if [ "$text" -gt "$ceiling" ]; then
        over=$((text - ceiling))
        fail "$target ($crate): .text=$text exceeds the $ceiling ceiling by $over bytes
              (was $measured when the ceiling was set).
              RAISING THE CEILING IS A DECISION, NOT A REPAIR. If the growth is
              worth it, say why in the commit message and move the number
              deliberately."
    else
        printf '\033[36m[size]\033[0m %-28s %-11s .text=%-7s ceiling=%-6s (was %s)\n' \
            "$target" "$crate" "$text" "$ceiling" "$measured"
    fi
done < "$CONF"

if [ "$checked" = 0 ]; then
    printf '\033[31m[size] NOTHING MEASURED — every declared target was skipped.\033[0m\n' >&2
    printf '        A check that measured nothing is not a pass.\n' >&2
    exit 1
fi

[ "$skipped" -gt 0 ] && warn "$skipped target(s) skipped for missing toolchains — coverage is incomplete"

if [ "$bad" -gt 0 ]; then
    printf '\033[31m[size] %d violation(s). REFUSING.\033[0m\n' "$bad" >&2
    exit 1
fi
say "OK — $checked artifact(s) within budget across the declared target set"
