#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Matthew Klapman
# SPDX-License-Identifier: Apache-2.0
#
# T8 -- does the committed C header still match the crate?
#
# Generating the header removes the drift hazard only if something checks that
# the COMMITTED file is what generation produces. Without this, the generator
# exists and the header still rots the first time someone edits the Rust and
# forgets to run it -- which is the same failure as before, with an extra script
# to make it look solved.
#
# Exit 0 pass, 1 drift, 3 cbindgen unavailable (reported, not a pass).
set -euo pipefail

cd "$(dirname "$0")/.."
BLUE=$'\033[36m'; RED=$'\033[31m'; OFF=$'\033[0m'
say()  { echo "${BLUE}[header]${OFF} $*"; }
fail() { echo "${RED}[header] $*${OFF}" >&2; }

if ! command -v cargo >/dev/null 2>&1 && [ -x "$HOME/.cargo/bin/cargo" ]; then
    PATH="$HOME/.cargo/bin:$PATH"; export PATH
fi
CBINDGEN=""
for c in cbindgen "$HOME/.cargo/bin/cbindgen"; do
    if command -v "$c" >/dev/null 2>&1; then CBINDGEN="$c"; break; fi
done
if [ -z "$CBINDGEN" ]; then
    say "cbindgen not installed — cannot check the header against the crate."
    say "This is NOT a pass. Install it (cargo install cbindgen) to gate T8."
    exit 3
fi

out=code/c-api/include/tethermesh.h
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
"$CBINDGEN" --config code/c-api/cbindgen.toml --crate tmffi code/c-api > "$tmp" 2>/dev/null

if ! diff -q "$out" "$tmp" >/dev/null; then
    fail "$out is not what the crate generates. Run gates/generate_header.sh."
    diff -u "$out" "$tmp" | head -40 >&2
    exit 1
fi

say "OK — the committed header is what the crate generates ($(grep -oE '\btm_[a-z0-9_]+\(' "$out" | sort -u | wc -l) symbols)"
