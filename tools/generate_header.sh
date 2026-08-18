#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The tetherpoint Authors
# SPDX-License-Identifier: Apache-2.0
#
# T8 -- regenerate ffi/include/tethermesh.h from the crate.
#
# The header was hand-written until 2026-08-18 because cbindgen was not
# installed here. A hand-written header drifts SILENTLY: a field added on the
# Rust side shifts every offset after it, and C then reads garbage that looks
# like a protocol bug rather than a build problem. tm_check_layout() narrowed
# that and could not remove it -- equal sizes do not prove equal field order.
#
# Run this after ANY change to the ABI surface, and commit the result.
# tools/check_header.sh fails if the committed file and the crate disagree.
set -euo pipefail

cd "$(dirname "$0")/.."

# Locate it; do not assume it. `cargo install` puts binaries in ~/.cargo/bin and
# nothing here puts that on PATH -- the same shape as the arm-none-eabi-nm and
# bare-`cargo` problems, each of which presented as a broken checkout.
# cbindgen shells out to `cargo metadata`, so cargo has to be findable too --
# it fails with a bare "No such file or directory" that names neither tool.
if ! command -v cargo >/dev/null 2>&1 && [ -x "$HOME/.cargo/bin/cargo" ]; then
    PATH="$HOME/.cargo/bin:$PATH"
    export PATH
fi

CBINDGEN=""
for c in cbindgen "$HOME/.cargo/bin/cbindgen"; do
    if command -v "$c" >/dev/null 2>&1; then CBINDGEN="$c"; break; fi
done
if [ -z "$CBINDGEN" ]; then
    echo "cbindgen not found (looked on PATH and in ~/.cargo/bin)." >&2
    echo "Install it with:  cargo install cbindgen" >&2
    exit 2
fi

out=ffi/include/tethermesh.h
"$CBINDGEN" --config ffi/cbindgen.toml --crate tmffi ffi > "$out.new"

# Verified rather than trusted: cbindgen 0.29.4 ignored the in-source
# `cbindgen:opaque` annotation on these repr(C) structs and emitted their
# fields, including `PacketHistory<HISTORY>` -- not valid C. They are excluded
# in cbindgen.toml instead, and this is the check that the exclusion held.
for leak in 'PacketHistory' 'Outbox<' 'uintptr_t' 'TmKey' 'TmCtx'; do
    if grep -q "$leak" "$out.new"; then
        echo "REFUSING: generated header leaks '$leak' -- check ffi/cbindgen.toml" >&2
        rm -f "$out.new"
        exit 1
    fi
done

mv "$out.new" "$out"
echo "generated $out ($(wc -l < "$out") lines, \
$(grep -oE '\btm_[a-z0-9_]+\(' "$out" | sort -u | wc -l) symbols)"
