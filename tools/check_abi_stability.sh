#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The tetherpoint Authors
# SPDX-License-Identifier: Apache-2.0
#
# DISTRIBUTION.md: "header struct layouts are frozen within a major version, and
# any break takes a major bump." Shipping binaries means owning an ABI, and an
# ABI break fails at RUNTIME rather than at compile time -- in the field,
# confusingly. This is the check behind that promise.
#
# It was listed as pending for a real reason: "unchanged within a major version"
# needs a previous version on record, and there had been no release. v0.1.0 is
# that record. The baseline is the ABI SURFACE of the released header, not the
# header itself -- comments and prose change constantly and mean nothing to a
# linker.
#
# WHAT THIS CATCHES: a signature, struct layout or constant that moved while
# TM_ABI_VERSION stayed put. That is the silent case, and the one a consumer
# discovers as a wrong field offset in the field.
#
# WHAT IT DOES NOT: it cannot tell an intended break from an accident. A bumped
# version passes, and refreshing the baseline is then a deliberate act.
set -euo pipefail

cd "$(dirname "$0")/.."
BLUE=$'\033[36m'; RED=$'\033[31m'; YEL=$'\033[33m'; OFF=$'\033[0m'
say()  { echo "${BLUE}[abi]${OFF} $*"; }
warn() { echo "${YEL}[abi] $*${OFF}"; }
fail() { echo "${RED}[abi] $*${OFF}" >&2; }

HEADER=ffi/include/tethermesh.h
BASE=ffi/abi-baseline.txt

# The surface a linker and a struct layout actually depend on: declarations,
# typedefs and constants. Comments are stripped because prose is not ABI.
surface() {
    sed -e 's://.*::' "$1" \
      | awk 'BEGIN{c=0} {
            line=$0
            while (1) {
                if (c==0) { i=index(line,"/*"); if (i==0) break; out=substr(line,1,i-1); line=substr(line,i+2); c=1; printf "%s", out }
                else { j=index(line,"*/"); if (j==0) { line=""; break } line=substr(line,j+2); c=0 }
            }
            if (c==0) print line
        }' \
      | tr -s ' \t' ' ' | sed -e 's/^ //' -e 's/ $//' \
      | grep -vE '^$' \
      | grep -vE '^#(ifndef|define TETHERMESH_H|endif|include|ifdef|if |else)' \
      | grep -vE '^(extern "C" \{|\}|struct tm_[a-z_]+;)$'
}

cur_ver=$(grep -oE '^#define TM_ABI_VERSION [0-9]+' "$HEADER" | grep -oE '[0-9]+$')
base_ver=$(grep -oE '^# TM_ABI_VERSION: [0-9]+' "$BASE" 2>/dev/null | grep -oE '[0-9]+$' || true)
base_ver=${base_ver:-0}

if [ "${1:-}" = "--accept" ]; then
    {
        echo "# tethermesh C ABI baseline -- the surface a consumer links against."
        echo "#"
        echo "# Refreshed DELIBERATELY, never to make a build pass. If this file"
        echo "# changed without TM_ABI_VERSION moving, that is the defect the"
        echo "# check exists to catch, and the fix is the version bump."
        echo "# TM_ABI_VERSION: $cur_ver"
        surface "$HEADER"
    } > "$BASE"
    say "baseline written at ABI version $cur_ver ($(wc -l < "$BASE") lines)"
    exit 0
fi

if [ ! -f "$BASE" ]; then
    warn "no baseline at $BASE -- nothing to compare against."
    warn "Create one with: tools/check_abi_stability.sh --accept"
    exit 3
fi


tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
# '^# ' -- hash-SPACE -- so the metadata header is dropped and the #define
# constants, which ARE part of the surface, are kept. Stripping all '#' lines
# silently removed every status code from the comparison.
{ grep -vE '^#($| )' "$BASE" || true; } > "$tmp"

if diff -q <(surface "$HEADER") "$tmp" >/dev/null; then
    say "OK — ABI surface unchanged since the baseline (version $cur_ver)"
    exit 0
fi

if [ "$cur_ver" -gt "$base_ver" ]; then
    say "ABI surface changed and TM_ABI_VERSION moved $base_ver -> $cur_ver."
    say "That is a declared break. Refresh with: tools/check_abi_stability.sh --accept"
    exit 0
fi

fail "ABI SURFACE CHANGED WITH TM_ABI_VERSION STILL AT $cur_ver."
fail "An ABI break fails at runtime, in the field. Bump the version."
diff -u "$tmp" <(surface "$HEADER") | head -30 >&2
exit 1
