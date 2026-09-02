#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Matthew Klapman
# SPDX-License-Identifier: Apache-2.0
#
# check_scope.sh — fail the build if a consuming product's name enters the tree.
#
# WHY THIS IS A GATE AND NOT A REVIEW HABIT
# -----------------------------------------
# docs/SCOPE.md is the only rule here whose cost is UNRECOVERABLE. It says so itself:
# this repository is open, everything committed will be read by people outside
# the project including competitors, and "a repository that has been cloned once
# cannot be un-cloned." Deleting the file in a later commit does not help --
# git history is permanent.
#
# Every other guard rail catches something fixable. A panic path can be removed,
# a stale cross-reference corrected, an ABI break reverted. Disclosure cannot be
# undone, so of all the checks here this is the one that most needs to run
# BEFORE the commit rather than after it.
#
# And docs/SCOPE.md names its own failure mode exactly:
#
#   "Anything describing a consuming product's architecture, security design,
#    key management, roadmap, or implementation status. This is the category
#    most likely to arrive by ACCIDENT, because it usually arrives inside
#    otherwise reasonable prose -- a rationale paragraph, a comparison table,
#    a commit message explaining why."
#
# That is how it actually happened on 2026-08-20. A wire-reference entry about
# the LORA_24 channel -- a legitimate on-air fact, correctly placed -- explained
# WHY the measurement was wanted, and in doing so named a consuming product's
# driver repository and the placeholder constant sitting in its header. The fact
# was in scope. The rationale around it was not. Nothing flagged it; it was
# caught by a passing question, which is not a control.
#
# WHAT THIS FORBIDS, AND WHY THERE IS NO EXEMPTION LIST
# ----------------------------------------------------
# Every name below is at ZERO occurrences in the tree as of 2026-08-20. That is
# deliberate and it is what makes this gate honest: it starts green on its own
# terms rather than by carving out the places it would otherwise fire. An
# allowlist is the mechanism by which a gate like this rots -- each exemption is
# individually reasonable and the set is eventually meaningless.
#
# So if one of these ever legitimately needs naming, that is a conversation and
# a deliberate edit to this list, not a quiet `grep -v`.
#
# WHAT THIS DELIBERATELY DOES NOT FORBID
# --------------------------------------
#   - `tetherpoint` alone: it is the copyright holder, in every SPDX header.
#     Only `tetherpoint-ncm`, a specific consuming product, is forbidden.
#   - `heltec`: docs/SCOPE.md's instrument carve-out is explicit -- tests/instrument/ holds
#     the receiver the wire reference was measured with, and it is EVIDENCE for
#     the clean-room claim. Measurement provenance is in scope.
#   - silicon part numbers such as `rp2350`: docs/DISTRIBUTION.md promises a declared
#     target set, and docs/HARDWARE-BACKENDS.md surveys crypto accelerators.
#     Naming a chip is not naming a product's architecture.
#
# The distinction throughout is docs/SCOPE.md's own: a fact about the protocol or the
# silicon may be stated; a consuming system's structure may not.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

say()  { printf '\033[36m[scope]\033[0m %s\n' "$*"; }
bad()  { printf '\033[31m[scope] %s\033[0m\n' "$*" >&2; }

# name|why it must not appear
FORBIDDEN=(
  'a consuming product|a consuming product (integration firmware)'
  'tetherpoint-ncm|a consuming product (USB-NCM + OTA)'
  'a sibling mesh layer|a sibling mesh layer in a consuming product'
  'a sibling PHY/MAC stack|a sibling PHY/MAC stack in a consuming product'
  'a companion radio driver|a radio driver repository; no driver detail belongs here'
  'that radio family|the same radio family, under its family name'
  'meshcore|a different mesh protocol carried by a consuming product'
  'tetherbot|a consuming product'
)

# This script names every forbidden string in the list above, so it would match
# itself. Excluding it is not an exemption -- it is the only file whose job is
# to hold these words.
PATHSPEC=(':(exclude)gates/check_scope.sh')

rc=0
hits=0
for entry in "${FORBIDDEN[@]}"; do
    name="${entry%%|*}"
    why="${entry#*|}"
    if out=$(git grep -Iin -- "$name" "${PATHSPEC[@]}" 2>/dev/null) && [ -n "$out" ]; then
        bad "FORBIDDEN: '$name' -- $why"
        printf '%s\n' "$out" | sed 's/^/         /' >&2
        hits=$((hits + 1))
        rc=1
    fi
done

scanned=$(git ls-files -- "${PATHSPEC[@]}" | wc -l)

if [ "$rc" = 0 ]; then
    say "OK — $scanned file(s) scanned, no consuming-product names"
else
    bad "$hits forbidden name(s) present. docs/SCOPE.md: this repository is OPEN and"
    bad "git history is permanent. Remove it BEFORE committing, not after."
fi
exit "$rc"
