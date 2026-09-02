#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Matthew Klapman
# SPDX-License-Identifier: Apache-2.0
#
# check_docs.sh — fail the build when documentation stops describing the code.
#
# WHY THIS IS A GATE AND NOT A REVIEW HABIT
# -----------------------------------------
# The 2026-08-16 audit found three documentation defects that had survived the
# span of work that introduced them, in a project where documentation is load
# bearing. All three were the same shape: a document asserting something that
# had been true when written and was not true any more.
#
#   - docs/CRYPTO-DEPENDENCY.md argued at length that fiat-crypto was a
#     crates.io dependency "rather than a submodule". The very next commit made
#     it a submodule and never touched the file.
#   - Cargo.toml and a test doc comment both carried a "58 panic symbols"
#     figure that docs/CRYPTO-DEPENDENCY.md had already retracted as wrong.
#   - The panic-symbol table could not be reproduced on the toolchain it named,
#     because neither the harness nor the matching pattern was recorded.
#
# README.md's own position is that a doc which drifted from the code is worse
# than no doc, because it will be trusted. That is exactly right, and none of
# the three was caught by review.
#
# BE HONEST ABOUT WHAT THIS GATE WOULD AND WOULD NOT HAVE CAUGHT
# --------------------------------------------------------------
# It would NOT have caught the first two. Both are prose making a false
# assertion -- a paragraph arguing for crates.io, a number in a comment -- and
# no script can tell a true paragraph from a false one. Claiming otherwise
# here would repeat the exact failure this file exists to catch.
#
# What it catches is the mechanical subset: a document naming something the
# tree either has or does not. Test names, proof harnesses, pinned commits,
# cited tooling. That subset matters because it rots WITHOUT ANYONE EDITING
# THE DOCUMENT -- rename a test and a doc three directories away silently
# becomes false. Prose at least requires someone to have written it.
#
# The third defect is the one this addresses head-on, via check 4: a measurement
# is reproducible only while the harness it cites still exists.
#
# So this narrows the gap rather than closing it. Prose drift is still caught
# by reading, and the audit that found these is still the mechanism.
#
# USAGE
#   gates/check_docs.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
say()  { printf '\033[36m[docs]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[docs] VIOLATION: %s\033[0m\n' "$*" >&2; violations=$((violations+1)); }
violations=0
checked=0

cd "$ROOT"

# ── 1. a document naming a test must name one that exists ──────────────────
# docs/HARDWARE-BACKENDS.md cites a test by path and asserts it has been seen
# red. A renamed or deleted test would leave the claim standing and false.
while IFS= read -r ref; do
    [ -n "$ref" ] || continue
    file="${ref%%::*}"
    name="${ref##*::}"
    checked=$((checked+1))
    if [ ! -f "$file" ]; then
        fail "a document cites tests in '$file', which does not exist."
        continue
    fi
    grep -qE "fn +${name}\b" "$file" \
        || fail "a document cites '$ref', but no 'fn $name' exists in that file.
              A named test is a claim that something is verified. If it was
              renamed, update the prose; if it was deleted, the claim goes too."
done < <(grep -rhoE '[a-zA-Z0-9_/]+\.rs::[a-z0-9_]+' --include='*.md' . 2>/dev/null \
         | grep -v '^code/third_party/' | sort -u)

# ── 2. the proof table must match the proofs, IN BOTH DIRECTIONS ───────────
# A missing row is as bad as a stale one: docs/FORMAL-VERIFICATION.md is the
# document that says what "verified" means in this project, so a harness it
# does not list is assurance nobody knows exists, and a row with no harness is
# assurance that is not actually running.
# EVERY file carrying harnesses, not one hardcoded path. This named
# code/protocol/proofs.rs alone until 2026-08-16; with the extension suite
# planned as one crate per bundle, a second crate's proofs would have gone
# undocumented and unnoticed. Found by content rather than by filename, so a
# harness in an unexpected place is still covered.
FV="docs/FORMAL-VERIFICATION.md"
proof_files=$(grep -rl 'kani::proof' --include='*.rs' . 2>/dev/null \
              | grep -v '^./target' | grep -v '^./third_party' | sort)
if [ -n "$proof_files" ] && [ -f "$FV" ]; then
    # Harness = the fn immediately following a #[kani::proof] attribute.
    # shellcheck disable=SC2086
    actual=$(awk '/#\[kani::proof\]/{p=1;next} p&&/^ *fn /{gsub(/^ *fn +/,"");sub(/\(.*/,"");print;p=0}' $proof_files | sort -u)
    # Table rows name the harness in the first backticked cell.
    documented=$(grep -oE '^\| *`[a-z0-9_]+` *\|' "$FV" | tr -d '|` ' | sort -u)

    while IFS= read -r h; do
        [ -n "$h" ] || continue
        checked=$((checked+1))
        printf '%s\n' "$documented" | grep -qx "$h" \
            || fail "harness '$h' has no row in $FV.
              A proof nobody documented is assurance nobody knows they have."
    done <<< "$actual"

    while IFS= read -r h; do
        [ -n "$h" ] || continue
        checked=$((checked+1))
        printf '%s\n' "$actual" | grep -qx "$h" \
            || fail "$FV documents harness '$h', which exists in no proof file.
              The document claims a property is machine-checked and it is not."
    done <<< "$documented"
fi

# ── 3. pinned commits in docs/DEPS.md must be the commits actually checked out ──
# docs/DEPS.md is the provenance record: "a compatibility result that cannot name
# the version it was obtained against is not a result." A submodule bumped
# without updating it silently reattributes every measurement in the tree.
if [ -f docs/DEPS.md ] && [ -f .gitmodules ]; then
    while read -r sha path _; do
        [ -n "$path" ] || continue
        sha="${sha#[-+U]}"          # strip submodule status markers
        checked=$((checked+1))
        if ! grep -q "$sha" docs/DEPS.md; then
            short="${sha:0:12}"
            fail "submodule '$path' is at $sha, which docs/DEPS.md does not record.
              docs/DEPS.md is the provenance record for every measurement in this
              tree. Bumping a pin without it reattributes results silently.
              (looked for the full SHA; it starts $short)"
        fi
    done < <(git submodule status 2>/dev/null || true)
fi

# ── 4. tooling a document tells you to run must exist ──────────────────────
# docs/CRYPTO-DEPENDENCY.md now cites a script instead of describing its
# method in prose, precisely so the figures stay reproducible. That only
# works while the script is there.
while IFS= read -r t; do
    [ -n "$t" ] || continue
    checked=$((checked+1))
    [ -f "$t" ] || fail "a document tells the reader to run '$t', which does not exist."
    [ -f "$t" ] && [ ! -x "$t" ] && fail "'$t' is cited as runnable but is not executable."
done < <(grep -rhoE '\bgates/[a-z0-9_]+\.sh' --include='*.md' . 2>/dev/null | sort -u)

if [ "$checked" -eq 0 ]; then
    # Same posture as check_rust_rules.sh: a check that inspected nothing must
    # not report success, or it is indistinguishable from a real pass in a log.
    printf '\033[33m[docs] NOTHING TO CHECK — no cross-references found\033[0m\n' >&2
    printf '        That is almost certainly a bug in this script rather than a\n' >&2
    printf '        property of the tree, so it is reported non-zero.\n' >&2
    exit 3
fi

if [ "$violations" -gt 0 ]; then
    printf '\033[31m[docs] %d violation(s). REFUSING.\033[0m\n' "$violations" >&2
    printf '        A document that drifted from the code is worse than no\n' >&2
    printf '        document, because it will be trusted.\n' >&2
    exit 1
fi
say "OK — $checked cross-reference(s) checked, documentation matches the tree"
