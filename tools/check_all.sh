#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 The tethermesh Authors
# SPDX-License-Identifier: Apache-2.0
#
# check_all.sh — the one entry point for this repository's guard rails.
#
# Every rule this project commits to in README.md, SCOPE.md and
# DISTRIBUTION.md is enforced by something here. A rule stated in a document
# and enforced by nobody decays silently, and usually in the direction of
# whoever is in a hurry.
#
# NO SILENT NO-OPS. A check with nothing to check yet reports that and returns
# non-zero. A pass that never ran is worse than a failure, because it is
# indistinguishable from a real one in a log.
#
# USAGE
#   tools/check_all.sh                run every applicable check
#   tools/check_all.sh --pending      list checks not yet implementable, and why
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
say()  { printf '\033[36m[check]\033[0m %s\n' "$*"; }
head() { printf '\n\033[1m── %s\033[0m\n' "$*"; }

if [ "${1:-}" = "--pending" ]; then
    cat <<'EOF'
Checks that exist as requirements but cannot run until there is something to
check. Each is listed here so the gap is visible rather than forgotten.

  size budget           needs a built staticlib and an agreed ceiling.
                        A protocol codec that lands at 100 KB is unusable on
                        the targets it is meant for; the ceiling is set once
                        the first real build exists, then regressions fail.

  reproducible build    needs a release pipeline. Build twice in clean
                        environments, compare hashes. This is what makes
                        "rebuild it yourself and compare" a real option rather
                        than a slogan, and it is the only thing that makes
                        shipping a crypto binary defensible.

  ABI stability         needs a released header. tm_abi_version() present,
                        struct layouts unchanged within a major version.
                        An ABI break fails at runtime, in the field.

  artifact test         needs release archives. Build a minimal C consumer
                        against each released .a for each target. Otherwise
                        the binaries are validated only in a form nobody uses.

  conformance vectors   needs the codec and captured frames. Decode real
                        traffic, re-encode, compare bit-for-bit.
EOF
    exit 0
fi

rc=0

head "licence declaration (SPDX)"
# Added with the 2026-08-16 licence decision. One licence today, which is
# exactly when this looks unnecessary and exactly when it is cheapest: the
# failure it prevents is a file arriving later with no header and inheriting
# nothing.
"$ROOT/tools/check_spdx.sh" || {
    s=$?
    [ "$s" = 3 ] || rc=1
}

head "clean-room (GPL boundary)"
"$ROOT/tools/check_cleanroom.sh" || rc=1

head "documentation matches the code"
# Added after the 2026-08-16 audit, which found three documents asserting
# things that had stopped being true -- including one arguing at length for a
# dependency arrangement the next commit reversed. Cross-references rot without
# anyone editing the document, so they are checked rather than reviewed.
"$ROOT/tools/check_docs.sh" || {
    s=$?
    [ "$s" = 3 ] || rc=1
}

head "crate rules (panic-free, no alloc, no global state)"
"$ROOT/tools/check_rust_rules.sh" || {
    s=$?
    # 3 means "nothing to check yet" — expected before the crate exists, and
    # reported rather than hidden. It is not a pass and not a failure.
    [ "$s" = 3 ] || rc=1
}

head "panic-free artifact (no path can fail on hostile input)"
# Built here rather than left to a --pending note, because this is the claim
# DISTRIBUTION.md leads with and it went unverified for as long as it was
# somebody's job to remember. LTO must be off or the emitted artifact is
# bitcode, which reads as an empty symbol table and passes without inspecting
# anything — see the note in check_rust_rules.sh.
if command -v cargo >/dev/null 2>&1 && [ -f "$ROOT/Cargo.toml" ]; then
    objdir="$ROOT/target/objcheck"
    rm -rf "$objdir"; mkdir -p "$objdir"
    if ( cd "$ROOT" && CARGO_PROFILE_RELEASE_LTO=false \
            cargo rustc --release --lib -- --emit=obj -o "$objdir/tm.o" ) >/dev/null 2>&1; then
        # A glob, not `ls | head -1`: this script defines its own `head`
        # function for section headings, so piping into head calls THAT,
        # discards stdin and kills the pipeline with SIGPIPE under pipefail.
        obj=""
        for f in "$objdir"/*.o; do
            [ -f "$f" ] || continue
            obj="$f"; break
        done
        if [ -n "$obj" ]; then
            "$ROOT/tools/check_rust_rules.sh" --binary "$obj" || rc=1
        else
            printf '\033[31m[check] object emit produced nothing\033[0m\n' >&2; rc=1
        fi
    else
        printf '\033[31m[check] could not build an object to inspect\033[0m\n' >&2; rc=1
    fi
else
    printf '\033[33m[check] cargo not available — panic-free artifact NOT verified\033[0m\n' >&2
fi

head "summary"
if [ "$rc" = 0 ]; then
    say "all applicable checks passed"
    say "run 'tools/check_all.sh --pending' for checks awaiting an artifact"
else
    printf '\033[31m[check] FAILED\033[0m\n' >&2
fi
exit "$rc"
