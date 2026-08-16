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
# EVERY crate with a library target, not just the default one.
#
# This built a single `--lib` until 2026-08-16. With the extension suite planned
# as one crate per bundle, a second crate's panic paths would simply never have
# been inspected -- and the panic-free artifact guarantee is the claim
# DISTRIBUTION.md leads with. Enumerated from cargo metadata rather than
# guessed, so a crate added later is covered without anyone remembering to.
if command -v cargo >/dev/null 2>&1 && [ -f "$ROOT/Cargo.toml" ]; then
    pkgs=$( cd "$ROOT" && cargo metadata --no-deps --format-version 1 2>/dev/null \
        | python3 -c 'import json,sys
try:
    m=json.load(sys.stdin)
except Exception:
    sys.exit(0)
for p in m.get("packages", []):
    # third_party/ is pinned upstream source. check_rust_rules.sh excludes it
    # from OUR source rules -- "we did not write it and may not edit it without
    # voiding its provenance" -- so holding it to our artifact rule separately
    # would be inconsistent, and would attribute a failure to the wrong place.
    # What it does to the linked object is still measured, because it is linked
    # INTO ours and inspected there.
    if "/third_party/" in p.get("manifest_path", ""):
        continue
    if any(t.get("crate_types") and set(t["crate_types"]) & {"lib","rlib","staticlib","cdylib"}
           for t in p.get("targets", [])):
        print(p["name"])' )
    [ -n "$pkgs" ] || pkgs="$(basename "$ROOT")"
    say "library crates to inspect: $(echo "$pkgs" | tr '\n' ' ')"

    rc_obj=0
    while IFS= read -r pkg; do
        [ -n "$pkg" ] || continue
        objdir="$ROOT/target/objcheck/$pkg"
        rm -rf "$objdir"; mkdir -p "$objdir"
        if ( cd "$ROOT" && CARGO_PROFILE_RELEASE_LTO=false \
                cargo rustc --release -p "$pkg" --lib -- --emit=obj -o "$objdir/tm.o" ) >/dev/null 2>&1; then
        # A glob, not `ls | head -1`: this script defines its own `head`
        # function for section headings, so piping into head calls THAT,
        # discards stdin and kills the pipeline with SIGPIPE under pipefail.
            obj=""
            for f in "$objdir"/*.o; do
                [ -f "$f" ] || continue
                obj="$f"; break
            done
            if [ -n "$obj" ]; then
                printf '\033[36m[check]\033[0m %s\n' "inspecting $pkg"
                "$ROOT/tools/check_rust_rules.sh" --binary "$obj" || rc_obj=1
            else
                printf '\033[31m[check] %s: object emit produced nothing\033[0m\n' "$pkg" >&2
                rc_obj=1
            fi
        else
            printf '\033[31m[check] %s: could not build an object to inspect\033[0m\n' "$pkg" >&2
            rc_obj=1
        fi
    done <<< "$pkgs"
    [ "$rc_obj" = 0 ] || rc=1
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
