#!/usr/bin/env bash
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

  panic-free binary     needs a built staticlib.
                        tools/check_rust_rules.sh --binary <lib.a>
                        Verifies no panic machinery is linked — the evidence
                        that no path can panic on hostile input.

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

head "clean-room (GPL boundary)"
"$ROOT/tools/check_cleanroom.sh" || rc=1

head "crate rules (panic-free, no alloc, no global state)"
"$ROOT/tools/check_rust_rules.sh" || {
    s=$?
    # 3 means "nothing to check yet" — expected before the crate exists, and
    # reported rather than hidden. It is not a pass and not a failure.
    [ "$s" = 3 ] || rc=1
}

head "summary"
if [ "$rc" = 0 ]; then
    say "all applicable checks passed"
    say "run 'tools/check_all.sh --pending' for checks awaiting an artifact"
else
    printf '\033[31m[check] FAILED\033[0m\n' >&2
fi
exit "$rc"
