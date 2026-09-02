#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Matthew Klapman
# SPDX-License-Identifier: Apache-2.0
#
# check_spdx.sh — every file must say what licence it is under.
#
# WHY THIS IS A GATE
# ------------------
# The licence decision (2026-08-16, docs/LICENSING-OPTIONS.md) is Apache-2.0
# for code and specification alike. That is a single licence today, which is
# exactly when a gate like this looks unnecessary and exactly when it is
# cheapest to add.
#
# The failure it prevents is not "someone picks the wrong licence". It is
# DRIFT: a file added six months from now with no header, inheriting nothing.
# For a repository whose entire value proposition is that it is auditable and
# permissively licensable, a file whose provenance is ambiguous is a real
# defect -- and the cost lands on an adopter's legal review, which is the one
# place this project cannot afford friction.
#
# docs/LICENSING-OPTIONS.md put it plainly while the mixed-licence option was
# still open: "Mixed-licence repos need unambiguous demarcation... Get that
# wrong and you have created confusion rather than removed it." Choosing one
# licence removes the demarcation problem; it does not remove the drift
# problem. This does.
#
# It is also what makes a SECOND licence safe to introduce later. Adding
# CC-BY-4.0 or a vendored third-party file becomes a deliberate act that must
# pass here, rather than something that quietly happens.
#
# TWO MECHANISMS, BOTH ACCEPTED
# -----------------------------
#   1. An inline `SPDX-License-Identifier:` tag in the file's own text. This is
#      preferred, because the file remains self-describing when it is copied
#      out of the repository -- which is precisely what a permissive licence
#      invites people to do.
#   2. Coverage by a REUSE.toml annotation, for files that CANNOT carry a
#      comment: JSON has no comment syntax, Cargo.lock is generated, .gitkeep
#      files are empty.
#
# Anything covered by neither is a violation.
#
# WHAT IS EXEMPT, AND WHY EACH ONE
# --------------------------------
#   LICENSE, NOTICE    the licence texts themselves. A licence does not need a
#                      licence header, and Apache-2.0's text must stay verbatim.
#   code/third_party/       pinned upstream source under its own terms. Stamping our
#                      header onto someone else's file would be a false claim
#                      about its provenance -- the opposite of what this checks.
#                      Their licences are recorded in docs/DEPS.md and NOTICE.
#
# USAGE
#   gates/check_spdx.sh            scan tracked files
#   gates/check_spdx.sh --staged   scan only staged files (pre-commit)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
say()  { printf '\033[36m[spdx]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[spdx] VIOLATION: %s\033[0m\n' "$*" >&2; violations=$((violations+1)); }
violations=0
inline=0
bulk=0

EXPECTED_LICENCE="Apache-2.0"
REUSE="$ROOT/REUSE.toml"

MODE="${1:-full}"
if [ "$MODE" = "--staged" ]; then
    files=$(git -C "$ROOT" diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)
else
    files=$(git -C "$ROOT" ls-files 2>/dev/null || true)
fi
[ -n "$files" ] || { say "no files to scan"; exit 0; }

# Does REUSE.toml cover this path? Globs there are shell-style, so they are
# matched with `case` rather than reimplemented.
covered_by_reuse() {
    local f="$1" pat
    [ -f "$REUSE" ] || return 1
    while IFS= read -r pat; do
        [ -n "$pat" ] || continue
        # `**.json` and `**/.gitkeep` are REUSE spelling; bash globs want `*`.
        local shell_pat="${pat//\*\*/\*}"
        # shellcheck disable=SC2254
        case "$f" in $shell_pat) return 0 ;; esac
    done < <(grep -oP '(?<=^path = ")[^"]+' "$REUSE" 2>/dev/null || \
             sed -n 's/^path = "\([^"]*\)".*/\1/p' "$REUSE")
    return 1
}

while IFS= read -r f; do
    [ -n "$f" ] || continue
    p="$ROOT/$f"
    [ -f "$p" ] || continue

    case "$f" in
        LICENSE|NOTICE) continue ;;
        code/third_party/*)  continue ;;
    esac

    # Only the HEADER is authoritative. Reading the whole file would pick up
    # gates/check_cleanroom.sh's quoted `SPDX-License-Identifier: *GPL` pattern,
    # which is a forbidden-string it enforces rather than a declaration -- the
    # same self-reference that file already exempts itself from elsewhere.
    if head -20 "$p" | grep -q 'SPDX-License-Identifier' 2>/dev/null; then
        got=$(head -20 "$p" | grep -m1 -o 'SPDX-License-Identifier:[[:space:]]*[A-Za-z0-9.+-]*' \
              | sed 's/.*:[[:space:]]*//')
        if [ "$got" != "$EXPECTED_LICENCE" ]; then
            fail "$f declares '$got', but this repository is $EXPECTED_LICENCE.
              A second licence is a deliberate decision, not an accident -- record
              it in docs/LICENSING-OPTIONS.md and NOTICE before adding it here."
        fi
        inline=$((inline+1))
        continue
    fi

    if covered_by_reuse "$f"; then
        bulk=$((bulk+1))
        continue
    fi

    fail "$f carries no SPDX-License-Identifier and is not covered by REUSE.toml.
              Add a header in the file's own comment syntax:
                  SPDX-FileCopyrightText: 2026 Matthew Klapman
                  SPDX-License-Identifier: $EXPECTED_LICENCE
              If the format cannot carry a comment, annotate it in REUSE.toml
              instead -- deliberately, so the exception is visible."
done <<< "$files"

if [ "$((inline + bulk))" -eq 0 ]; then
    # Same posture as the other checkers here: a check that inspected nothing
    # must not report success, because in a log it is indistinguishable from a
    # real pass.
    printf '\033[33m[spdx] NOTHING TO CHECK — no files inspected\033[0m\n' >&2
    exit 3
fi

if [ "$violations" -gt 0 ]; then
    printf '\033[31m[spdx] %d violation(s). REFUSING.\033[0m\n' "$violations" >&2
    printf '        A file whose licence is ambiguous is a defect that surfaces\n' >&2
    printf '        in someone else'"'"'s legal review, which is the one place this\n' >&2
    printf '        project cannot afford friction.\n' >&2
    exit 1
fi
say "OK — $inline file(s) with inline headers, $bulk covered by REUSE.toml, all $EXPECTED_LICENCE"
