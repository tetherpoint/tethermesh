#!/usr/bin/env bash
#
# check_cleanroom.sh — fail the build if GPL-derived material enters the tree.
#
# WHY THIS IS A CHECK AND NOT A POLICY NOTE
# -----------------------------------------
# `meshtastic/firmware` and `meshtastic/protobufs` are BOTH GPL-3.0. Copyleft
# is viral: anything derived from them makes tethermesh GPL-3.0, which would
#
#   - carry copyleft into every codebase this links with;
#   - foreclose the extension suite's entire purpose, which depends on other
#     implementers being free to use it from a permissively licensed spec;
#   - and drag in GPL-3.0's anti-tivoization terms, which require that users
#     can install modified firmware — incompatible with hardware-backed key
#     storage and secure boot.
#
# None of that is recoverable after the fact. Once GPL code is in the history,
# removing the file does not undo the derivation. So this is a gate, not a
# reminder: a policy that depends on everyone remembering is not a policy.
#
# WHAT IS ALLOWED, AND THE LINE
# -----------------------------
# ALLOWED — facts about the wire:
#   - reading upstream .proto files as SPECIFICATION (field numbers, types,
#     wire layouts) and writing our own codec from them
#   - published protocol documentation
#   - constants transcribed verbatim: sync word, header length, the default
#     channel PSK. These are facts, not expression.
#   - our own on-air captures
#
# FORBIDDEN — expression:
#   - copying implementation from firmware, mobile apps or clients
#   - VENDORING .proto files into this tree (read them upstream, pinned in
#     DEPS.md; a copy here is a GPL file in our repo)
#   - running a code generator over their .proto — the output is derived from
#     a GPL input. This is why PLAN.md specifies a hand-written ~300-line
#     protobuf codec instead of nanopb: licence-safe as well as dependency-light.
#   - linking RadioLib or any other GPL component
#
# THE RULE WHEN TEMPTED: if you find yourself wanting to copy a routing
# decision or a state machine, STOP. That means the spec is under-documented,
# and the correct response is to write down our own design and cite the wire
# behaviour it implements — not to read their source.
#
# USAGE
#   tools/check_cleanroom.sh            scan the tree
#   tools/check_cleanroom.sh --staged   scan only staged files (pre-commit)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
say()  { printf '\033[36m[cleanroom]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[cleanroom] VIOLATION: %s\033[0m\n' "$*" >&2; violations=$((violations+1)); }

violations=0
MODE="${1:-full}"

if [ "$MODE" = "--staged" ]; then
    files=$(git -C "$ROOT" diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)
else
    files=$(git -C "$ROOT" ls-files 2>/dev/null || true)
fi
[ -n "$files" ] || { say "no files to scan"; exit 0; }

while IFS= read -r f; do
    [ -n "$f" ] || continue
    p="$ROOT/$f"
    [ -f "$p" ] || continue

    # This checker quotes the very strings it forbids; exempt it and the docs
    # that explain the rule, or the rule cannot be written down.
    case "$f" in
        tools/check_cleanroom.sh|PLAN.md|README.md|docs/*|meshtastic/WIRE_REFERENCE.md) continue ;;
    esac

    case "$f" in
        *.proto)
            fail "$f — vendored .proto. Upstream protos are GPL-3.0; read them
              at the pinned commit in DEPS.md, never copy them into this tree." ;;
        *.pb.c|*.pb.h|*_pb2.py)
            fail "$f — generated protobuf output. Derived from a GPL-3.0 .proto.
              PLAN.md specifies a hand-written codec for exactly this reason." ;;
    esac

    grep -Iq . "$p" 2>/dev/null || continue   # skip binaries

    if grep -qE "GNU GENERAL PUBLIC LICENSE|GPL-3\.0|SPDX-License-Identifier: *GPL" "$p" 2>/dev/null; then
        fail "$f — carries a GPL licence header."
    fi
    if grep -qiE "\bRadioLib\b" "$p" 2>/dev/null; then
        fail "$f — references RadioLib (GPL-3.0). This stack carries no radio
              driver; if one is added it must be independently written."
    fi
done <<< "$files"

if [ "$violations" -gt 0 ]; then
    printf '\033[31m[cleanroom] %d violation(s). REFUSING.\033[0m\n' "$violations" >&2
    printf '        Clean-room is not a preference here, it is what keeps the\n' >&2
    printf '        extension suite permissively licensable and keeps secure\n' >&2
    printf '        boot compatible with our licence. Once GPL-derived code is\n' >&2
    printf '        in the history, deleting the file does not undo it.\n' >&2
    exit 1
fi
say "OK — $(echo "$files" | grep -c . ) file(s) scanned, no GPL-derived material"
