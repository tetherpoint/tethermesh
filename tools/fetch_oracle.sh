#!/usr/bin/env bash
#
# fetch_oracle.sh — obtain the reference implementation as a BLACK BOX, for
# differential testing. Binaries and containers only. Never source.
#
# WHAT THIS IS FOR
# ----------------
# Compatibility is proven by comparing bytes, in both directions:
#   their encoder -> our decoder   (do we read what they write?)
#   our encoder   -> their decoder (do THEY read what WE write?)
# The second direction is the one that fails in the field, and only an oracle
# tests it at scale. Run locally, it is not rate-limited by airtime: a frame
# that costs 805 ms on the air costs microseconds over loopback.
#
# WHY BINARY-ONLY IS THE WHOLE POINT
# ----------------------------------
# Running a program and observing its behaviour is the textbook clean-room
# method — observe, specify, implement from the specification. Reading its
# source is what forfeits that position. The distinction is not "did you have
# it available"; reference binaries are installed on the bench hardware
# regardless. The distinction is SOURCE.
#
# So the rule this script enforces mechanically: source is never fetched. Not
# discouraged, not fetched-then-ignored — never present. A source tree in the
# environment turns "read their implementation" from a deliberate act into an
# accident one grep away, and that temptation peaks exactly when someone is
# stuck at 2am on a mismatch.
#
# THE RULE THIS SCRIPT CANNOT ENFORCE
# -----------------------------------
# On a mismatch, DO NOT go looking for their source to explain it. Go back to
# the .proto, the published documentation, or a capture. If none of those
# resolves it, that is a finding: the specification is under-documented, and
# the answer is written into meshtastic/WIRE_REFERENCE.md as newly established
# fact — with both behaviours recorded.
#
# LOCAL ONLY. No public broker, no gateway, nothing bridged to RF. Traffic to
# a public mesh costs other people real airtime and publishes our test frames
# to a permanent public record.
#
# USAGE
#   tools/fetch_oracle.sh            fetch pinned artifacts into oracle/
#   tools/fetch_oracle.sh --verify   check what is present against the manifest
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# OUTSIDE the repository, deliberately. Three reasons: both the protocol work
# and the hardware bench need these artifacts, so one copy beats two; it
# matches how the bench already keeps toolchains; and their material never
# sits inside the clean-room implementation tree, which is the strongest
# answer to "what did you have in your source directory?".
# Override with TM_ORACLE_DIR — an outside adopter will want their own path.
DEST="${TM_ORACLE_DIR:-$(cd "$ROOT/.." && pwd)/meshtastic-oracle}"
MANIFEST="$ROOT/tools/oracle.manifest"

say()  { printf '\033[36m[oracle]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[oracle] %s\033[0m\n' "$*" >&2; exit 1; }

# ── refuse source, by construction ─────────────────────────────────────────
# Anything that would place source in the environment is rejected before it
# runs, rather than cleaned up afterwards.
reject_source() {
    local what="$1"
    case "$what" in
        *.tar.gz|*.tar.xz|*.zip|*source*|*src*)
            die "REFUSED: '$what' looks like a source archive.
       Binaries and containers only. See the header of this script — the
       clean-room position turns on source, not on availability." ;;
        *github.com/meshtastic/firmware*|*github.com/meshtastic/protobufs*)
            case "$what" in
                */releases/download/*) : ;;   # a release artifact is a binary
                *) die "REFUSED: '$what' is a source repository.
       Use a release artifact or a container image." ;;
            esac ;;
    esac
}

[ -f "$MANIFEST" ] || die "no manifest at $MANIFEST — nothing is pinned, so nothing can be fetched reproducibly"

mkdir -p "$DEST"
cat > "$DEST/README.txt" <<'EOF'
NOT TRACKED. Fetched by tools/fetch_oracle.sh, pinned by tools/oracle.manifest.

These are third-party binaries used as a BLACK BOX for differential testing.
They are GPL-3.0 licensed and are deliberately NOT committed to this
repository: using a program creates no derivative work, but vendoring its
code would place GPL files in our history.

Do not read their source. Do not fetch their source. On a mismatch, consult
the protocol definitions, the published documentation, or a capture.
EOF

mode="${1:-fetch}"

if [ "$mode" = "--verify" ]; then
    say "verifying $DEST against manifest"
    fail=0
    while read -r kind name version sha url; do
        case "$kind" in ''|'#'*) continue ;; esac
        case "$kind" in
            container)
                if command -v docker >/dev/null 2>&1; then
                    docker image inspect "$name:$version" >/dev/null 2>&1 \
                        && say "  container $name:$version present" \
                        || { printf '  MISSING container %s:%s\n' "$name" "$version" >&2; fail=1; }
                else
                    say "  docker not installed — cannot verify $name"
                fi ;;
            file)
                f="$DEST/$name"
                if [ -f "$f" ]; then
                    got=$(sha256sum "$f" | cut -d' ' -f1)
                    [ "$got" = "$sha" ] && say "  $name OK" \
                        || { printf '  CHECKSUM MISMATCH %s\n    want %s\n    got  %s\n' "$name" "$sha" "$got" >&2; fail=1; }
                else
                    printf '  MISSING %s\n' "$name" >&2; fail=1
                fi ;;
        esac
    done < "$MANIFEST"
    [ "$fail" = 0 ] || die "verification failed"
    say "OK — all pinned artifacts present and matching"
    exit 0
fi

# ── fetch ──────────────────────────────────────────────────────────────────
while read -r kind name version sha url; do
    case "$kind" in ''|'#'*) continue ;; esac
    reject_source "$url"
    case "$kind" in
        container)
            command -v docker >/dev/null 2>&1 || die "docker not installed; needed for $name"
            say "pulling $name:$version"
            docker pull "$name:$version" >/dev/null || die "pull failed: $name:$version"
            ;;
        file)
            out="$DEST/$name"
            if [ -f "$out" ] && [ "$(sha256sum "$out" | cut -d' ' -f1)" = "$sha" ]; then
                say "$name already present and matching"; continue
            fi
            say "fetching $name"
            curl -fsSL "$url" -o "$out" || die "download failed: $url"
            got=$(sha256sum "$out" | cut -d' ' -f1)
            [ "$got" = "$sha" ] || { rm -f "$out"; die "checksum mismatch for $name
       want $sha
       got  $got
       Refusing to keep an artifact that is not the pinned one."; }
            ;;
        *) die "unknown manifest kind '$kind'" ;;
    esac
done < "$MANIFEST"

say "OK — oracle ready in $DEST (outside the repo, never tracked)"
say "    reminder: black box only. Never read or fetch their source."
