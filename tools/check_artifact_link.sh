#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 The tethermesh Authors
# SPDX-License-Identifier: Apache-2.0
#
# check_artifact_link.sh — link a real consumer and inspect the real image.
#
# WHY THIS EXISTS, AND WHY IT IS NOT THE SAME CHECK AS check_rust_rules.sh
# -----------------------------------------------------------------------
# DISTRIBUTION.md promises: "CI builds a minimal C consumer against each
# released archive for each target. Publishing binaries whose only validation
# was that the Rust tests passed on the host would be publishing something
# untested in the form people actually use."
#
# This is that check, and it answers a question the object-level check cannot.
# check_rust_rules.sh --binary inspects the CRATE OBJECT for undefined
# references. That is the right question for the library. It is the wrong
# question for a shipped archive, because:
#
#   * `nm -u` on an ARCHIVE reports undefined symbols per member, including
#     ones other members of the same archive satisfy. rust_begin_unwind shows
#     up as BOTH defined and undefined in the same .a, which reads as a
#     violation and is not one.
#   * What a consumer actually gets is decided by the LINKER, after
#     --gc-sections has discarded everything unreachable.
#
# That misreading is what parked L8 from the start: Cargo.toml recorded a
# tension between shipping a staticlib and staying panic-free, and the tension
# did not exist. It was an artifact of inspecting the wrong thing.
#
# THE VACUITY TRAP THIS MUST AVOID
# --------------------------------
# "No panic symbols" is trivially true of an image containing no code. So this
# does NOT merely count panic symbols. It also requires that the library's own
# symbols are present and that the consumer's calls survive as real branches in
# the disassembly. A pass here means code was linked AND no panic path reached
# it -- the same posture as check_rust_rules.sh refusing an artifact too bare
# to demonstrate anything.
#
# USAGE
#   tools/check_artifact_link.sh <target> <path-to-cross-gcc-prefix>
#
#   e.g. tools/check_artifact_link.sh thumbv8m.main-none-eabihf \
#          "$HOME/.arduino15/packages/rp2040/tools/pqt-gcc/4.1.0-1aec55e/bin/arm-none-eabi"
#
# The toolchain path is an argument rather than discovered, because a cross
# compiler found by guessing is a cross compiler nobody can reproduce.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
say()  { printf '\033[36m[artifact]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[artifact] VIOLATION: %s\033[0m\n' "$*" >&2; violations=$((violations+1)); }
violations=0

TARGET="${1:-}"
PREFIX="${2:-}"
if [ -z "$TARGET" ] || [ -z "$PREFIX" ]; then
    printf 'usage: %s <rust-target> <cross-gcc-prefix>\n' "$0" >&2
    exit 2
fi
CC="${PREFIX}-gcc"; NM="${PREFIX}-nm"; OBJDUMP="${PREFIX}-objdump"
for t in "$CC" "$NM" "$OBJDUMP"; do
    command -v "$t" >/dev/null 2>&1 || { printf '\033[31m[artifact] no %s\033[0m\n' "$t" >&2; exit 1; }
done

# Machine flags per target. Extend deliberately rather than guessing from the
# triple: a wrong float ABI links but produces an image that faults at runtime.
case "$TARGET" in
    thumbv8m.main-none-eabihf) MFLAGS="-mcpu=cortex-m33 -mthumb -mfloat-abi=hard -mfpu=fpv5-sp-d16" ;;
    thumbv7em-none-eabihf)     MFLAGS="-mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16" ;;
    *) printf '\033[31m[artifact] no machine flags recorded for %s\033[0m\n' "$TARGET" >&2; exit 1 ;;
esac

WORK="${TMPDIR:-/tmp}/tm-artifact-link.$$"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/ffi/src"

# A thin FFI crate: staticlib, panic handler, C ABI. The library itself stays an
# rlib on purpose -- a crate defining a #[panic_handler] forces it on every
# consumer, and only one may exist per linked program.
cat > "$WORK/ffi/Cargo.toml" <<EOF
[package]
name = "tmffi"
version = "0.0.0"
edition = "2021"
[lib]
crate-type = ["staticlib"]
[dependencies]
tethermesh = { path = "$ROOT" }
[profile.release]
panic = "abort"
lto = false
codegen-units = 1
opt-level = "z"
EOF
cat > "$WORK/ffi/src/lib.rs" <<'EOF'
#![no_std]
#[panic_handler]
fn ph(_: &core::panic::PanicInfo) -> ! { loop {} }

#[no_mangle]
pub extern "C" fn tm_abi_version() -> u32 { 1 }

#[no_mangle]
pub extern "C" fn tm_channel_hash(name: *const u8, nlen: usize,
                                  psk: *const u8, plen: usize) -> u8 {
    if name.is_null() || psk.is_null() { return 0; }
    let n = unsafe { core::slice::from_raw_parts(name, nlen) };
    let p = unsafe { core::slice::from_raw_parts(psk, plen) };
    tethermesh::channel::channel_hash(n, p)
}
EOF

say "building staticlib for $TARGET"
( cd "$WORK/ffi" && cargo build --release --target "$TARGET" >/dev/null 2>&1 ) \
    || { fail "staticlib did not build for $TARGET"; exit 1; }
A="$WORK/ffi/target/$TARGET/release/libtmffi.a"
[ -f "$A" ] || { fail "no archive produced"; exit 1; }

# The consumer passes the EXPANDED 16-byte key, not the short PSK index. A C
# surface taking a pointer and a length cannot tell them apart, and passing the
# index yields a wrong channel hash silently -- 0x0b instead of 0x08. That
# mistake was made writing this and is pinned here so it stays made-once.
cat > "$WORK/entry.c" <<'EOF'
extern unsigned char tm_channel_hash(const unsigned char*, unsigned long,
                                     const unsigned char*, unsigned long);
extern unsigned tm_abi_version(void);
static const unsigned char NAME[8] = "LongFast";
static const unsigned char KEY[16] = {0xd4,0xf1,0xbb,0x3a,0x20,0x29,0x07,0x59,
                                      0xf0,0xbc,0xff,0xab,0xcf,0x4e,0x69,0x01};
volatile unsigned char sink;
void _start(void){ sink = (unsigned char)(tm_channel_hash(NAME,8,KEY,16) + tm_abi_version()); for(;;){} }
EOF

say "compiling and linking a C consumer with --gc-sections"
# shellcheck disable=SC2086
"$CC" $MFLAGS -ffunction-sections -fdata-sections -O2 -c "$WORK/entry.c" -o "$WORK/entry.o" 2>/dev/null
# --no-warn-rwx-segments only SILENCES A WARNING, and it arrived in binutils
# 2.39. Passing it unconditionally makes this check fail outright on an older
# linker -- the Zephyr SDK here ships 2.38 -- with "unrecognized option", which
# reads as a broken artifact rather than a missing flag. Probed, not assumed.
RWX=""
if echo 'int main(void){return 0;}' > "$WORK/probe.c" \
   && "$CC" $MFLAGS -nostdlib -nostartfiles -Wl,--no-warn-rwx-segments \
        -Wl,-e,main "$WORK/probe.c" -o "$WORK/probe.elf" >/dev/null 2>&1; then
    RWX="-Wl,--no-warn-rwx-segments"
fi

# shellcheck disable=SC2086
"$CC" $MFLAGS -nostdlib -nostartfiles -Wl,--gc-sections -Wl,-e,_start \
      $RWX -Ttext=0x10000000 \
      "$WORK/entry.o" "$A" -o "$WORK/linked.elf" 2>"$WORK/link.err" \
    || { fail "link failed:"; sed 's/^/                /' "$WORK/link.err" >&2; exit 1; }

# ── 1. the library must actually be in there ───────────────────────────────
lib_syms=$("$NM" "$WORK/linked.elf" 2>/dev/null | grep -c 'tethermesh' || true)
if [ "$lib_syms" -lt 1 ]; then
    fail "no tethermesh symbols in the linked image. --gc-sections discarded the
              library, so 'no panic paths' would be true of an empty image and
              would mean nothing."
else
    say "library symbols linked in: $lib_syms"
fi

# ── 2. the calls must survive as real branches ─────────────────────────────
calls=$("$OBJDUMP" -d "$WORK/linked.elf" 2>/dev/null | grep -c 'bl.*tm_channel_hash' || true)
if [ "$calls" -lt 1 ]; then
    fail "the consumer's call to tm_channel_hash is not a branch in the
              disassembly -- it was optimised away, so nothing was exercised."
else
    say "consumer call present in disassembly"
fi

# ── 3. and no panic path may have reached the image ────────────────────────
panics=$("$NM" "$WORK/linked.elf" 2>/dev/null \
         | grep -icE 'rust_begin_unwind|panicking|panic_bounds|len_mismatch|slice_index' || true)
if [ "$panics" -gt 0 ]; then
    fail "$panics panic-related symbol(s) survived --gc-sections in the linked image:"
    "$NM" "$WORK/linked.elf" 2>/dev/null \
      | grep -iE 'rust_begin_unwind|panicking|panic_bounds|len_mismatch|slice_index' \
      | sed 's/^/                /' >&2
fi

txt=$("$PREFIX-size" "$WORK/linked.elf" 2>/dev/null | awk 'NR==2{print $1}')
say "linked .text: ${txt:-?} bytes (only what the consumer reaches)"

if [ "$violations" -gt 0 ]; then
    printf '\033[31m[artifact] %d violation(s). REFUSING.\033[0m\n' "$violations" >&2
    exit 1
fi
say "OK — $TARGET: library linked, calls real, no panic path in the image"
