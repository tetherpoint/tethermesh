# host_unit — the algorithmic layer, no hardware

Host tests precede device work in every phase. What belongs here is anything
provable without a radio: header pack/unpack, channel hash, AES-CTR
known-answer vectors, `packet_id` non-repeat across a simulated reboot,
protobuf round-trip, flood LRU, duty accounting.

Two rules, both learned the hard way:

**Every gate has a negative twin, and the negative must be observed to fail.**
A test that has never been seen red is not yet a test — it is an assertion that
happens to pass. When adding a green test, add the red one and run it against a
deliberately broken build first.

The domain red list, as it becomes implementable:

- a forged `from` must **fail** the tag (once the suite lands)
- a wrong channel hash must **not** decrypt
- `hop_limit == 0` must **not** be forwarded
- a duplicate `(from, id)` must **not** be forwarded twice
- `packet_id` must **not** repeat across a simulated reboot
- the duty limiter must **drop** when over budget, and count the drop
- an unknown PortNum must be ignored, not crash
- a node without the extension must **not** read class-B traffic while still relaying it

**Captures are fixtures.** `tests/captures/` holds them, and tests read them
from there rather than from transcribed copies — a vector table copied into a
test drifts from the capture it came from, and the drift is invisible because
both sides still agree with themselves.

What is actually in there is **not** `ts / rssi / snr / raw-hex` on-air frames,
as this file previously said. As of 2026-08-15 there are three kinds, and they
are not interchangeable:

- **byte-exact protobuf** from the reference implementation's own encoder,
  captured at its API — the L3 corpus, and the only byte-level material so far;
- **field-level radio observations**, which name each header field and its
  value but say nothing about how those fields are packed;
- **synthetic known-answer vectors**, computed from verified functions.

**Raw on-air frames now exist** — `on_air_frames.json`, captured 2026-08-16 by
our own SX1262 receiver listening to a stock node. They are the only fixtures
that can catch an endianness or nonce error, because everything else in the
suite is checked against something we produced ourselves and would agree with
a wrong implementation perfectly.

## The check that passed without checking

Worth reading before trusting any gate here. `check_rust_rules.sh --binary`
existed from the start and was **vacuous in three independent ways at once**,
each of which produced a confident pass:

1. Pointed at an `.rlib` it saw 4 symbols, none of them ours — an rlib is
   mostly metadata, not linked object code.
2. `--emit=obj` under the release profile emits **LLVM bitcode**, which `nm`
   reads as an empty symbol table. LTO has to be off to get an ELF object.
3. Its patterns were written for **legacy symbol mangling**. This toolchain
   uses v0, where `core..panicking` never appears — and panic paths often
   surface as specialised symbols like `len_mismatch_fail` that contain no
   form of the word "panic" at all.

When it was fixed it immediately failed: `frame::encode` had a live panic path
through `copy_from_slice`. So the crate's headline promise was untrue for as
long as the check was broken, and nothing said so.

The check now refuses bitcode, refuses an artifact with too few symbols to be
meaningful, and tests for **undefined references outside a compiler-intrinsic
allowlist** rather than for names containing "panic". `check_all.sh` builds a
suitable object and runs it every time.

## Proven, not just tested

Some properties are now machine-checked over every input rather than sampled:
`cargo kani` verifies six harnesses in `meshtastic/core/proofs.rs`, all
against our own code. See `docs/FORMAL-VERIFICATION.md` for what is proven,
what is merely checked against a third party's answer, and what is neither.

A red test found its way in here too: the first draft of the proof module
carried a defensive `#![allow(clippy::indexing_slicing)]`, and
`check_rust_rules.sh` rejected it. Correctly — a proof module that suspends
the crate's rules proves things about code the crate would not accept.

## Coverage audit, 2026-08-16

Gaps found and closed:

- **AES-256 had no published vector.** It was exercised only through one
  captured CCM message, which would have caught a broken key schedule but
  only incidentally. Now checked against FIPS-197 Appendix C.3 directly.
- **CCM was only checked against itself and one message.** A round trip
  cannot catch a systematic error — an encrypt and decrypt wrong in the same
  way agree perfectly. Now checked against vectors from a different
  implementation.
- **X25519 had fixed vectors only.** Now differential-tested against an
  audited implementation across 512 random agreements per run, plus boundary
  values. See `docs/CRYPTO-DEPENDENCY.md`.
- **Two domain red-list items were unimplemented:** "a wrong channel hash must
  not decrypt" and "an unknown PortNum must be ignored, not crash".
- **`frame.rs` had no red test.** Its byte-for-byte rebuild was green-only.

Still open, and honestly so: the duty limiter and the extension-suite items
have no tests because neither exists yet.

## What has been observed red

Per the rule above, recorded rather than claimed:

| gate | broken how | observed |
|---|---|---|
| crate lints | a module using `buf[0]`, `a + b` and `.unwrap()` | 3 errors, build refused |
| `channel_hash` vectors | folded the name only, ignoring the PSK | `channel_hash("LongFast", …) = 0x0a, corpus says 0x08` |
| `arithmetic_side_effects`, after moving off the renamed lint | a module using `a + b` | error at the use site, build refused, exit 101 |
| `check_rust_rules.sh`'s attribute requirement | deleted the attribute from `lib.rs` | `VIOLATION: lib.rs is missing #![deny(clippy::arithmetic_side_effects)]`, exit 1 |
| protobuf round-trip (L3 gate) | made the writer emit **non-minimal** varints | gate failed on the first message |
| proto3 default omission | made the encoder emit a zero-valued field | `an all-default Data encoded to 2 bytes, expected 0` |
| `User` wrapper vs reference bytes | *not deliberate* — the wrapper was missing `macaddr` | failed with a 38-byte re-encode against 46 reference bytes |
| `packet_id` non-repeat across reboot | issued identifiers before the high-water mark was durable — the RAM-only-counter bug | `4 identifiers issued, 1 distinct` |
| duplicate suppression, key | keyed on `id` alone, ignoring `from` | a second sender's identical id read as a duplicate |
| duplicate suppression, recording | reported `New` but never stored the entry | 5 failures, including eviction ordering |
| header codec, endianness | read multi-byte fields big-endian | `sender does not match the transmitting board` |
| header codec, flag bits | read `hop_start` from bits 3-5 instead of 5-7 | `hop_start should match the original hop_limit` |
| CTR nonce byte order | big-endian `packet_id` in the nonce | captured frame decrypted to `fbd305d3…` instead of the text |
| PSK expansion | treated a one-byte PSK as a literal key | captured frames failed to decrypt, and the vector test failed |
| panic-free artifact | reintroduced a `copy_from_slice` with unprovable lengths | `references machinery outside the crate: …copy_from_slice_impl17len_mismatch_fail` |
| panic-free check, vacuity | pointed the check at the `.rlib` | `REFUSING: only 2 symbol(s)` |
| X25519 field arithmetic | *not deliberate* — `fe_sub` biased by p instead of 2p, and the final reduction was wrong | RFC 7748 vector returned `77b3cb27…` for `c3da5537…` |
| panic-free artifact, again | *not deliberate* — a `u128` shift pulled in `__ashlti3` | `references machinery outside the crate: __ashlti3` |
| AES-256 key schedule | dropped the extra `SubWord` at `i % 8 == 4` | FIPS-197 vector, both CCM vector sets, and the captured DM all failed |
| CCM flags byte | wrong tag-length field in `B0` | independent vectors and the captured DM failed |
| whole-frame encode | wrote the payload before the header | captured frame did not rebuild |

The X25519 row is the strongest argument in this table for published vectors.
The bug was a wrong constant in `fe_sub` — biasing by p rather than 2p — plus
a muddled final reduction. Both produce a field implementation that is
completely self-consistent: it adds, multiplies and inverts happily, and
agrees with itself on every round trip. Only a value computed by someone else
reveals it. There is no property test that would have caught it.

The `__ashlti3` row is worth reading too, because the check fired on something
that was *not* a panic path: a compiler-rt intrinsic for 128-bit shifts. The
right response was to remove the 128-bit shift rather than widen the
allowlist, since the serialisation never needed more than 64 bits.

The header rows are the ones that justify capturing real frames at all. A
big-endian header round-trips through our own encoder perfectly — it is only
wrong against the air. Nothing but captured bytes can catch that, which is
why `header_decodes_and_re_encodes_real_captured_frames` compares against
traffic a stock node actually transmitted rather than against anything we
produced.

The `packet_id` row is the domain red list's *"`packet_id` must **not** repeat
across a simulated reboot"*, and it is worth noting what the broken version
looked like: perfectly reasonable code that reserves a block and hands out an
identifier in the same step. It passes any single-run test. It only fails
once a restart is modelled, and then it reissues the *same* identifier every
time — which under CTR reissues a keystream.

The `User` row is the useful one, because nobody planted it. The wrapper was
built from a list of field numbers extracted with a regex that matched
`= 4;` and therefore skipped `bytes macaddr = 4 [deprecated = true];`. The
field is deprecated as of Meshtastic 2.1.x and firmware 2.7.26 **still emits
it**, as six zero bytes in every `User`.

Two things follow. **Deprecated in the schema is not absent from the wire**,
and byte identity is decided by the wire. And a lossy extraction of field
numbers produces a codec that is wrong in a way no amount of self-consistent
testing reveals — only comparison against real reference output caught it.

That last one is the reason the gate is phrased as *bit-identical* rather than
*equivalent*. A non-minimal varint decodes to exactly the same value, so a
test comparing decoded values would have passed it. Comparing bytes is what
catches an encoder that is correct and still emits frames the reference would
re-encode differently.

The second one is worth noting for what it also showed: the order-independence
test **still passed** against the broken implementation. A property test that
survives the bug is not a substitute for a vector tied to the reference.
