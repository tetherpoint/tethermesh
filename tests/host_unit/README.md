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
