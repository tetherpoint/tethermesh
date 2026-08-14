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

**Captures are fixtures.** `tests/captures/` holds real on-air frames as
`ts / rssi / snr / raw-hex`. The decoder replays them offline, so an interop bug
becomes a regression test and stops needing bench access to fix.
