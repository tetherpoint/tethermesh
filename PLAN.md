# PLAN — building the stack

**2026-08-14.** The roadmap for this library and nothing else. Every phase is justified on the library's own terms; if a phase cannot be, it belongs somewhere else.

Read `README.md` for what this is, `SCOPE.md` for what belongs here, `TESTING.md` for how compatibility is proven, and `meshtastic/WIRE_REFERENCE.md` before writing any codec.

## What changed the schedule

The reference implementation runs **locally, with no radio**, as a black box. That single fact reorders everything: protocol development is no longer gated on hardware, and it is no longer rate-limited by airtime — a frame costs ~805 ms on the air at the default preset and microseconds over loopback.

So hardware is needed for exactly two things: **the physical layer** (sync word register values, per-preset modulation parameters on real silicon, RF timing) and **the final interoperability gate**. Everything else — the codec, the crypto, the routing logic, the extension suite, and conformance in both directions — is host work.

---

## L0 — finish the wire reference

`meshtastic/WIRE_REFERENCE.md` exists and separates verified facts from unverified. **Six items remain unverified and block the codec**: header byte layout, CTR nonce construction, the channel hash function, PKI/DM details, the raw sync-word register value, and per-preset SF/BW/CR parameters.

Four of the six fall out of captured traffic at the simulated-radio boundary, where the raw frame appears. The sync word and modulation parameters need real silicon and stay open until then.

**Gate:** every item either verified with a source, or explicitly still open. No item silently promoted from "commonly asserted" to "fact".

## L1 — oracle harness and fixture corpus

Stand up the reference implementation locally per `TESTING.md` — binaries and containers only, pinned by checksum, source never fetched. Capture its output at the radio boundary into a fixture corpus.

The corpus matters more than the harness: **once captured, day-to-day testing runs against fixtures rather than against the oracle**, which makes results reproducible, keeps CI independent, and limits exposure to a moving upstream.

**Gate:** a byte-exact frame corpus committed as synthetic-equivalent vectors, with the oracle version recorded alongside.

## L2 — frame codec

Header pack and unpack, channel hash, AES-CTR with the verified nonce construction, PSK index expansion. Known-answer tests generated from the specification.

Includes the **packet-id discipline**: drawn from a CSPRNG and persisted across restart, with a test proving no `(packet_id, sender)` pair repeats across a simulated reboot. This is not hygiene — under CTR, a repeated pair leaks the XOR of two plaintexts, and the identifier is only 32 bits.

**Gate:** a real captured frame decrypts to parseable payload bytes.

## L3 — protobuf codec

Hand-written minimal encoder and decoder plus per-message wrappers. Hand-written for two reasons: no code-generation dependency in the build, and generated output would derive from a copyleft input.

**Gate:** every message in the corpus round-trips decode→encode bit-identically.

## L4 — conformance, both directions

The layer that actually proves compatibility:

- *their encoder → our decoder* — we read what they write
- *our encoder → their decoder* — **they read what we write**

The second is the direction that fails in the field, and the one a lenient decoder hides.

**Gate:** both directions clean across the corpus, plus fuzzing that reaches the panic-free requirement — `tools/check_rust_rules.sh --binary` showing no panic machinery linked. That is the evidence for the safety claim; fuzzing alone only shows nothing crashed today.

## L5 — routing

Managed flooding: hop-limit decrement, duplicate suppression keyed on sender and identifier, the SNR-scaled contention window, and duty-cycle accounting.

**And the assumption everything else rests on.** Whether nodes relay traffic on channels they cannot decrypt is currently PLAUSIBLE, UNPROVEN. Settle it here: several instances, controlled topology, inject a frame on a channel none of them holds, observe whether it is repeated. In simulation topology is a coordinate rather than a hardware problem.

**Gate:** relay behaviour matches the reference across a topology matrix, and the relay question is answered in the wire reference either way.

## L6 — PKI direct messages

X25519 key agreement and the AEAD path for direct messages. Identity persistence is a caller concern; this layer provides the construction.

**Gate:** decrypt a captured direct message; produce one the reference accepts.

## L7 — the extension suite

**Specification first, implementation second.** `suite/README.md` records the shape: authenticated channels with the AEAD tag bound to the cleartext header as additional data; managed groups with an owner, roster and revocation; location with pluggable sources.

Writing the spec first is not process for its own sake — the spec is the deliverable that adoption runs on, and an implementation written before it will quietly become the specification by default.

**Gate:** two instances exchange authenticated extension traffic that an unmodified reference node relays without reading; a forged sender fails the tag; a node without the extension falls back and still communicates.

## L8 — release engineering

The C ABI surface, `cbindgen` header, and the artifact discipline `DISTRIBUTION.md` commits to: a declared target set, reproducible builds, `tm_abi_version()`, a CI size budget, and a minimal C consumer built against each released archive.

**Gate:** every promise in `DISTRIBUTION.md` has a check behind it, and the caveat appears in the release notes, the archive and the generated header.

---

## What stays open

**The physical layer.** The sync-word register value and per-preset modulation parameters cannot be established without real silicon, and simulation will not reveal them.

**The interoperability gate.** A physical, unmodified device must show our node, render our text, accept a direct message, and list us in a route trace. Simulation green is not interoperability green, and treating it as such is the most likely way this project fools itself.

## Sequence

L0 and L1 are concurrent and unblock everything. L2 and L3 are independent of each other. L4 needs both. L5 can start after L2 since routing acts on the header alone. L6 and L7 follow L4. L8 runs alongside from L2 onward, because retrofitting the target matrix and reproducibility is far more expensive than carrying them.
