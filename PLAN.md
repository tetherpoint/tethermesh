<!-- SPDX-FileCopyrightText: 2026 The tethermesh Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# PLAN — building the stack

**2026-08-14.** The roadmap for this library and nothing else. Every phase is justified on the library's own terms; if a phase cannot be, it belongs somewhere else.

Read `README.md` for what this is, `SCOPE.md` for what belongs here, `TESTING.md` for how compatibility is proven, and `meshtastic/WIRE_REFERENCE.md` before writing any codec.

## What changed the schedule

The reference implementation runs **locally, with no radio**, as a black box. That single fact reorders everything: protocol development is no longer gated on hardware, and it is no longer rate-limited by airtime — a frame costs ~805 ms on the air at the default preset and microseconds over loopback.

So hardware is needed for exactly two things: **the physical layer** (sync word register values, per-preset modulation parameters on real silicon, RF timing) and **the final interoperability gate**. Everything else — the codec, the crypto, the routing logic, the extension suite, and conformance in both directions — is host work.

---

## L0 — finish the wire reference

`meshtastic/WIRE_REFERENCE.md` exists and separates verified facts from unverified. **Six items remain unverified and block the codec**: header byte layout, CTR nonce construction, the channel hash function, PKI/DM details, the raw sync-word register value, and per-preset SF/BW/CR parameters.

~~Four of the six fall out of captured traffic at the simulated-radio boundary, where the raw frame appears.~~ The sync word and modulation parameters need real silicon and stay open until then.

**Status 2026-08-15 — partially done, and the premise above was wrong.** The channel hash is **resolved** (`xor_fold(name) ^ xor_fold(psk)`, two data points, one with a PSK we supplied). PKI/DM detail is untouched. The sync word and preset parameters remain open on silicon, as expected.

The correction: **the raw frame does not appear at the simulated-radio boundary.** The reference's `SimRadio` is process-local — it loops the frame back inside the same process, no socket carries it, and two local instances do not hear each other. What the oracle yields is a *field-level* view (every header field named with its value), not a byte-level one, so it cannot settle header packing or the CTR nonce. Those now need a real radio, an authoritative document, or differential testing against their decoder. See `meshtastic/WIRE_REFERENCE.md` § UNVERIFIED.

**2026-08-16 — L0 IS COMPLETE.** All six items are resolved or explicitly bounded:

| item | state |
|---|---|
| 1 header byte layout | resolved by on-air capture |
| 2 AES-CTR nonce | resolved by decrypting captured frames to known plaintext |
| 3 channel hash | resolved by observation, two data points |
| 4 PKI/DM scheme | resolved by capturing and decrypting a real direct message |
| 5 sync word | resolved — `0x0740=0x24`, `0x0741=0xB4`, confirmed by decoding real traffic |
| 6 modem parameters | **fully resolved 2026-08-16** — SF, BW **and CR** measured for all nine valid presets |

**2026-08-16 — item 6 is now measured, and the estimate in it was wrong.** Writing each preset to a stock node and reading back what it programmed gives spreading factor and bandwidth for **all nine valid presets**, committed as `tests/captures/modem_presets.json` and cross-checked against `meshtastic/core/airtime.rs` by a test that would fail if the symbol-time formula were accidentally right at only one spreading factor.

**There were never sixteen presets to find — there are eight.** Presets 2 and 10–16 report `name=Invalid` and **silently serve LongFast parameters**, so a node set to an out-of-range preset does not fail, it quietly runs LongFast. That is worth more than the table it corrects, because a mismatch under those settings would otherwise be attributed to almost anything else.

**Coding rate is now measured too, and L0 is complete.** Every valid preset is **4/5** — so the table varies spreading factor and bandwidth only.

Getting there needed a correction first: **reception cannot reveal the coding rate.** Explicit-header mode carries the CR in the header and the receiver adopts it, so a deliberately mismatched receiver decodes anyway — demonstrated at 4/8 and 4/6. That also meant LongFast's "CR 4/5" had never been measured either; it was our receiver's *setting*, recorded next to measured values and inheriting their credibility.

**Timing settled it.** `header-valid` to `rx-done` is the payload airtime, and the difference between a 91-byte and a 44-byte relay cancels the constant offset of where `header-valid` fires. Residuals 0.2–4.3 ms against 4/5, all inside the 10 ms poll quantisation, with 4/6 between 27 and 328 ms away.

**One new protocol fact fell out:** the carrier moves with the preset, 902.688 to 926.750 MHz, because the channel slot depends on the bandwidth. The first sweep lost eight of nine presets to that — it matched SF and BW and stayed on LongFast's frequency, where "nothing received" looks exactly like "wrong parameters".

**Gate:** every item either verified with a source, or explicitly still open. No item silently promoted from "commonly asserted" to "fact". *Met.*

## L1 — oracle harness and fixture corpus

Stand up the reference implementation locally per `TESTING.md` — binaries and containers only, pinned by checksum, source never fetched. Capture its output at the radio boundary into a fixture corpus.

The corpus matters more than the harness: **once captured, day-to-day testing runs against fixtures rather than against the oracle**, which makes results reproducible, keeps CI independent, and limits exposure to a moving upstream.

**Status 2026-08-15 — harness done, corpus partially done, gate NOT met.**

Done: the oracle is pinned by digest (`meshtastic/meshtasticd@sha256:23e92b13…`, tag `2.7.26.54e0d8d`), fetched, verified, and runs locally; `fetch_oracle.sh --verify` checks the digest rather than mere presence; the harness (`oracle.sh`, `capture.py`) drives nodes and parses their radio-boundary output; provenance is recorded in `DEPS.md`; a corpus is committed under `tests/captures/`. Per the rule, the binaries, the harness and every tool that touches them live outside this tree.

Not achievable against this oracle: **byte-exact LoRa frames.** See the L0 correction — the packing never leaves the process.

**But byte-exact protobuf is, and it was the corpus worth having first.** The oracle's TCP API is a second boundary, and everything crossing it is encoded by their encoder: `tests/captures/fromradio_corpus.json` holds 43 messages across 9 `FromRadio` variants, captured over loopback in a second. Two properties were measured on capture — 43/43 re-emit bit-identically under minimal-varint re-encoding, and 43/43 carry fields in ascending order. Their encoder is canonical, which is what makes **L3's gate reachable at all**; had it emitted non-minimal varints or arbitrary field order, "bit-identical round-trip" would have been an impossible requirement and the gate would have needed rewriting.

So the committed corpus is three things, labelled distinctly rather than blurred: byte-exact protobuf, field-level radio observations, and synthetic known-answer vectors.

**2026-08-16 — byte-exactness arrived, by the route this section said it would need.** `tests/captures/on_air_frames.json` holds **raw LoRa PHY payloads** captured off the air by our own SX1262 receiver: three 35-byte frames from a stock Heltec on `2.7.26.54e0d8d`, at 906.875 MHz / SF11 / BW250 / CR4-5 / preamble 16 / sync `0x24 0xB4`. Our nodes, our channel, our own text — synthetic-equivalent under `TESTING.md`, with no third-party traffic — and the receiver's driver is independently written from the SX126x datasheet, recorded in the file's own `clean_room_note`.

That capture also corroborates the **sixteen-symbol preamble** from a third direction, independently of the 131 ms figure and of `airtime.rs`'s model.

**Gate:** a byte-exact frame corpus committed as synthetic-equivalent vectors, with the oracle version recorded alongside. ***Met.*** The version is in `DEPS.md`; the bytes are in `tests/captures/`.

**The honest qualifier: the corpus is thin.** Three frames, all the same length and portnum. It satisfies the gate and it is what unblocked L2's header work, but it is a sample rather than a survey — broadening it across payload sizes and message types is cheap now that the receiver exists, and worth doing before anything depends on frame diversity.

~~*Version recorded; byte-exactness outstanding, and it needs one of the three routes named in the wire reference — not more work against this oracle.*~~ **Struck** — written 2026-08-15, superseded the next day by the capture above. The judgement in it was correct: it did need a real radio, and more work against the oracle would not have produced it.

## L2 — frame codec

Header pack and unpack, channel hash, AES-CTR with the verified nonce construction, PSK index expansion. Known-answer tests generated from the specification.

Includes the **packet-id discipline**: drawn from a CSPRNG and persisted across restart, with a test proving no `(packet_id, sender)` pair repeats across a simulated reboot. This is not hygiene — under CTR, a repeated pair leaks the XOR of two plaintexts, and the identifier is only 32 bits.

**2026-08-16 — the packet-id discipline is done**, ahead of the rest of L2, because it needs no header layout and is the part with a security consequence. `meshtastic/core/packet_id.rs`.

It is a **counter, not a CSPRNG draw**, which is a deliberate departure from the line above. At 32 bits, random identifiers collide by the birthday bound after roughly 77,000 packets — a figure a busy node reaches — while a counter cannot collide until it wraps. Entropy still belongs at the seed, so a fresh node does not start at zero and announce its restarts, but the sequence itself must be a counter.

The hard part is restart, and the resolution is a **high-water mark persisted ahead of use, in blocks**: identifiers are only ever issued below a value already durably stored, so a power loss can lose the unissued remainder of a block and never an identifier that was actually used. One write per block instead of one per packet, which matters on flash with a finite erase budget. The API returns `PersistFirst` instead of an identifier when the mark must be written, so the obligation cannot be skipped by accident. Exhaustion is reported rather than wrapped — a node that stops identifying packets is visibly broken, which beats one that quietly starts leaking plaintext XORs.

**2026-08-16 — the gate is MET, and the phase is unblocked end to end.** A stock node transmitted; a second Heltec running our own SX1262 driver (written from the datasheet, not RadioLib) captured the PHY payload; the ciphertext decrypts under the default channel key to `Data{portnum=1, payload="sniff-probe-0"}` — the exact text sent.

That single capture resolved four open L0 items at once. The 16-byte header layout and the AES-CTR nonce were read off real frames. The sync word and LongFast's modem parameters were confirmed by construction, since nothing decodes without them.

`meshtastic/core/header.rs` implements pack and unpack, tested against the captured frames rather than against itself — the distinction matters, because a big-endian header round-trips through its own encoder perfectly and is wrong only on the air. Both that error and a flag-bit misplacement were observed red.

**AES-128-CTR and PSK expansion are done too** — `meshtastic/core/crypto.rs`. Encryption only, because CTR never invokes the inverse cipher. Verified against the FIPS-197 published vector first, then against captured traffic: our own Rust decrypts real over-the-air frames to the exact text that was transmitted.

Two notes on how it was built. The AES core needs variable indexing and index arithmetic on every line, which the crate denies outright; rather than suppress the lints for one file, every access goes through total accessors and wrapping index arithmetic. And a stored PSK is an **index, not a key** — feeding the stored bytes to AES computes a different key for the most common channel on the network, silently. Both the nonce byte order and that expansion were observed red against captured frames.

`meshtastic/core/frame.rs` frames the two halves together, and the gate for it is the strongest one available: **a captured frame decodes and re-encodes byte for byte.** If our encoder reproduces exactly what a stock node put on the air, then the header layout, endianness, flag packing, PSK expansion, nonce construction and CTR counter semantics are all simultaneously right.

**L2 is complete.**

**Gate:** a real captured frame decrypts to parseable payload bytes. *Met.*

## L3 — protobuf codec

Hand-written minimal encoder and decoder plus per-message wrappers. Hand-written for two reasons: no code-generation dependency in the build, and generated output would derive from a copyleft input.

**2026-08-15 — the crate exists.** `Cargo.toml` plus `meshtastic/core/lib.rs` carrying all seven required attributes, so `tools/check_rust_rules.sh` reports *"crate rules hold"* rather than *"NOTHING TO CHECK"*. The lints were red-tested: a module using slice indexing, bare arithmetic and `unwrap()` is rejected with three errors. The first real code is `channel::channel_hash`, the one wire fact verified well enough to implement, tested against the committed corpus and also observed red. Details in `tests/host_unit/README.md`.

**2026-08-15 — the wire layer is done and the gate is met.** `meshtastic/core/protobuf.rs` is a hand-written reader and writer for tags, wire types and lengths. **All 43 corpus messages round-trip bit-identically.** No allocation, no slice indexing, no bare arithmetic; malformed input returns an error and is tested against truncation, non-terminating and over-long varints, group and unassigned wire types, and field number zero.

The module is deliberately **schema-free** — it knows nothing of any message, field name or type. That is the clean-room boundary in code: a decoder that understood the messages is precisely the artefact that must not derive from their schema, so the message layer above it stays small and obviously ours.

**Wrappers and nested round-tripping are done too.** `meshtastic/core/message.rs` carries `Data` and `User`, written to proto3 rules — ascending field order, defaults omitted, `optional` modelled as real presence. `User` is verified against reference bytes lifted out of the corpus (`FromRadio.node_info` → `NodeInfo.user`), not against our own encoder's opinion of itself. The round-trip gate now recurses: **100 messages checked against 43 top-level**, which is where a mis-sized length prefix would hide, since the outer length still matches.

Two things this phase established that were not in the plan:

- **A relay path must not go through the wrapper layer.** These structs are fixed and allocate nothing, so an unknown field is dropped on decode and a re-encoded packet differs from the one received. Forward-compatibility lives in the primitive layer, which copies payloads verbatim. Written into the module documentation and asserted by a test, because it is an architectural constraint, not a caveat.
- **Deprecated in the schema is not absent from the wire.** `User.macaddr` has been deprecated since 2.1.x and 2.7.26 still emits it. A codec built from field numbers alone will miss it and fail byte identity.
- **Absent in the message is not empty on the wire.** The default channel carries no `name`, and the name to hash is the modem preset name. Folding the empty string gives `0x02` where the oracle uses `0x08` — wrong for the most common channel on the network, and silent.

`ChannelSettings` is wrapped as well, which closes a loop: reference bytes → PSK short index → expansion → `channel_hash` → `0x08`, the value the oracle was observed to use. That path is now a test.

**Not wrapped yet**, and not needed before L2: `Position`, `Routing`, `NodeInfo`, `MeshPacket`. The pattern is mechanical and the corpus can verify the first three.

**Gate:** every message in the corpus round-trips decode→encode bit-identically. *The corpus now exists — `tests/captures/fromradio_corpus.json`, 43 messages, 9 variants — and their encoder was measured to be canonical, so the gate is reachable. This is unblocked and ready to implement against.*

## L4 — conformance, both directions

The layer that actually proves compatibility:

- *their encoder → our decoder* — we read what they write
- *our encoder → their decoder* — **they read what we write** — **ACHIEVED 2026-08-16**

The second is the direction that fails in the field, and the one a lenient decoder hides.

**2026-08-16 — an unmodified stock node accepted a frame built entirely by our encoder.** Our SX1262 transmitter put the bytes on the air verbatim; the stock Heltec running `2.7.26.54e0d8d` logged:

```
[Router] Received text msg from=0x7e570001, id=0xbadc0de, msg=tethermesh-conformance-1
[Router] Rebroadcast received message coming from 1
```

It decrypted, decoded, displayed the text and **relayed it** — treating us as a peer on the mesh. One line validates the whole stack simultaneously: header layout and endianness, flag packing, channel hash, PSK expansion, AES key schedule, CTR keystream, nonce byte order, protobuf encoding with proto3 default omission, frame assembly, sync word and modem parameters. Any one of them wrong and there is no log line at all. Record in `tests/captures/conformance_record.json`.

**They list us as a peer too.** A `User` on portnum 4 was accepted and stored; the stock node now reports node `0x7e570001`, id `!7e570001`, long name `tethermesh`, short name `tm`, hw_model 43. That exercises the `User` wrapper in the emitting direction, including `macaddr` — deprecated since 2.1.x, still emitted by 2.7.26, and included precisely because byte-level agreement is decided by the wire and not by the schema.

**And they answer us.** A traceroute addressed to the stock node — not a broadcast — was accepted, traced and answered; our receiver captured the reply and decrypted it to `RouteDiscovery{snr_towards:[26]}` with `request_id` echoing our packet id. That is a complete round trip: we transmit, they process, they reply, we read it.

**The interoperability gate in this document reads: "a physical, unmodified device must show our node, render our text, accept a direct message, and list us in a route trace."** Three are done outright and the fourth is done for channel encryption — an addressed, non-broadcast packet was accepted and answered. Only the PKI path is untested, which is L6.

One behaviour worth carrying forward: a repeated `(from, id)` is silently dropped by their duplicate suppression — exactly what `history.rs` implements, observed from the far side. A rerun with a stale id is indistinguishable from a frame that never arrived, which cost a debugging cycle before the id was made overridable.

**2026-08-16 — the panic-free half of this gate is met, and the check that was supposed to prove it turned out to prove nothing.** `check_rust_rules.sh --binary` was vacuous three ways over: an `.rlib` exposes almost no symbols, `--emit=obj` under LTO produces bitcode that reads as an empty symbol table, and the patterns matched legacy mangling while the toolchain emits v0 — where panic paths appear as names like `len_mismatch_fail` containing no form of the word "panic".

Fixed, it failed immediately: `frame::encode` had a live panic path through `copy_from_slice`. Every such call is now an iterator zip, and the artifact has **no undefined references at all** — not even `memcpy`. The check refuses bitcode and refuses artifacts too bare to be meaningful, `check_all.sh` runs it on every invocation, and both the panic path and the vacuity were observed red.

**Gate:** both directions clean across the corpus, plus fuzzing that reaches the panic-free requirement — `tools/check_rust_rules.sh --binary` showing no panic machinery linked. That is the evidence for the safety claim; fuzzing alone only shows nothing crashed today.

*Status, stated precisely, because "ACHIEVED" above and "outstanding" here have read as a contradiction:*

- *their encoder → our decoder* — **met across the corpus**, 43/43 bit-identical (L3).
- *our encoder → their decoder* — **demonstrated, not yet corpus-wide.** A stock node accepted our text frame, our `User`, and answered our traceroute. That is three constructed frames, not a systematic sweep of every corpus message back at them.
- *panic-free artifact* — **met and continuously enforced** by `check_all.sh`.
- *fuzzing* — **met 2026-08-16**, and deliberately scoped as complementary rather than as the evidence.

**On what the fuzzing is and is not.** Two tests in `tests/host_unit`. The first drives every parse entry point — `Header::decode`, `frame::peek_header`, `frame::payload`, `Reader`, and the `Data`/`User`/`ChannelSettings` wrappers — with 20,000 rounds of random bytes at every length from 0 to 512. The second flips one to three bits in **real captured frames**, 12,000 mutations, because uniform random bytes essentially never produce a plausible 16-byte header and the interesting failures live in the neighbourhood of valid input: length prefixes pointing slightly too far, almost-correct wire types, off-by-one payload bounds.

Both use a fixed-seed xorshift rather than `rand`, so any failure replays exactly. A fuzz failure nobody can reproduce is not a bug report.

**This does not replace the artifact check, and the gate above still says so.** Kani proves the parse path panic-free over *every* input but only to a bounded length; these reach unbounded lengths at the cost of sampling rather than proving. The panic-free *claim* still rests on `check_rust_rules.sh` finding no panic machinery linked. Both fuzzers were seen red against injected faults — a byte-order flip in `Header::encode`, and a payload bound that lets `frame::payload` overrun.

## L5 — routing

Managed flooding: hop-limit decrement, duplicate suppression keyed on sender and identifier, the SNR-scaled contention window, and duty-cycle accounting.

**2026-08-16 — the load-bearing assumption is SETTLED, and the answer is yes.** Stock 2.7.26 nodes relay traffic on channels they cannot decrypt: measured on two Heltec V3s, with a same-channel control proving the link and a frequency check proving the receiver still heard the transmitter. The relaying node never decrypted, never handed the packet to a module, and rebroadcast it anyway with `hop_limit` decremented and **the originator's channel hash preserved**. Detail and the log-line evidence in `meshtastic/WIRE_REFERENCE.md`.

This is the assumption the whole extension suite rests on, so L7 is no longer contingent on it. It also removes the reason to hedge L5's design.

**2026-08-16 — duplicate suppression is done**, ahead of the rest of L5, because it needs no header layout: it takes two numbers and answers whether they have been seen. `meshtastic/core/history.rs`, a fixed-capacity age-evicting ring, default 400 entries to match what the reference was observed to use.

Deliberately **not** included at the time: a `should_relay`. Suppression is one input to the rebroadcast decision; the others are the hop limit, the contention window and the duty budget — and, then, whether a node relays on channels it cannot decrypt. Writing that function while the last one was open would have meant taking a position on an open question in code, which is how an assumption stops looking like one.

**That reason expired almost immediately, and the stale text outlived it by the whole project.** The relay question was not settled late — it was one of the *first* things hardware established. Bench work began at 01:44 on 2026-08-16 with the airtime comparison; the relay finding landed at **02:20** (`7bae50c`), the third hardware commit, **before the 16-byte header layout was known** (02:40), before AES-CTR (02:44), before any of the three conformance results (03:23–03:30), and before L6 decrypted anything (04:00).

So the two paragraphs above stood falsified from the very beginning of the hardware phase and were carried through every result that followed. **`should_relay` was then deliberately withheld for the project's entire productive life on a justification that had expired thirty-six minutes into using the radios.** That is the cost of stale prose, stated concretely: not an inaccuracy in a document, a design decision frozen by one.

`should_relay` landed 2026-08-16 in `meshtastic/core/routing.rs`, with the contention window and duty-cycle accounting it was genuinely waiting on.

**2026-08-16 — the rest of L5 is implemented.** Three pieces:

- **`meshtastic/core/airtime.rs`** — LoRa time-on-air from **Semtech's** published formula (the radio vendor's, not the reference implementation's), plus a caller-owned `DutyCycle` budget. Anchored by two independent checks: sixteen preamble symbols reproduce the 131 ms the reference was observed to report, and a 70-byte packet models 1.18% above the simulator's 755 ms — the direction and roughly the magnitude by which the simulator's bitrate is already known to be optimistic against silicon.
- **`meshtastic/core/routing.rs`** — the SNR-scaled contention window and `should_relay`, combining hop limit, duplicate suppression, role and duty budget into one decision with a distinct reason for each refusal. A full budget is reported separately from a loop, because one is a property of this node and the other of the frame.
- **17 tests**, every one mutated red first: inverting the contention window, shortening the preamble, letting `charge` saturate instead of refuse, dropping the hop decrement, making routers defer, and letting the decision spend the budget.

**One gap is recorded rather than papered over.** The contention window's *bounds* have never been observed — only the documented direction that a weaker signal takes a shorter backoff. Ours is our own parameterisation, marked as such in the module and listed as item 7 in the wire reference's UNVERIFIED section. Frames are unaffected and suppression still works, so interoperability holds; our timing will simply not match a stock node's.

**Gate, restated:** what remains for L5 is *validation against the reference across a topology matrix*, not implementation.

~~**And the assumption everything else rests on.** Whether nodes relay traffic on channels they cannot decrypt is currently PLAUSIBLE, UNPROVEN. Settle it here: several instances, controlled topology, inject a frame on a channel none of them holds, observe whether it is repeated. In simulation topology is a coordinate rather than a hardware problem.~~ **Struck 2026-08-16 — answered, and the answer is yes.** Kept struck rather than deleted because the two paragraphs above only make sense against it.

**A note on how this contradiction survived**, since it is the same failure the 2026-08-16 audit chased through three other documents: the settling measurement was appended at the top of the section, and the two paragraphs stating the opposite were left in place below it. Nothing was edited to become false — a true statement was added and its predecessors were not retired. `tools/check_docs.sh` cannot catch this; a document that contradicts *itself* in prose is exactly the residue that gate does not cover.

**2026-08-15 — the simulation route was tried and does not work.** Two local instances can be made to form a mesh, by enabling `UDP_BROADCAST`; the process-local SimRadio alone will not do it. But captured UDP traffic carries `hop_limit = 0`, so those packets are never candidates for rebroadcast and the managed-flooding decision is never reached. A local UDP mesh produces traffic that looks like a mesh and cannot answer this question. Settling it needs two real radios. Detail in `meshtastic/WIRE_REFERENCE.md`.

### The gap this phase did not scope: acknowledgement and retransmission

**Recorded 2026-08-16.** L5 was scoped as hop-limit handling, duplicate suppression, the contention window and duty accounting. It never mentioned delivery, so the phase reads as complete while a load-bearing part of the protocol is absent. That omission was not deliberate — it was unstated, which is worse.

**This belongs here, not above.** `want_ack` is a header flag this crate already parses and encodes; `ROUTING` is portnum 5 and carries the responses; upstream's documented routing falls back *"to flooding on the final retry"*. And nothing below supplies it: LoRa has forward error correction and a CRC, but **no ARQ at all**. A frame lost beyond FEC's reach is lost silently. Flood redundancy raises the odds of arrival and is not delivery confirmation.

**What is missing, concretely:** emitting a routing acknowledgement for a `want_ack` packet addressed to us; matching an incoming acknowledgement to a pending transmission; a retransmission policy; and the pending-transmission queue.

#### Design constraints, which the crate rules already fix

- **No clock in here.** A deadline arrives as `now_us`, exactly as `DutyCycle` takes it. A hidden clock would be untestable and unportable.
- **No allocation.** The pending queue is caller-provided and fixed-capacity, like `PacketHistory`.
- **No global state.** It is owned by the caller.
- **Retransmission is airtime**, so it must be charged through `DutyCycle` like any other transmission. A retry policy that can outrun the duty budget is a bug, not a tuning choice.

#### Match upstream, or design it properly?

The question splits, and the halves have different answers.

**The wire format must match exactly, and is not a design space.** What an acknowledgement *is* — portnum 5, the `request_id` echo, the flag bit — is the protocol. An acknowledgement a stock node does not recognise is not an acknowledgement.

**The policy — how many retries, what backoff, when to stop — is local behaviour, but it is not free to choose.** Retransmission spends a *shared* resource, and on a flood mesh each retry is re-broadcast by every neighbour that hears it, so the cost multiplies by the local node count. A policy more aggressive than upstream's would take more than its share of a common channel and degrade the mesh for stock nodes that have no say in it.

So: **measure upstream's policy first and treat it as a ceiling, never a target.** Being less aggressive is always safe for the network and costs only our own delivery odds. Being more aggressive is antisocial, and being *differently* aggressive makes field failures hard to attribute — the same reasoning behind the instrument rule.

Where measurement shows upstream's policy is genuinely poor — synchronised retry storms from a fixed backoff, say — deviate **downward**, and write down both what they do and what we do instead. That is the wire reference's standing instruction for a mismatch, applied to behaviour rather than bytes.

**The extension suite is the opposite case.** L7 defines new portnums with no compatibility constraint, so there the answer is to design it correctly from the start rather than inherit anything.

**This project has now twice invented a parameter and been badly wrong** — the contention window's scale, off by more than an order of magnitude, and a part credited with a crypto accelerator it does not have. Both were caught by measuring. That is the argument for measuring retry behaviour before choosing a policy, rather than after.

#### How to measure it, with the bench that exists

Nothing new is needed. Make a stock node originate a `want_ack` packet and **withhold the acknowledgement** — our receiver sends none, so this is the default. Then count retransmissions and time the intervals from the sniffer's `RAWFRAME` output, which already timestamps and prints every frame verbatim.

That yields the retry count, the backoff shape, and whether the interval is fixed or randomised. It also settles a related question this project has assumed nothing about: **whether an overheard rebroadcast of one's own packet is treated as an implicit acknowledgement.** Withholding an explicit ack while a relay does occur separates the two.

**2026-08-16 — the measurement is done.** Three attempts per message, roughly 7 s apart (6.38–7.67 s over eight samples), header byte-identical across attempts, payload re-encrypted each time. Four trials, recorded in `tests/captures/retry_behaviour.json` and summarised in the wire reference.

So the ceiling is **3 attempts at ~7 s**. Our policy sits at or below that.

**One thing the measurement deliberately does not claim.** Whether retry behaviour differs *per hop* is untested: the header did not change across attempts, but with two nodes there is no multi-hop path for next-hop routing to engage on, so the single-hop case may simply not exercise the documented *"flooding on the final retry"* fallback. That needs a third node, and until then the implementation should not encode a position on it.

**And one deliberate deviation, with its justification.** We need not re-encrypt per attempt. Holding the encoded frame and resending it verbatim is cryptographically safe — nonce reuse only endangers *different* plaintexts — costs less state under the no-allocation rule, and is indistinguishable to a receiver, which drops the repeated `(from, id)` as a duplicate regardless.

**2026-08-16 — implemented.** `meshtastic/core/delivery.rs`: a caller-owned fixed-capacity `Outbox<N>`, `RetryPolicy::MEASURED_CEILING` (3 attempts, ~7 s) alongside `SEND_ONCE`, acknowledgement construction from the measured bytes, and matching on `Data.request_id` alone. Ten tests, each seen red first.

The shape follows the crate's existing seams rather than inventing new ones: `now_us` is an argument as it is for `DutyCycle`, the queue is caller-provided like `PacketHistory`, and `next_due` **checks** the duty budget without charging it — the caller charges on actual transmission, exactly as `should_relay` does. Charging in the decision would bill a node for a frame it had not sent.

**Gate for this item:** retry count and backoff recorded in `meshtastic/WIRE_REFERENCE.md` with the capture behind them, and our policy stated as at-or-below what was measured. ***Met.***

**2026-08-16 — validated on hardware, with a control.** A stock node sent a `want_ack` direct message twice: unacknowledged it retransmitted three times, acknowledged it sent once. The acknowledgement was built by `delivery::acknowledgement` rather than reassembled in the test, so what was validated is the shipped path. Record in `tests/captures/routing_ack.json`.

**Still not implemented, deliberately:** emitting an acknowledgement requires framing and encrypting it, and measurement showed the reply travels *channel-encrypted even when acknowledging a PKI message*. That is a caller decision about which key to use, so `delivery::acknowledgement` returns the `Data` and stops there.

**Gate:** relay behaviour matches the reference across a topology matrix, and the relay question is answered in the wire reference either way. *Now gated on hardware, not on effort.*

## L6 — PKI direct messages

X25519 key agreement and the AEAD path for direct messages. Identity persistence is a caller concern; this layer provides the construction.

**2026-08-16 — the construction is now fully specified**, so this phase is implementation rather than investigation:

```
key agreement  X25519
KDF            SHA-256 over the raw shared secret
cipher         AES-256-CCM, 8-byte tag, full 32-byte key
nonce (13 B)   packet_id (u32 LE) || extra_nonce (4 B) || from (u32 LE) || 0x00
payload        ciphertext || tag(8) || extra_nonce(4)
channel byte   0x00 distinguishes a PKI packet on the wire
```

**Direct messages are authenticated and channel messages are not.** The forgery weakness this project keeps flagging applies to channel traffic only; CCM's tag means a forged DM fails verification. That asymmetry is worth carrying into the suite's design, because it narrows what the AEAD extension has to add.

Two behaviours constrain any implementation: a stock node uses PKI for DMs **by default and refuses to fall back** to channel encryption without the destination's public key, so a node that never publishes a key cannot be messaged directly at all; and the key must have been learned in the current boot.

**2026-08-16 — the first half of the gate is met.** `meshtastic/core/sha256.rs` and the CCM half of `meshtastic/core/crypto.rs` decrypt a real captured direct message to `Data{portnum=1, payload="pki-probe-B"}`, using our own SHA-256 for the KDF and our own AES-256-CCM.

SHA-256 is checked against the published FIPS 180-4 vectors first, and then against something better: it reproduces the exact shared-key prefix a stock node logged while encrypting to us. AES-256 needed its own key schedule rather than a longer loop — the extra `SubWord` every eighth word is easy to omit and yields a cipher that is self-consistent and wrong.

Tamper tests matter more here than anywhere else in the crate, because **this is the one layer that can tell a forgery from a message.** Flipping any byte of ciphertext or tag, or using the wrong key, returns `Unauthentic` rather than plaintext.

**X25519 is done** — `meshtastic/core/x25519.rs`, five 51-bit limbs, Montgomery ladder, fixed-chain inversion, arithmetic conditional swaps. It matches the RFC 7748 vectors, agrees in both directions, rejects small-order public keys, and reproduces the bench exchange: our published key, their key, the same shared secret, the same derived AES key, the same decrypted text.

That completes the chain in our own code, with no dependencies: **key agreement → SHA-256 KDF → AES-256-CCM → protobuf**, verified against a message a stock node actually sent.

The first attempt was wrong in a way worth recording: `fe_sub` biased by p instead of 2p, and the final reduction was muddled. The result was a field implementation that is entirely self-consistent — it adds, multiplies, inverts and round-trips happily — and disagrees with the published vectors. No property test would have found it.

**2026-08-16 — THE SECOND HALF IS MET. A stock node accepted a PKI direct message built entirely by our code.** An unmodified Heltec V3 on `2.7.26.54e0d8d` logged:

```
[Router] Attempt PKI decryption
[Router] Attempt decrypt with nonce:  21 0d ad 0b 21 0d 00 52 01 00 57 7e 00
[Router] Attempt decrypt with shared_key starting with:  d8 85 d2 24 e6 cc 3d e0
[Router] PKI Decryption worked!
[Router] Packet decrypted using PKI!
[Router] Received text msg from=0x7e570001, id=0xbad0d21, msg=tethermesh-pki-1
```

Record in `tests/captures/pki_dm_outbound_record.json`. Three things are confirmed at once, and the second and third are worth more than the headline:

- **The nonce construction, verified from the far side.** The receiver logged the nonce it reconstructed: `21 0d ad 0b | 21 0d 00 52 | 01 00 57 7e | 00` — packet id LE, extra nonce LE, `from` LE, then `0x00`. Until now that layout was read off a message *they* sent; it has now been independently rebuilt by the reference from a message *we* sent.
- **The shared secret agrees in both directions.** Their derived key prefix, `d8 85 d2 24 e6 cc 3d e0`, is byte-identical to the value already recorded in `WIRE_REFERENCE.md` from the inbound exchange. Our X25519 and our SHA-256 KDF produce the key a stock node produces, now demonstrated **both ways** rather than once.
- **It reached the application layer**, decoded at `Portnum=1`, marked `PKI`, and rendered as text.

**Gate:** decrypt a captured direct message; produce one the reference accepts. ***Both halves met.***

**One incidental observation, recorded but not promoted.** While relaying our broadcast NodeInfo the node logged `rx_snr found. hop_limit:2 rx_snr:6.750000` and then `Setting tx delay:3360` — a 3360 ms delay at 6.75 dB, which is 120 slots at the 28 ms slot time. That is the first direct sight of the contention-window mechanism `WIRE_REFERENCE.md` item 7 lists as unverified. **It settles nothing:** one sample cannot distinguish a deterministic delay from a single draw out of a random window, and gives no second point to fit a slope. A sweep across SNR would.

## L7 — the extension suite

**Specification first, implementation second.** `suite/README.md` records the shape: authenticated channels with the AEAD tag bound to the cleartext header as additional data; managed groups with an owner, roster and revocation; location with pluggable sources.

Writing the spec first is not process for its own sake — the spec is the deliverable that adoption runs on, and an implementation written before it will quietly become the specification by default.

**Gate:** two instances exchange authenticated extension traffic that an unmodified reference node relays without reading; a forged sender fails the tag; a node without the extension falls back and still communicates.

## L8 — release engineering

The C ABI surface, `cbindgen` header, and the artifact discipline `DISTRIBUTION.md` commits to: a declared target set, reproducible builds, `tm_abi_version()`, a CI size budget, and a minimal C consumer built against each released archive.

**Gate:** every promise in `DISTRIBUTION.md` has a check behind it, and the caveat appears in the release notes, the archive and the generated header.

---

## What stays open

**The physical layer — mostly closed, and by exactly the route predicted.** The claim here was that the sync word and per-preset modulation parameters could not be established without real silicon. That held, and silicon settled them: the sync word is resolved (`0x0740=0x24`, `0x0741=0xB4`, confirmed by decoding real traffic) and LongFast's parameters with it. **Sixteen presets remain** — bounded, mechanical, same method.

**The interoperability gate — ALL FOUR, on hardware.** A physical, unmodified device must show our node, render our text, accept a direct message, and list us in a route trace. As of 2026-08-16 a stock Heltec on `2.7.26.54e0d8d` shows us as a peer, renders our text, answers an addressed traceroute, **and accepts a PKI direct message** — decrypting it with a shared secret it derived independently and matching ours byte for byte. The last of these was L6's open half and closed on 2026-08-16; see that section for the log.

Simulation green is not interoperability green, and treating it as such is the most likely way this project fools itself. That warning is retained deliberately — the items above were closed on hardware, which is the only reason they may be marked closed.

## Sequence

L0 and L1 are concurrent and unblock everything. L2 and L3 are independent of each other. L4 needs both. L5 can start after L2 since routing acts on the header alone. L6 and L7 follow L4. L8 runs alongside from L2 onward, because retrofitting the target matrix and reproducibility is far more expensive than carrying them.
