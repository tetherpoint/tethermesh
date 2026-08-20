<!-- SPDX-FileCopyrightText: 2026 The tethermesh Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# tethermesh

**A clean-room-built Meshtastic-compatible stack, with new extensions.**

Status: **L0–L6 complete.** Wire reference settled, codec and crypto implemented, routing done, and a stock unmodified node accepts our traffic — including PKI direct messages — on real hardware. Extension suite (L7) and release engineering (L8) remain. Licensed **Apache-2.0**.

## Purpose

**To let anyone build on the Meshtastic mesh without inheriting its licence, its firmware, or its limits.**

Meshtastic works and its network exists. What it lacks is a way for someone else to add capability to that network: the firmware and schemas are GPL-3.0, so building on them means becoming GPL-3.0, and the protocol has no authentication on channel traffic at all. tethermesh answers both. It is an independently written, permissively licensed implementation of the on-air protocol — usable from C, C++ or Rust firmware as an ordinary static library — plus an extension suite that adds authenticated messaging and managed groups **while remaining invisible to, and carried by, unmodified stock nodes**.

The goal is adoption by other implementers, including commercial ones. Everything below follows from that.

## Principles

These are enforced by `tools/check_all.sh` on every run, not left to discipline. Each has already caught a real defect.

- **Clean-room from the protocol, never from the source.** Facts about the wire may be learned; expression may not. The `.proto` files are read as specification and never vendored or run through a code generator; the radio-driver library this ecosystem builds on — RadioLib, which is **MIT** — may be read for facts and is never derived from. Enforced by `tools/check_cleanroom.sh`, over the working tree *and* the vendored submodules.
- **No panics on hostile input.** This parses untrusted frames from a public mesh. With `panic = "abort"` a panic halts the node, so an unchecked panic path turns a memory bug into a remote denial of service. No `unwrap`, no indexing, no bare arithmetic. Checked against the **built object**, not the source — which is what caught a live panic path in `frame::encode` that source review had missed.
- **No allocation.** `no_std`, no global allocator, caller-provided buffers. An allocator on a microcontroller is a failure mode, not a convenience. This is why a formally verified crypto crate was rejected after measurement.
- **No mutable global state.** `Send`/`Sync` do not cross an FFI boundary that a foreign RTOS scheduler calls into, so concurrency safety is a property of API shape, not of the language.
- **No `unsafe`** in our own code.
- **Nothing overstated.** Documentation separates *proven* from *checked against someone else's answer* from *neither*, and says which document would settle an open claim. See `docs/FORMAL-VERIFICATION.md`.
- **Green and red, with red proven.** Every guard has been observed to fire. A test that has never failed is not yet a test.
- **Measure, don't assume.** Where a figure could be derived or observed, it is observed. Two claims written from documentation alone turned out wrong on contact with hardware, and both were caught this way rather than by review.

## Enforcement

One entry point, `tools/check_all.sh`, runs every applicable check and exits non-zero if any fails. Nothing here is advisory.

- **`check_all.sh`** — the single gate. Also `--pending`, which lists checks that cannot run yet and why, so a gap is visible rather than forgotten.
- **`check_spdx.sh`** — every file declares its licence, inline or via `REUSE.toml`. Prevents a file arriving later with no header and inheriting nothing.
- **`check_cleanroom.sh`** — the GPL boundary. Refuses vendored `.proto`, generated `*.pb.*`, GPL licence headers and radio-library references; sweeps the vendored submodules' working trees too, since `git ls-files` reports a submodule as one gitlink and would otherwise never see the code that actually compiles.
- **`gpl-patterns.txt`** — the forbidden strings, as data rather than code. A scanner that defines its own blacklist cannot check itself, so this file is the only thing exempt; deleting or emptying it makes the gate refuse rather than silently pass.
- **`check_rust_rules.sh`** — no panics, no allocation, no mutable global state, no `unsafe`. Checks the crate attributes, then the **built object** for panic machinery and undefined references — which is what caught a live panic path source review had missed. Also enforces that field values reach `fiat-crypto` only through its bounds-typed wrappers.
- **`check_docs.sh`** — documentation cross-references must resolve: named tests must exist, the proof table must match the harnesses in both directions, `DEPS.md`'s pinned commits must match the actual submodules, cited tooling must be present.
- **`REUSE.toml`** — bulk licence annotation for files that cannot carry a comment header: JSON fixtures, `Cargo.lock`, `.gitkeep`. An exception here is deliberate and visible rather than a silent gap.
- **crate-level `deny` attributes** in `meshtastic/core/lib.rs` — `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `unsafe_code`, `missing_docs`. The compiler is the first line of enforcement; `check_rust_rules.sh` verifies the attributes are present *and* separately greps for local `#[allow]`, because a local allow silently defeats a crate-level deny and is invisible to review.
- **`measure_panic_symbols.sh`** — reproduces the dependency measurements the crypto decision rests on. Committed because a measurement nobody can re-run is a claim.
- **`cargo kani`** — machine-checked proofs over the parse path in `meshtastic/core/proofs.rs`, covering every possible input rather than the ones a test happened to try.

Every one of these has been observed to fire against a deliberately introduced fault. Several were found to be vacuous when first tested — passing while proving nothing — and that is recorded in their headers rather than quietly fixed.

## Cryptography: verified where it counts, and offloadable

**The X25519 field arithmetic is formally verified and is not ours.** Multiplication, squaring, addition, subtraction, carrying, the 121666 scalar multiply, serialisation and the constant-time select all come from [`fiat-crypto`](https://github.com/mit-plv/fiat-crypto), generated from **Coq proofs** by MIT PLV — the same pipeline BoringSSL uses — and called unmodified from an in-tree pinned submodule.

**Be precise about the split, because it matters.** What is proven is the field arithmetic. The Montgomery ladder and the fixed-chain inversion built on top are **ours and are not proven**; they are checked against RFC 7748's published vectors and against two independent implementations (`x25519-dalek` and the formally verified `libcrux-curve25519`) across hundreds of random agreements per test run. That split is deliberate: the ladder is short and public, while field arithmetic is where subtle bugs live — and the one bug this project actually shipped, a `fe_sub` biased by `p` instead of `2p`, was in the half that is now verified.

fiat-crypto was chosen because it is the only option measured that is formally verified **and** costs nothing against the rules above: no allocator, and **zero panic paths above a no-dependency baseline**. Measured, not assumed — `tools/measure_panic_symbols.sh` reproduces it.

**Hardware acceleration is a supported seam.** `meshtastic/core/backend.rs` lets an implementer route any subset of the primitives — X25519, SHA-256, AES-CTR, AES-CCM — onto silicon, per primitive rather than all-or-nothing, with a software default for everything not overridden. The reason is side-channel resistance and key custody rather than speed: a part with key storage can perform an agreement using a private key that never becomes addressable, which is a promise software on a general-purpose core cannot make.

**With a caveat worth stating up front: X25519 acceleration is rare.** Of nine parts surveyed in `docs/HARDWARE-BACKENDS.md`, exactly **one** accelerates Curve25519. Most parts advertising an "ECC accelerator" implement NIST prime curves only and cannot touch it — several even advertise constant-time point multiplication, on curves this stack does not use. Check the specific part; do not assume.

## What this is

A portable `no_std` Rust implementation of the Meshtastic on-air protocol, written from the published specification rather than derived from the upstream firmware, plus extensions that ride the same mesh at the same time. It links into C and C++ firmware as an ordinary static library — see `DISTRIBUTION.md` for the language rationale, the prebuilt artifacts and their caveat.

Two things live side by side on one radio, one preset, one mesh — not switched between:

- **Meshtastic-native channels.** Fully compatible: a stock, unmodified Meshtastic device sees a tethermesh node as an ordinary peer, reads its messages, and DMs it.
- **Extension channels.** Authenticated crypto, and groups with an owner, a member roster and revocation — carried on a private PortNum (≥ 256, the range upstream reserves for exactly this) which stock nodes **relay without being able to read**.

That second point is the structural fact the design rests on: Meshtastic's flood router decides on the unencrypted header, not on whether it can decrypt the payload. Extensions therefore travel over stock infrastructure for free.

The extension boundary is precise. Everything new lives in the payload and the channel/PortNum space; the 16-byte header and the modem preset are fixed, because changing either stops stock nodes relaying.

## Extensions that break compatibility, and where they live

**The compatibility claim above is the point of this repository, and it is narrow on purpose:** a stock node relays what it cannot read. Anything that breaks that stops being an extension in the sense used here.

Some work does break it — a different modulation, or a mode that deliberately silences the mesh in order to take a measurement. Neither can ride a PortNum, because both change the physical layer or the channel's availability rather than the payload, and a stock node cannot relay either. **That work lives in a separate repository, `tethermesh-extensions`. Nothing here depends on it, and taking this library never means taking it.**

The test is written the same way in both places, so it can be applied rather than argued. An extension belongs **here** only if both hold:

1. **an unmodified stock node relays it**, and
2. **a node without the extension still communicates normally.**

Work that fails either test is outside this repository *and outside the compatibility claim this repository makes*. That boundary is stated from both sides deliberately: a reader who finds one of those crates first should not have to infer it.

## What this library is, and what has to sit around it

This is a **protocol layer**. It is not a node. An implementer supplies a radio driver below and a scheduler above, and needs to know exactly where the seam falls — including one capability the protocol requires that this library does **not** currently provide.

### Below — yours, and deliberately not ours

The radio driver: the part's command set, SPI, interrupts, and programming the modulation. From it you get, at the physical layer:

- **Forward error correction** (the coding rate) and a **CRC**. FEC repairs some corrupted symbols; the CRC detects what it cannot.
- **Nothing else.** In particular there is **no retransmission below this library.** LoRa has no ARQ, no link-layer acknowledgement, no MAC-level retry. A frame that arrives corrupted beyond FEC's reach is simply lost, silently, and the physical layer neither knows nor cares.

`meshtastic/core/backend.rs` is the seam for routing cryptographic primitives onto hardware, if the part has it. A *radio* driver is not included at all — implementers have their own, and tying the stack to one part would narrow it for no benefit.

### Here — the protocol

The frame header, channel hashing, channel and PKI cryptography, the protobuf codec, and the routing decision: hop-limit handling, duplicate suppression, the SNR-scaled contention window and duty-cycle accounting.

### Above — yours, because this library holds no state it does not have to

- **The clock.** There is none in here. Anything time-dependent takes `now_us` as an argument — `DutyCycle` does exactly this — because a `no_std` library cannot portably know the time and a hidden one would be untestable.
- **The scheduler and the radio itself.** We return *"wait a backoff drawn from this window, then transmit if nobody else did"*. Waiting, drawing, and arbitrating access to the radio are yours.
- **Locking, if two tasks touch one context.** `DISTRIBUTION.md` forbids mutable global state precisely because `Send`/`Sync` do not cross an FFI boundary a foreign scheduler calls into — so concurrency safety here is a property of *API shape*, state in a caller-owned context, rather than of the language. One task per context needs no lock; sharing one needs yours. Nothing in this library can enforce that, and it does not pretend to.
- **Buffers, and they are not small.** Nothing here allocates, so every stateful type is yours to place. Measured sizes:

  | type | bytes |
  |---|---|
  | `DutyCycle` | 32 |
  | `Outbox<4>` | 1,096 |
  | `PacketHistory<64>` | 528 |
  | `PacketHistory<400>` | 3,216 |

  400 is the history depth the reference was observed using. A node carrying that plus a small outbox needs roughly **4.3 KB of state**. This is the practical shape of "no allocation": the memory does not vanish, it becomes yours to place deliberately.

  **Where you place it is genuinely your call, and the stack is a legitimate answer.** "No allocation" constrains *this library* — no global allocator, no heap — and says nothing about your RTOS, which can size a task stack however it likes. These types are also task-lifetime rather than call-lifetime: a `PacketHistory` exists to persist across packets, so declaring one in a task function and holding it for the task's duration is idiomatic, not a misuse. What matters is that the RAM is *accounted* somewhere deliberate. Two ways to get that wrong: putting 4 KB of state on a default-sized task stack, and assuming a static context is free of the sharing question.

  To size a stack you also need our call-depth usage, which is separate from the structs above. Measured on the Cortex-M33 object by summing frame allocations along the deepest call chain:

  | chain | bytes |
  |---|---|
  | `ccm_decrypt_in_place` (deepest in the library) | 696 |
  | `ccm_encrypt_in_place` | 664 |
  | `x25519` scalar multiplication | < 500 |

  The Montgomery ladder is iterative, so X25519 is not the deep one — the AES key schedules are. **Budget ~1 KB for this library's call depth**, on top of whatever state you place and your own frames. That number is reproducible from the build and will move if the code does; it is a measurement, not a guarantee.
- **Identity, key custody, persistence.**

### The gap you must fill yourself today: delivery

**There is no acknowledgement or retransmission in this library, and the protocol has one.** `want_ack` is a header flag that we parse and encode (`header.rs`), `ROUTING` is portnum 5 and carries the responses, and upstream's own documented routing falls back *"to flooding on the final retry"*. So this is not a layer above the protocol — it is **part of it**, and it is missing here.

Concretely, a caller wanting reliable delivery must currently implement: emitting a routing acknowledgement for a `want_ack` packet addressed to it, matching an incoming acknowledgement to a pending transmission, a retransmission policy, and the pending-transmission queue itself.

Flood routing gives *redundancy* — several neighbours may relay the same frame — which raises the odds of arrival. **It is not delivery confirmation**, and treating it as one is the mistake this section exists to prevent.

See `PLAN.md` § L5 for the design constraints this has to satisfy and what about upstream's retry behaviour is still unmeasured.

## Clean-room, and why it is enforced rather than encouraged

Meshtastic's firmware and its protobuf definitions are **both GPL-3.0**. This project derives from neither. It is built from the `.proto` files read as *specification*, from published protocol documentation, and from our own on-air captures.

**Compatibility does not require shared code.** Two independent implementations interoperate by putting the same bytes on the air. That is what `meshtastic/WIRE_REFERENCE.md` is for, and why every acceptance gate is phrased as "a stock device reads us" rather than "we compile their source".

The line is **facts versus expression**. Field numbers, wire layouts and transcribed constants — sync word, header length, the default channel PSK — are facts about the wire. Implementation is expression. Reading upstream `.proto` as specification is fine; **vendoring one into this tree is not**, and neither is running a code generator over one, since the output derives from a GPL input. That is why the protobuf codec here is hand-written.

**When tempted, stop.** If a piece of work seems to need a routing decision or a state machine copied from upstream, that means the specification is under-documented. The correct response is to write down our own design and cite the wire behaviour it implements — never to read their source.

Enforced by `tools/check_cleanroom.sh`, which refuses vendored `.proto`, generated `*.pb.*` and GPL licence headers, and is red-tested against each.

**On RadioLib, and this changed on 2026-08-20.** It is **MIT**, and referencing or reading it is no longer refused. Documents here called it GPL-3.0 until 2026-08-17 — simply wrong about somebody else's project — and the blanket refusal that outlasted that correction was a stricter rule than the facts supported. **What still holds is non-derivation**, which `NOTICE` states and which no script can check: a gate that matched the word never proved anything about expression, only about vocabulary.

### The four sources, and nothing else

Everything in `meshtastic/WIRE_REFERENCE.md` is tagged with which of these it came from. Anything that came from none of them is listed as UNVERIFIED rather than assumed.

1. **The upstream `.proto` files, read as specification** — pinned at a named commit in `DEPS.md`. Field numbers and wire layouts are facts. The files themselves are never copied here and never run through a code generator, because generated output derives from a GPL input. That is why the protobuf codec is hand-written.
2. **Published protocol documentation.**
3. **Black-box observation of a pinned reference binary** — the `meshtasticd` container, fetched by digest and run as a program, never built from source. Using a program creates no derivative work; vendoring its code would.
4. **Our own on-air captures**, from real radios.

**Source is the line, not availability.** Reference *binaries* are installed — they have to be, to observe them. Reference *source* is never fetched at all: not fetched-then-ignored, never present. A source tree in the environment turns "read their implementation" from a deliberate act into an accident one `grep` away, and the temptation peaks exactly when someone is stuck on a mismatch. `check_cleanroom.sh` refuses any script that would clone or build it.

**The reference implementation, the harness that drives it, and every tool that touches its binaries live outside this repository**, in a sibling directory shared with the hardware bench. The strongest answer to *"what was in your source tree?"* is a source tree containing only our own work. What stays here is the **provenance of our claims** (`DEPS.md`) and fixtures that are ours to publish.

### Why hardware was necessary, and not a nice-to-have

The original plan assumed the reference's simulated radio would expose packed frames. **It does not, and that assumption was wrong in a way that would have produced confident, wrong results.** `SimRadio` is process-local: it hands a frame to a simulated PHY inside the same process and loops it straight back. No socket carries it, two local instances cannot hear each other, and what the oracle yields is a *field-level* view — every header field named with its value — which looks like a capture right up until you try to read a byte offset off it.

So the byte-level facts needed real radios. The bench is two Heltec V3s (ESP32-S3 + SX1262) about 3 m apart:

- **One runs stock Meshtastic**, the same build as the pinned container, so bench and oracle observations are comparable.
- **One runs our own SX1262 driver**, written from the SX126x datasheet's documented command set — not from any radio library. It prints raw PHY payloads verbatim and parses nothing, so the layout is decided by inspection afterwards rather than by whatever the receiver assumed.

Facts that only silicon could settle: the 16-byte header layout, the AES-CTR nonce construction, the sync-word register values, per-preset modulation parameters, and the load-bearing routing assumption that stock nodes relay traffic on channels they cannot decrypt.

That last one shows the method. Node B's channel PSK was replaced with sixteen zero bytes **while its name was left unchanged** — moving B's channel hash so it could not decrypt A, but leaving it on the same frequency slot, because the slot derives from the channel *name*. Renaming B would have made "did not hear" indistinguishable from "did not relay" in the log. B was confirmed still on the same frequency after the change, and then observed rebroadcasting a frame it could not read.

### Correctness is proven in both directions

A decoder that reads their traffic proves half of compatibility. The half that fails in the field is the other one, and a lenient decoder hides it.

- **Their encoder → our decoder.** Every message in the committed corpus decodes and re-encodes **bit-identically**.
- **Our encoder → their decoder.** A stock, unmodified node accepted a frame built entirely by our code, displayed the text, and relayed it. It lists us as a peer, answers an addressed traceroute, and **accepts a PKI direct message** — deriving the shared secret independently and matching ours byte for byte.

**The instrument rule.** Never measure a suspect through its own counters. For interoperability the stock device is the instrument; our own decoder reporting success is not evidence. Every acceptance gate is phrased as *"a stock device reads us"*.

**Every capture becomes a committed fixture**, so an interop bug turns into a regression test that is fixable without a radio — and so the full suite, the Kani proofs and `tools/check_all.sh` run against a bare clone with **no oracle, no network and no hardware**. Fixtures are synthetic-equivalent: our nodes, our channels, our own text, never third-party traffic.

### On a mismatch, and why this is the rule that matters

**Do not go looking for their source to explain it.** Go to the protocol definitions, the published documentation, or a capture. If none of those resolves it, that is not a blocker — it is a finding, and it gets written into `meshtastic/WIRE_REFERENCE.md` recording **both** behaviours.

Measurement has twice overturned something written confidently from documentation alone: a part credited with a crypto accelerator it does not have, and a routing parameter whose real value was more than an order of magnitude off the guess. Both were caught by measuring rather than reviewing, which is the argument for the discipline in one line.

## Layout

```
meshtastic/WIRE_REFERENCE.md   the on-air facts, every claim sourced
meshtastic/core/              header · channel hash · AES-CTR · protobuf codec
meshtastic/routing/           managed flood · dedup · hop limit · duty accounting
suite/                        the extension suite and its specification
instruments/                  test instrumentation — the SX1262 receiver the
                              wire reference was measured with. Not a driver
                              for the stack, and not linked into anything.
tests/host_unit/              algorithmic tests, green and red
tests/captures/               replay fixtures, synthetic-equivalent
DEPS.md                       what every result was obtained against
tools/check_cleanroom.sh      the GPL gate
```

Nothing here needs them to be verified: every fixture the tests read is committed under `tests/captures/`, so the full suite, the proofs and `tools/check_all.sh` run against a bare clone with no oracle, no network and no hardware. The reference implementation, the harness that drives it and the tools that fetch it are **not** in this tree. They live in a sibling directory alongside the hardware bench's copy, untracked — see `TESTING.md` and that directory's own `RULE.md`. What stays here is the provenance of our claims and fixtures that are ours to publish.

Portable `no_std` Rust with no hardware dependency, exported over a C ABI. **A radio driver is deliberately not included** — implementers have their own, and tying the stack to one part would narrow it for no benefit.

`instruments/` does not contradict that. It holds the SX1262 receiver used to *measure* the wire reference: written from the vendor datasheet, it prints raw PHY payloads verbatim and parses nothing, so a layout claim is decided by inspection afterwards rather than by whatever the receiver assumed. It is committed because it **is the evidence** for the clean-room claim and the instrument behind every byte-level fact — a claim of that kind whose evidence is absent is worth nothing. It is not linked into the crate and not shipped. See `instruments/README.md`.

## Read this first

`meshtastic/WIRE_REFERENCE.md`. It is pinned to a specific upstream schema commit and splits **verified** facts from **unverified** ones, because the wire format moves between releases and because several widely repeated claims turned out to be stale. Notably: `DATA_PAYLOAD_LEN` is 233, there are 17 modem presets rather than the 7 usually listed, and routing has included next-hop since firmware 2.6.

All six items that once blocked the frame codec are now settled on hardware — header byte layout, CTR nonce, channel hash, PKI/DM scheme, sync-word register values and per-preset modulation parameters. What remains open is listed in that document's UNVERIFIED section with the measurement each would need.

## Working conventions

Beyond the principles above, which are enforced mechanically:

- **No silent no-ops.** Anything unimplemented says so and exits non-zero. A check that passed because there was nothing to check is indistinguishable from a real pass in a log, which makes it worse than a failure. Every gate here refuses rather than shrugs.
- **Provenance, or it is not a result.** A compatibility claim that cannot name the version it was obtained against is not a claim. `DEPS.md` records the pinned schema commit, the reference build and its digest, the toolchain, and the vendored submodules — updated at every milestone, not at release.
- **A measurement nobody can re-run is a claim.** Where a figure decides something, the method is committed as a script rather than described in prose. `tools/measure_panic_symbols.sh` exists because a table of numbers with no recorded harness could not be defended or refuted when someone tried.
- **Corrections stay visible.** Where a conclusion changed, the superseded reasoning is struck rather than deleted, and the reason it was wrong is recorded next to it. Several entries here were confidently wrong; the record of *how* is more useful than a tidy document.

## How this was built

tethermesh was written with **Anthropic's Claude Opus 5**, working against the bench and the pinned reference described above.

That is recorded for the same reason everything else here is: so a reader can weigh the evidence. It changes nothing about what is claimed — the gates in `tools/` do not care what wrote the code, the proofs in `meshtastic/core/proofs.rs` hold or they do not, and a stock node either accepted our frames or it did not. Those checks exist precisely so that correctness rests on measurement rather than on who or what produced a line.

It is worth knowing for the clean-room position specifically. The rule was enforced mechanically throughout rather than trusted: reference source was never fetched into the environment, `tools/check_cleanroom.sh` gates every run over the working tree and the vendored submodules, and the history was audited separately for material that had been committed and later removed. The instrument that measured the wire is committed in `instruments/` so the byte-level facts can be re-derived independently.

## Licence

**Apache-2.0**, for the code and the specification alike. See `LICENSE` and `NOTICE`; the reasoning is in `docs/LICENSING-OPTIONS.md`.

Apache-2.0 over MIT for its **explicit patent grant**, because the strategy is adoption by other implementers — possibly commercial ones — of a *cryptographic* suite, which is where patent uncertainty is taken most seriously.

The specification carries the same licence rather than CC-BY-4.0, for the same reason: **CC-BY-4.0 licenses no patent rights at all**, so a separate spec licence would deny a patent grant to precisely the adopter this project exists for — the one who reads the specification and writes their own clean-room implementation.

`suite/README.md` additionally carries an **unconditional patent non-assertion pledge**. You may implement this specification independently, commercially, in any language, without permission and without telling anyone.

Every file declares its licence; `tools/check_spdx.sh` enforces that, so a file cannot arrive undeclared. Vendored submodules under `third_party/` retain their own licences — see `DEPS.md` and `NOTICE`.
