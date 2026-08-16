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

- **Clean-room from the protocol, never from the source.** Facts about the wire may be learned; expression may not. The `.proto` files are read as specification and never vendored or run through a code generator; the GPL-3.0 radio-driver library this ecosystem builds on is off limits entirely. Enforced by `tools/check_cleanroom.sh`, over the working tree *and* the vendored submodules.
- **No panics on hostile input.** This parses untrusted frames from a public mesh. With `panic = "abort"` a panic halts the node, so an unchecked panic path turns a memory bug into a remote denial of service. No `unwrap`, no indexing, no bare arithmetic. Checked against the **built object**, not the source — which is what caught a live panic path in `frame::encode` that source review had missed.
- **No allocation.** `no_std`, no global allocator, caller-provided buffers. An allocator on a microcontroller is a failure mode, not a convenience. This is why a formally verified crypto crate was rejected after measurement.
- **No mutable global state.** `Send`/`Sync` do not cross an FFI boundary that a foreign RTOS scheduler calls into, so concurrency safety is a property of API shape, not of the language.
- **No `unsafe`** in our own code.
- **Nothing overstated.** Documentation separates *proven* from *checked against someone else's answer* from *neither*, and says which document would settle an open claim. See `docs/FORMAL-VERIFICATION.md`.
- **Green and red, with red proven.** Every guard has been observed to fire. A test that has never failed is not yet a test.
- **Measure, don't assume.** Where a figure could be derived or observed, it is observed. Two claims written from documentation alone turned out wrong on contact with hardware, and both were caught this way rather than by review.

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

## Clean-room, and why it is enforced rather than encouraged

Meshtastic's firmware and its protobuf definitions are **both GPL-3.0**. This project derives from neither. It is built from the `.proto` files read as *specification*, from published protocol documentation, and from our own on-air captures.

**Compatibility does not require shared code.** Two independent implementations interoperate by putting the same bytes on the air. That is what `meshtastic/WIRE_REFERENCE.md` is for, and why every acceptance gate is phrased as "a stock device reads us" rather than "we compile their source".

The line is **facts versus expression**. Field numbers, wire layouts and transcribed constants — sync word, header length, the default channel PSK — are facts about the wire. Implementation is expression. Reading upstream `.proto` as specification is fine; **vendoring one into this tree is not**, and neither is running a code generator over one, since the output derives from a GPL input. That is why the protobuf codec here is hand-written.

**When tempted, stop.** If a piece of work seems to need a routing decision or a state machine copied from upstream, that means the specification is under-documented. The correct response is to write down our own design and cite the wire behaviour it implements — never to read their source.

Enforced by `tools/check_cleanroom.sh`, which refuses vendored `.proto`, generated `*.pb.*`, GPL licence headers and RadioLib references, and is red-tested against all three.

## Layout

```
meshtastic/WIRE_REFERENCE.md   the on-air facts, every claim sourced
meshtastic/core/              header · channel hash · AES-CTR · protobuf codec
meshtastic/routing/           managed flood · dedup · hop limit · duty accounting
suite/                        the extension suite and its specification
tests/host_unit/              algorithmic tests, green and red
tests/captures/               replay fixtures, synthetic-equivalent
DEPS.md                       what every result was obtained against
tools/check_cleanroom.sh      the GPL gate
```

Nothing here needs them to be verified: every fixture the tests read is committed under `tests/captures/`, so the full suite, the proofs and `tools/check_all.sh` run against a bare clone with no oracle, no network and no hardware. The reference implementation, the harness that drives it and the tools that fetch it are **not** in this tree. They live in a sibling directory alongside the hardware bench's copy, untracked — see `TESTING.md` and that directory's own `RULE.md`. What stays here is the provenance of our claims and fixtures that are ours to publish.

Portable `no_std` Rust with no hardware dependency, exported over a C ABI. A radio driver is deliberately not included — implementers have their own, and tying the stack to one part would narrow it for no benefit.

## Read this first

`meshtastic/WIRE_REFERENCE.md`. It is pinned to a specific upstream schema commit and splits **verified** facts from **unverified** ones, because the wire format moves between releases and because several widely repeated claims turned out to be stale. Notably: `DATA_PAYLOAD_LEN` is 233, there are 17 modem presets rather than the 7 usually listed, and routing has included next-hop since firmware 2.6.

All six items that once blocked the frame codec are now settled on hardware — header byte layout, CTR nonce, channel hash, PKI/DM scheme, sync-word register values and per-preset modulation parameters. What remains open is listed in that document's UNVERIFIED section with the measurement each would need.

## Conventions

- **Green and red, with red proven.** Every guard has been observed to fire. A test that has never failed is not yet a test.
- **No silent no-ops.** Anything unimplemented says so and exits non-zero. A pass that never ran is worse than a failure.
- **Captures are fixtures.** Every on-air capture enters a replay corpus, so an interop bug becomes a regression test that is fixable without a radio.
- **The instrument rule.** Never measure a suspect through its own counters. For interop the stock device is the instrument; our own decoder reporting 98 % is not evidence.

## Licence

**Apache-2.0**, for the code and the specification alike. See `LICENSE` and `NOTICE`; the reasoning is in `docs/LICENSING-OPTIONS.md`.

Apache-2.0 over MIT for its **explicit patent grant**, because the strategy is adoption by other implementers — possibly commercial ones — of a *cryptographic* suite, which is where patent uncertainty is taken most seriously.

The specification carries the same licence rather than CC-BY-4.0, for the same reason: **CC-BY-4.0 licenses no patent rights at all**, so a separate spec licence would deny a patent grant to precisely the adopter this project exists for — the one who reads the specification and writes their own clean-room implementation.

`suite/README.md` additionally carries an **unconditional patent non-assertion pledge**. You may implement this specification independently, commercially, in any language, without permission and without telling anyone.

Every file declares its licence; `tools/check_spdx.sh` enforces that, so a file cannot arrive undeclared. Vendored submodules under `third_party/` retain their own licences — see `DEPS.md` and `NOTICE`.
