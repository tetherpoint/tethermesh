<!-- SPDX-FileCopyrightText: 2026 Matthew Klapman -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# tethermesh

**Talk to the Meshtastic mesh from your own firmware, under a permissive licence.**

Meshtastic works, and its network already exists. What it does not offer is a way for someone else to build on that network: the firmware and schemas are GPL-3.0, so building on them means becoming GPL-3.0 too, and channel traffic carries no authentication at all.

tethermesh is an independent, clean-room implementation of the Meshtastic on-air protocol. It is `no_std` Rust with no allocator, and it links into C or C++ firmware as an ordinary static library. A stock, unmodified Meshtastic device sees a tethermesh node as a normal peer — reads its messages, direct-messages it, relays for it.

It also carries **extensions** that stock nodes relay without being able to read, so you can add authenticated messaging and managed groups to a mesh you do not control. Everything is **Apache-2.0**, including the specification, with an explicit patent grant.

## Quick start

```sh
git clone --recurse-submodules <this repo> && cd tethermesh
cargo test --workspace          # 147 tests, no hardware or network needed
./gates/check_all.sh            # every check this project holds itself to
```

To build the C library for your target:

```sh
cargo build --release -p tmffi --target thumbv7em-none-eabihf
#   -> target/thumbv7em-none-eabihf/release/libtmffi.a
#   -> code/c-api/include/tethermesh.h
```

Link the `.a`, include the header, and supply a radio driver. Four targets are built and size-checked on every run: `thumbv7em-none-eabihf`, `thumbv8m.main-none-eabi`, `thumbv8m.main-none-eabihf` and `riscv32imc-unknown-none-elf`.

## Repository layout

```
tethermesh/
│
├── code/                     everything that compiles
│   ├── protocol/             the Meshtastic-compatible implementation
│   │                           header · channel hash · AES-CTR · X25519
│   │                           protobuf codec · flood forwarding · airtime
│   ├── groups/               an extension: owner, member roster, revocation
│   ├── c-api/                the static library you link
│   │   ├── src/                the C ABI
│   │   └── include/            tethermesh.h (generated, and checked)
│   └── third_party/          vendored, pinned: fiat-crypto · libcrux
│
├── docs/                     every written document
│   ├── WIRE_REFERENCE.md       the on-air facts, each one sourced
│   ├── PLAN.md                 the roadmap and what each phase closed
│   ├── SCOPE.md                what may and may not enter this repository
│   ├── DISTRIBUTION.md         the rules the shipped artifact must meet
│   ├── DEPS.md                 what every result was measured against
│   ├── TESTING.md              how to run everything, including on hardware
│   ├── EXTENSIONS.md           the extension suite, and its patent pledge
│   └── …                       crypto audit, formal verification, backends
│
├── tests/
│   ├── host_unit/            the test suite — runs with no hardware
│   ├── captures/             recorded real traffic, replayed as fixtures
│   └── instrument/           the SX1262 receiver used to MEASURE the wire
│                               evidence for the clean-room claim, not a driver
│
└── gates/                    the checks — see "How this stays honest"
```

Nothing outside this tree is needed to build or test. Every fixture is committed, so the full suite, the proofs and `gates/check_all.sh` all run against a bare clone with no radio, no network and no reference implementation.

## What you get, and what you must supply

This is a **protocol layer, not a node.** You bring a radio driver below it and a scheduler above it.

**Below is yours.** The part's command set, SPI, interrupts and modulation. From the physical layer you get forward error correction and a CRC — and **nothing else**. LoRa has no link-layer acknowledgement and no retry: a frame corrupted beyond FEC's reach is simply lost, silently.

**Above is yours too**, because this library holds no state it does not have to:

- **The clock.** There is none in here. Anything time-dependent takes `now_us` as an argument.
- **The scheduler and the radio.** We answer *"wait a backoff drawn from this window, then transmit if nobody else did"*. The waiting and the arbitration are yours.
- **Locking, if two tasks share one context.** Concurrency safety here is a property of API shape, not of the language — `Send`/`Sync` do not cross an FFI boundary a foreign RTOS calls into.
- **Buffers, and they are not small.** Nothing allocates, so every stateful type is yours to place:

  | type | bytes |
  |---|---|
  | `DutyCycle` | 32 |
  | `Outbox<4>` | 1,096 |
  | `PacketHistory<64>` | 528 |
  | `PacketHistory<400>` | 3,216 |

  A node using the history depth the reference was observed using needs roughly **4.3 KB of state**, plus about **1 KB of call depth** for this library (the AES key schedules are the deep ones, not X25519). "No allocation" means the memory does not vanish — it becomes yours to place deliberately.

### One gap you must fill yourself today

**There is no acknowledgement or retransmission here, and the protocol has one.** `want_ack` is parsed and encoded, and `ROUTING` (portnum 5) carries the responses — so this is part of the protocol rather than a layer above it, and it is missing.

A caller wanting reliable delivery must currently implement: emitting a routing acknowledgement for a `want_ack` packet addressed to it, matching an incoming acknowledgement to a pending transmission, a retransmission policy, and the pending queue itself.

Flood forwarding gives *redundancy*, not delivery confirmation. Treating one as the other is the mistake this section exists to prevent. See `docs/PLAN.md` § L5.

## What the extensions are, and where the line falls

Two things share one radio, one preset and one mesh — not switched between:

- **Meshtastic-native channels** — fully compatible, both directions.
- **Extension channels** — authenticated messaging and managed groups, carried on a private PortNum (≥ 256, the range upstream reserves for this) that stock nodes **relay without being able to read**.

That works because Meshtastic's flood forwarding decides on the *unencrypted header*, not on whether it can decrypt the payload. So extensions travel over stock infrastructure for free — and the header and modem preset are therefore fixed, because changing either stops stock nodes relaying.

An extension belongs here only if **both** hold: an unmodified stock node relays it, and a node without the extension still communicates normally. Work that fails either test — a different modulation, or a mode that deliberately silences the mesh to take a measurement — lives in a separate repository and nothing here depends on it.

## How this stays honest

`gates/check_all.sh` runs every check and exits non-zero if any fails. Nothing is advisory, and **each of these has already caught a real defect**.

| the rule | how it is checked |
|---|---|
| Clean-room from the protocol, never the source | `check_cleanroom.sh` — refuses vendored `.proto`, generated `*.pb.*` and GPL headers, across the working tree *and* the submodules |
| No panics on hostile input | `check_rust_rules.sh` — inspects the **built object and shipped archive**, not the source. This caught a live panic path in `frame::encode` that source review had missed |
| No allocation, no mutable global state, no `unsafe` | the same check, plus crate-level `deny` attributes |
| Every file declares its licence | `check_spdx.sh` |
| Documentation matches the code | `check_docs.sh` — named tests must exist, cited tooling must be present, pinned commits must match the submodules |
| The C header matches the crate | `check_header.sh` — regenerates and compares |
| The ABI does not break within a major version | `check_abi_stability.sh` |
| The artifact fits the target | `check_size_budget.sh`, per target |
| The build is reproducible | `check_reproducible.sh` — builds twice, the second time from a copy at a different path |
| Nothing about a consuming product leaks in | `check_scope.sh` |

**The checks are themselves checked.** `check_rust_rules_selftest.sh` runs the artifact check against archives built to be refused, and against deliberately broken copies of itself — because a check that has never failed proves nothing. Several were found to be vacuous when first tested, and that is recorded rather than quietly fixed.

## Cryptography

**The X25519 field arithmetic is formally verified, and is not ours.** It comes from [`fiat-crypto`](https://github.com/mit-plv/fiat-crypto) — generated from Coq proofs by MIT PLV, the same pipeline BoringSSL uses — called unmodified from a pinned submodule.

**Be precise about the split.** What is proven is the field arithmetic. The Montgomery ladder and the inversion built on it are **ours and are not proven**; they are checked against RFC 7748's vectors and against two independent implementations across hundreds of random agreements per run. That split is deliberate: the ladder is short and public, while field arithmetic is where subtle bugs live — and the one bug this project actually shipped, an `fe_sub` biased by `p` instead of `2p`, was in the half that is now verified.

**Hardware acceleration is a supported seam.** `code/protocol/backend.rs` lets you put any subset of X25519, SHA-256, AES-CTR and AES-CCM onto silicon, per primitive, with a software default for the rest. The motive is side-channel resistance and key custody rather than speed. **But X25519 acceleration is rare** — of nine parts surveyed in `docs/HARDWARE-BACKENDS.md`, exactly one accelerates Curve25519; most "ECC accelerators" are NIST-curve only. Check your specific part.

## Clean-room

Meshtastic's firmware and its protobuf definitions are both GPL-3.0. **This project derives from neither.** Compatibility does not require shared code — two independent implementations interoperate by putting the same bytes on the air.

The line is **facts versus expression**. Field numbers, wire layouts and transcribed constants are facts about the wire. Implementation is expression. Reading upstream `.proto` as specification is fine; vendoring one or running a code generator over it is not, which is why the protobuf codec here is hand-written.

Everything in `docs/WIRE_REFERENCE.md` is tagged with which of four sources it came from — the `.proto` files read as specification, published documentation, black-box observation of a pinned reference binary, and our own on-air captures — and anything from none of them is marked UNVERIFIED rather than assumed.

**Source is the line, not availability.** Reference *binaries* are installed, because observing them requires it. Reference *source* is never fetched at all — not fetched-then-ignored, never present.

**Correctness is proven in both directions.** Their encoder → our decoder: every message in the committed corpus decodes and re-encodes bit-identically. Our encoder → their decoder: a stock unmodified node displays our text, relays it, lists us as a peer, answers an addressed traceroute, and accepts a PKI direct message — deriving the shared secret independently and matching ours byte for byte.

## Status

**L0–L6 complete.** The wire reference is settled on hardware, the codec and cryptography are implemented, forwarding is done, and a stock node accepts our traffic including PKI direct messages. **L7** (the extension suite) and **L8** (release engineering) remain. `docs/PLAN.md` carries the phase ledger and what closed each one.

The interoperability gate is all four on real hardware, not in simulation — *simulation green is not interoperability green*, and treating it as such is the most likely way a project like this fools itself.

## Licence

**Apache-2.0**, for the code and the specification alike — see `LICENSE` and `NOTICE`, with the reasoning in `docs/LICENSING-OPTIONS.md`.

Apache over MIT for its **explicit patent grant**, because the aim is adoption by other implementers — possibly commercial ones — of a *cryptographic* suite. The specification carries the same licence rather than CC-BY-4.0 for the same reason: CC-BY-4.0 licenses no patent rights at all, which would deny a patent grant to exactly the adopter this project exists for.

`docs/EXTENSIONS.md` additionally carries an **unconditional patent non-assertion pledge**. You may implement this specification independently, commercially, in any language, without permission and without telling anyone.

## How this was built

tethermesh was written with Anthropic's Claude, working against a hardware bench and a pinned reference implementation.

That is recorded so a reader can weigh the evidence, and it changes nothing about what is claimed: the checks in `gates/` do not care what wrote the code, the proofs in `code/protocol/proofs.rs` hold or they do not, and a stock node either accepted our frames or it did not. Those checks exist precisely so correctness rests on measurement rather than on who produced a line.

It matters most for the clean-room position, which was enforced mechanically rather than trusted: reference source was never fetched into the environment, `gates/check_cleanroom.sh` covers every run, and the history was audited separately for material committed and later removed. The instrument that measured the wire is committed in `tests/instrument/` so the byte-level facts can be re-derived independently.
