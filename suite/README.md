<!-- SPDX-FileCopyrightText: 2026 The tethermesh Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# suite — the extension set

Extensions ride the same mesh as ordinary Meshtastic traffic, on a private PortNum (≥ 256, the range upstream reserves for exactly this). Stock nodes relay them and ignore them, so an extension travels over existing infrastructure without asking anything of it.

The boundary is fixed and non-negotiable: **extensions live in the payload and the channel/PortNum space. The 16-byte header and the modem preset are never touched**, because changing either stops stock nodes relaying — which would cost the one property that makes extensions viable.

Nothing here is implemented yet. This file records what the set is and why, so the shape is settled before code exists.

## Design rules

**Incrementally adoptable.** A node with an extension must interoperate with a node without it by falling back to plain Meshtastic behaviour. There is never a flag day, and a mesh may be arbitrarily mixed.

**Airtime is the budget.** On LongFast every added byte costs roughly 7.7 ms of airtime. An extension that costs 60 bytes will not be adopted however good it is. Every design decision below is costed in bytes before it is argued for.

**Compatible by construction.** If an extension cannot be expressed without changing the header or the preset, it is the wrong design, not a licence to break compatibility.

---

## 1. Authenticated channels

Meshtastic channel messages carry no authentication. Anyone holding the pre-shared key can send as any node — and, because the cipher is CTR with no tag, an attacker who can deduce a known plaintext can forge by reusing a `(node, packet_id)` pair **without holding the key at all**. Bit-flips in ciphertext are bit-flips in plaintext, undetectably.

The extension adds an AEAD tag and, crucially, **binds it to the 16-byte cleartext header as additional authenticated data**. That costs zero extra bytes and authenticates `from`, `to`, `packet_id`, channel and hop fields — so a forged sender or a tampered hop count fails verification. An 8-byte tag is roughly 10 % airtime on LongFast.

Deliberately *not* included: per-message author signatures. Upstream is adding XEdDSA signing in 2.8.x — same primitive family, same 64-byte cost — so this would be duplication rather than extension.

## 2. Managed groups

A Meshtastic channel is a group in the user interface but not in structure: membership is implicit, being whoever holds the key. Nobody — including whoever created it — can enumerate the members, add one, or remove one. There is no owner and no revocation; a departed member keeps the key forever.

The extension adds an **owner, a member roster, invitation, and revocation via a channel epoch**. The epoch costs one byte per packet; rekeying costs one wrapped key per member and is therefore a deliberate, infrequent act rather than a routine one.

This is the largest genuine gap in the protocol as it stands and nothing upstream addresses it.

## 3. Location, with pluggable sources

Meshtastic has `POSITION_APP` for GNSS fixes and `ZPS_APP` for position estimation without GPS, but no notion of measured distance between nodes.

The extension defines **how location information is requested, carried and distributed** — subscription-gated, so a node emits only while somebody is actively interested, because both the measurement and the traffic cost airtime.

**The measurement source is pluggable, and this is the point of the design.** Two sources, interchangeable in purpose and different in shape:

| source | produces | needs |
|---|---|---|
| **GNSS** | absolute coordinates, altitude, precise time, velocity and heading, and a fix-quality estimate | a receiver, available to anyone |
| **Radio time-of-flight** | pairwise distance to a named peer | silicon that supports ranging |

They are not interchangeable in data. GNSS yields considerably more than a coordinate pair, and the extension should carry it as a **record of optional fields** rather than a fixed position struct — each source populates what it actually has, and a consumer uses whatever arrives. Ranging fills in distance; GNSS fills in coordinates, altitude, time, motion and accuracy; a node with both fills in both.

Three of the GNSS fields are worth calling out because they are not merely "extra position detail":

- **Precise time.** A GNSS fix carries time far more accurate than anything a mesh node can otherwise obtain, which is a foundation for anything time-coordinated — and a possible aid to ranging itself.
- **Velocity and heading.** These meshes are mobile. A stale position from a moving node is worse than no position; motion is what tells a consumer how fast a fix decays.
- **Fix quality.** Without an accuracy estimate a consumer cannot tell a surveyed position from a poor urban fix, and will present both with equal confidence.

Sparseness is not a nicety here. Every optional field costs airtime at roughly 7.7 ms per byte on LongFast, so a location record must send only what was asked for and only what changed — which is the same argument that makes the whole exchange subscription-gated.

Two consequences worth stating plainly. A ranging exchange needs the radio to itself for a bounded window, so the extension must define a **radio yield** that is bounded, counted and charged against the duty budget — an unbounded yield is a mesh outage. And because GNSS is available to any implementer while ranging silicon is not, **the specification is useful and implementable with GNSS alone**. A ranging source is an optimisation, not a prerequisite.

---

## Not in this repository

Source implementations that require particular hardware — a GNSS driver, a ranging driver — are out of scope here, as is any radio driver. This repository specifies the protocol and provides a portable implementation of it. See `SCOPE.md`.

---

## Licence and patent pledge

This specification and the reference implementation are licensed under the
**Apache License, Version 2.0**. See `LICENSE`; the reasoning is in
`docs/LICENSING-OPTIONS.md`.

**You may implement this specification.** Independently, commercially, in any
language, on any hardware, without permission and without notifying anyone.
Copyright protects the expression in this document, not the protocol it
describes, and Apache-2.0 §2 grants you the right to reproduce and adapt the
document itself as well.

### Patent non-assertion

**The tethermesh Authors will not assert any patent they hold or control
against an implementation of this specification.**

This is stated separately from the licence deliberately. Apache-2.0 §3 grants a
patent licence tied to "the Work", and its reach over someone who *reads this
document and writes independent code* — rather than copying ours — is arguable
rather than certain, because copyright and patent attach differently to a
description than to an implementation. That ambiguity is exactly what makes a
cautious implementer's legal review stall, and stalling that review defeats the
purpose of publishing a specification at all.

So the pledge is unconditional and does not depend on which licence a reader
concludes applies to their situation. It is not a grant of trademark rights,
and it is not a warranty: see `LICENSE` §§6-8.

### On the reference implementation

`tethermesh` is a clean-room implementation. It derives nothing from the
Meshtastic firmware, its clients, its protobuf schemas, or from RadioLib — all
GPL-3.0 — and `tools/check_cleanroom.sh` enforces that on every run. An
implementer adopting this suite inherits no copyleft obligation from us. See
`NOTICE`.

Meshtastic is a trademark of Meshtastic LLC. This project is not affiliated
with or endorsed by it.
