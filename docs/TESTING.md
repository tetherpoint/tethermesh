<!-- SPDX-FileCopyrightText: 2026 Matthew Klapman -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# TESTING — how compatibility is proven

**Settled 2026-08-14.**

Compatibility is a claim about bytes: does a stock, unmodified device read what we write, and do we read what it writes? Four layers answer that, and only the last needs a radio.

## The four layers

**1. Property and known-answer tests.** Round-trip encode→decode→compare, plus fuzzing. Tests our reading of the specification, not reality — necessary, never sufficient.

**2. Differential testing against a reference implementation, run locally.** The high-coverage layer, in both directions:

- *their encoder → our decoder* — do we read what they write?
- *our encoder → their decoder* — **do they read what we write?**

The second direction is the one that fails in the field. A decoder that is merely lenient passes the first while emitting frames nobody accepts, so testing only inbound proves very little.

Run locally this is not rate-limited by airtime. A frame costs ~805 ms on the air at the default preset and microseconds over loopback, which is the difference between a handful of cases a day and millions.

**3. Capture corpus.** Real frames, decoded offline, kept as permanent regression fixtures. See the privacy constraint below — this is not simply "record everything".

**4. On-air interoperability with a physical stock device.** The final gate, and the only layer that exercises the PHY, sync word, timing and real RF. Low throughput, high authority. **Nothing in layers 1–3 substitutes for it.**

## The reference implementation is a black box

Observing a running program's behaviour is the textbook clean-room method — observe, specify, implement from the specification. Reading its source is what forfeits that position.

**Availability is not the line.** Reference binaries are installed regardless, because the interoperability gate is defined as a stock device running stock firmware, which must be flashed. Whether that binary executes on a microcontroller or on a host machine is not a distinction any clean-room analysis turns on. **Source is the line.**

So:

- **Binaries and containers only, pinned by digest.** `fetch_oracle.sh` refuses source archives and source repositories before fetching, and `oracle.manifest` pins what is fetched. Both live in the oracle directory, not here — see below. The digest is the pin; a tag can be moved, and a result obtained against a moved tag names nothing.
- **Their source is never fetched and never present.** Not discouraged, not fetched-then-ignored: absent. A source tree in the environment turns "read their implementation" from a deliberate act into an accident one grep away, and that temptation peaks exactly when someone is stuck on a mismatch. `gates/check_cleanroom.sh` refuses any script that clones or builds it, and fails if reference source appears in the tree at all — tracked or untracked.
- **Artifacts live outside this repository**, in a separate directory shared with any hardware bench. Their material never sits inside the implementation tree.
- **So do the harness and any tool that interacts with their binaries.** `fetch_oracle.sh`, `oracle.manifest`, the run harness and the capture parser all live in that same outside directory, untracked. The test of which side a tool belongs on is whether it touches their binaries; `gates/check_cleanroom.sh` and `gates/check_rust_rules.sh` police our own tree and stay here. The reasoning is the reasoning above, one step further out: the strongest answer to *"what was in your source directory?"* is a source directory holding only our own work, and a harness is where the pressure to go looking actually builds. What stays in the repository is **provenance** — `docs/DEPS.md` names the oracle by version and digest — and **fixtures**, which are synthetic-equivalent.
- **On a mismatch, do not go looking.** Return to the protocol definitions, the published documentation, or a capture. If none resolves it, that is a finding: the specification is under-documented, and the answer is written into `docs/WIRE_REFERENCE.md` as newly established fact, recording both behaviours.

**Local only.** No public broker, no gateway, nothing bridged to RF.

## Why not a public mesh, and why not a third-party oracle

**A public mesh is not a test rig.** Publishing to a public broker reaches real deployments over real RF. At the default preset a whole mesh sustains roughly two messages per minute, so automated injection would deny service to people relying on it. It also writes our test frames — including any extension format — into a permanent, public, searchable record, disclosing the wire format before it is specified, licensed, or ready.

**Passive collection is free but not consequence-free.** Nobody can see you subscribe and no airtime is consumed, but you become the holder of other people's node identities, message metadata and positions.

**Third-party implementations were evaluated and rejected.** The permissively licensed ones found were two years stale — predating current routing, key verification and signing — too small to be authoritative, and of unverifiable provenance, since a permissive licence does not prove the author had the right to grant it. Using one could launder a contamination problem while appearing clean.

## Capture corpus — the privacy constraint

Real captured traffic contains identifiable node numbers, message metadata and **position reports**. On the default public channel the key is published, so those payloads are readable by anyone. Committing such a corpus to a public repository would republish strangers' locations and messages, collected without their knowledge and permanently.

Therefore:

- **Public fixtures are synthetic**, generated from the specification. They are reproducible in a way real captures are not, which makes them better fixtures regardless.
- **Captures from our own nodes on our own channel** may be published. That is our traffic.
- **Third-party captures stay private** and are treated as personal data, not test data.
- If a real third-party frame must be published to demonstrate something, node numbers are randomised, position payloads dropped, and anything decryptable under the published key removed — deliberately, and checked.

Airtime recovers in seconds. A published location history does not.
