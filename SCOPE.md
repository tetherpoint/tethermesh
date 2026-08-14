# SCOPE — what belongs in this repository, and what must never enter it

This repository is **open**. Assume everything committed here will be read by people outside the project, including competitors, and that git history is permanent — a file deleted in a later commit is still in the history, and a repository that has been cloned once cannot be un-cloned.

That makes this document a gate, not a preference. It is easier to keep something out than to take it back.

## The rule

> **If it is not part of a Meshtastic-compatible protocol implementation or its extensions, it does not belong here.**

Everything in this repository should make sense to someone who has never heard of the products that consume it, and should be usable by them.

## In scope

- The Meshtastic on-air protocol: frame header, channel hashing, channel and PKI cryptography, the protobuf codec.
- Routing behaviour needed for compatibility: managed flooding, duplicate suppression, hop-limit handling, duty-cycle accounting.
- The extension suite and its specification — the wire format, its cryptographic construction, and its rationale.
- `WIRE_REFERENCE.md`: on-air facts with sources, verified separated from unverified.
- Host-side tests and on-air capture fixtures.
- Tooling that operates on the above without hardware — for example the clean-room checker.

## Out of scope — must not be committed

- **Any radio driver, board bring-up, or hardware abstraction.** This stack is portable by design; a driver would both narrow it and pull in code that is not ours to publish.
- **Any product integration** — application layers, transport shims, backends, host interfaces, or the names and internal structure of systems that consume this library.
- **Bench and laboratory tooling**: build and flash scripts, device discovery, port and probe identification, hardware test runners, hardware inventories.
- **Anything describing a consuming product's architecture, security design, key management, roadmap, or implementation status.** This is the category most likely to arrive by accident, because it usually arrives inside otherwise reasonable prose — a rationale paragraph, a comparison table, a commit message explaining *why*.
- **GPL-derived material of any kind.** Separate concern, separately enforced; see `README.md` and `tools/check_cleanroom.sh`.

## Two categories that leak most easily

**Commit messages.** They are published with the code and cannot be edited after a push. A message explaining that a change exists "because our transport does X" discloses that a transport exists and what it does. Write commit messages that explain the change in terms of the protocol.

**Rationale prose.** "We chose Y because our product needs Z" is a disclosure of Z. Where a design decision was driven by a private requirement, state the decision and a *general* justification, not the private one. If the general justification does not hold on its own, the decision may not belong in this repository either.

## When unsure

Keep it out. Adding something later is cheap; removing it after publication is impossible. An item that arguably belongs here but was withheld costs a later commit. An item that arguably did not, and was published, cannot be recovered.

If a change genuinely needs private context to be understood, that is a strong signal it belongs on the private side of the boundary instead.

## Relationship to consumers

This library is consumed by other software that is not published. That relationship is deliberately invisible from inside this repository: no names, no paths, no build coupling, no assumptions about a caller. The dependency runs one way — consumers depend on this, never the reverse — which is what keeps this repository independently useful and independently publishable.
