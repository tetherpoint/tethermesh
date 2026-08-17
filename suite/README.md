<!-- SPDX-FileCopyrightText: 2026 The tethermesh Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# suite — the extension set

Extensions ride the same mesh as ordinary Meshtastic traffic, on a private PortNum (≥ 256, the range upstream reserves for exactly this). Stock nodes relay them and ignore them, so an extension travels over existing infrastructure without asking anything of it.

The boundary is fixed and non-negotiable: **extensions live in the payload and the channel/PortNum space. The 16-byte header and the modem preset are never touched**, because changing either stops stock nodes relaying — which would cost the one property that makes extensions viable.

## What this set is, and what it is not

**Anything needing a hardware source belongs to a consuming product, not here.** Location and ranging were both specified in this file and are both gone as of 2026-08-17: one needed a GNSS receiver, the other ranging silicon, and neither is something a portable protocol library can carry. `SCOPE.md` said as much all along — *"source implementations that require particular hardware — a GNSS driver, a ranging driver — are out of scope here"* — and the specifications drifted across that line before the implementations could.

What is left is what this repository can hold honestly: extensions that are **message formats and state**, testable on any machine, with no hardware precondition. `groups` is one. A future bundle qualifies on the same test.

This repository otherwise tracks Meshtastic. New work here should be **aligning with upstream protocol features**, not growing a parallel feature set.

## Design rules

**Incrementally adoptable.** A node with an extension must interoperate with a node without it by falling back to plain Meshtastic behaviour. There is never a flag day, and a mesh may be arbitrarily mixed.

**Airtime is the budget.** On LongFast every added byte costs roughly 7.7 ms of airtime. An extension that costs 60 bytes will not be adopted however good it is. Every design decision below is costed in bytes before it is argued for.

**Compatible by construction.** If an extension cannot be expressed without changing the header or the preset, it is the wrong design, not a licence to break compatibility.

---

## 1. Authenticated channels

Meshtastic channel messages carry no authentication. Anyone holding the pre-shared key can send as any node — and, because the cipher is CTR with no tag, an attacker who can deduce a known plaintext can forge by reusing a `(node, packet_id)` pair **without holding the key at all**. Bit-flips in ciphertext are bit-flips in plaintext, undetectably.

The extension adds an AEAD tag and, crucially, **binds it to the cleartext header as additional authenticated data**. That costs zero extra bytes — the header is already on the wire — and authenticates `from`, `to`, `packet_id` and channel, so a **forged sender** fails verification. An 8-byte tag is roughly 10 % airtime on LongFast.

> **Corrected 2026-08-17, while writing `groups/SPEC.md`.** This paragraph said the tag binds *the 16-byte header* and that "a tampered hop count fails verification". Both are wrong, and implementing them as written would have broken the extension in the field while it worked on the bench. `hop_limit`, `next_hop` and `relay_node` **legitimately change in transit** — every relay decrements the first and stamps the last — so a tag covering them verifies only for a packet that has never been relayed, and fails on every multi-hop delivery. The AAD is therefore the *invariant subset* of the header, and hop fields are **not authenticated and cannot be**. `header.rs` already says routing fields are "hints, never evidence"; this suite authenticates origin and content, not path. See `groups/SPEC.md` § 3.1.

Deliberately *not* included: per-message author signatures. Upstream is adding XEdDSA signing in 2.8.x — same primitive family, same 64-byte cost — so this would be duplication rather than extension.

## 2. Managed groups

A Meshtastic channel is a group in the user interface but not in structure: membership is implicit, being whoever holds the key. Nobody — including whoever created it — can enumerate the members, add one, or remove one. There is no owner and no revocation; a departed member keeps the key forever.

**Put more sharply, and confirmed against upstream's own documentation on 2026-08-16: the URL *is* the key exchange.** The pre-shared key travels inside the channel link, so sharing the link shares the key and there is no separate exchange step to attach membership to. Upstream states the consequence plainly — *"there is no per-member revocation; revoking access means rotating the key and re-sharing a new URL"* — which is not a gap in their implementation but the design working as intended for what it is.

**Nothing upstream addresses this, and nothing appears to be coming.** The 2.8.x work is XEdDSA packet signing, which this suite deliberately does not duplicate, and `KEY_VERIFICATION_APP = 12` addresses trust-on-first-use. Both are adjacent to membership and neither is membership. Re-checked 2026-08-16 against the published encryption documentation.

The extension adds an **owner, a member roster, invitation, and revocation via a channel epoch**. The epoch costs one byte per packet; rekeying costs one wrapped key per member and is therefore a deliberate, infrequent act rather than a routine one.

**What revocation does and does not give, stated before anyone assumes otherwise.** It protects *future* traffic: a revoked member cannot read anything sent under a later epoch. It does **not** retroactively protect past traffic, because that traffic was encrypted under a key the member legitimately held. Upstream has the same property and says so — *"everything sent on a channel can be stored and decrypted later by anyone who gains access to the key"* — and this extension does not change it.

**This is not forward secrecy and must not be described as such.** Achieving that would need per-message ephemeral keys, which costs a key exchange per message and is not viable at 233 bytes and sub-kilobit airtime. What the epoch buys is *membership control going forward*, which is a different and more modest property than the word "revocation" tends to suggest.

This is the largest genuine gap in the protocol as it stands and nothing upstream addresses it.

## Not in this repository

Source implementations that require particular hardware — a GNSS driver, a ranging driver — are out of scope here, as is any radio driver. This repository specifies the protocol and provides a portable implementation of it. See `SCOPE.md`.

## Bundles, and what each one needs before it can be written

The suite is **one crate per bundle**, so a consumer takes the core plus only what they want. `SCOPE.md` records how a bundle crate is added and gated; this is what each one *depends on*.

| bundle | depends on | can be specified now? |
|---|---|---|
| **groups** | nothing beyond the core | **yes** — pure protocol |

### groups

Owner, member roster and revocation, over authenticated channels. No hardware precondition: it is message formats and state, testable against the existing bench and provable with the same Kani harnesses the core uses. A roster under the no-allocation rule is a caller-provided fixed-capacity collection — the pattern `PacketHistory` and `delivery::Outbox` already use, so this is a known shape rather than an open question.

**This is the bundle to specify first**, because nothing gates it.

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
Meshtastic firmware, its clients and its protobuf schemas — all GPL-3.0 — and
also nothing from RadioLib, which is **MIT** and kept out for a different
reason: independence of implementation, not licence contamination.
`tools/check_cleanroom.sh` enforces both on every run. An
implementer adopting this suite inherits no copyleft obligation from us. See
`NOTICE`.

Meshtastic is a trademark of Meshtastic LLC. This project is not affiliated
with or endorsed by it.
