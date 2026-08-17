<!-- SPDX-FileCopyrightText: 2026 The tethermesh Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# groups — authenticated channels with membership

**Status: specified and implemented, 2026-08-17.** `suite/groups/`, 9 tests,
gated like every other crate. The spec was written first on purpose — an
implementation written before its specification quietly *becomes* the
specification — and that ordering paid for itself twice: see § 3 and § 3.1 for
the two design errors writing code against this document exposed.

Read `../README.md` first for why the suite exists and what it may not touch.
The licence and patent pledge there cover this document.

This bundle is specified first because nothing gates it: it is message formats
and state, with no hardware precondition.

---

## 1. What this adds, and to what

Meshtastic channel traffic is encrypted with AES-CTR under a pre-shared key and
carries **no authentication whatsoever**. Two consequences follow, and the second
is worse than it first sounds:

- Anyone holding the key can send as any node. The `from` field is a claim.
- Because CTR is a stream cipher with no tag, **an attacker who can guess a
  plaintext can forge a packet without holding the key at all**, by reusing a
  `(from, packet_id)` pair and XOR-ing the difference. Bit-flips in ciphertext
  are bit-flips in plaintext, undetectably.

And a channel is a group in the user interface but not in structure. Membership
is implicit — whoever holds the key — so nobody, including its creator, can
enumerate members, add one, or remove one. Upstream states the consequence
plainly: *"there is no per-member revocation; revoking access means rotating the
key and re-sharing a new URL."*

This bundle adds an AEAD tag and a membership structure on top, **without
touching the 16-byte header or the modem preset**, so stock nodes continue to
relay the traffic while ignoring it.

## 2. Wire placement

An extension message is the `Data.payload` of an ordinary Meshtastic packet on
**PortNum 256**, inside the normal channel CTR encryption.

> **PortNum 256 is provisional and unregistered.** Upstream reserves ≥ 256 for
> private use, which makes the *range* safe and a specific value nobody's to
> claim. Two independent suites picking 256 would collide and each would see the
> other's traffic as malformed. Fixing this needs a registry that does not exist;
> until it does, a deployment that expects foreign extension traffic should treat
> an unparseable envelope as ordinary and drop it, which §7 requires anyway.

So the layering, outermost first:

```
16-byte cleartext header          ← relayed by stock nodes, never modified by us
  AES-CTR under the channel PSK   ← ordinary Meshtastic, makes us look like traffic
    Data{ portnum = 256, payload = envelope }
      envelope = version ‖ type ‖ group ‖ epoch ‖ ciphertext ‖ tag
```

The outer CTR layer is not security — every channel member holds that key. It is
**camouflage and compatibility**: it is what makes a stock node treat the packet
as ordinary channel traffic and relay it. The security is entirely in the inner
AEAD.

## 3. The AEAD construction

**Cipher: AES-CCM**, which `meshtastic/core/crypto.rs` provides, with
`CCM_TAG_LEN = 8` and `CCM_NONCE_LEN = 13`. No new *cipher* is required — a
suite needing one would need a new audit.

> **It did require extending the existing one, 2026-08-17.** The CCM here had
> **no AAD support at all**: `cbc_mac` covered only the payload, and the flags
> byte carried a comment reading "no additional data here". Since this bundle's
> central security property is binding the header as AAD, the spec was not
> implementable as written.
>
> `ccm_encrypt_in_place_aad` / `ccm_decrypt_in_place_aad` now implement
> RFC 3610 §2.2 framing; the original functions delegate with an empty AAD and
> are byte-identical to before, which the committed vectors confirm.
>
> **Verified against someone else's answer, not our own round trip.** A new
> corpus, `tests/captures/ccm_aad_vectors.json`, was generated with `python
> cryptography`'s `AESCCM` (OpenSSL) and includes the exact 14-byte AAD shape
> below. The generator is itself cross-checked: its empty-AAD case reproduces a
> vector already committed. Both an unset Adata flag and an omitted AAD were
> injected and observed to fail.

### 3.1 What the tag covers — and the correction that matters

`../README.md` says the tag is bound to "the 16-byte cleartext header" and that
"a tampered hop count fails verification". **The second half of that is wrong,
and binding the whole header would break the extension outright.**

Three header fields *legitimately change in transit*:

| byte | field | mutates? |
|---|---|---|
| 0–3 | `to` | no |
| 4–7 | `from` | no |
| 8–11 | `id` | no |
| 12 bits 0–2 | `hop_limit` | **yes** — every relay decrements it |
| 12 bits 3–7 | `want_ack`, `via_mqtt`, `hop_start` | no |
| 13 | `channel` | no |
| 14 | `next_hop` | **yes** — routing sets it |
| 15 | `relay_node` | **yes** — each relay stamps its own low byte |

A tag over all sixteen bytes verifies only for a packet that has never been
relayed. On a flood mesh — the only kind this runs on — it would fail on every
multi-hop delivery, and the symptom would be "the extension works on the bench
and not in the field", which is the worst possible place to find it.

**AAD is therefore the invariant subset, 14 bytes:**

```
AAD = header[0..12] ‖ (header[12] & 0xF8) ‖ header[13]
```

The mask keeps `want_ack`, `via_mqtt` and `hop_start` and clears `hop_limit`.

**State plainly what this does not protect.** `hop_limit`, `next_hop` and
`relay_node` are **not authenticated and cannot be**, end to end, because they
are mutable by design. A relay may lie about any of them. `header.rs` already
says routing fields are "hints, never evidence", and this bundle does not change
that — it authenticates *origin and content*, not *path*. Anyone describing this
as authenticating the header should be corrected.

`hop_start` **is** covered, so a relay cannot rewrite it to fake how far a packet
has travelled — but only in combination with `hop_limit`, which it can. The pair
gives distance travelled; one half is authenticated and the other is not, so the
distance is not trustworthy. Do not build on it.

### 3.2 Nonce

```
nonce[13] = from[4, LE] ‖ id[4, LE] ‖ epoch[1] ‖ 0x00 × 4
```

Uniqueness rests on a sender never reusing a `packet_id` under one key.
`meshtastic/core/packet_id.rs` already refuses to reissue an id past a persisted
high-water mark, for the CTR layer's sake; the same discipline carries the AEAD.

**A repeated `(from, id)` under one epoch key is a nonce reuse and breaks
confidentiality and authenticity together**, which is more than it costs the CTR
layer alone. An implementation that cannot persist the high-water mark across
restarts MUST NOT originate group traffic after a restart until it has drawn a
fresh epoch.

### 3.3 Key

A 256-bit AES key derived per epoch:

```
K_epoch = SHA-256( K_group ‖ "tethermesh-groups-v1" ‖ epoch[1] )
```

`sha256` is already present, and its 32-byte output is exactly an AES-256 key —
no truncation step, so no opportunity to truncate inconsistently.

> **Corrected 2026-08-17, at implementation.** This said the key was truncated
> to 128 bits "matching what the core already links". Wrong: `crypto.rs`'s CCM
> is **AES-256 only** — `ccm_encrypt_in_place` takes `&[u8; 32]` and builds an
> `Aes256` internally. A 16-byte key was not merely suboptimal, it would not
> have compiled. Second spec error found by writing code against it; see § 3.1
> for the first, which was worse.

## 4. Envelope

```
offset  size  field
  0      1    version        = 1
  1      1    type           see §5
  2      4    group_id       LE, non-zero
  6      1    epoch          wraps 0..255, see §6.3
  7      n    ciphertext     AEAD-encrypted body
  7+n    8    tag
```

**Fixed overhead: 15 bytes** — 7 of envelope plus an 8-byte tag.

## 5. Message types

| type | name | direction | body |
|---|---|---|---|
| 1 | `DATA` | any member → group | the application payload |
| 2 | `INVITE` | owner → one member | wrapped epoch key |
| 3 | `REVOKE` | owner → group | announces an epoch bump |
| 4 | `ROSTER` | owner → group | current membership |
| 5 | `LEAVE` | member → owner | voluntary departure |

`INVITE` is addressed to one node and wraps `K_group` to that member's X25519
public key, using the shared secret from `x25519(owner_private, member_public)`.
Both halves already exist in the core. This is the only message that is not
encrypted under the group key, for the obvious reason that its recipient does not
have it yet.

## 6. Membership

### 6.1 Roster

A group has one **owner** — the node that created it — and a roster of member
node numbers with their public keys. Under the no-allocation rule the roster is
a **caller-provided fixed-capacity collection**, the same shape
`history::PacketHistory` and `delivery::Outbox` already use, so capacity is the
integrator's decision and a full roster is a refusal rather than a reallocation.

### 6.2 Owner

A single owner is a deliberate simplification and a real limitation: **if the
owner is lost, the group cannot be changed again**, only abandoned. Multi-owner
consensus over a lossy mesh with no ordering guarantees is a distributed-systems
problem this bundle declines to solve at 233 bytes per message. An implementation
wanting resilience should create the group from a node that is unlikely to
vanish, and treat groups as cheap to recreate.

### 6.3 Epochs and revocation

Revoking a member means bumping the epoch and re-wrapping `K_group` to every
*remaining* member — one `INVITE` each. That is deliberately expensive so that it
is an infrequent, considered act rather than routine.

The epoch is one byte and wraps. **A wrap is not a rekey**: after 256 bumps the
epoch byte repeats, and since `K_epoch` derives from it, so does the key — which
would reuse nonces catastrophically. An implementation MUST rotate `K_group`
itself before the epoch wraps, and MUST refuse to originate rather than wrap
silently.

### 6.4 What revocation gives, and what it does not

It protects **future** traffic: a revoked member cannot read anything sent under
a later epoch.

It does **not** protect past traffic. That traffic was encrypted under a key the
member legitimately held, and they may have kept it, and every packet they heard.
Upstream has the same property and says so: *"everything sent on a channel can be
stored and decrypted later by anyone who gains access to the key."*

**This is not forward secrecy and must never be described as such.** Forward
secrecy needs per-message ephemeral keys — a key exchange per message, which is
not viable at 233 bytes and sub-kilobit airtime. What an epoch buys is
*membership control going forward*, a more modest property than the word
"revocation" tends to suggest.

Nor is it deniability, or protection against a member who leaks the key while
still a member. A group is only as private as its least trustworthy current
member, exactly as a channel is.

## 7. Fallback, and mixed meshes

A node **without** this extension receives PortNum 256, does not recognise it,
and drops it. It still relays it, which is the whole basis of the design. So a
mixed mesh works: extension traffic passes over stock infrastructure and stock
nodes are unaffected.

A node **with** the extension MUST:

- treat an unparseable envelope as ordinary traffic and drop it, never as an
  attack and never as a reason to stop relaying;
- treat a failed tag as a **drop, silently** — a node that answered "your tag was
  wrong" would confirm group membership to an attacker probing for it;
- continue to speak plain Meshtastic to nodes not in any group.

There is no flag day and no negotiation. A group member and a stock node
communicate exactly as two stock nodes do.

## 8. What it costs

At LongFast, roughly **7.7 ms of airtime per byte**.

| item | bytes | airtime |
|---|---|---|
| envelope header | 7 | ~54 ms |
| AEAD tag | 8 | ~62 ms |
| **total fixed overhead** | **15** | **~116 ms** |

Against the 233-byte payload limit that leaves **218 bytes** for the application.

A 15-byte overhead on a 40-byte message is 37%, which is substantial and is the
honest number. On a 200-byte message it is 7.5%. The extension is well suited to
carrying meaningful payloads and poorly suited to chatter, and an implementation
that sends frequent tiny authenticated messages will notice.

`INVITE` costs one message per member per rekey, which is why §6.3 makes
revocation deliberate.

## 9. Security properties, stated as claims that could be checked

Written this way so each can be tested or refuted rather than admired.

| # | claim | rests on |
|---|---|---|
| 1 | A packet with a valid tag was composed by a holder of `K_epoch` | AES-CCM integrity |
| 2 | `from`, `to`, `id`, `channel`, `hop_start` cannot be altered without failing the tag | AAD covers them |
| 3 | A revoked member cannot read traffic from a later epoch | key derivation per epoch |
| 4 | A stock node relays extension traffic unchanged | header and preset untouched |
| 5 | A forged sender fails verification | claim 1 + `from` in AAD |

**Not claimed, and each is a real limitation:**

- Path integrity. `hop_limit`, `next_hop`, `relay_node` are unauthenticated (§3.1).
- Forward secrecy (§6.4).
- Protection against a current member.
- Traffic analysis resistance. Group traffic is identifiable as *some* group's by
  its portnum, and `group_id` is in the clear. An observer learns that a group
  exists, its id, which nodes send to it and how often — everything except
  content. Hiding that needs cover traffic, which airtime forbids.
- Availability. A jammer stops this exactly as it stops Meshtastic.

## 10. Gate

From `PLAN.md`, unchanged:

> Two instances exchange authenticated extension traffic that an unmodified
> reference node relays without reading; a forged sender fails the tag; a node
> without the extension falls back and still communicates.

Three of the four are testable on the existing bench. **The forged-sender test
needs care**: it must forge at the point a real attacker would — re-using a
`(from, id)` pair with modified ciphertext — rather than by corrupting a tag at
random, which any AEAD rejects and proves nothing.

## 11. Open questions, named rather than deferred quietly

- **PortNum 256 is unregistered** (§2). No registry exists.
- **How a group is first created and its owner's key distributed** is out of
  scope here and is not solved by hand-waving: it is the same key-exchange
  problem the channel URL solves for channels, and `KEY_VERIFICATION_APP = 12`
  addresses adjacently upstream. This bundle assumes members' X25519 public keys
  are already known, which the Meshtastic node database already carries.
- **Epoch wrap** (§6.3) needs a rotation policy, not just a refusal.
- **Roster capacity** is the integrator's, and the failure mode of a full roster
  during an invite has not been specified.
- **No harness exists yet.** The core's Kani harnesses cover parsing, arithmetic
  and delivery; a roster and an epoch are state machines and are the natural next
  subject, but nothing here is proven.
