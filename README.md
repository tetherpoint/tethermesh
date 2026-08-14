# tethermesh

**A clean-room-built Meshtastic-compatible stack, with new extensions.**

Status: **early. Specification work landed; codec implementation not started.** No LICENSE yet — see below before relying on anything here.

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
tests/captures/               real on-air frames as replay fixtures
tools/check_cleanroom.sh      the GPL gate
```

Portable `no_std` Rust with no hardware dependency, exported over a C ABI. A radio driver is deliberately not included — implementers have their own, and tying the stack to one part would narrow it for no benefit.

## Read this first

`meshtastic/WIRE_REFERENCE.md`. It is pinned to a specific upstream schema commit and splits **verified** facts from **unverified** ones, because the wire format moves between releases and because several widely repeated claims turned out to be stale. Notably: `DATA_PAYLOAD_LEN` is 233, there are 17 modem presets rather than the 7 usually listed, and routing has included next-hop since firmware 2.6.

Six items remain unverified and block the frame codec — header byte layout, CTR nonce construction, channel hash function, PKI/DM details, the raw sync-word register value, and per-preset SF/BW/CR parameters. Most fall out of decoding a single real frame.

## Conventions

- **Green and red, with red proven.** Every guard has been observed to fire. A test that has never failed is not yet a test.
- **No silent no-ops.** Anything unimplemented says so and exits non-zero. A pass that never ran is worse than a failure.
- **Captures are fixtures.** Every on-air capture enters a replay corpus, so an interop bug becomes a regression test that is fixable without a radio.
- **The instrument rule.** Never measure a suspect through its own counters. For interop the stock device is the instrument; our own decoder reporting 98 % is not evidence.

## Licence

**Not yet chosen.** Nothing here should be relied on until it is — an unlicensed work is all-rights-reserved by default, which is the opposite of the intent.

The intent is permissive. `docs/LICENSING-OPTIONS.md` sets out the trade-offs: Apache-2.0 versus MIT for the code, and whether the specification should carry CC-BY-4.0 separately. The standing recommendation is Apache-2.0 for code and CC-BY-4.0 for the spec, plus an explicit patent pledge — because a clean-room implementer working from the spec alone otherwise receives no patent assurance at all.
