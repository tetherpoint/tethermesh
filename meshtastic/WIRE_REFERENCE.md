# WIRE_REFERENCE — Meshtastic on-air facts

**Status: v2, 2026-08-15. P0 deliverable, partially complete — read the UNVERIFIED section before writing any codec.** v2 adds a section of facts verified by observing a pinned local oracle, resolves the channel hash, and corrects an assumption about what a local oracle can show.

This is the single source of truth for what tethermesh puts on and takes off the air. Every claim is sourced. Where this document disagrees with any secondary description of the Meshtastic protocol — including widely repeated ones — this document wins, because those descriptions were checked and several were stale.

## Provenance and method

Clean-room. Sources are the upstream `.proto` files, which are the wire contract and are treated as ABI documentation, plus the published protocol documentation. No implementation is read or copied from firmware, mobile apps or clients.

**Pinned source:** `meshtastic/protobufs` @ `84bfb0fdb3b853ea18abc4535497fa41a1b09546` (short `84bfb0fd`, 2026-08-11). Record this in `DEPS.md` at every milestone; **the wire format moves**, and a result that cannot name the schema version it was derived against is not a result.

Every fact below is tagged with where it came from. Facts that could not be established are listed as UNVERIFIED rather than assumed. Secondary sources asserted several of them confidently and at least four turned out wrong or stale, which is the whole reason this document exists.

---

## VERIFIED — from the pinned `.proto`

### `Data` (mesh.proto)

```
portnum          = 1   PortNum
payload          = 2   bytes
want_response    = 3   bool
dest             = 4   fixed32
source           = 5   fixed32
request_id       = 6   fixed32
reply_id         = 7   fixed32
emoji            = 8   fixed32
bitfield         = 9   optional uint32
xeddsa_signature = 10  bytes
```

### `MeshPacket` (mesh.proto)

```
from = 1 fixed32          rx_rssi     = 12 optional int32
to   = 2 fixed32          delayed     = 13 Delayed
channel = 3 uint32        via_mqtt    = 14 bool
decoded   = 4 Data  |     hop_start   = 15 uint32
encrypted = 5 bytes       public_key  = 16 bytes
id      = 6 fixed32       pki_encrypted = 17 bool
rx_time = 7 optional      next_hop    = 18 uint32
rx_snr  = 8 float         relay_node  = 19 uint32
hop_limit = 9 uint32      tx_after    = 20 uint32
want_ack  = 10 bool       transport_mechanism = 21
priority  = 11 Priority   xeddsa_signed = 22 bool
```

**`Constants.DATA_PAYLOAD_LEN = 233`** — not 237, which is the figure usually quoted. Any payload budget computed at 237 is 4 bytes optimistic.

Documented semantics worth carrying verbatim:

- **`channel`** — "the index in the secondary_channels table… channel_index is inherently a local concept and meaningless to send between nodes. Very briefly, while sending and receiving deep inside the device Router code, this field instead contains the **'channel hash'** instead of the index." Confirms hash-on-wire, index-in-API.
- **`hop_start`** — "Sent via LoRa using three bits in the unencrypted header… firmware prior to 2.3.0 never populated this field, so a receiver can only trust `hop_start == 0` as genuine once it has decoded the packet and confirmed the sender's bitfield is present (added in 2.5.0). Until then… treat `hop_start == 0` as unknown, not direct."
- **`next_hop` / `relay_node`** — "Last byte of the node number… Set by the firmware internally, clients are not supposed to set this."
- **`xeddsa_signature`** — "XEdDSA signature for the payload". **`xeddsa_signed`** — "Indicates whether the packet has a valid signature."

### `ChannelSettings` (channel.proto)

`channel_num`(1, deprecated) · `psk`(2 bytes) · `name`(3 string) · `id`(4 fixed32) · `uplink_enabled`(5) · `downlink_enabled`(6) · `module_settings`(7). `Channel.Role` = DISABLED 0 / PRIMARY 1 / SECONDARY 2, where PRIMARY sets the radio frequency and SECONDARY affects only crypto.

**PSK encoding — confirmed:** 0 bytes = no crypto; 16 bytes = AES-128; 32 bytes = AES-256; 1 byte is shorthand where `0` = no crypto, `1` = the default channel key, and `2..10` = that key with 1..9 added to the **last byte** ("simple1".."simple10").

Default channel key: `d4 f1 bb 3a 20 29 07 59 f0 bc ff ab cf 4e 69 01`.

### `PortNum` (portnums.proto)

Core 0–63: UNKNOWN 0, TEXT_MESSAGE 1, REMOTE_HARDWARE 2, POSITION 3, NODEINFO 4, ROUTING 5, ADMIN 6, TEXT_MESSAGE_COMPRESSED 7, WAYPOINT 8, AUDIO 9, DETECTION_SENSOR 10, ALERT 11, **KEY_VERIFICATION 12**, REMOTE_SHELL 13, REPLY 32, IP_TUNNEL 33, PAXCOUNTER 34, STORE_FORWARD_PLUSPLUS 35, NODE_STATUS 36, MESH_BEACON 37.

Third-party 64–127: SERIAL 64, STORE_FORWARD 65, RANGE_TEST 66, TELEMETRY 67, **ZPS 68 ("position estimation without GPS")**, SIMULATOR 69, TRACEROUTE 70, NEIGHBORINFO 71, ATAK_PLUGIN 72, MAP_REPORT 73, POWERSTRESS 74, LORAWAN_BRIDGE 75, RETICULUM_TUNNEL 76, CAYENNE 77, ATAK_PLUGIN_V2 78, LORA_OTA 79, GROUPALARM 112.

**`PRIVATE_APP = 256`, documented "Private applications should use portnums >= 256". `MAX = 511`.** This is the sanctioned carriage for tethermesh extensions, and it is explicit rather than inferred.

### `LoRaConfig` (config.proto)

**17 modem presets, not the 7 usually listed:** LONG_FAST 0, LONG_SLOW 1 *(deprecated 2.7)*, VERY_LONG_SLOW 2 *(deprecated 2.5)*, MEDIUM_SLOW 3, MEDIUM_FAST 4, SHORT_SLOW 5, SHORT_FAST 6, LONG_MODERATE 7, SHORT_TURBO 8, LONG_TURBO 9, LITE_FAST 10, LITE_SLOW 11, NARROW_FAST 12 (62.5 kHz), NARROW_SLOW 13 (62.5 kHz), TINY_FAST 14 (20 kHz), TINY_SLOW 15 (20 kHz), MEDIUM_TURBO 16.

**`RegionCode` has 38 values** including `LORA_24 = 13` — the 2.4 GHz WLAN band is a supported region.

`hop_limit` is documented **max 7, default 3**. `tx_power` in dBm, zero meaning "default max legal continuous power". `channel_num` zero triggers a hash-based frequency-slot algorithm.

---

## VERIFIED — from official documentation

**Channel messages have no authentication, and forgery does not require the key.** Quoted: *"This encryption type does not include authentication, and as such, anyone with the PSK can send a message as any other user on that channel"*, and — worse than commonly assumed — *"if an attacker can deduce the exact plaintext of an encrypted message, an attacker can re-use the Nodenum and PacketID combination to send spoofed messages, **even without knowing the PSK**."* That is keystream recovery, and it makes the CTR-without-a-tag problem a forgery primitive rather than only an integrity gap.

**TOFU has a documented hole:** *"When a node rolls off the NodeDB, the Meshtastic firmware has no way to confirm that a future User packet isn't a spoof of that Node Number, with a different public key."*

**Routing is managed flooding, not naive flooding.** A node decrements `hop_limit` and rebroadcasts if non-zero, but only after listening to see whether someone else already did, suppressing itself if so. The contention window is **SNR-scaled** — *"The CW size is small for a low SNR, such that nodes that are further away are more likely to flood first"* — a notably more adaptive suppression than a flat random delay. ROUTER and REPEATER roles rebroadcast regardless of hearing others.

**Next-hop routing exists since firmware 2.6** for direct messages: after initial managed flooding locates the destination, later packets route via identified relays, falling back to flooding on the final retry.

**Node-density scaling is built in:** above 40 online nodes, telemetry/position/ancillary intervals scale as `Interval × (1 + (OnlineNodes − 40) × 0.075)`.

**XEdDSA packet signing is being added in firmware 2.8.x.** It reuses each node's existing X25519 keypair to produce Ed25519-style signatures, so no second keypair is needed; signatures are **64 bytes**; a `HAS_XEDDSA_SIGNED` bit is set on NodeInfoLite once a node has signed a User message, surfacing as `has_xeddsa_signed` on NodeInfo, and verified packets display a shield icon.

---

## VERIFIED — from oracle observation

**2026-08-15**, against `meshtastic/meshtasticd@sha256:23e92b13…` (tag `2.7.26.54e0d8d`), run locally in simulated-radio mode. Provenance in `DEPS.md`; the observations themselves in `tests/captures/oracle_observations.json`.

These are **field-level** observations — the node names each header field and its value as it hands the frame to the radio. They establish what the header *contains*, not how it is *packed*. That distinction is kept explicitly, because collapsing it is how an unverified layout becomes a "fact".

**The channel hash function is `xor_fold(name) ^ xor_fold(psk)`**, folding every byte of each with XOR, yielding one byte. Draft item 3 is resolved. Two independent data points:

| channel name | PSK | predicted | observed |
|---|---|---|---|
| `LongFast` | default PSK #1 | `0x08` | `0x08` |
| `TetherTest` | `000102…0f` (XOR-fold `0x00`) | `0x0c` | `0x0c` |

The second case is the one that carries the weight. We supplied the PSK, so the result does not depend on the commonly-asserted default-PSK value being correct, and a second match rules out the 1-in-256 coincidence the first case alone would leave open. Vectors in `tests/captures/channel_hash.json`.

**The default channel's name is empty on the wire, and hashing the empty string is wrong.** Proto3 omits defaults, so the primary channel's `ChannelSettings` carries no `name` field at all — confirmed in the reference's own saved `channels.proto` and in the captured API stream. Folding an empty name yields `0x02`, not the observed `0x08`. The name that is hashed is the **modem preset name**, `LongFast`, substituted when the field is absent. An implementation that takes the name straight from the message will compute the wrong hash for the single most common channel on the network, and will do so silently.

A side effect worth recording: the oracle **loaded a `ChannelFile` we hand-encoded** (`Loaded /prefs/channels.proto successfully`). That is an early, narrow instance of the direction that matters — our encoder, their decoder.

**The default primary channel's stored PSK is the single byte `0x01`** — a short index, not a key, expanded at use (`Expand short PSK #1`) into a 128-bit key (`Use AES128 key!`). A 16-byte PSK supplied directly also selects AES128. This corroborates the asserted default-PSK value without independently proving it: given the now-verified hash function, the observed `0x08` requires `xor_fold(default_psk) == 0x02`, which the asserted value satisfies — necessary, not sufficient.

**`relay_node` is a one-byte truncation of the sender's node number.** Node `0x7739e49b` transmitted `relay=0x9b`. Confirmed twice more, and independently of the log channel, on captured UDP traffic: `0x266cbc2b → 0x2b` and `0x2f7f90dc → 0xdc` (`tests/captures/udp_mesh_capture.json`).

**The `channel` field carries the one-byte channel hash.** Captured packets on the default channel show `channel = 8`, matching `xor_fold("LongFast") ^ xor_fold(default_psk)` — the hash function verified above, now corroborated at a second boundary.

**Header fields confirmed present, with observed values:** `id` (32-bit), `from`, `to` (`0xffffffff` for broadcast), `hop_limit` (3 by default), `hop_start` (3), `want_ack`, the one-byte channel hash, `relay_node`, and a `transport` field observed as 0. Payload length is reported separately as `encrypted len`.

**A deprecated schema field is still on the wire.** `User.macaddr` (field 4, `bytes`) is marked `[deprecated = true]` and was deprecated in Meshtastic 2.1.x, yet firmware 2.7.26 emits it in every `User` — six zero bytes. Anything reproducing reference output must carry it. The general form of this matters more than the instance: **the schema says what a field means, not whether it is transmitted**, so a codec derived from field numbers alone will be wrong in ways only comparison against real output reveals. Found exactly that way, by a wrapper failing to re-encode captured bytes.

**Packet identifiers are 32-bit and re-randomised per packet** — the node logs `Initial packet id`, then `Partially randomized packet id` for each transmission. Relevant to the L2 packet-id discipline: under CTR a repeated `(packet_id, sender)` pair leaks the XOR of two plaintexts.

**The simulator and real silicon disagree on airtime, by about 1.2%.** Same firmware version (`2.7.26.54e0d8d`), same preset, same region UNSET, same 104 × 250 kHz, same 906.875 MHz, same 28 ms slot and 131 ms preamble — and different computed bitrates:

| build | reported bitrate |
|---|---|
| `meshtasticd`, portduino (`S:B:37,…,native,…`) | 118.394310 bytes/sec |
| Heltec V3, real SX1262 (`S:B:43,…,heltec-v3,…`) | 116.967873 bytes/sec |

Small, and it matters where it lands: duty-cycle accounting and the contention window in L5 are computed from airtime, so a figure taken from the simulator is roughly 1.2% optimistic against hardware. **Use the hardware figure for anything that budgets airtime.** Recorded because a discrepancy this size is exactly the kind that gets attributed to measurement noise once it shows up downstream.

**Default LongFast radio parameters, as computed by the reference at runtime** — region UNSET on a 902–928 MHz band: 104 channels × 250 kHz, channel number 20, frequency 906.875 MHz, slot time 28 ms, preamble 131 ms, bitrate 118.394 bytes/sec. A 70-byte encrypted NodeInfo reported `Packet TX: 755ms`. These are the *simulator's* numbers and are consistent with the ~805 ms figure used for planning; they are **not** a substitute for measuring real silicon.

---

## UNVERIFIED — do not write a codec against these yet

These are commonly asserted in secondary descriptions and are **not** confirmed by any primary source read so far. The official "encryption technical" page is explicitly a high-level overview and omits packet-level specification.

1. **The 16-byte header byte layout** — field order, endianness, and the exact flag bit positions. Only `hop_limit` (3 bits) and `hop_start` (3 bits, per the proto comment) are documentarily confirmed as living in the unencrypted header.
2. **The AES-CTR nonce construction** — the draft's `packet_id(8) ‖ from(4) ‖ extra_nonce(4)` layout and the 4-byte counter size.
3. ~~**The channel hash function**~~ — **RESOLVED 2026-08-15** by oracle observation, above. It is `xor_fold(name) ^ xor_fold(psk)`.
4. **The PKI/DM scheme details** — the docs confirm Curve25519 with "encryption and digital signatures" and mention "AES-CTR or AES-CCM" for admin session keys, but not the DM KDF, tag size, or where the extra nonce travels.
5. **The raw sync-word register value a receiver must be programmed with.** The commonly quoted `0x2B` is a library API-level value that gets expanded into a register pair by the driver beneath it; a different radio family's register model will differ. Nothing read so far pins the on-air value itself.
6. **Preset SF/BW/CR parameters.** The enum names are confirmed; the numeric parameters behind each are not, and with 17 presets including 62.5 kHz and 20 kHz variants the draft's 7-row table cannot be complete.

**Resolving these needs either an authoritative byte-level document or a first capture.** Item 3 is now resolved. Items 1 and 2 remain, and the route to them is narrower than this document previously assumed.

**Correction, 2026-08-15 — the local oracle cannot supply the packed bytes.** The plan assumed the raw frame appears at the simulated-radio boundary. It does not. The reference's `SimRadio` is process-local: it hands the frame to a simulated PHY inside the same process and loops it straight back, so no socket ever carries it and nothing outside the process observes the packing. Two instances on one host do not hear each other at all.

The UDP transport is not a way around this. The binary's own strings read `Broadcasting packet over UDP (id=%u)` and `Decoding MeshPacket from UDP len=%u` — UDP over mesh carries a protobuf `MeshPacket`, not the packed LoRa frame. Capturing it would re-encode the same fields in a different encoding and still say nothing about wire layout.

So items 1 and 2 are reachable by exactly three routes, and passive local capture is not among them:

- **a real radio** receiving ambient traffic, which is also what items 5 and 6 need;
- **an authoritative byte-level document**, which has not been found; or
- **differential testing against their decoder** — construct a frame under a candidate layout, offer it to the oracle, and let acceptance or rejection decide. This is slower than reading a capture and it is available now, entirely locally. It is the L4 direction that matters, applied earlier than planned.

---

## THE LOAD-BEARING ASSUMPTION — still unproven, now with evidence

Whether stock nodes relay traffic on channels they cannot decrypt. The entire extension strategy rests on it.

**Supporting:** the routing description makes rebroadcast a function of `hop_limit` and suppression only, never mentioning decryption as a precondition. And the mesh-algorithm page states: *"Only the SubPacket is encrypted, while headers are not. This allows the option of eventually allowing nodes to route packets without knowing anything about the encrypted payload."*

**Why that is not yet proof:** "allows the option of **eventually** allowing" is forward-looking. It describes what the header design permits, not what current firmware does. The channel-hash filter is applied on receive, and whether a hash miss drops before or after the rebroadcast decision is exactly the question — and it is not documented either way.

**Status: PLAUSIBLE, UNPROVEN.** Settle it by observation, or by a targeted test with any stock device to hand: put a frame on a channel that device does not hold, and watch whether it repeats it. Until then, no code should assume free carriage.

**2026-08-15 — still open, and now with a measured reason why the cheap route fails.** The plan expected to answer this in local simulation, where topology is a coordinate rather than a hardware problem.

The first obstacle is that the reference's simulated radio is process-local, so two instances on one host hear nothing of each other. **That obstacle is removable:** setting `network.enabled_protocols = UDP_BROADCAST (0x0001)` makes meshtasticd join multicast `224.0.0.69:4403`, and two local instances then do form a mesh — each node's database independently listed the other. An earlier note here said no such transport existed; that was wrong, and this supersedes it.

**The second obstacle is not removable, and it is the one that matters.** Captured UDP traffic carries `hop_limit` and `hop_start` **absent, i.e. zero**. A packet with no hops left is not a candidate for rebroadcast at all, so this transport never reaches the managed-flooding decision — the exact decision the question is about. Two nodes exchanging over UDP demonstrate delivery, not relay.

So the position is unchanged in substance and better understood: settling this needs two real radios. A local UDP mesh will produce traffic that *looks* like a mesh and cannot answer the question, which makes it a trap worth naming rather than a route worth trying.

---

## Corrections this phase forces

**To the commonly-repeated description of the protocol:** the preset table (7 vs 17, two deprecated), `DATA_PAYLOAD_LEN` (233 not 237), the absence of `next_hop` routing, and the absence of XEdDSA and KEY_VERIFICATION.

**To the extension design, and these matter strategically:**

- **Per-author signing is not a gap an extension needs to fill — upstream is filling it.** Any plan to add "a signature on control events" should be retired or reframed as *alignment*: upstream's 2.8.x XEdDSA is the same idea, the same primitive family, the same 64-byte cost, and the same key-reuse trick.
- **Key verification is not a gap either.** `KEY_VERIFICATION_APP = 12` exists, which addresses the trust-on-first-use weakness directly.
- **The remaining genuine differentiators are narrower than written: groups with a roster, an owner and revocation; and ranging.** Both survive this phase intact — nothing upstream addresses either.
- **The AEAD-tag proposal survives and is strengthened**, because the documented spoofing weakness is worse than assumed: forgery does not require the PSK.
- Any airtime table computed at 237-byte payloads must be re-derived at 233.

The strategic read: **upstream is actively closing the security gaps, so "extend" has a shrinking window on crypto and a durable one on features.** Worth re-testing the plan's premise before Tier 3 is scheduled — Tier 1 and Tier 2 are unaffected.
