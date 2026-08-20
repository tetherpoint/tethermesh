<!-- SPDX-FileCopyrightText: 2026 The tethermesh Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# WIRE_REFERENCE — Meshtastic on-air facts

**Status: v4, 2026-08-16. P0 deliverable, partially complete — read the UNVERIFIED section before writing any codec.** v3 adds on-air capture from real hardware: the 16-byte header layout, the AES-CTR nonce, the sync word and LongFast's modem parameters are all resolved, and the load-bearing relay assumption is settled. **Every item that can be settled without a second hardware generation is now settled.**

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

**A `Position` sender quantises its own coordinates and declares by how much — MEASURED 2026-08-18.** Handed `latitude_i = 123456789` (`0x075BCD15`) over its serial API, a stock node put `123469824` (`0x075C0000`) on the air — **rounded, not truncated**, to eighteen trailing zero bits — and added `Position` field 23, `precision_bits = 13`, which was never supplied to it. `altitude` and `time` went out exactly as given.

**It happens on TRANSMIT, and the receiver's log says otherwise.** Reading only the receiving node's `updatePosition` line suggests the receiver reduced the precision; capturing the frame off the air shows the sender did. The first reading was believed for an hour. A log is one party's account of an event; the bytes are the event.

Consequences for an implementation: `latitude_i` and `longitude_i` are **`sfixed32`** and `time` is `fixed32` — 32-bit, not varint, the same trap as `MeshPacket`'s `from`/`to`/`id` — and an encoder that omits `precision_bits` produces a shorter payload than the reference does. Frame and both directions in `tests/captures/position_record.json` and `on_air_frames.json`.

**`next_hop` is optional on an addressed frame.** A Routing reply carried the destination's low byte; a node-to-node `Position` carried zero while addressed. So the field is set when the sender has a next hop to name and zero when it does not — "addressed implies `next_hop`" was a property of one sample.

**The hop fields' bit positions are pinned by a RELAYED frame, and nothing else could pin them.** `flags` bit 0-2 is `hop_limit` and bits 5-7 are `hop_start` — but every originated frame has the two EQUAL, so an all-originated corpus cannot tell them apart. Measured 2026-08-18: transposing the two fields in both the decoder and the encoder passed all 102 host tests, all 24 ABI tests and every Kani harness, because each gate was self-consistent and the sample could not distinguish them. A frame would have gone on the air with the fields swapped and nothing would have objected.

`on_air_frames.json` now carries a relayed frame — `flags = 0x62`, `0b0110_0010`, `hop_limit = 2` of `hop_start = 3` — and the receiving stock node independently logged `HopLim=2 hopStart=3` for that packet id, so the assignment comes from their decoder rather than ours. The transposition now fails in both crates.

**An ORIGINATING node stamps `relay_node` with its own low byte — it is not left zero.** Measured 2026-08-18 by decoding the corpus rather than by reading prose: all five frames in `on_air_frames.json` are originated (`hop_limit == hop_start`) and every one carries `relay_node = 0x64` for node `0x3369e764`. A stock node originating a direct message logs the same, `relay=0x64` on its own `enqueue for send`.

That matters because zero is the tempting default and it is *tolerated*: frames we sent with `relay_node = 0` were rendered normally by stock nodes, so nothing on the air reports the deviation. Two encoders in our own C ABI wrote 0 and two wrote the low byte, and the disagreement survived until somebody decoded the corpus.

**`relay_node` is a one-byte truncation of the sender's node number.** Node `0x7739e49b` transmitted `relay=0x9b`. Confirmed twice more, and independently of the log channel, on captured UDP traffic: `0x266cbc2b → 0x2b` and `0x2f7f90dc → 0xdc` (`tests/captures/udp_mesh_capture.json`).

**The `channel` field carries the one-byte channel hash.** Captured packets on the default channel show `channel = 8`, matching `xor_fold("LongFast") ^ xor_fold(default_psk)` — the hash function verified above, now corroborated at a second boundary.

**Header fields confirmed present, with observed values:** `id` (32-bit), `from`, `to` (`0xffffffff` for broadcast), `hop_limit` (3 by default), `hop_start` (3), `want_ack`, the one-byte channel hash, `relay_node`, and a `transport` field observed as 0. Payload length is reported separately as `encrypted len`.

**A traceroute reply carries `request_id` and per-hop SNR, and the SNR is quarter-dB.** Captured from a stock node answering our request: `Data{portnum=70, payload=RouteDiscovery{snr_towards:[26]}, request_id=0x0badd002}`. The 26 is 6.5 dB — SNR travels as quarter-dB signed units, matching the packet-status encoding the radio reports. `request_id` echoes the initiator's packet id, which is how a reply is matched to its request.

**A deprecated schema field is still on the wire.** `User.macaddr` (field 4, `bytes`) is marked `[deprecated = true]` and was deprecated in Meshtastic 2.1.x, yet firmware 2.7.26 emits it in every `User` — six zero bytes. Anything reproducing reference output must carry it. The general form of this matters more than the instance: **the schema says what a field means, not whether it is transmitted**, so a codec derived from field numbers alone will be wrong in ways only comparison against real output reveals. Found exactly that way, by a wrapper failing to re-encode captured bytes.

**Packet identifiers are 32-bit and re-randomised per packet** — the node logs `Initial packet id`, then `Partially randomized packet id` for each transmission. Relevant to the L2 packet-id discipline: under CTR a repeated `(packet_id, sender)` pair leaks the XOR of two plaintexts.

**An empty submessage is transmitted, and dropping it breaks byte identity.** The corpus `NodeInfo` carries `1a 00` — field 3, present, zero bytes. proto3 omits an empty scalar, and this project's own `User` encoder omits empty byte fields on exactly that reasoning; applied to a submessage the same rule re-encodes two bytes short. So *absent* and *present-but-empty* are distinct on this wire and a wrapper has to represent both — `meshtastic/core/message.rs` uses `Option<&[u8]>`, where `None` is absent and `Some(&[])` is present-and-empty.

This is the **second** instance of one pattern, which is what makes it a rule rather than a quirk: `User.macaddr` is deprecated in the schema and still emitted, and field 3 here is empty in the schema's terms and still emitted. **The schema says what a field means; the wire decides whether it is transmitted.** Anything reproducing reference bytes must be checked against bytes, because semantic equality passes both of these and byte identity fails them.

**`NodeInfo` layout, as measured.** From `tests/captures/fromradio_corpus.json`:

| field | wire type | observed | established? |
|---|---|---|---|
| 1 | varint | `0x021e81dd`, matching the `!021e81dd` in its own nested `User.id` | yes — value corroborated twice within the message |
| 2 | len | a `User` | yes |
| 3 | len | **zero bytes** | present; contents never observed non-empty |
| 10 | varint | `1` | **the field exists; its meaning does not follow.** One capture of a varint `1` names nothing, and no primary document read here records it |

Fields 4–9 do not appear. That is not evidence they do not exist — this corpus is one node's own record on a local simulation, so a field only populated by a heard neighbour would be absent for that reason alone. The wrapper carries 1, 2, 3 and 10 and drops the rest, which is recorded in its own documentation as a limitation rather than presented as completeness.

**LongFast is bandwidth 250 kHz, spreading factor 11, coding rate 4/5** — on real hardware, from the firmware's own mouth. This is the first hard data against draft item 6.

Method matters here, because it is what makes this evidence rather than another assertion. A `LoRaConfig` was written to a Heltec V3 running `2.7.26.54e0d8d` with `use_preset = true`, `modem_preset = LONG_FAST`, and the bandwidth, spreading-factor and coding-rate fields **absent** — proto3 default, i.e. zero. Reading the config back returned `bandwidth = 250`, `spread_factor = 11`, `coding_rate = 5`. The firmware populated them, so these are its values for the preset and not an echo of anything we supplied.

~~It covers **one preset of seventeen**. The commonly repeated table happens to agree for this row; that is now checked rather than assumed for LongFast alone, and says nothing about the other sixteen — including the 62.5 kHz and 20 kHz variants that made the draft's 7-row table impossible in the first place. The bench was found running `VLongSlow` at 62.5 kHz, so that row is reachable the same way.~~

**Struck 2026-08-17.** Written while this was the only measured row, and left standing when the sweep closed item 6. There are **nine valid presets, not seventeen**, and all nine are measured — see item 6 below for the table and the method. The paragraph is kept because the caution in it was right: the commonly repeated table was not evidence, and checking it is what revealed that seven of its rows do not exist.

**The simulator and real silicon disagree on airtime, by about 1.2%.** Same firmware version (`2.7.26.54e0d8d`), same preset, same region UNSET, same 104 × 250 kHz, same 906.875 MHz, same 28 ms slot and 131 ms preamble — and different computed bitrates:

| build | reported bitrate |
|---|---|
| `meshtasticd`, portduino (`S:B:37,…,native,…`) | 118.394310 bytes/sec |
| Heltec V3, real SX1262 (`S:B:43,…,heltec-v3,…`) | 116.967873 bytes/sec |

Small, and it matters where it lands: duty-cycle accounting and the contention window in L5 are computed from airtime, so a figure taken from the simulator is roughly 1.2% optimistic against hardware. **Use the hardware figure for anything that budgets airtime.** Recorded because a discrepancy this size is exactly the kind that gets attributed to measurement noise once it shows up downstream.

**Default LongFast radio parameters, as computed by the reference at runtime** — region UNSET on a 902–928 MHz band: 104 channels × 250 kHz, channel number 20, frequency 906.875 MHz, slot time 28 ms, preamble 131 ms, bitrate 118.394 bytes/sec. A 70-byte encrypted NodeInfo reported `Packet TX: 755ms`. These are the *simulator's* numbers and are consistent with the ~805 ms figure used for planning; they are **not** a substitute for measuring real silicon.

---

## VERIFIED — from on-air capture, 2026-08-16

**Items 1, 2, 5 and 6 are resolved.** A Heltec V3 running stock Meshtastic `2.7.26.54e0d8d` transmitted; a second Heltec ran our own SX1262 receiver — written from the datasheet, not RadioLib — and printed the PHY payload verbatim. Frames and decodes in `tests/captures/on_air_frames.json`.

That the frames arrived at all resolves two items by construction: **nothing decodes without the right sync word and the right modem parameters.**

### Item 5 — sync word

**Registers `0x0740 = 0x24`, `0x0741 = 0xB4`.** This is the expansion of the commonly quoted API-level `0x2B`, and it is now confirmed on air rather than assumed: a receiver programmed with these values decodes stock traffic.

### Item 6 — modem parameters, for LongFast

**SF 11, BW 250 kHz, CR 4/5, preamble 16 symbols, explicit header, CRC on, standard IQ**, at 906.875 MHz. Confirmed twice over: the firmware reported them through `get_config`, and a receiver configured with them decodes real frames.

This section covers LongFast only because LongFast is the row with two independent derivations behind it. That is no longer the extent of what is measured — the sweep below covers **all nine valid presets**. The sentence "Still one preset of seventeen" stood here until 2026-08-17; there are nine, and they are all measured.

### Item 1 — the 16-byte header

```
offset  size  field       encoding
   0     4    to          u32 little-endian
   4     4    from        u32 little-endian
   8     4    id          u32 little-endian
  12     1    flags       bits 0-2 hop_limit, bit 3 want_ack,
                          bit 4 via_mqtt, bits 5-7 hop_start
  13     1    channel     one-byte channel hash
  14     1    next_hop    low byte of node number, 0 = none
  15     1    relay_node  low byte of the relaying node's number
```

A captured frame, split at the boundary:

```
ffffffff 64e76933 432397ea 63 08 00 64 | b430ebee...
   to      from      id     ^  ^  ^  ^
                           flags |  | relay_node 0x64
                              channel hash 0x08
                                     next_hop 0
```

Every field cross-checks against something established independently. `to` is the broadcast address. `from` little-endian is `0x3369e764`, the transmitting node. `0x08` is the channel hash the verified `xor_fold` function predicts for LongFast with the default PSK. `0x64` is the low byte of `0x3369e764`, matching the `relay_node` rule. And `flags = 0x63` is `hop_limit = 3` in bits 0-2 with `hop_start = 3` in bits 5-7 — exactly the three-bits-each the proto comments describe, and exactly the `hop_limit` that was requested.

**All multi-byte fields are little-endian.** Note this is the opposite of the protobuf `fixed32` byte order intuition some readers bring, and it is the single most likely thing to get silently wrong.

### Item 4 — PKI direct messages

**Resolved 2026-08-16.** We published an X25519 public key for a synthetic node, drove the stock node's own API to send that node a text, captured the frame off the air, and decrypted it with the matching private key.

```
key agreement  X25519
KDF            SHA-256 over the raw shared secret
cipher         AES-256-CCM, 8-byte tag
key size       32 bytes — the FULL SHA-256 output, not truncated to 128 bits
nonce (13 B)   packet_id (u32 LE) || extra_nonce (4 B) || from (u32 LE) || 0x00
payload        ciphertext || tag(8) || extra_nonce(4)
channel byte   0x00 — this is how a PKI packet is distinguished on the wire
```

The extra nonce travels **appended to the payload**, which is the part the draft could not say. A receiver reads the last four bytes first, rebuilds the nonce, then authenticates and decrypts what precedes them.

Confirmed against the firmware's own debug output, which prints both the nonce and the first bytes of the derived key: our reconstruction matched `9a f4 4f c0 2d f4 51 58 64 e7 69 33 00` and `d8 85 d2 24 e6 cc 3d e0` exactly, and the ciphertext decrypted to `Data{portnum=1, payload="pki-probe-B"}`.

**Direct messages are authenticated; channel messages are not.** CCM carries a tag, so a forged DM fails verification. That is a real asymmetry: the forgery weakness recorded above applies to channel traffic, not to the PKI path.

**Two behaviours that constrain any implementation.** A stock node uses PKI for direct messages **by default and refuses to fall back** to channel encryption when it does not hold the destination's public key — *"Unknown public key for destination node …, refusing to send legacy DM"*. A node that has never published a key cannot be sent a direct message at all. And the key must have been learned in the current boot; a node learned and then lost across a reset takes the key with it.

### Item 2 — the AES-CTR nonce

```
nonce = packet_id (u64 little-endian) || from (u32 little-endian) || extra_nonce (u32 little-endian)
```

Sixteen bytes, used as the **initial CTR block and incremented as a 128-bit big-endian integer**. The draft's layout was right; the byte order and the counter semantics were not established until now.

Proof is direct rather than plausible: the captured ciphertext decrypts under the default channel key to

```
0801 120d 736e6966662d70726f62652d30 4800
```

which is `Data{portnum = 1 (TEXT_MESSAGE_APP), payload = "sniff-probe-0", bitfield = 0}` — the exact text that was transmitted. Three frames, each 19 bytes of ciphertext, so the decryption spans two AES blocks and confirms the counter increment as well as the first block.

**The security consequence is now concrete.** `extra_nonce` was zero in every frame observed, so the nonce is a pure function of `packet_id` and `from`. A repeated `(packet_id, sender)` pair therefore reproduces the keystream exactly — which is what makes `meshtastic/core/packet_id.rs` a security component rather than a bookkeeping one.

---

## UNVERIFIED — do not write a codec against these yet

These are commonly asserted in secondary descriptions and are **not** confirmed by any primary source read so far. The official "encryption technical" page is explicitly a high-level overview and omits packet-level specification.

1. ~~**The 16-byte header byte layout**~~ — **RESOLVED 2026-08-16** by on-air capture, above.
2. ~~**The AES-CTR nonce construction**~~ — **RESOLVED 2026-08-16** by decrypting captured frames to known plaintext, above.
3. ~~**The channel hash function**~~ — **RESOLVED 2026-08-15** by oracle observation, above. It is `xor_fold(name) ^ xor_fold(psk)`.
4. ~~**The PKI/DM scheme details**~~ — **RESOLVED 2026-08-16** by capturing and decrypting a real direct message, above. The docs had confirmed Curve25519 and mentioned "AES-CTR or AES-CCM" without saying which, nor the KDF, the tag size, or where the extra nonce travels. All four are now measured.
5. ~~**The raw sync-word register value**~~ — **RESOLVED 2026-08-16**: `0x0740 = 0x24`, `0x0741 = 0xB4`, confirmed by decoding real traffic.
6. ~~**Preset SF/BW/CR parameters**~~ — **RESOLVED 2026-08-16 for every valid preset.** SF and BW by writing each preset to a stock node and reading back what it programmed; **coding rate by timing**, and it is 4/5 on all nine — see below. Full table in `tests/captures/modem_presets.json`. (This line read "coding rate remains unmeasured" until 2026-08-17; it was written between the two measurements and not revisited.)

**The count in this item was wrong, and the correction is the more useful finding.** It said "sixteen presets remain". There are **eight** further valid presets beyond LongFast, not sixteen. Presets 2 and 10–16 are not presets at all: the node reports `name=Invalid` and **silently serves LongFast parameters**. Preset 2 is the deprecated `VERY_LONG_SLOW`; 10–16 are past the end of the enum. A node configured to an out-of-range preset does not fail — it quietly runs LongFast, which is worth knowing before attributing a mismatch to something else.

| preset | name | BW kHz | SF | bitrate B/s |
|---|---|---|---|---|
| 0 | LongFast | 250 | 11 | 116.967873 |
| 1 | LongSlow | 125 | 12 | 27.011360 |
| 2 | *Invalid* | — | — | falls back to LongFast |
| 3 | MediumSlow | 250 | 10 | 216.141006 |
| 4 | MediumFast | 250 | 9 | 394.915253 |
| 5 | ShortSlow | 250 | 8 | 703.927490 |
| 6 | ShortFast | 250 | 7 | 1239.361694 |
| 7 | LongMod | 125 | 11 | 49.343502 |
| 8 | ShortTurbo | 500 | 7 | 2478.723389 |
| 9 | LongTurbo | 500 | 11 | 233.935745 |
| 10–16 | *Invalid* | — | — | fall back to LongFast |

**Method, and why SF is trustworthy when the node never reports it.** Bandwidth is stated outright at boot. SF is not — it falls out of the preamble time, since sixteen preamble symbols give `T_sym = preamble_ms / 16` and `2^SF = T_sym × BW`. At LongFast that yields SF11, which **on-air capture had already established independently**. One preset with two independent derivations is what licenses the derivation for the other eight. All nine are cross-checked against `meshtastic/core/airtime.rs` by a committed test.

**Coding rate — MEASURED 2026-08-16, and it is `4/5` on every valid preset.** So the preset table varies **spreading factor and bandwidth only**; coding rate is constant across all nine.

| | LongFast | LongSlow | MedSlow | MedFast | ShortSlow | ShortFast | LongMod | ShortTurbo | LongTurbo |
|---|---|---|---|---|---|---|---|---|---|
| CR | 4/5 | 4/5 | 4/5 | 4/5 | 4/5 | 4/5 | 4/5 | 4/5 | 4/5 |
| residual | 1.4 | 1.6 | 0.2 | 3.4 | 3.6 | 1.7 | 3.9 | 1.6 | 4.3 ms |

**Reception cannot reveal the coding rate, and the earlier record wrongly implied it had.** In explicit-header mode the header carries the payload's CR, is itself sent at a fixed 4/8, and the receiver reconfigures from it. Demonstrated: a receiver deliberately set to 4/8 and to 4/6 decoded the same frames `crc=ok` at matched SF and BW. So `on_air_frames.json`'s "CR 4/5" was our *receiver's setting*, not a measurement — corrected in that file.

**What worked was timing.** The receiver timestamps `header-valid` against `rx-done`, which is the payload airtime, and airtime is a function of the coding rate. The CR is read from the **difference between a 91-byte and a 44-byte relay**, which cancels the constant offset of wherever `header-valid` fires. Residuals against the 4/5 prediction ran 0.2–4.3 ms — all inside the receiver's 10 ms polling quantisation — while the nearest alternative, 4/6, sat between 27 ms and 328 ms away depending on preset. LongFast was measured three times independently (366.7, 360.0, 370.0 ms against 368.6 predicted).

**This settles a drift recorded while CR was unknown.** The ratio of the node's reported bitrate to `SF·BW/2^SF` varies with spreading factor — 0.697 at SF11, 0.725 at SF7. With CR now known to be constant, that drift can only be the packet-overhead term. The earlier refusal to invert the bitrate to recover CR was correct, and for the right reason.

**And a fact that was not previously recorded at all: THE CARRIER MOVES WITH THE PRESET.** The channel slot derives from the channel name *and the number of slots available at the configured bandwidth*, so each preset lands on a different frequency — 902.688 MHz (LongMod) to 926.750 MHz (ShortTurbo). A receiver matching spreading factor and bandwidth but not frequency hears nothing, and "nothing received" is indistinguishable from "wrong parameters". The first attempt at this measurement lost eight of nine presets to exactly that.

| preset | freq MHz | | preset | freq MHz |
|---|---|---|---|---|
| LongFast | 906.875 | | ShortFast | 918.875 |
| LongSlow | 905.312 | | LongMod | 902.688 |
| MediumSlow | 914.875 | | ShortTurbo | 926.750 |
| MediumFast | 913.125 | | LongTurbo | 908.750 |
| ShortSlow | 920.625 | | | |
7. **Contention window** — **PARTIALLY RESOLVED 2026-08-16.** Three properties measured, one still open. Record in `tests/captures/contention_window.json`; 33 relays observed off a stock node.

   **Settled:**
   - **The backoff is a random draw, not a deterministic delay.** At essentially constant SNR (5.50–6.75 dB) the observed delays spread from 644 ms to 3976 ms. No deterministic function of SNR produces a 3332 ms spread from a fixed input. This was precisely the ambiguity a single earlier sample could not resolve.
   - **Delays are quantised to the slot time.** All 33 were exact integer multiples of **28 ms**, without exception — confirming the window is counted in slots, and that the slot time the node reports is the quantum actually used.
   - **At ~6 dB SNR the window reaches at least 142 slots**, draws spanning 23–142, mean 79.8, broadly uniform — consistent with a uniform draw over roughly 17–143 slots.

   **Still open: the SNR scaling.** The measurement's primary axis *failed*. Sweeping our transmitter from +14 to −9 dBm — 23 dB — moved the reported SNR by **1.25 dB**, because at ~3 m separation even −9 dBm arrives around −46 dBm against an SF11/BW250 sensitivity near −134 dBm. With ~88 dB of margin LoRa's reported SNR simply sits at its ceiling. **Varying it needs real attenuation or much greater separation, not a power setting.** So the low-SNR end of the window, and the slope between the ends, remain unmeasured.

   **Consequence for our code, recorded because it is the point.** `meshtastic/core/routing.rs` shipped `max_slots: 8`. The measured window is at least 142 slots — wrong by more than an order of magnitude. The documented *direction* was right and the *scale* was a guess. It also returned a deterministic wait where the real behaviour draws within a window, which would have made every node at similar SNR transmit simultaneously and collide instead of suppressing. Both are now corrected, and a test ties the constant to the fixture so it cannot drift from its evidence again. The official documentation says only *"The CW size is small for a low SNR, such that nodes that are further away are more likely to flood first."* No primary source read so far gives `CW_MIN`, `CW_MAX`, or the SNR range they map across. `meshtastic/core/routing.rs` implements the documented direction with **our own** parameterisation, marked as ours in that module rather than presented as theirs. Frames stay identical and suppression still works, so this does not affect interoperability — but our *timing* will not match a stock node's, so we may win or lose races we would otherwise have lost or won. Settling it needs a timed capture of several nodes relaying one frame.

**Airtime, and what is actually established about it.** `meshtastic/core/airtime.rs` computes time-on-air from **Semtech's** published LoRa formula — the radio vendor's, not the reference implementation's. Two things anchor it here rather than to itself:

- **The preamble lands exactly.** At SF11/BW250 the symbol time is 8.192 ms, so sixteen preamble symbols are 131.07 ms — matching the **131 ms** recorded below from oracle observation. That pins the preamble at sixteen symbols, which would otherwise have been a free parameter.
- **The residual points the right way.** A 70-byte packet models at 763.9 ms where the *simulator* reported 755 ms, +1.18%. The simulator's bitrate is separately measured as ~1.2% optimistic against silicon, so the formula disagrees with the simulator by very nearly the amount the simulator is already known to be wrong by — and therefore agrees with hardware.

**That is corroboration from a single observed packet, not a measurement.** A direct hardware sweep across payload sizes is still wanted, and until then airtime is *checked against someone else's answer* rather than verified.

~~**Only item 6 remains.** Items 1–5 are resolved above, each by capture or observation rather than by assertion. Sixteen presets are outstanding, and they are bounded rather than unknown: the method that resolved LongFast works unchanged.~~

**Struck 2026-08-17 — all six items are resolved.** Items 1–5 by capture or observation; item 6 by the preset sweep on 2026-08-16, SF and BW read back from a stock node and coding rate settled by timing. The prediction in the struck sentence held exactly: the method that resolved LongFast did work unchanged. Only the count was wrong, and there were eight further presets to find rather than sixteen.

~~**Resolving these needs either an authoritative byte-level document or a first capture.** Item 3 is now resolved. Items 1 and 2 remain, and the route to them is narrower than this document previously assumed.~~ **Struck 2026-08-16** — this sentence and the three-routes analysis below it were written while items 1 and 2 were open, and were left standing when the capture closed them. The analysis is kept because it is *how* they were closed: the first of the three routes is the one that worked.

**Correction, 2026-08-15 — the local oracle cannot supply the packed bytes.** The plan assumed the raw frame appears at the simulated-radio boundary. It does not. The reference's `SimRadio` is process-local: it hands the frame to a simulated PHY inside the same process and loops it straight back, so no socket ever carries it and nothing outside the process observes the packing. Two instances on one host do not hear each other at all.

The UDP transport is not a way around this. The binary's own strings read `Broadcasting packet over UDP (id=%u)` and `Decoding MeshPacket from UDP len=%u` — UDP over mesh carries a protobuf `MeshPacket`, not the packed LoRa frame. Capturing it would re-encode the same fields in a different encoding and still say nothing about wire layout.

So items 1 and 2 were reachable by exactly three routes, and passive local capture was not among them:

- **a real radio** receiving ambient traffic, which is also what items 5 and 6 need — **this is the one that worked**, 2026-08-16;
- **an authoritative byte-level document**, which was never found; or
- **differential testing against their decoder** — construct a frame under a candidate layout, offer it to the oracle, and let acceptance or rejection decide. Not needed for items 1 and 2 in the end, but this became the L4 conformance direction independently.

**Why the correction above is worth keeping rather than deleting.** The premise that the raw frame appears at the simulated-radio boundary was wrong, and it was wrong in a way that would have produced *confident* results: a field-level view looks like a capture until you try to read byte offsets off it. The route that settled these items required hardware that had not arrived when the plan was written.

---

## `RouteDiscovery` field 2 — DERIVED 2026-08-16

From a traceroute reply already held in `tests/captures/conformance_record.json`, no new capture required. Its decrypted plaintext is `0846120312011a3502d0ad0b4800`:

```
08 46              Data.portnum = 70 (TRACEROUTE_APP)
12 03  12 01 1a    Data.payload = RouteDiscovery
                     └─ field 2, length 1, value 26      <- snr_towards
35 02d0ad0b        Data.request_id = 0x0badd002
48 00              Data.bitfield = 0
```

So **`RouteDiscovery` field 2 is `snr_towards`**, length-delimited and carrying quarter-dB values — 26 is 6.5 dB, matching the SNR the node reported for that hop by other means.

**Only field 2, and only because one hop was traced.** A single-hop trace has a trivial route, so the route list itself is empty and its field number stays unestablished. A multi-hop trace would populate it.

---

## `next_hop` — OBSERVED 2026-08-16

The schema documents it as *"Last byte of the node number… Set by the firmware internally, clients are not supposed to set this."* Now seen directly:

| frames | `next_hop` | `hop_limit` / `hop_start` |
|---|---|---|
| broadcasts (`to = 0xffffffff`) | `0x00` | 3 / 3 |
| an addressed reply (`to = 0x7e570001`) | **`0x01`** — the destination's last byte | 2 / 2 |

So `next_hop` is **zero on broadcasts and the destination's low byte on addressed frames**, and an addressed reply travels on a shorter hop budget than the broadcast that provoked it. This is the first direct evidence of next-hop routing on this bench.

**It does not settle the per-hop retry question.** That asks whether the routing *mode* changes across retransmission attempts, which needs a multi-hop path to observe. This shows only that the field is populated as documented on a single hop.

---

## ACKNOWLEDGEMENTS — MEASURED 2026-08-16

`PortNum ROUTING = 5` was known from the schema; the message it carries was not, so acknowledgement **generation** could not be written from verified facts. A stock node was asked for one instead. Record in `tests/captures/routing_ack.json`.

```
Data { portnum: 5, request_id: <the original packet's id>, payload: <Routing> }
Routing field 3 = 0   accepted
Routing field 3 = 6   rejected (one observed case)
```

**`Data.request_id` is the whole matching key**, and it needs nothing this project had not already verified. Matching an acknowledgement requires no knowledge of the `Routing` message at all — only interpreting its *status* does.

**Success is encoded EXPLICITLY as field 3 = 0 — the two bytes `18 00` — not omitted.** proto3 normally drops a zero varint, so an acknowledgement generated from first principles would have carried an empty payload. This is the single most useful thing the capture produced, and it is exactly the kind of detail that is invisible until something refuses to accept your frame.

Three further observations, recorded as observed rather than explained:

- **The reply comes back channel-encrypted (`ch=0x08`) even when the message being acknowledged was PKI (`ch=0x00`).** The acknowledgement does not inherit the request's encryption mode.
- **The positive acknowledgement itself sets `want_ack`**, and was therefore retransmitted three times on the ~7 s ladder, because this stack never acknowledges anything. The rejection did **not** set `want_ack` and was sent once. The asymmetry is observed; no explanation is claimed.
- `hop_limit` on both replies was 2 with `hop_start` 2, against the probe's 3.

**Our acknowledgement is accepted — validated 2026-08-16, with a control.** A stock node was driven to send a `want_ack` direct message twice. Unacknowledged it transmitted **three** times at 7.08 and 7.34 s. Acknowledged — with a frame built by `meshtastic/core/delivery.rs`, sent 1.4 s after their first — it transmitted **once**. Same session, same nodes; the only variable was whether we replied.

That is the direction that matters. Everything before it proved we can *read* an acknowledgement; this proves we can *write* one they accept. It also confirms the `18 00` payload is right: had it been the empty payload proto3 would generate, the ladder would have continued and the failure would have looked like a radio problem.

**A stock node acknowledges a `want_ack` direct message that we originate — measured 2026-08-17.** Everything above tested the other direction: a stock node sent, and we replied in a form it accepted. This is the reverse, and it is a separate claim, because it depends on our *request* being well-formed rather than our *reply*.

An addressed message with `want_ack` set was encoded here and transmitted. The destination replied, and the reply decoded on the receiving hardware as:

```
08 05            Data.portnum = 5   ROUTING
12 02 18 00      Data.payload = Routing{ field 3 = 0 }   accepted
35 06 00 00 51   Data.request_id = 0x51000006            our packet's id
```

`request_id` matching the transmitted packet is the part that matters: it is the whole matching key, so an acknowledgement that carried anything else would be unattributable even though it decoded.

**What this does NOT establish, and the distinction is easy to lose.** The reply above reached us over a two-hop path — but the topology was imposed in software, by dropping frames that arrived directly from the destination, rather than by RF range. All three nodes were in mutual range throughout. That is sound for protocol questions, because nothing in the protocol can distinguish a filtered frame from an unheard one, and it is worth nothing for RF questions. **Per-hop retry behaviour therefore remains unsettled**: observing it needs a stock node retransmitting across a path it genuinely cannot shortcut, and no such path existed. The position taken in `core/delivery.rs` — that none is taken — still stands.

**The enum name for status 6 is not established here.** Naming it needs the schema read as specification. The plausible cause — the destination holds our public key and expects PKI for direct messages, and the probe was channel-encrypted — is inference and is not claimed.

---

## RETRY BEHAVIOUR — MEASURED 2026-08-16

A stock node was driven to send a `want_ack` direct message to a node that **never acknowledges anything**, and every transmission was captured on the air with a firmware timestamp. Withholding the acknowledgement required no special mode: this stack sends none at all. Record in `tests/captures/retry_behaviour.json`.

| what | measured |
|---|---|
| attempts per message | **3** — one initial plus two retransmissions, then it stops |
| interval | **~7 s**, observed 6.38–7.67 s across eight samples |
| header across attempts | **byte-identical** — `flags 0x6b` throughout, `hop_limit` stays 3 |
| payload across attempts | **changes every time** — re-encrypted with a fresh extra nonce |

Consistent across four trials.

**The payload result is the one to notice.** The packet id is unchanged while the ciphertext differs, which means each retransmission is re-encrypted rather than resent verbatim. An implementer need not copy that: resending the identical frame is cryptographically safe, because nonce reuse is only dangerous across *different* plaintexts, and the receiver drops the repeated `(from, id)` as a duplicate either way.

**What this does NOT establish: whether retry behaviour differs per hop.** This document records that next-hop routing falls back *"to flooding on the final retry"*, which implies the routing mode changes across attempts. Nothing of the kind is visible here — the header is identical across all three. **But the bench has two nodes, so there is no multi-hop path for next-hop routing to engage on**, and the single-hop case may simply not exercise it. No claim is made either way. Settling it needs a third node.

---

## THE LOAD-BEARING ASSUMPTION — SETTLED 2026-08-16, ON HARDWARE

**Stock nodes DO relay traffic on channels they cannot decrypt.** Measured, not inferred, on two Heltec V3s running `2.7.26.54e0d8d` about 3 m apart at 10 dBm.

**Method.** Node A transmitted a broadcast text with `hop_limit = 3` on the default channel (hash `0x08`). Node B's primary channel had its **PSK replaced with sixteen zero bytes while its name was left as `LongFast`** — moving B's channel hash to `0x0a` and leaving it unable to decrypt anything from A.

Changing only the PSK is the point. The frequency slot derives from the channel *name*, so renaming B would have moved it to a different frequency, and "did not hear" is indistinguishable in a log from "did not relay". B was confirmed still on `channel_num: 20`, `906.875 MHz` after the change.

**Result.** Against a control run on a matching channel:

| log line | control | hash mismatch |
|---|---|---|
| `[RadioIf] Lora RX … Ch=0x8` | yes | **yes** |
| `[Router] Use channel 0 (hash 0x8)` | yes | **no** |
| `[Router] decoded message` | yes | **no** |
| `[Router] handleReceived(REMOTE)` | yes | **no** |
| `[Router] Rebroadcast received message` | yes | **yes** |
| `[RadioIf] Started Tx … HopLim=2` | yes | **yes** |

B never matched the channel, never decrypted, never handed the packet to any module — **and rebroadcast it regardless**, with `hop_limit` decremented 3 → 2.

**Three details that matter to the extension design:**

- **The channel hash is preserved on relay.** The forwarded frame still carries `Ch=0x8`, A's hash, not B's. A relaying node does not restamp it.
- **`hop_limit` is the only field observed to change** (3 → 2). `transport` also moved 0 → 1, marking the packet as relayed rather than local.
- **Duplicate suppression runs even for undecryptable traffic.** B logged `Packet History - insert` for the frame it could not read, so a node's dedup window is spent on foreign traffic too.

The documentation's *"allows the option of eventually allowing"* understated current behaviour: 2.7.26 already does it. **Free carriage may now be assumed** — for this firmware version, which is the only claim the measurement supports.

## The earlier reasoning, kept for the record

Whether stock nodes relay traffic on channels they cannot decrypt. The entire extension strategy rests on it.

**Supporting:** the routing description makes rebroadcast a function of `hop_limit` and suppression only, never mentioning decryption as a precondition. And the mesh-algorithm page states: *"Only the SubPacket is encrypted, while headers are not. This allows the option of eventually allowing nodes to route packets without knowing anything about the encrypted payload."*

**Why that is not yet proof:** "allows the option of **eventually** allowing" is forward-looking. It describes what the header design permits, not what current firmware does. The channel-hash filter is applied on receive, and whether a hash miss drops before or after the rebroadcast decision is exactly the question — and it is not documented either way.

**Status: PLAUSIBLE, UNPROVEN.** Settle it by observation, or by a targeted test with any stock device to hand: put a frame on a channel that device does not hold, and watch whether it repeats it. Until then, no code should assume free carriage.

**2026-08-15 — still open, and now with a measured reason why the cheap route fails.** The plan expected to answer this in local simulation, where topology is a coordinate rather than a hardware problem.

The first obstacle is that the reference's simulated radio is process-local, so two instances on one host hear nothing of each other. **That obstacle is removable:** setting `network.enabled_protocols = UDP_BROADCAST (0x0001)` makes meshtasticd join multicast `224.0.0.69:4403`, and two local instances then do form a mesh — each node's database independently listed the other. An earlier note here said no such transport existed; that was wrong, and this supersedes it.

**The second obstacle is not removable, and it is the one that matters.** Captured UDP traffic carries `hop_limit` and `hop_start` **absent, i.e. zero**. A packet with no hops left is not a candidate for rebroadcast at all, so this transport never reaches the managed-flooding decision — the exact decision the question is about. Two nodes exchanging over UDP demonstrate delivery, not relay.

So the position is unchanged in substance and better understood: settling this needs two real radios. A local UDP mesh will produce traffic that *looks* like a mesh and cannot answer the question, which makes it a trap worth naming rather than a route worth trying.

**That prediction held.** Two real radios settled it in a single afternoon, and the local routes never could have. Recorded because the reasoning was right for the right reason, and the same shape of argument applies to what is still open: the packed header bytes are not obtainable from any local boundary either.

---

## PUBLIC KEYS ARE PINNED ON FIRST USE — MEASURED 2026-08-18, ON HARDWARE

**A node does not replace a public key it has already learned for a peer.** The
later `NodeInfo` is received, parsed and applied to the node database, and the
key in it is silently discarded.

**How it was measured.** Our node published a `NodeInfo` carrying key A, which
three stock nodes learned. Its key was then changed twice, to B and finally to
C, and further `NodeInfo` frames were broadcast. All three stock nodes continued
to report key A.

The obvious confound — that they simply never received the later frames — was
excluded from both ends:

- The nearest stock node's own log shows the frame arriving and being applied:
  `Received nodeinfo from=0x…, portnum=4, payloadlen=78`, then
  `Update DB node 0x…`. It even rebroadcast the frame.
- Our transmitted frame was decrypted independently and confirmed to carry key
  **C**, not key A — so the stale key is on the receiving side, not ours. The
  decrypted `User` was `id`, `long_name`, `short_name`, `macaddr` (six zeros)
  and a 32-byte `public_key`, totalling the 78 bytes their log reported.

**Nothing is logged about the key at all.** No warning, no rejection, no mention
of a change. Searching the receiving node's output for any key-related line
returns nothing, so from the outside a pinned stale key and a correctly updated
one are indistinguishable until a direct message fails to decrypt.

**This is trust-on-first-use, observed.** It is the behaviour `KEY_VERIFICATION_APP
= 12` exists to strengthen, and it is the correct security choice: a node that
accepted any new key for a known number would let an attacker take over an
identity by broadcasting one. Recorded here because the *consequence* is severe
and undocumented in what we can read.

**The consequence, stated plainly: a node's key pair is drawn once and then
never rotated.** Rotating it makes the node unaddressable by every peer that
already knew it — their cached key no longer matches, direct messages are
encrypted to a key it does not hold, and nothing on either side reports why.
Recovery needs each peer to forget the node, not another broadcast.

**What still works when the key is stale, and why.** Acknowledgement is decided
from the 16-byte header alone, so a node whose key is stale still acknowledges a
direct message it cannot decrypt — confirmed on the same run: the stock node
logged `Received a ACK for 0x…, stopping retransmissions` for a message whose
body the receiver never read. That separation is deliberate; see the
acknowledgement section above.

---

## LORA_24 — THE 2.4 GHz DEFAULT CHANNEL — MEASURED 2026-08-20, FROM THE ORACLE

**The `LORA_24` default channel is not published anywhere reachable, and is now measured.** It could not be derived: the frequency slot is a hash of the channel name modulo a **band-dependent** slot count, so knowing the US answer does not yield the 2.4 GHz one. No published source gives it, and no capture from a real 2.4 GHz node was available.

**Nothing was reverse-engineered — the reference was asked.** `meshtasticd` prints its whole derivation whenever a region is applied, so the region was set over the TCP API and the answer read out of the node's own log. No source was read. Same pinned build as every other oracle observation here; the harness that drives it lives outside this repository with the binary it drives.

**The control is what makes the rest of the table trustworthy.** Region US was probed in the same sweep and returned **906.875 MHz, 104 × 250 kHz** — the frequency this project already interoperates with on air. A 2.4 GHz row from an instrument that could not reproduce the known answer would be worth nothing.

| region | band MHz | slots | BW kHz | ch | frequency MHz | slot ms | preamble ms |
|---|---|---|---|---|---|---|---|
| US *(control)* | 902.000 – 928.000 | 104 | 250.0 | 19 | **906.875000** | 28 | 131 |
| **LORA_24** | **2400.000 – 2483.500** | **102** | **812.5** | **5** | **2404.468750** | **17** | **40** |
| NZ_865 | 864.000 – 868.000 | 16 | 250.0 | 3 | 864.875000 | 28 | 131 |
| TH | 920.000 – 925.000 | 20 | 250.0 | 15 | 923.875000 | 28 | 131 |
| UA_433 | 433.000 – 434.700 | 6 | 250.0 | 5 | 434.375000 | 28 | 131 |
| UA_868 | 868.000 – 868.600 | 2 | 250.0 | 1 | 868.375000 | 28 | 131 |
| MY_433 | 433.000 – 435.000 | 8 | 250.0 | 3 | 433.875000 | 28 | 131 |

**`LORA_24 = 13` is now confirmed twice over**, which is why the neighbours are in the table at all: the value was already recorded above from the pinned `.proto`, and this sweep independently had the binary name each integer back — 11→`NZ_865`, 12→`TH`, 13→`LORA_24`, 14→`UA_433`, 15→`UA_868`, 16→`MY_433`. Two routes, one answer.

**The slot arithmetic is identical on both bands**, and all seven rows satisfy it: `numChannels = floor(span / BW)` and `freq = freqStart + BW/2 + ch × BW`. US gives 902 + 0.125 + 19 × 0.25 = 906.875; LORA_24 gives 2400 + 0.40625 + 5 × 0.8125 = 2404.46875. **A trap in reading the log: the node prints both `ch=5` and `channel_num: 6`, and the multiplier the arithmetic uses is the SMALLER one.** Taking the printed `channel_num` puts the carrier exactly one slot high — 2405.28125 instead of 2404.46875, which is a plausible-looking wrong answer of precisely the kind this measurement existed to avoid.

**A trap for anyone estimating the slot count rather than measuring it.** Applying the sub-GHz bandwidth of 250 kHz across 2400–2483.5 predicts roughly 334 slots, and that is wrong: the bandwidth up there is 812.5 kHz, so the count is **102**, which floor(83.5 / 0.8125) confirms. The slot arithmetic is right and the bandwidth assumed inside it is not — a wrong number reached by a correct method.

**Bandwidth is 812.5 kHz and the spreading factor does NOT change.** Bandwidth is read directly from `numChannels: 102 x 812.5kHz`. SF follows from the preamble times in the same logs: sub-GHz, 131 ms over 16 symbols is an 8.192 ms symbol, which is 2¹¹ / 250 kHz; at 2.4 GHz, 40 ms / 16 = 2.5 ms, and 2.5 ms × 812.5 kHz = 2031 ≈ 2¹¹. So **LongFast at 2.4 GHz is SF11 on BW 812.5** — the same spreading factor on 3.25× the bandwidth. That is also *why* the carrier moves: the slot count moves with the bandwidth, exactly as the per-preset table above records for sub-GHz.

**The coding rate is NOT measured, and must not be inferred from this.** This file already records that reception cannot reveal CR, and that an earlier "CR 4/5" was our receiver's setting rather than an observation. The oracle log does not print CR and this run produced no transmit to time. The LongFast preset's 4/5 is the reasonable expectation and it remains an expectation. **Settling it needs what settled it sub-GHz — a timing measurement differencing two payload lengths — which requires 2.4 GHz hardware.**

**What this licenses, and what it does not.** It fixes the carrier, the bandwidth and the spreading factor for `LORA_24`, which is enough that a 2.4 GHz preset is no longer a guess. It is a **simulator** observation, from the same source that is 1.2% optimistic on airtime against real hardware. Nothing here has transmitted or received on 2.4 GHz. Until something has, a failing 2.4 GHz link should be suspected of this row before it is suspected of the radio.

---

## Corrections this phase forces

**To the commonly-repeated description of the protocol:** the preset table (7 vs 17, two deprecated), `DATA_PAYLOAD_LEN` (233 not 237), the absence of `next_hop` routing, and the absence of XEdDSA and KEY_VERIFICATION.

**To the extension design, and these matter strategically:**

- **Per-author signing is not a gap an extension needs to fill — upstream is filling it.** Any plan to add "a signature on control events" should be retired or reframed as *alignment*: upstream's 2.8.x XEdDSA is the same idea, the same primitive family, the same 64-byte cost, and the same key-reuse trick.
- **Key verification is not a gap either.** `KEY_VERIFICATION_APP = 12` exists, which addresses the trust-on-first-use weakness directly.
- **The remaining genuine differentiator is narrower than written: groups with a roster, an owner and revocation.** (Ranging was a second, and left this repository on 2026-08-17 — it needs ranging silicon, so it belongs to a consuming product.) It survives this phase intact — nothing upstream addresses either. **Re-checked 2026-08-16** against the published encryption documentation: it contains nothing on membership management, and upstream states outright that *"there is no per-member revocation"* and that the channel URL *is* the key exchange. The 2.8.x work is XEdDSA signing and `KEY_VERIFICATION_APP = 12` is trust-on-first-use — both adjacent to membership, neither of them membership.
- **The AEAD-tag proposal survives and is strengthened**, because the documented spoofing weakness is worse than assumed: forgery does not require the PSK.
- Any airtime table computed at 237-byte payloads must be re-derived at 233.

The strategic read: **upstream is actively closing the security gaps, so "extend" has a shrinking window on crypto and a durable one on features.** Worth re-testing the plan's premise before Tier 3 is scheduled — Tier 1 and Tier 2 are unaffected.
