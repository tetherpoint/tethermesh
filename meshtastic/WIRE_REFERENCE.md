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

**`relay_node` is a one-byte truncation of the sender's node number.** Node `0x7739e49b` transmitted `relay=0x9b`. Confirmed twice more, and independently of the log channel, on captured UDP traffic: `0x266cbc2b → 0x2b` and `0x2f7f90dc → 0xdc` (`tests/captures/udp_mesh_capture.json`).

**The `channel` field carries the one-byte channel hash.** Captured packets on the default channel show `channel = 8`, matching `xor_fold("LongFast") ^ xor_fold(default_psk)` — the hash function verified above, now corroborated at a second boundary.

**Header fields confirmed present, with observed values:** `id` (32-bit), `from`, `to` (`0xffffffff` for broadcast), `hop_limit` (3 by default), `hop_start` (3), `want_ack`, the one-byte channel hash, `relay_node`, and a `transport` field observed as 0. Payload length is reported separately as `encrypted len`.

**A traceroute reply carries `request_id` and per-hop SNR, and the SNR is quarter-dB.** Captured from a stock node answering our request: `Data{portnum=70, payload=RouteDiscovery{snr_towards:[26]}, request_id=0x0badd002}`. The 26 is 6.5 dB — SNR travels as quarter-dB signed units, matching the packet-status encoding the radio reports. `request_id` echoes the initiator's packet id, which is how a reply is matched to its request.

**A deprecated schema field is still on the wire.** `User.macaddr` (field 4, `bytes`) is marked `[deprecated = true]` and was deprecated in Meshtastic 2.1.x, yet firmware 2.7.26 emits it in every `User` — six zero bytes. Anything reproducing reference output must carry it. The general form of this matters more than the instance: **the schema says what a field means, not whether it is transmitted**, so a codec derived from field numbers alone will be wrong in ways only comparison against real output reveals. Found exactly that way, by a wrapper failing to re-encode captured bytes.

**Packet identifiers are 32-bit and re-randomised per packet** — the node logs `Initial packet id`, then `Partially randomized packet id` for each transmission. Relevant to the L2 packet-id discipline: under CTR a repeated `(packet_id, sender)` pair leaks the XOR of two plaintexts.

**LongFast is bandwidth 250 kHz, spreading factor 11, coding rate 4/5** — on real hardware, from the firmware's own mouth. This is the first hard data against draft item 6.

Method matters here, because it is what makes this evidence rather than another assertion. A `LoRaConfig` was written to a Heltec V3 running `2.7.26.54e0d8d` with `use_preset = true`, `modem_preset = LONG_FAST`, and the bandwidth, spreading-factor and coding-rate fields **absent** — proto3 default, i.e. zero. Reading the config back returned `bandwidth = 250`, `spread_factor = 11`, `coding_rate = 5`. The firmware populated them, so these are its values for the preset and not an echo of anything we supplied.

It covers **one preset of seventeen**. The commonly repeated table happens to agree for this row; that is now checked rather than assumed for LongFast alone, and says nothing about the other sixteen — including the 62.5 kHz and 20 kHz variants that made the draft's 7-row table impossible in the first place. The bench was found running `VLongSlow` at 62.5 kHz, so that row is reachable the same way.

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

**SF 11, BW 250 kHz, CR 4/5, preamble 16 symbols, explicit header, CRC on, standard IQ**, at 906.875 MHz. Confirmed twice over: the firmware reported them through `get_config`, and a receiver configured with them decodes real frames. Still one preset of seventeen.

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
6. ~~**Preset SF/BW/CR parameters**~~ — **SF and BW RESOLVED 2026-08-16 for every valid preset**, by writing each one to a stock node and reading back what it programmed. Coding rate remains unmeasured; see below. Full table in `tests/captures/modem_presets.json`.

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

**Coding rate is still unmeasured, and is recorded as `null` rather than guessed.** The node does not report it, and the reported bitrate cannot be inverted to recover it: the ratio of bitrate to `SF·BW/2^SF` drifts with spreading factor — 0.697 at SF11, 0.725 at SF7 — so that figure carries packet overhead of a shape this project has not established. Inferring CR from it would mean assuming a formula in order to manufacture a fact, which is the error this document exists to prevent. **LongFast's CR4/5 is known from on-air capture and is the only one.** Settling the rest needs a receiver deliberately configured to the wrong coding rate, since it will fail to decode — a differential test, not a log read.
7. **Contention-window bounds** — **the direction is documented, the numbers are not.** *(2026-08-16: one direct observation now exists. Relaying a broadcast at `rx_snr = 6.75`, a stock node logged `Setting tx delay:3360` — 3360 ms, or 120 slots at the 28 ms slot time. **This does not resolve the item.** A single sample cannot separate a deterministic delay from one draw out of a random window, and offers no second point to fit a slope. Recorded in `tests/captures/pki_dm_outbound_record.json`; a sweep across SNR would settle it.)* The official documentation says only *"The CW size is small for a low SNR, such that nodes that are further away are more likely to flood first."* No primary source read so far gives `CW_MIN`, `CW_MAX`, or the SNR range they map across. `meshtastic/core/routing.rs` implements the documented direction with **our own** parameterisation, marked as ours in that module rather than presented as theirs. Frames stay identical and suppression still works, so this does not affect interoperability — but our *timing* will not match a stock node's, so we may win or lose races we would otherwise have lost or won. Settling it needs a timed capture of several nodes relaying one frame.

**Airtime, and what is actually established about it.** `meshtastic/core/airtime.rs` computes time-on-air from **Semtech's** published LoRa formula — the radio vendor's, not the reference implementation's. Two things anchor it here rather than to itself:

- **The preamble lands exactly.** At SF11/BW250 the symbol time is 8.192 ms, so sixteen preamble symbols are 131.07 ms — matching the **131 ms** recorded below from oracle observation. That pins the preamble at sixteen symbols, which would otherwise have been a free parameter.
- **The residual points the right way.** A 70-byte packet models at 763.9 ms where the *simulator* reported 755 ms, +1.18%. The simulator's bitrate is separately measured as ~1.2% optimistic against silicon, so the formula disagrees with the simulator by very nearly the amount the simulator is already known to be wrong by — and therefore agrees with hardware.

**That is corroboration from a single observed packet, not a measurement.** A direct hardware sweep across payload sizes is still wanted, and until then airtime is *checked against someone else's answer* rather than verified.

**Only item 6 remains.** Items 1–5 are resolved above, each by capture or observation rather than by assertion. Sixteen presets are outstanding, and they are bounded rather than unknown: the method that resolved LongFast works unchanged.

~~**Resolving these needs either an authoritative byte-level document or a first capture.** Item 3 is now resolved. Items 1 and 2 remain, and the route to them is narrower than this document previously assumed.~~ **Struck 2026-08-16** — this sentence and the three-routes analysis below it were written while items 1 and 2 were open, and were left standing when the capture closed them. The analysis is kept because it is *how* they were closed: the first of the three routes is the one that worked.

**Correction, 2026-08-15 — the local oracle cannot supply the packed bytes.** The plan assumed the raw frame appears at the simulated-radio boundary. It does not. The reference's `SimRadio` is process-local: it hands the frame to a simulated PHY inside the same process and loops it straight back, so no socket ever carries it and nothing outside the process observes the packing. Two instances on one host do not hear each other at all.

The UDP transport is not a way around this. The binary's own strings read `Broadcasting packet over UDP (id=%u)` and `Decoding MeshPacket from UDP len=%u` — UDP over mesh carries a protobuf `MeshPacket`, not the packed LoRa frame. Capturing it would re-encode the same fields in a different encoding and still say nothing about wire layout.

So items 1 and 2 were reachable by exactly three routes, and passive local capture was not among them:

- **a real radio** receiving ambient traffic, which is also what items 5 and 6 need — **this is the one that worked**, 2026-08-16;
- **an authoritative byte-level document**, which was never found; or
- **differential testing against their decoder** — construct a frame under a candidate layout, offer it to the oracle, and let acceptance or rejection decide. Not needed for items 1 and 2 in the end, but this became the L4 conformance direction independently.

**Why the correction above is worth keeping rather than deleting.** The premise that the raw frame appears at the simulated-radio boundary was wrong, and it was wrong in a way that would have produced *confident* results: a field-level view looks like a capture until you try to read byte offsets off it. The route that settled these items required hardware that had not arrived when the plan was written.

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

## Corrections this phase forces

**To the commonly-repeated description of the protocol:** the preset table (7 vs 17, two deprecated), `DATA_PAYLOAD_LEN` (233 not 237), the absence of `next_hop` routing, and the absence of XEdDSA and KEY_VERIFICATION.

**To the extension design, and these matter strategically:**

- **Per-author signing is not a gap an extension needs to fill — upstream is filling it.** Any plan to add "a signature on control events" should be retired or reframed as *alignment*: upstream's 2.8.x XEdDSA is the same idea, the same primitive family, the same 64-byte cost, and the same key-reuse trick.
- **Key verification is not a gap either.** `KEY_VERIFICATION_APP = 12` exists, which addresses the trust-on-first-use weakness directly.
- **The remaining genuine differentiators are narrower than written: groups with a roster, an owner and revocation; and ranging.** Both survive this phase intact — nothing upstream addresses either.
- **The AEAD-tag proposal survives and is strengthened**, because the documented spoofing weakness is worse than assumed: forgery does not require the PSK.
- Any airtime table computed at 237-byte payloads must be re-derived at 233.

The strategic read: **upstream is actively closing the security gaps, so "extend" has a shrinking window on crypto and a durable one on features.** Worth re-testing the plan's premise before Tier 3 is scheduled — Tier 1 and Tier 2 are unaffected.
