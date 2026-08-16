<!-- SPDX-FileCopyrightText: 2026 The tethermesh Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Capture corpus

Fixtures the day-to-day tests run against, so that testing does not depend on the oracle being present or on it staying still. Every file names the oracle it came from; see `DEPS.md`.

## What is here

| file | what it is |
|---|---|
| `fromradio_corpus.json` | **Byte-exact protobuf produced by their encoder**, captured at the oracle's TCP API. 43 messages across 9 `FromRadio` variants. This is L3's corpus. |
| `channel_hash.json` | Known-answer vectors for the channel hash. Two rows observed from the oracle, the rest computed from the verified function. |
| `oracle_observations.json` | Field-level observations captured at the oracle's radio boundary, produced by `../../../meshtastic-oracle/capture.py`. |
| `udp_mesh_capture.json` | `MeshPacket`s captured off multicast `224.0.0.69:4403` with `UDP_BROADCAST` enabled. Confirms `relay_node` and the channel hash at a second boundary; shows `hop_limit = 0`, which is why this transport cannot answer the relay question. |

## The protobuf corpus is byte-exact; the radio observations are not

Worth being blunt about, because the two files look alike and are not.

`fromradio_corpus.json` holds **actual bytes their encoder produced**. Every message is stored as hex, with its top-level field number and the wire types of its top-level fields. L3's gate applies to it directly: each must round-trip decode→encode bit-identically through our codec.

Two properties were measured on capture, and both matter:

- **43/43 re-emit bit-identically** when top-level tags and lengths are re-encoded as minimal varints with payloads verbatim.
- **43/43 carry their fields in ascending field-number order.**

Together those say their encoder is canonical. That is what makes a bit-identical round-trip an achievable requirement rather than an impossible one — had they emitted non-minimal varints or arbitrary field order, byte-identity would have been unreachable and the gate would have needed rewriting.

The labels are produced by a **schema-free** wire-format scan that walks tag and length prefixes and nothing else. Deliberately: a labeller that understood the messages would be a codec, and deriving that from a capture is how a capture quietly becomes the specification.

## Field-level, not byte-level — and the difference matters

`oracle_observations.json` records what the reference implementation says it is putting on the radio, at the moment it hands the frame over:

    [SimRadio] Start low level send (id=0x59e2815c fr=0x7739e49b to=0xffffffff,
        transport = 0, WantAck=0, HopLim=3 Ch=0x8
        encrypted len=70 hopStart=3 relay=0x9b priority=10)

That pins down **what the header contains and what each field's value is**. It does **not** pin down the order, width, endianness or packing of those fields on the wire. A test that treats these observations as a byte layout would be asserting something never measured.

**The raw packed bytes are not obtainable from this oracle.** Its simulated radio is process-local — it hands the frame to a simulated PHY inside the same process and loops it back, and no socket carries it. The UDP transport is not a substitute: the binary's own strings say `Decoding MeshPacket from UDP len=%u`, so UDP over mesh carries a protobuf `MeshPacket`, not the packed LoRa frame. See `meshtastic/WIRE_REFERENCE.md`.

## Privacy

Per `TESTING.md`: public fixtures are synthetic, and captures from our own nodes on our own channels may be published. Everything here is one or the other — these are nodes we started, on channels we set, in a local simulation with no radio. **No third-party traffic is in this corpus, and none may be added.** Real ambient traffic carries identifiable node numbers, message metadata and position reports, and on the default channel the key is published, so those payloads are readable by anyone.

## Regenerating

    ../../../meshtastic-oracle/oracle.sh setup          # fetch + verify every digest
    ../../../meshtastic-oracle/oracle.sh run 2          # start simulated nodes
    ../../../meshtastic-oracle/oracle.sh capture > oracle_observations.json
    ../../../meshtastic-oracle/oracle.sh corpus  > fromradio_corpus.json
    ../../../meshtastic-oracle/oracle.sh stop

No container runtime is required — see `DEPS.md`. Message counts vary slightly between runs (the node emits a few `fileInfo` records depending on what it has written), so treat the corpus as a sample of their encoder's output, not a fixed-size manifest.

The harness lives outside this repository with the binaries it drives. See `../../../meshtastic-oracle/RULE.md`.
