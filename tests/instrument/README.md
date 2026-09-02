<!-- SPDX-FileCopyrightText: 2026 Matthew Klapman -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Instruments

**Test instrumentation. Not part of the library, and not a radio driver for it.**

`README.md` says of the stack: *"A radio driver is deliberately not included — implementers have their own, and tying the stack to one part would narrow it for no benefit."* That still holds and is not contradicted here. What lives in this directory is the **measuring equipment** used to establish the facts in `docs/WIRE_REFERENCE.md`. Nothing here is linked into the crate, shipped in an artifact, or intended for production use.

## Why it is in the repository at all

Because it is the evidence.

The clean-room argument in `README.md` rests on a specific claim: that the byte-level facts were obtained by receiving real traffic with a radio driver **we wrote from the vendor datasheet**, not from any existing library. A claim of that kind whose evidence is absent is worth nothing — it is the same defect this project rejects when a measurement has no committed harness, which is why `gates/measure_panic_symbols.sh` exists.

It is also the **instrument**, and provenance requires it. `docs/DEPS.md` holds the position that a result which cannot name what it was obtained against is not a result. Every byte-level entry in the wire reference — the 16-byte header layout, the AES-CTR nonce, the sync-word register values, the preset table, the contention-window measurement — was read through this receiver. If the receiver is wrong, those are wrong, and a reader auditing them needs to be able to check how the bytes were captured.

## Why it is *here* and not in the oracle directory

The reference implementation, its harness, and every tool that drives it live outside this tree, in a sibling directory. That directory's `RULE.md` gives the test:

> The test of which side a tool belongs on: **does it interact with their binaries?** If yes, it lives here.

This does not. It is a radio receiver. It never invokes `meshtasticd`, never reads their firmware image, never touches their tooling — it listens to RF and prints bytes. By that rule it belongs in this repository, and it was verified to contain **zero code originating from the material it was previously stored beside** before being moved: no GPL headers, no radio library, includes limited to ESP-IDF and libc, and no component dependency beyond ESP-IDF.

The scripts that *do* drive stock nodes — region setting, preset sweeps, the PKI exchange driver, board probing — stay outside, because they interact with their firmware.

## `heltec_v3_sniffer`

An SX1262 driver for the Heltec V3 (ESP32-S3), written from the SX126x datasheet's documented command set.

It **parses nothing**. It prints the raw PHY payload verbatim as `RAWFRAME len,rssi,snr,hex`, so the frame layout is decided afterwards by inspection rather than by whatever the receiver assumed it would find. That property is the reason it can serve as evidence for a layout claim at all: a receiver that already knew the header format could not be used to discover it.

It also transmits, on `TX <hex>`, which is what puts frames built by our own crate on the air for the conformance direction that matters — *their decoder reading our bytes*. `PWR <dBm>` sets transmit power, added to sweep received signal level for the contention-window measurement.

### Two firmware traps recorded, because each presented as something else

- **Garbled output (`0TXDONE`).** The UART driver installed on UART0 collides with the ESP-IDF console: `printf` goes through the VFS path while `uart_read_bytes` drives the driver, so there are two writers on one peripheral. The fix is `uart_vfs_dev_use_driver(0)` immediately after `uart_driver_install`, before any logging.
- **Watchdog trips on every transmit.** The main loop ended in `vTaskDelay(pdMS_TO_TICKS(5))`. At the default 100 Hz tick that expression is **zero**, and `vTaskDelay(0)` does not yield — so the "5 ms delay" was a busy loop starving the idle task. A sub-tick delay is not expressible, and asking for one silently asks for none. 27 watchdog trips before, 0 after.

Related: `BUSY` on the SX1262 stays high for the whole transmission — around 800 ms at SF11 — so waiting on it is not a short wait and must not be a spin.

## Building and flashing

The build and flash scripts live with the bench, outside this tree, because flashing resolves a board *identity* to a port and that registry is bench state rather than repository state. Two Heltec V3s are indistinguishable over USB — same VID, PID, product string and USB serial — so they are addressed by burned-in MAC and never by `/dev/tty*` path.

```
idf.py -B build build          # from tests/instrument/heltec_v3_sniffer/
```

Generated output (`build/`, `sdkconfig`) is gitignored. `sdkconfig.defaults` records that no non-default configuration is needed.
