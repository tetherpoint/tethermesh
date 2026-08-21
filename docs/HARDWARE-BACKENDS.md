<!-- SPDX-FileCopyrightText: 2026 The tethermesh Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Hardware crypto accelerators: what each part actually covers

**2026-08-16.** `meshtastic/core/backend.rs` lets an implementer route any subset of the crate's cryptographic primitives onto silicon. This document records which parts cover which primitive, **how confident each claim is**, and which document would settle it. It follows the convention of `docs/FORMAL-VERIFICATION.md`: the point is to separate what was verified from what is believed, because a confident summary of an accelerator's feature list is exactly the kind of claim that is stale as often as not.

## Why a backend at all

Not speed. A frame is at most 233 bytes and the radio spends the better part of a second sending it, so software crypto is never the bottleneck on this stack. Two other reasons matter:

- **Side-channel resistance.** `meshtastic/core/x25519.rs` states that its constant-time property is a strong expectation, not a guarantee — Rust cannot express "do not compile this mask into a branch" and nothing in this project inspects the emitted code for it. Hardware built against timing and power analysis can promise what software on a general-purpose core cannot.
- **Key custody.** A part with key custody performs an agreement using a private key that never becomes addressable. Nothing running on the MCU can read it, including this crate.

  **Custody is not the same as storage, and this document used to blur them.** Somewhere to *put* a key is common; somewhere a key can be *used from without being read* is rare. A part can have write-once memory, page locks and read protection and still have no custody, because if the agreement runs on the CPU the scalar has to reach a register to be used at all. Custody requires an engine that performs the operation with the key in place. That distinction is what `SecretKey::Slot` means, and getting it wrong is not academic — see the RP2350 note below.

## Confidence convention

| mark | meaning |
|---|---|
| **verified** | read out of a primary source, quoted below with its path |
| **believed** | consistent with what the vendor publishes, but not confirmed against a primary source in this project |

No entry here is "proven" in the sense `docs/FORMAL-VERIFICATION.md` uses that word. A datasheet is a claim by a vendor, not a machine-checked proof.

## Coverage

| part | X25519 | SHA-256 | AES | key custody | confidence |
|---|---|---|---|---|---|
| **nRF54LM20** (CRACEN) | **yes**, with side-channel countermeasures | yes | yes | yes | verified for the curve, believed for the rest |
| **ESP32-S31** | no — ECC unit is NIST-prime only | yes | yes | no | verified for the unit, believed for the curve list |
| **ESP32-P4** | no — ECC unit is NIST-prime only | yes | yes | no | verified for the unit, believed for the curve list |
| **ESP32-C6** | no — ECC unit is NIST-prime only | yes | yes | no | verified for the unit, believed for the curve list |
| **ESP32-S3** | no — **no ECC unit at all** | yes | yes | no | verified |
| **ESP32-S2** | no — **no ECC unit at all** | yes | yes | no | verified |
| **ESP32-C3** | no — **no ECC unit at all** | yes | yes | no | verified |
| **RP2350** | no | yes | no | no — **but it does have key storage**; see below | verified |
| **ATECC608B** (companion, I²C) | no — NIST P-256 only | yes | AES-128 | **yes** | verified |

**No two of the original four accelerate the same set.** That is the entire justification for the seam being per-primitive rather than all-or-nothing: an implementer would otherwise have to reimplement everything or use none of it.

**Across every part surveyed, exactly one accelerates this stack's curve.** The nRF54LM20 is the only entry with a *yes* in the X25519 column. That is worth stating plainly because it inverts the intuition an implementer arrives with: an "ECC accelerator" on the datasheet is overwhelmingly likely to be a NIST-prime engine that cannot touch Curve25519 at all.

**The last column says CUSTODY, and it used to say STORAGE — the rename is a correction, not tidying.** Under the old heading the RP2350's *no* read as "this part has nowhere to put a key", which is false: it has 8 kB of antifuse OTP with lockable pages. The cell was right about custody and wrong about everything a reader would take from it, and this document contradicted itself eleven lines into the RP2350 section, where its own feature list says "8 kB of antifuse OTP for key storage".

**It was believed downstream, which is how a one-word column becomes a defect.** Two files in the consuming integration tree carried "the RP2350 has no key storage" on the strength of this table until 2026-08-21. Nothing they concluded from it was wrong — `SecretKey::Slot` really is `Unsupported` on that part — but they had the reason wrong, and a correct conclusion resting on a false premise fails silently the moment the premise is load-bearing for something else. The lesson is the same one the ESP32-H2 note below records: **directionally right and factually wrong is still wrong**, and a column that answers a subtle question in one word invites exactly that.

### nRF54LM20 / CRACEN — the only one that does X25519

Verified from Nordic's own driver Kconfig, `subsys/nrf_security/src/drivers/cracen/Kconfig` in `nrfconnect/sdk-nrf`:

```
line 46:  "This excludes Montgomery and Twisted Edwards curves which use
           random generation with bit manipulation instead of PKE operations."
line 193: extended ECC countermeasures include
          "- Montgomery curve multiplication"
```

Curve25519 is a Montgomery curve, so CRACEN handles it. The second quote is the more valuable one for this project: it is a vendor statement that Montgomery curve multiplication has **extended side-channel countermeasures** on some SoCs. That is precisely the guarantee `x25519.rs` documents itself as unable to make.

Note "on some SOCs" — that is Nordic's hedge, not this document's. Confirm against the nRF54LM20 product specification before relying on the countermeasures specifically; CRACEN's feature set varies across the nRF54L family.

### ATECC608B — no X25519, but real key custody

Verified from Microchip's `cryptoauthlib`: `lib/cryptoauthlib.h` and `lib/calib/calib_command.h` mention P-256 thirteen times between them and **25519 zero times**. It is NIST P-256 for ECDSA and ECDH, plus AES-128 and SHA-256, with hardware key slots.

So it accelerates none of this stack's asymmetric work — Meshtastic's curve and the ATECC608B's curve simply do not match. Its value here is the key custody and the AES/SHA engines, not the ECC unit.

It is also the part that drove the seam's error handling. It is an **off-chip I²C device**: it can NAK, time out, return a bad CRC, or report a self-test failure. That is not a hypothetical failure mode, it is ordinary bus behaviour.

### The Espressif family, surveyed by capability header

Espressif publishes a machine-readable capability header per part, `components/soc/<chip>/include/soc/soc_caps.h` in `espressif/esp-idf`. ESP-IDF itself uses it to gate the ECC driver, which makes it better evidence than a marketing page or a summary — it is the definition the vendor's own build compiles against. Read on 2026-08-16:

| part | `SOC_ECC_SUPPORTED` | const-time point mul | extended modes | `SOC_ECDSA_SUPPORTED` | AES | SHA |
|---|---|---|---|---|---|---|
| ESP32-S2 | **absent** | — | — | absent | 1 | 1 |
| ESP32-S3 | **absent** | — | — | absent | 1 | 1 |
| ESP32-C3 | **absent** | — | — | absent | 1 | 1 |
| ESP32-C6 | 1 | **absent** | absent | absent | 1 | 1 |
| ESP32-H2 | 1 | 1 | 1 | 1 | 1 | 1 |
| ESP32-P4 | 1 | 1 | 1 | 1 | 1 | 1 |
| ESP32-S31 | 1 | 1 | 1 | 1 | 1 | 1 |

**None of them helps X25519, including the ones with a full ECC unit.** The hardware-accelerated curve set is NIST prime throughout. ESP-IDF's mbedTLS integration states it directly, in `components/mbedtls/Kconfig`:

```
"Enable hardware accelerated ECC point multiplication and point verification
 for points on curve SECP192R1 and SECP256R1 in mbedTLS"
```

and Curve25519 appears in that same menu as a **software-only** option with no hardware acceleration. The ESP32-H2 ECDSA documentation puts the same list in prose — *"Two different elliptic curves, namely P-192 and P-256 (FIPS 186-3 specification)"* — and the P4's chip revision v3.x adds P-384. Every one of these is a Weierstrass curve over a NIST prime. Curve25519 is a Montgomery curve, and the peripheral has no mode for it.

The H2's header corroborates the curve list from another direction: it carries `SOC_ECDSA_P192_CURVE_DEFAULT_DISABLED (1)`, which only makes sense for a unit whose curve set is P-192 and P-256.

**The `SOC_ECC_CONSTANT_TIME_POINT_MUL` column is a trap worth naming.** On the S31, P4 and H2 it is set, and constant-time point multiplication is exactly the side-channel property this document exists to hunt for. It does not apply here: it is constant-time point multiplication *on the NIST curves the unit supports*, which is not the operation this stack performs. A capability flag that names the right property on the wrong curve is precisely the kind of evidence that produces a confident, wrong summary.

**The C6 is the odd one out and the reason this table has that column.** It sets `SOC_ECC_SUPPORTED` and nothing else — no constant-time point multiplication, no extended modes, no ECDSA peripheral. "Has an ECC accelerator" is therefore not one fact but several, and they do not travel together. An implementer reading only the coverage table above would see the same *no* for the C6 and the S31 and be right about X25519 for both, while being wrong about everything else the two parts offer.

The curve-list rows are marked *believed* rather than *verified* for the S31, P4 and C6 because the statement above is ESP-IDF-wide rather than part-specific; per-part reference manuals were not read for those three. The *presence or absence of an ECC unit* is verified for all of them, and that is the fact the coverage table turns on.

### ESP32-S3 — there is no ECC unit to have a curve list

**This entry was wrong until 2026-08-16, and the correction is more interesting than the original claim.** It previously read: *"its ECC unit covers NIST prime curves rather than Curve25519."* That sentence attributes an ECC accelerator to a part which does not have one.

Verified from Espressif's own capability header, `components/soc/esp32s3/include/soc/soc_caps.h` in `espressif/esp-idf`. This is the machine-readable definition ESP-IDF itself uses to gate the ECC driver, which makes it better evidence than prose:

```
SOC_ECC_SUPPORTED     — absent entirely
SOC_ECDSA_SUPPORTED   — absent entirely
SOC_AES_SUPPORTED     1
SOC_SHA_SUPPORTED     1
SOC_HMAC_SUPPORTED    1
SOC_DIG_SIGN_SUPPORTED 1
```

For contrast, the same header for the ESP32-H2 (`components/soc/esp32h2/include/soc/soc_caps.h`) defines `SOC_ECC_SUPPORTED 1` and `SOC_ECC_CONSTANT_TIME_POINT_MUL 1`. The ECC peripheral is real in that family — it is simply not on this part. So the AES and SHA rows stand, and the X25519 row is *no* for a stronger reason than previously recorded: not "its ECC unit does other curves" but "it has no ECC unit at all".

The lesson generalises, which is why the wrong sentence is quoted rather than deleted: the original was **directionally right and factually wrong**. It reached the correct conclusion — no X25519 acceleration — through a specific claim that was false. A summary that lands on the right answer is not thereby verified, and this row was marked *believed* for exactly that reason until someone read the primary source.

### RP2350

Verified. SHA-256 acceleration is stated by the pico-sdk's own header, `src/rp2_common/pico_sha256/include/pico/sha256.h` in `raspberrypi/pico-sdk`:

```
"RP2350 is equipped with a hardware accelerated implementation of the
 SHA-256 hash algorithm."
```

Secure boot uses secp256k1 ECDSA over a SHA-256 image hash, with allowed public-key fingerprints in OTP — Raspberry Pi's *Understanding RP2350's security features* white paper. The security feature set is signed boot, 8 kB of antifuse OTP, SHA-256 acceleration, a hardware TRNG and glitch detectors; **no AES engine and no Curve25519 engine appear anywhere in it.**

Note that secp256k1 is a Koblitz curve used for boot-image signatures, not a key-agreement engine this stack could route X25519 onto, so it does not change the coverage row.

#### It has key storage. It does not have key custody, and that is why the column says *no*

Verified from the RP2350 datasheet, not from a summary. §13: **8 kB of one-time-programmable storage**, physically 4096 rows of 24 bits, whose listed contents include *"symmetric keys for decryption of flash contents into SRAM"* and *"any other user-defined data, such as per-device personalisation values"*. §10.1.2 gives the protection, in two forms quoted verbatim:

> hard locks, which permanently revoke read or write access by Secure or Non-secure code
>
> soft locks, which revoke permissions only until the next reset of the OTP block

So a key can be placed in OTP and made unreadable to every later boot stage, including the PICOBOOT path `picotool` reads OTP over. **That is real key storage and this document should never have implied otherwise.**

**It is still not custody, because custody is about use and not about rest.** The RP2350 has no Curve25519 engine — the point the row above establishes — so an X25519 agreement runs on the CPU, and the scalar has to be readable into a register for that to happen at all. OTP would protect the key while nothing is using it and protect nothing while something is. `SecretKey::Slot` promises a scalar that is *never* addressable, which is a promise this part cannot make for this curve at any storage configuration. Hence `Unsupported`, on the same grounds as `Software` and for a completely different reason from "nowhere to put it".

**What would change the answer** is not better storage but an engine: a Curve25519 unit that takes a key by reference. Nothing in the RP2350's published feature set is one.

**A note for anyone acting on this section rather than reading it.** OTP is antifuse — bits program from zero to one and never back — and a hard lock is permanent and takes the value with it. There is no erase and no second attempt on that part. This document records a capability; it is not a recommendation to program anything.

## How the seam is used

Every method on the `Crypto` trait has a software default, so a backend implements only what its part covers. Accelerating one primitive really is a short `impl` with one method:

```rust
use tethermesh::backend::{Crypto, Error};

struct MyPart;

impl Crypto for MyPart {
    fn sha256(&self, data: &[u8]) -> Result<[u8; 32], Error> {
        my_hardware_digest(data).ok_or(Error::Hardware)
    }
}
```

Everything else — X25519, AES-CTR, both CCM directions — falls through to the portable implementation unchanged. `tests/host_unit/main.rs::overriding_one_primitive_leaves_the_others_alone` is that guarantee as a test, and it has been seen red.

Use `backend::Software` to state explicitly that no accelerator is in play, rather than leaving it implicit.

## Two things the seam learned from these parts

The first version of this trait was written against an on-chip accelerator and was wrong for two of the parts above. Both corrections are recorded here because both are invisible until an implementer hits them.

**Hardware fails, and failure is not an answer.** Methods originally returned bare values — `sha256` returned `[u8; 32]`. A backend on an I²C companion that NAKed had exactly two options, both unacceptable: panic, which `DISTRIBUTION.md` forbids outright, or invent a digest, which is worse. Every method now returns `Result`.

**A key that never leaves the part cannot be passed as bytes.** The custody argument above is void if the signature demands the scalar, and the original `x25519(&self, secret: &[u8; 32], ...)` demanded it. The caller now *names* the key — `SecretKey::Bytes` for software, `SecretKey::Slot` for a key the accelerator holds and will not surrender. A backend without key custody returns `Error::Unsupported`, which is what every software default does. Accepting a slot number and quietly agreeing a secret under some other key would have been the worst available outcome, so that path is tested.

### Errors that must stay distinct

`Error` separates three failures that a bare `Option` conflated:

| variant | means | retryable |
|---|---|---|
| `Hardware` | bus fault, NAK, timeout, busy, failed self-test — **says nothing about the input** | yes |
| `SmallOrderPeer` | the peer's public key is small-order; RFC 7748 requires rejecting it | never |
| `Ccm(Unauthentic)` | the tag did not verify: forged, corrupted, or wrong key | never |

The distinction is load-bearing in both directions. Reporting a small-order peer as `Hardware` makes an active attack look like a loose connector. Reporting a failed CCM tag as `Hardware` invites a caller to retry its way past authentication. Both are tested, and both tests have been seen red.
