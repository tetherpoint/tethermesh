# Hardware crypto accelerators: what each part actually covers

**2026-08-16.** `meshtastic/core/backend.rs` lets an implementer route any subset of the crate's cryptographic primitives onto silicon. This document records which parts cover which primitive, **how confident each claim is**, and which document would settle it. It follows the convention of `docs/FORMAL-VERIFICATION.md`: the point is to separate what was verified from what is believed, because a confident summary of an accelerator's feature list is exactly the kind of claim that is stale as often as not.

## Why a backend at all

Not speed. A frame is at most 233 bytes and the radio spends the better part of a second sending it, so software crypto is never the bottleneck on this stack. Two other reasons matter:

- **Side-channel resistance.** `meshtastic/core/x25519.rs` states that its constant-time property is a strong expectation, not a guarantee — Rust cannot express "do not compile this mask into a branch" and nothing in this project inspects the emitted code for it. Hardware built against timing and power analysis can promise what software on a general-purpose core cannot.
- **Key custody.** A part with key storage performs an agreement using a private key that never becomes addressable. Nothing running on the MCU can read it, including this crate.

## Confidence convention

| mark | meaning |
|---|---|
| **verified** | read out of a primary source, quoted below with its path |
| **believed** | consistent with what the vendor publishes, but not confirmed against a primary source in this project |

No entry here is "proven" in the sense `docs/FORMAL-VERIFICATION.md` uses that word. A datasheet is a claim by a vendor, not a machine-checked proof.

## Coverage

| part | X25519 | SHA-256 | AES | key storage | confidence |
|---|---|---|---|---|---|
| **nRF54LM20** (CRACEN) | **yes**, with side-channel countermeasures | yes | yes | yes | verified for the curve, believed for the rest |
| **ESP32-S3** | no | yes | yes | no | believed |
| **RP2350** | no | yes | no | no | believed |
| **ATECC608B** (companion, I²C) | no — NIST P-256 only | yes | AES-128 | **yes** | verified |

**No two of these accelerate the same set.** That is the entire justification for the seam being per-primitive rather than all-or-nothing: an implementer on any of these four parts would otherwise have to reimplement everything or use none of it.

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

So it accelerates none of this stack's asymmetric work — Meshtastic's curve and the ATECC608B's curve simply do not match. Its value here is the key storage and the AES/SHA engines, not the ECC unit.

It is also the part that drove the seam's error handling. It is an **off-chip I²C device**: it can NAK, time out, return a bad CRC, or report a self-test failure. That is not a hypothetical failure mode, it is ordinary bus behaviour.

### RP2350 and ESP32-S3

RP2350 exposes a SHA-256 accelerator (`pico_sha256` in the pico-sdk) and a TRNG; its secure boot uses secp256k1. No Curve25519 engine, and no AES engine. ESP32-S3 has dedicated AES and SHA accelerators; its ECC unit covers NIST prime curves rather than Curve25519.

Both entries are marked *believed*. The conclusion — neither part accelerates X25519 — is not in doubt. The exact curve list for the ESP32-S3's ECC unit has not been confirmed against the technical reference manual in this project, and is flagged rather than asserted.

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

The first version of this trait was written against an on-chip accelerator and was wrong for two of the four parts above. Both corrections are recorded here because both are invisible until an implementer hits them.

**Hardware fails, and failure is not an answer.** Methods originally returned bare values — `sha256` returned `[u8; 32]`. A backend on an I²C companion that NAKed had exactly two options, both unacceptable: panic, which `DISTRIBUTION.md` forbids outright, or invent a digest, which is worse. Every method now returns `Result`.

**A key that never leaves the part cannot be passed as bytes.** The custody argument above is void if the signature demands the scalar, and the original `x25519(&self, secret: &[u8; 32], ...)` demanded it. The caller now *names* the key — `SecretKey::Bytes` for software, `SecretKey::Slot` for a key the accelerator holds and will not surrender. A backend without key storage returns `Error::Unsupported`, which is what every software default does. Accepting a slot number and quietly agreeing a secret under some other key would have been the worst available outcome, so that path is tested.

### Errors that must stay distinct

`Error` separates three failures that a bare `Option` conflated:

| variant | means | retryable |
|---|---|---|
| `Hardware` | bus fault, NAK, timeout, busy, failed self-test — **says nothing about the input** | yes |
| `SmallOrderPeer` | the peer's public key is small-order; RFC 7748 requires rejecting it | never |
| `Ccm(Unauthentic)` | the tag did not verify: forged, corrupted, or wrong key | never |

The distinction is load-bearing in both directions. Reporting a small-order peer as `Hardware` makes an active attack look like a loose connector. Reporting a failed CCM tag as `Hardware` invites a caller to retry its way past authentication. Both are tested, and both tests have been seen red.
