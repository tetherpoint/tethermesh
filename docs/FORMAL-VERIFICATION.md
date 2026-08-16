# What is proven, what is checked, and what is neither

**2026-08-16.** Three different kinds of assurance are used in this crate and
they are not interchangeable. Conflating them is the main way a security
claim gets overstated, so they are separated here.

## Proven — machine-checked, over every input

`cargo kani` runs the harnesses in `meshtastic/core/proofs.rs` against **our
own code**. No third-party library is involved. Kani explores the whole input
space symbolically, so a harness that passes has ruled out panics, arithmetic
overflow and out-of-bounds access on that path altogether — not for the inputs
a test happened to try.

| harness | property |
|---|---|
| `header_decode_never_panics` | no 16-byte input panics |
| `header_roundtrip_is_the_identity` | decode then encode returns the original bytes, for all inputs |
| `relaying_spends_one_hop_and_preserves_the_rest` | relaying decrements `hop_limit` by exactly one and alters nothing else; refuses at zero |
| `short_frames_are_rejected_not_read_past` | every under-length input is rejected |
| `protobuf_reader_never_panics_on_arbitrary_bytes` | no 8-byte input panics the wire reader |
| `channel_hash_is_total` | total over its inputs |

**Why this matters more than the artifact check.** `check_rust_rules.sh`
inspects the built object for panic machinery. That is evidence — it says the
compiler emitted no panic path *it could see*, on one target, at one
optimisation level. A proof says no such path exists at all. Both are kept:
the check runs on every invocation and costs nothing, the proofs run on
demand.

The round-trip harness is the more interesting one. It rules out an
endianness or bit-position error across the entire input space, which is
exactly the class of bug that is self-consistent and only wrong against the
wire.

## Checked against someone else's answer

Not proven, but not self-referential either. Each of these is compared to a
value computed by an implementation that is not ours:

- **AES-128 / AES-256** — FIPS-197 published vectors.
- **SHA-256** — FIPS 180-4 vectors, and the derived key a stock node logged.
- **AES-256-CCM** — vectors from an independent implementation.
- **X25519** — RFC 7748 vectors, plus differential testing against
  `x25519-dalek` across 512 random agreements per run.
- **The whole frame path** — real traffic captured off the air, decoded and
  re-encoded byte for byte.

## Proven by someone else, and linked

The X25519 **field arithmetic** is `fiat-crypto`'s, generated from Coq proofs.
Addition, subtraction, multiplication, squaring, carrying, the 121666 scalar
multiply, serialisation and the constant-time select are all verified upstream
and used unmodified. The Montgomery ladder and the inversion chain built on
them are ours.

That split is deliberate: the ladder is short, public and checked against RFC
7748 vectors and two independent implementations; the field arithmetic is
where subtle bugs live and where a proof is worth having. The bug this project
actually shipped — `fe_sub` biased by `p` instead of `2p` — was in the half
that is now verified.

## Neither proven nor independently checked

Stated plainly, because the gap is real:

- **Constant-time behaviour.** `x25519.rs` uses arithmetic masks rather than
  branches, but Rust cannot express "do not turn this into a branch" and no
  tool here verifies the emitted code. This is a strong expectation, not a
  guarantee, and it is not a defence against physical side-channel attack.
  Hardware can close this gap where software cannot: of the parts surveyed in
  `docs/HARDWARE-BACKENDS.md`, only the nRF54LM20's CRACEN accelerates
  Curve25519, and Nordic documents extended side-channel countermeasures for
  Montgomery curve multiplication on some SoCs. `meshtastic/core/backend.rs`
  is the seam that lets an implementer take it.
- **The ladder.** The field operations under it are proven; that the
  Montgomery ladder composes them into the right group operation is supported
  by RFC 7748 vectors and agreement with two independent implementations, not
  by proof.

## Why the verified library was not used instead

Measured, not argued — see `docs/CRYPTO-DEPENDENCY.md`. `libcrux-curve25519`
is genuinely formally verified Rust, derived from HACL*. It also **requires a
global allocator**, which `DISTRIBUTION.md` forbids outright, and adds 37
panic-related symbols over a no-dependency baseline where ours adds zero.

That is not a contradiction, and it is worth understanding rather than
dismissing: **"formally verified" names a specific property.** libcrux proves
functional correctness and secret independence. It does not prove
panic-freedom or allocation-freedom, and on those two it is the worst of the
options measured. Different proofs, different properties.
