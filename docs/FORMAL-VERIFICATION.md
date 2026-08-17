<!-- SPDX-FileCopyrightText: 2026 The tethermesh Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

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

**The scope grew on 2026-08-16** from the parse path to the L5 arithmetic —
airtime, the duty budget and the contention window. Those are total-function
claims over wide numeric ranges, which is precisely what a bounded test samples
badly and a proof settles outright: `slots_for_snr` takes every `i16`, and
`airtime_us` every payload length against every parameter combination.

**One harness is deliberately narrowed, and the narrowing is worth reading.**
`a_duty_cycle_can_never_be_charged_beyond_its_budget` leaves the **charges
symbolic and the configuration fixed**. The first version made the window and
permille symbolic too and did not terminate in nine minutes; `budget_us`
divides, and bit-vector division is expensive for a solver whatever the operand
size. Bounding the operands did not help, so the *shape* changed rather than the
bound — and it then verified in 65 milliseconds.

That is a real reduction in what is claimed. What remains proven is the part
that can actually be wrong — the guard in `charge`, over **every** pair of
charge values, plus the property that a refused charge bills nothing — at a
representative 1% hourly budget. The multiply and divide in `budget_us` are
covered by tests instead.

Recorded because the alternative was a harness that looked stronger and hung. A
proof that does not terminate proves nothing.

| harness | property |
|---|---|
| `header_decode_never_panics` | no 16-byte input panics |
| `header_roundtrip_is_the_identity` | decode then encode returns the original bytes, for all inputs |
| `relaying_spends_one_hop_and_preserves_the_rest` | relaying decrements `hop_limit` by exactly one and alters nothing else; refuses at zero |
| `short_frames_are_rejected_not_read_past` | every under-length input is rejected |
| `protobuf_reader_never_panics_on_arbitrary_bytes` | no 8-byte input panics the wire reader |
| `channel_hash_is_total` | total over its inputs |
| `symbol_time_never_panics_for_any_modem_parameters` | no spreading factor or bandwidth panics it; out-of-range inputs are refused rather than approximated |
| `airtime_never_panics_for_any_payload_or_parameters` | total over every payload length and parameter set, including the short-payload case where the symbol count goes negative and must clamp |
| `a_duty_cycle_can_never_be_charged_beyond_its_budget` | no accepted sequence of charges overruns the budget |
| `the_contention_window_is_total_and_stays_within_its_bounds` | every SNR yields a window inside the configured bounds; a degenerate range still answers |
| `should_relay_is_total_and_spends_exactly_one_hop` | relaying decrements `hop_limit` by exactly one and never relays a spent frame |
| `retransmission_never_exceeds_the_configured_ceiling` | the outbox never hands out more transmissions than the policy allows, counting the caller's own first send — over arbitrary times, including clocks that run backwards |
| `an_acknowledged_entry_is_never_retransmitted` | an acknowledgement retires only the entry its id names, and nothing is retransmitted afterwards; `acknowledge` and `reap` are total |

### `suite/groups` — the extension bundle

`SCOPE.md` requires a bundle crate to inherit the whole regime, and the proof
table is part of it. Run with `cargo kani -p tethermesh_groups`.

| harness | property |
|---|---|
| `parsing_an_envelope_never_panics` | no input panics the parser — the attacker-reachable path, which runs **before** the tag is checked and so cannot be protected by it |
| `a_short_envelope_is_refused_not_read_past` | every under-length input is refused rather than read past |
| `the_aad_ignores_every_mutable_header_field` | two headers differing only in `hop_limit`, `next_hop` or `relay_node` produce the identical AAD — so a relayed frame authenticates as the one that was sent |
| `the_aad_covers_every_immutable_header_field` | and changing any immutable field *does* change the tag input. Not redundant: an AAD that returned a constant would satisfy the row above perfectly while authenticating nothing |
| `the_epoch_never_wraps_from_any_starting_value` | from any epoch, a bump either advances by exactly one or refuses at 255. A wrap would reproduce epoch 0's key and reuse every nonce under it |
| `nonce_construction_is_total_and_carries_the_epoch` | total, 13 bytes, and the epoch reaches the nonce |

**What these do not cover, stated because the gap is easy to misread.** Nothing
here proves the AEAD is sound — that is AES-CCM's property, checked instead
against an independent implementation's answers in
`tests/captures/ccm_aad_vectors.json`. And `epoch_key` is deliberately absent:
proving anything about a digest's output means modelling SHA-256, and an earlier
draft of that harness asserted "distinct epochs derive distinct keys" — SHA-256
injectivity — which did not terminate.

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
