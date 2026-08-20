<!-- SPDX-FileCopyrightText: 2026 The tethermesh Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# SCOPE — what belongs in this repository, and what must never enter it

This repository is **open**. Assume everything committed here will be read by people outside the project, including competitors, and that git history is permanent — a file deleted in a later commit is still in the history, and a repository that has been cloned once cannot be un-cloned.

That makes this document a gate, not a preference. It is easier to keep something out than to take it back.

**Part of it is now mechanically enforced.** `tools/check_scope.sh`, wired into `check_all.sh`, fails the build if a consuming product's name appears in a tracked file. It exists because on 2026-08-20 one did: a wire-reference entry about the `LORA_24` channel — a legitimate on-air fact, correctly placed — explained *why* the measurement was wanted and named a consuming product's driver repository and a constant from its header. **The fact was in scope and the rationale around it was not**, which is exactly the accidental arrival this document warns about below. Nothing flagged it; it was caught by a passing question, and a question is not a control.

**What that check cannot do is decide whether a fact belongs here.** It matches names, so it catches the crude case and none of the interesting ones — a paragraph describing a consuming system's design without naming it passes cleanly. The judgement stays human; the check only removes the excuse of not noticing.

## The rule

> **If it is not part of a Meshtastic-compatible protocol implementation or its extensions, it does not belong here.**

And narrower than that reads on its own: this repository **tracks Meshtastic**, and holds extensions that sit **above** it — protocol features that could plausibly be adopted upstream one day. Ongoing work is aligning with upstream, not growing a product's feature set under a protocol library's name. An extension qualifies only if it is pure protocol — message formats and state, no hardware source — which is what removing location and ranging on 2026-08-17 settled in practice.

Everything in this repository should make sense to someone who has never heard of the products that consume it, and should be usable by them.

## In scope

- The Meshtastic on-air protocol: frame header, channel hashing, channel and PKI cryptography, the protobuf codec.
- Routing behaviour needed for compatibility: managed flooding, duplicate suppression, hop-limit handling, duty-cycle accounting.
- The extension suite and its specification — the wire format, its cryptographic construction, and its rationale. **Bundles that need a hardware source do not qualify**; location and ranging were specified here and moved out on 2026-08-17 for exactly that reason. A bundle must be message formats and state, testable with no hardware — **it must be a separate crate the core does not depend on**, so that taking the protocol library never means taking the extensions with it; **and it must be plausibly adoptable upstream** — a feature that sits above Meshtastic and extends the protocol, rather than one serving a single product. `groups` satisfies all three and stays: upstream documents the gap it fills in its own words, and the Apache-2.0 licence and patent pledge exist so the answer can be adopted rather than merely admired.
- `WIRE_REFERENCE.md`: on-air facts with sources, verified separated from unverified.
- Host-side tests and on-air capture fixtures.
- Tooling that operates on the above without hardware — for example the clean-room checker.
- **Measuring instruments, and only as evidence.** `instruments/` holds the SX1262 receiver the wire reference was measured with. See the carve-out below, which is narrow and was written *after* the fact rather than before.

## Out of scope — must not be committed

- **Any radio driver, board bring-up, or hardware abstraction *in the shipped stack*.** This library is portable by design; a driver in it would narrow it to one part for no benefit. Nothing in `meshtastic/core/` may touch hardware.
- **Any product integration** — application layers, transport shims, backends, host interfaces, or the names and internal structure of systems that consume this library.
- **Bench and laboratory tooling**: build and flash scripts, device discovery, port and probe identification, hardware test runners, hardware inventories.
- **Anything describing a consuming product's architecture, security design, key management, roadmap, or implementation status.** This is the category most likely to arrive by accident, because it usually arrives inside otherwise reasonable prose — a rationale paragraph, a comparison table, a commit message explaining *why*.
- **GPL-derived material of any kind.** Separate concern, separately enforced; see `README.md` and `tools/check_cleanroom.sh`.

## The instrument carve-out, and why it is narrow

`instruments/heltec_v3_sniffer` is an SX1262 driver, and the exclusion above says no radio drivers. **That exclusion is about the shipped stack, and this is not in it.** The carve-out is stated explicitly because the repository otherwise contradicts its own scope document — which it did, briefly, until this paragraph was written.

It qualifies on all four counts, and a future instrument must qualify on all four too:

1. **Not linked, not shipped.** It is a separate ESP-IDF application. `check_rust_rules.sh` inspects the crate object and never sees it.
2. **It is evidence.** `README.md` claims the byte-level facts were obtained with a receiver written from the vendor datasheet rather than an existing library. A claim of that kind whose evidence is absent is worth nothing.
3. **It is the instrument of record.** Every byte-level entry in `WIRE_REFERENCE.md` was measured through it. If it is wrong, they are wrong, and a reader auditing them must be able to see how the bytes were captured.
4. **It is entirely ours**, and was verified so before being moved: no GPL headers, no radio library, includes limited to ESP-IDF and libc, no third-party component.

**The bench tooling exclusion below still stands in full.** Build and flash scripts, device discovery, probe identification, hardware inventories and test runners remain outside this repository, because they drive the reference implementation's binaries. The distinction is not "hardware versus not" — it is **does it interact with their material**.

## The C ABI crate, and why it is in scope

`ffi/` builds `libtmffi.a` plus `include/tethermesh.h`: the protocol library with
a C API, so a consumer can link it from a C build **without a Rust toolchain at
all**. That is the second of the two things this repository ships, and
`DISTRIBUTION.md` makes promises about it — a declared target set, a stable ABI
within a major version, a size budget, artifact-level testing.

**It belongs here because the repository making those promises should own the
artifact they are about.** It lived in a consuming product until 2026-08-17,
which meant this repository committed to an ABI it did not build, could not
gate, and could not version. `PLAN.md` L8 had described the correct shape from
the start — *"tethermesh as an rlib, plus a thin FFI crate carrying the
staticlib, the panic handler and the C ABI"* — and the multi-crate gate work was
done specifically so that crate would be held to the same rules automatically.

It passes the scope rule on its own terms: every exported symbol is protocol
(`tm_ctx_*`, `tm_rx_observe`, `tm_frame_decrypt`, `tm_outbox_*`), and it names no
product, board, radio or bench. That was checked before the move rather than
assumed — a single doc comment referencing a consuming project's task number was
found and removed, which is exactly the *"arrives inside otherwise reasonable
prose"* category this document warns about.

**Two rules bend for it, both narrowly and both recorded in the gate itself:**

1. **`no_std` may be written `#![cfg_attr(not(test), no_std)]`, and only that
   form.** A crate carrying a `#[panic_handler]` cannot host `cargo test` while
   unconditionally `no_std`, because the harness links std and brings its own
   handler. `not(test)` covers every build that ships. Any other predicate is
   refused, since `not(feature = "x")` would let a flag quietly make a shipped
   artifact `std`.
2. **`deny(unsafe_code)` is not required of it.** An FFI boundary cannot exist
   without `unsafe`. `forbid(unsafe_op_in_unsafe_fn)` is required instead — and
   see that crate's own header for an honest note on how much that currently
   buys, which is less than it looks.

**The undefined-reference check also had to learn about workspace siblings.** A
shim calls its own library constantly, so `tethermesh::frame::encode` appears
undefined in `ffi`'s object. Those are now allowed *because every workspace crate
is inspected by the same check*, a panicking generic instantiated here would be a
defined symbol and still caught, and the linked image is checked separately. The
crate list is derived from `cargo metadata`, never typed in — a hardcoded name
keeps passing after the crate it named is deleted.

## Adding an extension bundle as a crate

The suite is planned as **one crate per bundle**, so a consumer takes the core plus only the bundles they want. `groups` is the first and currently the only one — location and ranging were specified here and moved out on 2026-08-17, because both need a hardware source and the exclusion above always said so. Two things must hold, and both were verified on 2026-08-16 against a throwaway second crate rather than assumed:

**Every crate is gated, not just the first.** Three checks silently assumed a single crate and were fixed before any bundle existed: `check_rust_rules.sh` took the first `lib.rs` it found, `check_all.sh` inspected one `--lib` object, and `check_docs.sh` read one hardcoded `proofs.rs`. All three would have **passed while proving less** the moment a second crate arrived — the failure mode `check_rust_rules.sh`'s own header records being caught by three times. They now cover every crate root, every library artifact, and every file carrying harnesses.

A bundle crate therefore inherits the whole regime: the crate-level `deny` attributes, the panic-free artifact check, SPDX, clean-room, and the proof table. A crate too small to produce a meaningful object is **refused**, not waved through — *"a check that passes because there is nothing to look at is not a check."*

**Declare workspace keys, never inherit them.** `DEPS.md` records why: libcrux could not be used as a path dependency because *"`hacl-rs`'s manifest inherits workspace keys that cannot be parsed from outside its workspace"*, which broke resolution for downstream consumers. `fiat-rust` works precisely because it inherits nothing. A bundle crate that inherits `[workspace.package]` keys would reproduce that failure for our own consumers, and it would show up in *their* build rather than ours. Verify by building an external crate against it, as was done for fiat.

`third_party/` is excluded from the per-crate artifact sweep for the same reason it is excluded from the source rules: it is not ours to hold to them. What it does to the linked object is still measured, because it is linked into ours and inspected there.

## Two categories that leak most easily

**Commit messages.** They are published with the code and cannot be edited after a push. A message explaining that a change exists "because our transport does X" discloses that a transport exists and what it does. Write commit messages that explain the change in terms of the protocol.

**Rationale prose.** "We chose Y because our product needs Z" is a disclosure of Z. Where a design decision was driven by a private requirement, state the decision and a *general* justification, not the private one. If the general justification does not hold on its own, the decision may not belong in this repository either.

## When unsure

Keep it out. Adding something later is cheap; removing it after publication is impossible. An item that arguably belongs here but was withheld costs a later commit. An item that arguably did not, and was published, cannot be recovered.

If a change genuinely needs private context to be understood, that is a strong signal it belongs on the private side of the boundary instead.

## Relationship to consumers

This library is consumed by other software that is not published. That relationship is deliberately invisible from inside this repository: no names, no paths, no build coupling, no assumptions about a caller. The dependency runs one way — consumers depend on this, never the reverse — which is what keeps this repository independently useful and independently publishable.
