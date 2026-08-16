<!-- SPDX-FileCopyrightText: 2026 The tethermesh Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# DEPS — what every result was obtained against

**2026-08-15.**

A compatibility result that cannot name the version it was obtained against is not a result. The wire format moves, and so does the reference implementation. This file is the record; update it at every milestone.

It exists in the repository even though the artifacts and the tooling that fetches them do not. That separation is deliberate: **their material lives outside the tree, the provenance of our claims lives inside it.** Moving the harness out must not cost us the ability to say what we tested against.

## Wire specification

| what | value |
|---|---|
| source | `meshtastic/protobufs`, read as specification |
| pinned commit | `84bfb0fdb3b853ea18abc4535497fa41a1b09546` (short `84bfb0fd`) |
| commit date | 2026-08-11 |
| verified | 2026-08-15, against the GitHub commit API |

Read at that commit, never vendored, never run through a code generator. Field numbers and wire layouts are facts; the file is expression. See `README.md` § clean-room.

## Reference implementation (oracle)

| what | value |
|---|---|
| artifact | `meshtastic/meshtasticd` container image |
| tag | `2.7.26.54e0d8d` |
| digest | `sha256:23e92b1331a3a471eaef0c63cbca4365ca40b3111a9781cfdbe5a5114e5773d4` |
| firmware string reported at runtime | `S:B:37,2.7.26.54e0d8d,native,meshtastic/firmware` |
| obtained | 2026-08-15 |
| lives in | `../meshtastic-oracle/` — outside this repository, never tracked |

**The digest is the pin, not the tag.** Tags are mutable; a result obtained against a moved tag names nothing. `fetch_oracle.sh --verify` checks the digest.

**Why 2.7.26 and not 2.8.0.** As measured on 2026-08-15, 2.8.0 exists only as `daily` and `GHA-2.8.0.<sha>` continuous builds; the newest tag corresponding to a non-prerelease firmware release is 2.7.26.54e0d8d (2026-06-24). A daily build is not a version anyone else can be pointed at.

**Known coverage hole.** XEdDSA packet signing lands in firmware 2.8.x (`meshtastic/WIRE_REFERENCE.md`). A 2.7.26 oracle cannot exercise it. Revisit when 2.8.0 releases.

## Pinned third-party source, in tree

Both are git submodules, sparse-checked-out, so the exact source that compiles
is present in the working tree and auditable offline. Clone with
`--recurse-submodules`.

| submodule | commit | checked out | role |
|---|---|---|---|
| `third_party/fiat-crypto` | `a6ddbd4e89e1714cb825437a401505b9c76537cf` | `fiat-rust/` only, 4.9 MB | **linked.** Coq-verified curve25519 field arithmetic, MIT/Apache-2.0/BSD-1-Clause |
| `third_party/libcrux` | `9ea7743c201ae861625dccb171f7c42d6b831927` | `crates/utils/` only, 744 KB | **not linked.** Basis for `docs/UPSTREAM-HACL-PANIC-FREEDOM.md` |

**Why a submodule rather than a registry pull.** A registry dependency is
pinned by checksum in `Cargo.lock`, which is a real pin — but the source lives
in `~/.cargo/registry`, so nobody reviewing this repository can see what is
actually compiled without fetching it. A submodule puts it in the tree at a
named commit. For the one dependency that performs cryptography, that is worth
a few megabytes.

It also works, which was not a foregone conclusion: `fiat-rust` inherits no
workspace keys and has no dependencies of its own, so a path dependency on it
resolves for **downstream** consumers too. That was verified by building an
external crate against this one. The same approach with `libcrux` fails at
exactly that step, because `hacl-rs`'s manifest inherits workspace keys that
cannot be parsed from outside its workspace.

## Toolchain

| what | value |
|---|---|
| built with | `rustc 1.97.1` / `cargo 1.97.1` |
| declared MSRV | `1.75` (`Cargo.toml` `rust-version`) |
| dependencies | none, and that is a requirement — see `Cargo.toml` |

No `rust-toolchain.toml` yet: pinning an exact toolchain belongs with the
reproducible-build work in L8, and pinning it earlier would force every
contributor onto one compiler for no benefit the MSRV does not already give.

## Environment notes that affect reproducibility

The oracle is a container image, fetched by digest, and **no container runtime is involved at any stage**. It is run by extracting the image filesystem and launching `meshtasticd` through the image's own dynamic loader, because a nested-container environment refuses the `/proc` mount a container run requires. Since nothing runs as a container, nothing needs a runtime installed either: the fetch is plain HTTPS.

This changes nothing the clean-room position rests on — the artifact is still the pinned image, still digest-verified, still never built from source, still observed from outside. A container is an isolation mechanism, not a clean-room mechanism.

It also makes the pin **stronger**. A runtime would be trusted to have checked the digest; instead the top-level manifest, the per-architecture manifest and every layer blob are each hashed and compared before anything is written to disk, and a mismatch aborts rather than warns. A partially-verified oracle is worse than none, because results obtained against it would look attributable and would not be.

Recorded here because these are the details that silently invalidate a reproduction attempt if they go unwritten.

## Oracle quirks that will waste your time

**Enabling `UDP_BROADCAST` breaks the console log.** With `network.enabled_protocols = 1`, meshtasticd's stdout keeps emitting log *prefixes* (`DEBUG | hh:mm:ss 0 `) but drops the message bodies partway through boot. The node runs correctly — it binds multicast, transmits, and its API is fully functional — but the log stops being a usable observation channel. Observe over the API or on the wire instead of over the log when UDP is on.

**Hand-writing a whole `LocalConfig` replaces every section.** The prefs file is not a patch. A `LocalConfig` containing only `network` leaves `lora`, `device`, `position` and the rest at proto3 zero values rather than at firmware defaults. Writing an explicitly populated `lora` section did not help either and stopped the nodes transmitting entirely; the minimal `network`-only config is what worked. Prefer setting config over the API, which mutates one section and leaves the others alone, over writing prefs files directly.

**The node database is discarded across restarts** in this setup (`NodeDatabase 0 is old, discard`), so a node that has learned a peer forgets it on reboot. Any experiment about what a node knows must run within a single boot.
