<!-- SPDX-FileCopyrightText: 2026 Matthew Klapman -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# DISTRIBUTION — language, artifacts, and what is guaranteed

**Settled 2026-08-14.** Recorded before implementation, because both decisions are expensive to reverse once code and consumers exist.

## Three things ship, and they are not equal

| artifact | role | status |
|---|---|---|
| **Specification** | the primary deliverable — what adoption actually runs on | authoritative |
| **Rust source** | reference implementation, conformance oracle, provenance evidence | authoritative |
| **Prebuilt libraries + C header** | convenience for C and C++ firmware | **best effort, see the caveat** |

Adoption is expected to be **specification-led**: implementers read the spec and write their own code, in whatever language suits their firmware. That is how protocols actually spread, and it is why the specification — not the implementation — is the deliverable that matters.

## Language: Rust, `no_std`

Three reasons, in order of weight.

**Provenance.** Clean-room's value is evidentiary, and Rust makes the evidence intrinsic to the artifact. The upstream firmware is C++. A C implementation invites the question "is this a translation?" — the languages are close enough for a structural-similarity argument to be constructed even when untrue. Rust's ownership model, `Result`-based error handling and trait structure make copying impossible without a genuine rewrite, which is precisely what clean-room means. The code argues for its own independence rather than relying on process documents.

**Provable absence of panics on hostile input.** This library parses untrusted network frames from a public mesh where some participants are assumed adversarial. Memory-safety alone is not the win — an aborting panic converts remote code execution into remote denial of service, which on a mesh node is still a serious defect. The discipline is therefore: no panicking paths in the parse path at all. `Result` everywhere; no `unwrap()`; no slice indexing; checked or saturating arithmetic. **And this is verifiable rather than aspirational** — the lints are denied at crate level and the linked binary is checked for the absence of panic machinery. That is a stronger guarantee than fuzzing alone can give.

**It does not foreclose C consumers.** `no_std` Rust has no runtime — no scheduler, no green threads, no initialisation that assumes ownership of the system. It compiles to ordinary objects with the C calling convention and links into a C firmware, under an RTOS or bare metal, like any other static library.

Design constraints that follow, and which would apply to a C implementation equally:

- **No mutable global state.** All state lives in a caller-owned context passed by pointer. Rust's `Send`/`Sync` guarantees do not cross an FFI boundary where a foreign scheduler calls in, so concurrency safety is a matter of API shape, not language.
- **Bounded stack.** RTOS tasks have small fixed stacks; stack use is measured, not assumed.
- **No allocation.** Buffers are caller-provided with explicit lengths.
- **The FFI boundary is the trust edge.** A caller passing a bad pointer or a wrong length cannot be validated. The exported surface is kept narrow and every call takes explicit lengths.

## Prebuilt binaries — the caveat, stated plainly

> **The prebuilt libraries are provided as a convenience only.**
> **If you encounter ABI boundary issues, rebuild from source.**

This is not a disclaimer of quality; it is an accurate description of what a cross-compiled binary can and cannot promise. Float ABI variants, toolchain versions, calling-convention flags and linker expectations differ between build environments in ways a published artifact cannot anticipate. Rebuilding from source resolves them definitively, and the source is right here.

The caveat appears in the release notes, in the release archive, and in the generated C header — not only in this document, because the person who hits the problem is unlikely to have read this.

## What the binaries do guarantee

**Reproducibility.** Anyone can rebuild them bit-identically: the toolchain version is pinned, the build command published, paths remapped, and artifacts signed. This matters more than usual here — a security-relevant binary for a cryptographic library, offered to an audience that reasonably prefers to build its own, is only acceptable if "build your own and compare" is a real option rather than a slogan.

**A declared target set.** Supported targets and ABI variants are listed explicitly rather than shipped as a scattering that leaves people guessing which gaps are deliberate.

**A stable ABI within a major version.** Shipping binaries means owning an ABI, and an ABI break fails at runtime rather than at compile time — in the field, confusingly. So: `tm_abi_version()` is callable by consumers, header struct layouts are frozen within a major version, and any break takes a major bump.

**A size budget.** Rust static libraries bloat easily through monomorphisation, panic machinery and formatting code. Since this library is panic-free and allocation-free by construction it should be small; the size is gated in CI and a regression fails the build, rather than being discovered on a device with 256 KB of flash.

**Artifact-level testing.** CI builds a minimal C consumer against each released archive for each target. Publishing binaries whose only validation was that the Rust tests passed on the host would be publishing something untested in the form people actually use.

**And the archive itself is now read, not only linked.** Until 2026-08-27 the panic-freedom and no-allocator promises above were discharged on a crate *object* and on a *linked image*, and never on the `.a` in between — the file this repository actually hands people. `gates/check_rust_rules.sh` accepted archives from the start and rejected every one of them, because nothing had ever passed it one; `gates/release.sh` built each archive and copied it into the release without running the gate at all. Both are closed: the gate resolves cross-member references the way a linker does, `check_all.sh` inspects the staticlib for every declared target on every run, and the release refuses to ship an archive that does not pass.
