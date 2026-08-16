# The curve implementation: verified field arithmetic, our ladder

**RESOLVED 2026-08-16.** The field arithmetic is now `fiat-crypto`'s —
generated from Coq proofs by mit-plv, the same pipeline BoringSSL uses. The
Montgomery ladder on top is ours. Everything below is the reasoning that led
there, kept because the measurements are the point.

The short version:

| | allocator | panic paths above baseline | verified |
|---|---|---|---|
| **fiat-crypto field arithmetic (chosen)** | no | **+0** | **yes, Coq** |
| our hand-written field arithmetic | no | +0 | no |
| `x25519-dalek` | no | +8 | audited only |
| `salty` | no | +6 | no |
| `libcrux-curve25519` (HACL*) | **required** | +37 | yes, F* |

fiat-crypto is the only option that is formally verified **and** costs nothing
against the rules that may not be violated. It is triple-licensed
MIT/Apache-2.0/BSD-1-Clause, is `no_std`, has **zero dependencies of its own**,
and its generated code uses fixed-size arrays — which is exactly why it has no
bounds-check panics where HACL's slice-typed extraction does.

It also covers precisely the layer where the hand-written code failed: the
first draft of `x25519.rs` biased `fe_sub` by `p` instead of `2p`. That is a
field-arithmetic bug, and field arithmetic is what fiat proves.

**On linkage.** It is an in-tree git submodule, pinned at
`a6ddbd4e89e1714cb825437a401505b9c76537cf` and sparse-checked-out to
`fiat-rust/` only. `Cargo.toml` carries a path dependency on it; see `DEPS.md`
for the pin of record.

An earlier draft of this section argued the opposite — that a crates.io pull
was preferable, because `Cargo.lock` records a SHA256 of the crate contents
(pinning content rather than history) and because the upstream repository is
176 MB of Coq development for roughly 700 lines of generated Rust. That
reasoning was overtaken within one commit and is kept here only so the
reversal is legible:

- The size objection was answered by sparse checkout. Only `fiat-rust/` is
  fetched, which is 4.9 MB rather than 176 MB.
- The auditability argument won. A registry checksum is a genuine pin, but
  the source then lives in `~/.cargo/registry`, where nobody reviewing this
  repository can see what actually compiles without fetching it. For the one
  dependency that performs cryptography, having the exact source in the tree
  at a named commit is worth a few megabytes.

It also had to be shown to *work*, which was not a foregone conclusion:
`fiat-rust` inherits no workspace keys and has no dependencies of its own, so
a path dependency on it resolves for **downstream** consumers too. That was
verified by building an external crate against this one. The same approach
with libcrux fails at exactly that step, because `hacl-rs`'s manifest inherits
workspace keys that cannot be parsed from outside its workspace.

## The earlier reasoning, kept for the record

**2026-08-16.** Recorded because "we wrote our own crypto" is normally the
wrong answer, and the reasoning needs to survive someone reading it later and
assuming nobody thought about it.

## The case against writing it

Overwhelming, and it should be stated first. A bug in a curve implementation
is not a crash — it is silent key compromise. The first draft of
`meshtastic/core/x25519.rs` biased `fe_sub` by `p` instead of `2p` and had a
muddled final reduction. The result was **entirely self-consistent**: it
added, multiplied, inverted and round-tripped without complaint, and agreed
with itself everywhere. Only RFC 7748's published vectors exposed it. No
property test would have found it, and no amount of internal testing would
have.

Vetted crates are also audited, and use `subtle` for constant-time behaviour
that `x25519.rs` itself admits Rust cannot guarantee. Licensing is not an
obstacle: `x25519-dalek` is BSD-3-Clause and `salty` is Apache-2.0/MIT, both
compatible with this project's permissive intent.

## The constraint that decided it

`DISTRIBUTION.md` promises that no path can panic on hostile input, and
`tools/check_rust_rules.sh` enforces it against the built artifact. A
dependency's panic paths become ours.

Measured as staticlibs, `no_std`, `panic = "abort"`, LTO off, each against a
baseline containing no dependency at all — because `core` contributes panic
symbols regardless and counting them absolutely makes any crate look bad.

**Run it yourself: `tools/measure_panic_symbols.sh`.** The methodology lives in
that script rather than in this prose, for a reason given below.

Re-measured 2026-08-16 on `rustc 1.97.1`, the toolchain `DEPS.md` pins:

| staticlib | total symbols | panic-related (raw) | distinct names | above baseline |
|---|---|---|---|---|
| baseline, no dependency | 2037 | 65 | 64 | — |
| `x25519-dalek` 2.0.1 | 2441 | 71 | 64 | **+0 distinct** (+6 raw) |
| `libcrux-curve25519` 0.0.8 | — | — | — | **does not build `no_std`** |

`libcrux-curve25519` is not a row that can be filled in: it fails to compile
with *"no global memory allocator found but one is required"*. That is the
finding, and it is the one that actually rules it out — `DISTRIBUTION.md`
forbids an allocator outright, so the panic count never gets a vote.

**Why this table was rewritten, and what it costs the argument.** The earlier
version reported a baseline of 2038 total / 48 panic-related and put dalek at
+8. The 2026-08-16 audit could not reproduce it *on the same toolchain this
document names*: the totals matched almost exactly (2037 vs 2038), which shows
the artifact was built the same way, but the panic count did not (65 vs 48).
The gap is the symbol-matching pattern, and the document never recorded it —
nor the harness source. So the figures could be neither defended nor refuted.
That is why the method is now a committed script and this table cites it.

**The honest reading is that this argument is weak against `x25519-dalek`, and
has been getting weaker each time it was checked.** It began as "58 symbols",
was retracted to +8 on the grounds that the original had counted `core`'s
unreachable code, and re-measures now at +0 distinct panic symbol names. A
figure that shrinks every time someone looks at it should not be load-bearing.

It is not load-bearing here. `fiat-crypto` was chosen because it is **formally
verified and costs nothing** — it dominates on its own merits. Nothing in the
decision requires dalek to have been disqualified, and this document should not
be read as claiming it was. `salty` 0.3 was measured in the original round and
has not been re-measured; treat its figure as unverified.

## What was done instead

The implementation stays ours, and the audited one is used as a **test
oracle**: `x25519-dalek` is a dev-dependency, never linked into the shipped
library. `tests/host_unit` compares the two across 512 random agreements per
run plus boundary values including `p-1`, `p`, zero and `2^255`.

That is most of the assurance a dependency would have bought, at none of its
cost to the artifact. It is also strictly more than a fixed vector gives: the
`fe_sub` bug would have been caught on the first random input, not by luck in
choosing the right constant.

## The submodule option, measured

Proposed: vendor the verified code as a pinned git submodule and strip its
panics — losing the exact proof but keeping the algorithmic work. A pinned
submodule is genuinely different from a fork, so this was measured rather than
argued.

`libcrux-curve25519` is a 169-line wrapper with **no alloc and no panics**.
Everything objectionable is in its dependencies, and the curve code itself is
narrow: `curve25519_51.rs` (342 lines) and `bignum25519_51.rs` (726) plus
about 180 lines of support. Both are alloc-free and free of `panic!`,
`unwrap` and `assert`. Compiled standalone, `no_std`, they need **no
allocator at all** — versus the full crate, which does.

So far so good. Then the metric that actually governs:

| | allocator | undefined refs from the object |
|---|---|---|
| ours | no | **0** |
| HACL curve files, isolated | no | **8** |
| full `libcrux-curve25519` | **required** | — |

The eight are not incidental:

```
core::panicking::panic_bounds_check      array indexing
core::slice::index::slice_index_fail     slicing
copy_from_slice_impl::len_mismatch_fail
core::panicking::panic_fmt
core::fmt::Formatter::pad
```

**The generated HACL Rust is not panic-free.** Its bounds checks are real
panic paths, and there are several. Removing them means rewriting indexing
throughout machine-generated code — which is precisely the modification that
voids the proof.

That is the whole argument in one line: **the proof is the only thing their
code has that ours does not.** The algorithm is the same — `curve25519_51` is
the 51-bit limb Montgomery ladder from RFC 7748, which is what `x25519.rs`
implements, because there is only one sensible way to do it. Discard the proof
and what remains is ~1,250 lines of `uu____0` and `r#priv` that nobody here
can review, implementing an algorithm we already have, needing a proc-macro
the build rules bar, and still not panic-free.

There is also a real option that keeps the proof intact, and it is a product
decision rather than a technical one: **put PKI behind a feature flag** where
allocation and panics are acceptable, and use `libcrux-curve25519`
unmodified. That trades the crate-wide guarantee on one path for a machine
-checked curve. It has not been taken, but it is the only version of "use the
verified library" that keeps the verification.

What was done instead costs nothing and captures most of the value: **both**
`x25519-dalek` and `libcrux-curve25519` are dev-dependency oracles, and the
suite cross-checks ours against both on every run. Agreement with two
independent implementations — one audited, one formally verified — is a
stronger claim than agreement with either.

## The submodule was tried, not just discussed

`third_party/libcrux` is a real pinned submodule (`9ea7743c`, sparse, 744 KB)
and the curve code was linked into the crate and measured. It builds. It is
not shippable, for two reasons found by doing it:

1. **It reintroduces panic paths.** `+3` above baseline in the linked
   artifact, from `len_mismatch_fail`, `panic_bounds_check` and
   `slice_index_fail`. The rule that no panics and no allocation may be
   violated is not negotiable, so that ends it.
2. **Downstream consumers cannot resolve it.** `hacl-rs`'s manifest inherits
   workspace keys; parsing it from outside the libcrux workspace fails, so any
   crate depending on tethermesh fails to build.

The cause of (1) is narrow and fixable upstream — see
`docs/UPSTREAM-HACL-PANIC-FREEDOM.md`, which is written to be usable as an
issue against cryspen/libcrux. The fix is extracting fixed-size array types
where lengths are static, which belongs in the extraction backend rather than
in a patch to generated files.

The submodule is kept because it is the basis for that analysis, and because
if upstream takes the change, linking becomes possible without a fork.

## When to revisit

- If a panic-free, audited X25519 appears, prefer it.
- If the panic-free guarantee is ever narrowed to the parse path rather than
  the whole crate, the trade changes and a dependency becomes the better
  answer immediately.
- If this code ever needs to resist physical side-channel attack rather than
  remote timing, hand-written constant-time code is not sufficient and
  hardware or an audited implementation is required.
