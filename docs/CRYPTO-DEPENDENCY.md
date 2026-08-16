# Why the curve implementation is ours, and measured rather than argued

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

Measured, as staticlibs, `no_std`, `panic = "abort"`, LTO off, each against a
baseline containing no dependency at all — because `core` contributes panic
symbols regardless and counting them makes any crate look bad:

| staticlib | total symbols | panic-related | above baseline |
|---|---|---|---|
| baseline, no dependency | 2038 | 48 | — |
| **ours** | 2103 | 48 | **+0** |
| `x25519-dalek` 2.0.1 | 2612 | 56 | +8 |
| `salty` 0.3 | 2312 | 54 | +6 |

`salty` is written for Cortex-M and still adds panic paths. No panic-free
X25519 crate was found.

An earlier note in this project put dalek's contribution at 58 symbols. That
was wrong — it counted `core`'s unreachable code. The corrected figure is +8,
which is a much weaker argument than the original number implied, and it is
recorded here rather than quietly replaced.

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

## When to revisit

- If a panic-free, audited X25519 appears, prefer it.
- If the panic-free guarantee is ever narrowed to the parse path rather than
  the whole crate, the trade changes and a dependency becomes the better
  answer immediately.
- If this code ever needs to resist physical side-channel attack rather than
  remote timing, hand-written constant-time code is not sufficient and
  hardware or an audited implementation is required.
