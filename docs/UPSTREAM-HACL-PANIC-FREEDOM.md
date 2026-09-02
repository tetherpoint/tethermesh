<!-- SPDX-FileCopyrightText: 2026 Matthew Klapman -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Making HACL*'s extracted Rust panic-free — analysis for upstream

**2026-08-16.** Written to be usable as an upstream issue against
[cryspen/libcrux](https://github.com/cryspen/libcrux), pinned here in
`code/third_party/libcrux` at `9ea7743c`.

## What we wanted

To link `libcrux-hacl-rs`'s curve25519 rather than ship a hand-written
X25519, so the field arithmetic carries HACL*'s provenance instead of ours.
That is worth more to anyone adopting this library than another ladder
written from scratch.

## What blocks it

This crate guarantees no panics and no allocation, enforced against the built
artifact. Measured on a linked `no_std` staticlib against a baseline with no
dependency at all:

| | allocator | panic paths above baseline |
|---|---|---|
| our implementation | no | **0** |
| hacl-rs curve files, isolated | no | **+3** |
| `libcrux-curve25519` (whole crate) | **required** | +37 |

**VERIFIED 2026-08-18, BY BUILDING IT BOTH WAYS — and the distinction is sharper
than "the curve path never uses it" suggests.**

| built as | allocator | panic symbols |
|---|---|---|
| the curve path's own modules — `fstar`, `lowstar`, `bignum25519_51`, `curve25519_51` | **no** | **+3** |
| the whole `libcrux-hacl-rs` crate, *calling only that same curve path* | **REQUIRED — build fails** | n/a |
| `libcrux-curve25519` from crates.io (what `measure_panic_symbols.sh` builds) | **REQUIRED — build fails** | n/a |

**THE ALLOCATOR REQUIREMENT IS A CRATE-LEVEL PROPERTY, NOT A CALL-GRAPH ONE.**
`lib.rs` declares `pub mod prelude { extern crate alloc; }`, and compiling the
crate compiles that module — so a consumer that touches only the allocation-free
curve path still fails with `no global memory allocator found but one is
required`. Reasoning about which functions you call will not save you, and this
is exactly the reasoning that produced a wrong summary on 2026-08-18: *"libcrux
requires an allocator"*, unqualified, read as a claim about the curve code, which
is false about it.

The precise statement, and the only one to repeat: **the curve code is
disqualified by the PANIC rule (+3 paths); the crate around it is additionally
disqualified by the ALLOCATION rule.** Taking only the modules that avoid the
allocator means forking generated files, which the analysis below explains voids
the verification it exists to provide.

The three panic symbols were confirmed by the same build:
`core::panicking::panic_bounds_check`, `core::panicking::panic_fmt`,
`core::slice::index::slice_index_fail`.

The good news is how narrow it is. `curve25519_51.rs` (342 lines) and
`bignum25519_51.rs` (726) contain **no `panic!`, no `unwrap`, no `assert`,
and no allocation**. Compiled with about 180 lines of `fstar`/`lowstar`
support they need no allocator. The whole-crate allocator requirement comes
from `lib.rs`'s `prelude`, which the curve path never uses.

## The root cause is one thing, repeated

Every panic path traces to **slice parameters whose lengths are statically
known but not statically expressed**:

```rust
// curve25519_51.rs, 22 sites of this shape
((&mut f1_copy)[0usize..5usize]).copy_from_slice(&c0.1[0usize..5usize]);
```

The buffers are always exactly 5 or 10 limbs. The parameters are typed
`&mut [u64]`, so the compiler cannot prove the lengths agree and emits
`copy_from_slice_impl::len_mismatch_fail`. The same applies to indexing
inside `unroll_for!` bodies, which emits `panic_bounds_check`:

```rust
// bignum25519_51.rs:722
let dummy: u64 = mask & (p1[i as usize] ^ p2[i as usize]);
```

Undefined references in the resulting object:

```
core::slice::copy_from_slice_impl::len_mismatch_fail
core::panicking::panic_bounds_check
core::slice::index::slice_index_fail
core::panicking::panic_fmt
core::fmt::Formatter::pad
```

None of these are reachable — the sizes really are fixed. They are artefacts
of the type used to express them.

## What would fix it, and where the fix belongs

**Extract fixed-size array types where the length is static:** `&mut [u64; 5]`
instead of `&mut [u64]`. Then `copy_from_slice` between two `[u64; 5]` is
provably equal-length, constant indices are provably in range, and every one
of these paths disappears at compile time.

This is a change to the **extraction backend**, not to the generated files. A
pull request editing `curve25519_51.rs` by hand would be overwritten by the
next extraction, which is why none is offered here. The useful contribution is
this measurement plus the request.

**Why it is worth doing upstream.** `no_std` embedded consumers frequently
promise panic-freedom and verify it by inspecting the linked artifact, as this
project does. Under `panic = "abort"` a panic halts the device, so an
unreachable panic path is still a linked code path and still fails that check.
Fixed-size extraction would make libcrux usable by that whole class of
consumer without any of them forking generated code — and forking it is the
only alternative, which voids the verification it exists to provide.

## What this project did meanwhile

Kept the hand-written implementation, which satisfies the guarantee, and used
upstream as a **test oracle** instead: `x25519-dalek` and
`libcrux-curve25519` both cross-check it on every run, over 512 random
agreements plus boundary values. The submodule is retained as the basis for
this analysis rather than as a dependency.

One further practical obstacle, recorded because it would bite anyone trying
the same thing: a path dependency on the sparse submodule **fails to resolve
for downstream consumers** — `hacl-rs`'s manifest inherits workspace keys, and
parsing it from outside the libcrux workspace fails. A library meant to be
depended upon cannot ship that.
