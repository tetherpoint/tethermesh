<!-- SPDX-FileCopyrightText: 2026 The tethermesh Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# AUDIT — the cryptographic core, 2026-08-16

**Completed over `c277d09^..HEAD`. The cryptographic core came back clean; four
documentation defects were found and fixed.**

This was a working note in an untracked hand-off file until 2026-08-18. It is
tracked now for the reason the rest of this repository is: it is a claim about
our own code that someone may want to check, and a claim no gate can see is a
claim nobody maintains. `tools/check_docs.sh` now covers its cross-references.

It is publishable on its own terms — it concerns our own cryptography, our own
gates and our own history. The two paragraphs that did *not* move are the ones
about repository infrastructure and session state, which stay in the untracked
hand-off note where they belong.

Completed over `c277d09^..HEAD`. **The cryptographic core came back clean; four documentation defects were found and fixed.** Nothing required rewriting history — see below, because that question came up and the answer matters.

**What was verified clean, and how:**

- **fiat precondition discipline** — exactly four `.0` sites, three in `cswap` moving limb arrays through `selectznz`, none doing arithmetic. Now enforced by a gate rather than by grep (see below).
- **The inversion chain** — re-derived independently of the comments. Resolves to `a^(2^255−21)` = `a^(p−2)`. Correct.
- **The ladder** — matches RFC 7748 step for step. One line *textually* differs and is fine: `:278` computes `E·(BB + 121666·E)` where the RFC writes `E·(AA + a24·E)`, `a24 = 121665`. These are algebraically identical (checked over 100,000 random field-element pairs). It is the ref10 formulation. **Do not "fix" it** — a naive RFC comparison flags a false positive here.
- **The zero path** — `scalarmult` is private with two in-file callers; the `backend.rs` mapping to `SmallOrderPeer` is total.
- **Provenance** — both pins match DEPS.md; libcrux is genuinely unlinked (the dev-dep resolves from the registry, the submodule is unreferenced by `Cargo.toml`).
- **Red-test integrity** — six mutations (inversion chain, swap carry, zero check, top-bit mask, backend mapping, clamp). All went red, both differential oracles fired. The oracles are live, not vacuous.
- **History** — clean. No upstream source file has ever existed; the only GPL-header blobs are `check_cleanroom.sh` quoting its own patterns. RadioLib appears in 21 blobs, all four distinct lines being our own prose saying we do not use it.

**On history rewriting: it was not needed and is not pending.** The only defect class that would force it is GPL contamination, because deleting the file does not undo the derivation. That did not occur. Documentation asserting something false is fully corrected by a forward commit, and the record of the correction is worth keeping.

**Scope was `c277d09^..HEAD`** — ten commits at the time of writing, now eleven (`4850fe0` landed after). Note the `^`: `c277d09..HEAD` alone excludes the X25519 commit and gives eight.

```
c277d09  L6: X25519, and the whole PKI chain in our own code
cf71cfa  Audit: close coverage gaps, settle the crypto-dependency question
827654a  Prove the parse path with Kani, record what "verified" means
ee08f59  Measure the submodule proposal, add a second verified oracle
966e527  Try the submodule properly, write up the upstream fix it needs
7325e1b  Use Coq-verified field arithmetic: fiat-crypto under our ladder
d655099  Pin fiat-crypto as an in-tree submodule
f9c247a  Document exactly where fiat's proof stops and ours begins
ff89cfb  Backend seam: hardware failure and key custody
21cd1b5  Clean-room gate: close the docs/ hole, sweep submodules
```

### The four defects found, all fixed

1. **`docs/CRYPTO-DEPENDENCY.md` argued for a decision that had been reversed.** Its "On linkage" section said fiat-crypto was a crates.io dependency "rather than a submodule" and explained why crates.io won. `d655099` made it a submodule the very next commit and never touched the file. Rewritten to describe the submodule, keeping the reversal legible rather than silently overwriting it.
2. **A retracted figure was still live in two places.** `Cargo.toml` and a test doc comment both claimed x25519-dalek brings "58 panic symbols"; `CRYPTO-DEPENDENCY.md` had already retracted that to +8. Re-measured: **+0 distinct panic symbol names**, +6 raw archive entries. Both corrected. The honest consequence is recorded — this argument is weak against dalek and has shrunk every time anyone checked it, so it is no longer presented as load-bearing. fiat was chosen because it is verified and free, not because dalek was disqualified.
3. **The panic-symbol table did not reproduce on the toolchain it names.** Doc said baseline 2038 total / 48 panic-related; re-measuring on the same pinned rustc 1.97.1 gave 2037 / 65. Totals matched, so the artifact was built the same way — the gap was the symbol-matching pattern, which was never recorded. Fixed by committing the method as `tools/measure_panic_symbols.sh`; the doc now cites the script instead of describing it.
4. **`docs/HARDWARE-BACKENDS.md` credited the ESP32-S3 with an ECC unit it does not have.** It read "its ECC unit covers NIST prime curves rather than Curve25519." Espressif's own `soc_caps.h` for the S3 has **no `SOC_ECC_SUPPORTED` at all**. The conclusion was right for a wrong reason. The ESP32-S3 and RP2350 rows are now **verified** against primary sources quoted with paths — closing the item this file previously flagged as unverified.

   **The survey was extended while fixing this**, to S2, S3, C3, C6, H2, P4 and S31, each read out of `components/soc/<chip>/include/soc/soc_caps.h` in `espressif/esp-idf` — the header ESP-IDF itself uses to gate the ECC driver, so it is better evidence than any datasheet summary. Result: **of nine parts now surveyed, exactly one (nRF54LM20) accelerates this stack's curve.** S2/S3/C3 have no ECC unit at all; C6/H2/P4/S31 have one that is NIST-prime only. Note the trap — S31, P4 and H2 all set `SOC_ECC_CONSTANT_TIME_POINT_MUL`, which names precisely the side-channel property this project wants, *on curves this stack does not use*. **The ESP32-S31 is a real part** (launched April 2026, `components/soc/esp32s31` exists); it is not a typo for the S3.

### Two gates added, both seen red

- **`check_rust_rules.sh` now enforces the fiat `.0` discipline.** An **allowlist** of adjudicated line shapes, not a blocklist of operators — a blocklist must anticipate every way to write arithmetic, an allowlist need only recognise what was approved. Red-tested against `a.0[0] = a.0[0] + 1` and a `wrapping_add` hidden inside a write-back. **If it fires, do not widen the pattern to make it pass.**
- **`tools/check_docs.sh` is new and wired into `check_all.sh`.** Checks doc-cited test names exist, the Kani harness table matches `proofs.rs` in *both* directions, DEPS.md's pinned SHAs match the actual submodules, and cited tooling exists. All four red-tested. **Be clear about its limits: it would not have caught defects 1 or 2.** Both are prose making a false assertion, and no script distinguishes a true paragraph from a false one. It catches the mechanical subset, which matters because that subset rots without anyone editing the document.

### Original audit checklist, for reference

**1. The fiat-crypto precondition discipline.** The safety argument in `meshtastic/core/x25519.rs` is structural: fiat's `tight`/`loose` types *are* the magnitude bounds its Coq proof assumes, so misuse is a compile error rather than a silent wrong answer. That argument holds only if every field value flows through the wrappers. Grep for `.0` in `meshtastic/core/x25519.rs` and confirm each occurrence. There are currently four: one in a doc comment, and three inside `cswap` — the single legitimate site, which moves limb arrays through fiat's `selectznz` and performs no arithmetic on them. Any *arithmetic* on `.0` would void the proof silently; that is the failure mode to hunt.

**2. The inversion chain.** `invert` computes `a^(p-2)` by a fixed addition chain. Re-derive the exponent rather than trusting the comments — this is unverified, ours, and the kind of code that is self-consistent when wrong.

**3. The ladder.** Confirm `scalarmult` against RFC 7748 step by step, particularly the conditional-swap sequencing around `swap ^= bit` / `swap = bit` and the final unswap. Check the `pos as usize` / `pos as u32` casts on the bit-extraction path.

**4. The zero-result path.** `invert(0)` returns 0, so a small-order peer yields an all-zero secret that only `x25519`'s explicit check rejects. Confirm nothing reaches `scalarmult` directly and bypasses it. `meshtastic/core/backend.rs` now maps this to `Error::SmallOrderPeer` — check that mapping is total.

**5. Dependency provenance.** Confirm `third_party/fiat-crypto` is pinned at `a6ddbd4e89e1714cb825437a401505b9c76537cf`, sparse to `fiat-rust/`, and that `third_party/libcrux` (`9ea7743c`) is genuinely **not linked** — it is a dev-time oracle only. Check the license situation still matches `DEPS.md`, and that `DEPS.md` still names the oracle version and digest the fixtures were actually obtained against.

**6. Do the docs still describe the code?** This span wrote a lot of prose. Verify the harness table in `docs/FORMAL-VERIFICATION.md` matches the actual harnesses in `meshtastic/core/proofs.rs`; that `docs/HARDWARE-BACKENDS.md`'s verified/believed marks are still honest; that `docs/CRYPTO-DEPENDENCY.md`'s panic-symbol measurements can still be reproduced. A doc that drifted from the code is worse than no doc, because it will be trusted.

**7. Red-test integrity.** Every test in this span was supposed to be seen red before being trusted. Spot-check by mutating the claim and confirming the test fails — especially the differential tests against `x25519-dalek` and `libcrux-curve25519`, where a broken oracle setup would pass vacuously.

**8. Are the past commits clean, not just the working tree?** The gates run on `git ls-files` — the *current* tree. A file that was committed and later removed is never re-examined, and "once GPL-derived code is in the history, deleting the file does not undo it" is the project's own stated position. So history needs its own check.

Two queries matter, and both were run on 2026-08-16 at `ff89cfb` and came back **clean**:

```
# Has any upstream source file ever existed here?
git rev-list --objects --all | awk 'NF>1{print substr($0, index($0," ")+1)}' \
  | grep -vE "^third_party/" | grep -iE "\.(proto|c|cc|cpp|cxx|h|hpp|ino)$" | sort -u
# -> empty

# Has any blob ever carried a GPL licence header?
#    (excluding tools/check_cleanroom.sh, which quotes every pattern it enforces)
```

**Do not run the clean-room gate naively over every historical blob.** It reports 24 hits and all of them are benign: the scanner quoting its own patterns, and older drafts of `PLAN.md`, `README.md` and `meshtastic/WIRE_REFERENCE.md` naming the forbidden library in our own prose while saying we do not use it. Those three files are on the gate's sanctioned exemption list precisely so the rule can be written down. Naming a library is not deriving from it. Expect the 24, adjudicate them, do not panic.



**That previously-flagged unverified claim is now closed.** Both rows were promoted to *verified* on 2026-08-16 against primary sources. The ESP32-S3 claim turned out to be **wrong**, not merely unconfirmed — see defect 4 above. The instinct to distrust a confident accelerator summary was right.

