<!-- SPDX-FileCopyrightText: 2026 Matthew Klapman -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Licensing — DECIDED

**Status: DECIDED 2026-08-16. Apache-2.0, for code and specification alike.
`LICENSE` and `NOTICE` are in the repo, `Cargo.toml` carries
`license = "Apache-2.0"`, and `gates/check_spdx.sh` enforces that every file
declares it.**

## The decision, and the reasoning that settled it

**Apache-2.0 for the code**, over MIT, for the reason set out below: the
explicit patent grant. The strategy is adoption by other implementers,
possibly commercial ones, of a *cryptographic* suite — the area where patent
uncertainty is taken most seriously. MIT is silent there; Apache answers.

**Apache-2.0 for the specification too**, rather than CC-BY-4.0, and this
follows directly from the first choice. **CC-BY-4.0 licenses no patent rights
at all** — it says so explicitly. Putting the spec under it would deny a patent
grant to *precisely the adopter this project is aiming at*: the one who reads
the specification and writes their own clean-room implementation. Choosing
Apache-2.0 for its patent grant and then exempting the one document
implementers actually work from would be self-defeating.

Three things reinforce it:

- **These "spec" files are not prose.** `docs/WIRE_REFERENCE.md` carries
  hex frames, byte-offset tables, register values, a measured preset table.
  The argument against a code licence for documents is weakest exactly here.
- **It removes the demarcation problem entirely.** The objection recorded
  below — that mixed-licence repos need unambiguous boundaries and create
  confusion when those go wrong — does not arise with one licence.
- **It is established practice.** OCI, OpenAPI and CloudEvents all license
  specifications under Apache-2.0.

**What is given up:** Apache-2.0's vocabulary — "Source form", "Object form",
"compilation" — genuinely does not describe a document. That is a real cost and
it is aesthetic; it was traded against a substantive patent benefit.

**Also accepted:** §4(b) requires modified files to carry change notices, so
anyone adapting the spec must mark their changes. For a specification that is
arguably a feature: forks stay identifiable.

**And the patent pledge is kept anyway**, in `docs/EXTENSIONS.md`. Apache §3's
grant attaches to "the Work", and its reach over *someone read the document and
wrote independent code* is not airtight — copyright does not restrict
implementing a described method in the first place, which is what makes the
grant's edges fuzzy there. Under a single Apache-2.0 the pledge is
belt-and-braces rather than load-bearing, but it is cheap and it removes the
residual doubt that makes a cautious implementer hesitate.

---

## The options as recorded 2026-08-14, kept for the reasoning

What *is* settled: tethermesh will be **permissively** licensed, not copyleft. That is a decision, because the clean-room constraint depends on it — refusing GPL derivation only makes sense if the result ends up permissive. See `docs/PLAN.md` § clean-room constraint.

What is open: **which** permissive licence for the code, and **whether to license the specification separately**. Neither blocks development. Both block publication, because an unlicensed spec is an unusable one and the entire extend strategy depends on other people being free to implement it.

---

## Why this decision carries more weight here than usual

For most projects the permissive licences are interchangeable in practice. Here they are not, because of what the project is trying to do:

- The deliverable is a **specification plus a reference implementation, intended for adoption by other vendors** — possibly commercial ones, possibly Meshtastic upstream itself.
- Adoption is not a nice-to-have. It is the strategy. A licence that makes a corporate legal review pause is a licence that costs adoption.
- The suite is **cryptographic**, which is the area where patent uncertainty is taken most seriously by adopters.

---

## Option A — Apache-2.0 for the code

**What it adds over MIT**

| | |
|---|---|
| **Explicit patent grant** | Every contributor grants a licence to any patents their contribution needs. An adopter knows we cannot later assert a patent on the thing we published. |
| **Patent retaliation** | If an adopter sues over patents, their licence terminates. Defensive, not offensive. |
| **Explicit trademark non-grant** | The licence gives no right to the project name. Useful once a name exists that others might trade on. |
| **Contribution terms (§5)** | Contributions are under the same licence unless stated otherwise — removes ambiguity about outside patches. |
| **"State your changes"** | Modified files must be marked. Mild compliance burden for adopters, mild traceability benefit for us. |

**Why it fits this project.** The patent grant lands squarely on the strategy's weak point. A vendor deciding whether to ship our extension suite is asking "can these people come after us later?" — MIT is silent, Apache answers. It is also the de facto standard for multi-vendor protocol work (ESP-IDF, Zephyr, mbedTLS), so it reads as unremarkable rather than as something to escalate internally.

**What it costs.** Roughly ten times MIT's length, a NOTICE file convention, and the change-marking requirement. And one hard incompatibility: **Apache-2.0 cannot be included in GPL-2.0-only projects.** GPL-3.0 is fine — so Meshtastic upstream could absorb our suite — but a GPLv2-only consumer could not.

## Option B — MIT for the code

**What it gives up:** everything in the table above, principally the patent grant.

**What it gains, and these are real**

- **Brevity.** About 170 words. A human reads it in under a minute; many organisations approve it without legal review at all. Apache-2.0 usually gets read by someone.
- **Universal recognition.** Zero friction, no explaining.
- **Lower compliance burden on adopters** — no NOTICE handling, no change marking.
- **Wider copyleft compatibility.** Works with GPL-2.0-only as well as GPL-3.0. If the suite ever wanted to live in a GPLv2 codebase, MIT permits it and Apache does not.

**The honest case for MIT here:** if we hold no patents and never will, the Apache grant costs us nothing and buys adopters reassurance — but it also protects against nothing real, while adding length. If the priority is the lowest possible barrier to someone copying the suite into their firmware on a weekend, MIT is the lower barrier.

## The comparison that actually decides it

| | Apache-2.0 | MIT |
|---|---|---|
| Patent assurance for adopters | **yes** | no |
| Corporate legal friction | low | **lowest** |
| Length / readability | long | **short** |
| GPL-3.0 compatible (one-way) | yes | yes |
| GPL-2.0-only compatible | **no** | yes |
| Standard for protocol reference impls | **yes** | common |

**The question to answer is: who is the adopter we care most about not losing?** A commercial vendor's legal team → Apache-2.0. An individual developer copying files into their own firmware → MIT. Both routes reach Meshtastic upstream, since GPL-3.0 accepts either.

---

## Separating the specification — CC-BY-4.0

The proposal is `LICENSE` (Apache-2.0 or MIT) for code, `LICENSE-SPEC` (CC-BY-4.0) for `suite/EXTENSION_SUITE.md` and `docs/WIRE_REFERENCE.md`.

**Arguments for**

- **A specification is a document, not software.** Code licences are written around "source form", "object form" and compilation, none of which describe a prose document. CC-BY-4.0 is written for documents and says plainly: copy, redistribute, adapt, including commercially, with attribution.
- **It removes an ambiguity that directly threatens the strategy.** Under a code licence, someone could wonder whether an implementation is a "derivative work" of the spec document. That doubt is precisely what stops a cautious implementer. CC-BY makes reuse of the *text* explicit, and implementing from a description has never been the thing copyright restricts.
- **It is what standards work normally looks like**, so it signals "this is a specification you may implement" rather than "this is our code you may copy".

**Arguments against**

- **Two licences is more to explain.** Mixed-licence repos need unambiguous demarcation — a `LICENSE`, a `LICENSE-SPEC`, and a README statement of exactly which files fall under which. Get that wrong and you have created confusion rather than removed it.
- **CC licences are not designed for software.** If any spec file ever contains normative code — reference vectors, a sample codec — the boundary blurs and CC-BY is the wrong instrument for that part.
- **CC-BY-4.0 carries no patent grant.** This is the subtle one and it matters here.

**The gap worth noticing before deciding.** If the patent grant rides only on the *code* licence, then someone who reads the spec and writes their own clean-room implementation — exactly the adopter the strategy is aiming at — receives **no patent assurance at all**. The grant protects people who copy our code, not people who implement our spec. Closing that means either an explicit patent non-assertion pledge in the spec text, or accepting the gap. Worth resolving deliberately rather than discovering later, since it undercuts the main reason for choosing Apache in the first place.

---

## How the recommendation changed on the way to the decision

The recommendation on file was **Apache-2.0 for code, CC-BY-4.0 for the spec,
plus an explicit patent pledge**. The decision kept two of those three and
dropped the split.

What changed was noticing that the CC-BY-4.0 leg *worked against* the reason
for choosing Apache in the first place. The gap identified above — that a
patent grant riding only on the code licence leaves a clean-room implementer
with no assurance — is not a footnote to the split proposal. It is an argument
against it. Closing the gap with a pledge while still splitting the licence
would have been treating the symptom.

Putting the spec under Apache-2.0 closes it structurally, and the pledge then
covers the residue rather than doing the work alone.
