---
name: odf-crypto-readme-spine
description: The README section order odf-crypto shares with msoffice-crypto, the three named slots and why each is empty where it is empty. Use when adding, removing or reordering a README section, when the two crates' READMEs look out of step, or when an asymmetry between them looks like untidiness worth fixing.
---

# README spine — odf-crypto

`odf-crypto` and `msoffice-crypto` are siblings: same method, same author,
different format family. Their READMEs share a section order so that knowing one
file tells you where to look in the other.

Agreed 2026-09-21 between the two repositories. **Neither crate is the authority
over the other** — this file records what was settled, and the same content lives
in msoffice-crypto's own profile. If the two disagree, that is a coordination
failure to resolve by talking, not by one file deferring to the other.

> **Why a duplicated section rather than one shared skill.** A single global
> skill was the other candidate and has the better drift story. It was not
> chosen: each repo staying self-describing was judged worth the second copy.
> **So this file has a known failure mode — it can drift from its twin, and
> nothing detects that.** When you change the spine here, say so to the other
> repo in the same piece of work.

## Semi-unified, not identical

The shared part is shared **because the question is shared**. Where the crates
genuinely differ, the difference is a **named slot**, not a file quietly carrying
an extra heading.

That distinction is the whole design. Three unexplained asymmetries read as
untidiness and invite tidying; three *named* slots, each with its reason
recorded, read as decisions. The reasons below are therefore load-bearing —
**empty-because-measured and empty-because-not-applicable look identical once
the reason is gone.**

## The spine

Eleven headings, same words, same order, both crates.

| # | heading | |
| --- | --- | --- |
| 1 | title + one-line pitch | |
| 2 | badges | five, same order |
| 3 | pitch paragraph + status blockquote | |
| 4 | `## What it does` | ✅/❌/n-a capability grid, `Needs` row |
| | *slot C* | |
| 5 | `## Install` | commented two-line toml + pre-release caveat |
| | *slot A* | |
| 6 | `## Usage` | |
| 7 | `## Command line` | |
| 8 | `## Features` | table with measured crate counts |
| 9 | `## How it's verified` | |
| 10 | `## Security` | |
| 11 | `## MSRV` | |
| 12 | `## Sibling crate` | |
| | *slot B* | |
| 13 | `## Acknowledgements` | |
| 14 | `## License` | |

**Features sits after Usage, and that depends on something.** It is licensed by
the two-line commented `Install` block, which answers the feature question in
place — so Features is no longer urgent and belongs with the other *what does
this cost me* material. **Collapse that block to one line and the ordering
silently becomes wrong.** The dependency is recorded here because it is not
visible from either section alone.

## The three slots

Each is filled by exactly one crate.

| slot | odf-crypto | msoffice-crypto |
| --- | --- | --- |
| **A** — format-detail table, after `Install` | `## Supported algorithms` | **empty** |
| **B** — crate-specific legal, after `Sibling crate` | **empty** | `## Trademarks` |
| **C** — pre-adoption question, after `What it does` | **empty** | `## Why this one` |

**Slot A is empty there because the formats are shaped differently**, not because
that README is less thorough. This crate's cipher, KDF and start-key are three
independent axes and need their own table; MS-OFFCRYPTO's are hash × keyBits
*within* a family, which fits inside a grid cell. Same question, different shape.

**Slot B is empty here because this crate names no vendor's trademarks.**
msoffice-crypto names Microsoft products and carries the exposure.

**Slot C is empty here on measurement, not assumption.** msoffice-crypto competes
with four existing implementations, so *"why not use one of those"* is a real
question a reader arrives with. Searching crates.io for `odf`, `opendocument`,
`odt` and `libreoffice` returned 80 crates, of which **only odf-crypto mentions
encryption at all** — there is no competitor to answer. Re-run that search before
concluding the slot is still empty; it is a fact about the registry on a date,
not a property of the format.

## The four sibling signals

Order alone does not make two files read as related — plenty of unrelated crates
share one. These do the work:

1. **Identical badge row.** Five badges, same order. Above the fold, cheapest
   signal there is.
2. **`## Sibling crate`, reciprocal and in parallel words** — not a bare link.
   Here: *"`msoffice-crypto` does for Microsoft Office what this crate does for
   OpenDocument — same method, same author, different format family."* The other
   file mirrors it.
3. **A parallel pitch cadence**, `… detect it, decrypt it, write it`. **The
   cadence is shared; the opening clause is not.** An earlier draft proposed the
   template `<reference-implementation>-faithful <format>` and it was wrong,
   because the slot has no occupant there: this crate is faithful to the
   *implementation that made the files* — for the profile it writes there is no
   OASIS specification to comply with — while msoffice-crypto is faithful to a
   *specification* that the vendor's own implementation sometimes departs from.
   Flattening those into one template would have made both first lines slightly
   false.
4. **`## How it's verified` over deliberately different apparatus.** Four COM/UNO
   readers there, UNO-driven LibreOffice goldens and a human double-click verdict
   here. Matching the *content* would have been easy and dishonest; a shared
   heading over visibly different evidence says *these two hold themselves to the
   same standard* more credibly than a shared table would.

## Mechanical rules — named, not restated

Each of these is owned by a skill that already states it. **Point at the owner;
do not copy the rule here**, or this file becomes a second copy free to drift.

| rule | owner |
| --- | --- |
| README wired into doctests; examples as `fn main() -> Result<…>` with `no_run`; prove the guard once | `readme-doctests` |
| A README link into a directory `include` does not ship must be **absolute** | `publish-prep` |
| Every concrete version in the README moves at bump time | `changelog-protocol`, and [the repo profile](../odf-crypto-changelog-protocol/SKILL.md) for which four references those are |

Two checks that are not rules but belong beside a structural edit:

- **Scan for untagged fences after reordering, not only at adoption.**
  An untagged fence is a live Rust doctest — reordering is exactly when one gets
  introduced.

  ````bash
  awk '/^```/ { if (!b) { b=1; t=substr($0,4);
         if (t=="") printf "%d: UNTAGGED\n", NR } else { b=0 } }' README.md
  ````

- **Diff relative links against `cargo package --locked --list`, not against the
  `include` allowlist.** Cargo auto-includes `README.md` and `LICENSE-*` without
  their appearing in `include`, so reading the allowlist alone reports shipping
  files as broken.
