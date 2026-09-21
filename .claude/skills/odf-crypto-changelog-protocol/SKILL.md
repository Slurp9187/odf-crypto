---
name: odf-crypto-changelog-protocol
description: odf-crypto's changelog and release facts — version of record, release marker, what a bump touches, and what enforces it. Use when adding a changelog entry, bumping the version, cutting or tagging a release, publishing to crates.io, or when a heading looks out of step with the manifest or the tags.
---

# Changelog protocol — odf-crypto

The protocol, the invariants, the heading format and the tag mechanics live in the
global `changelog-protocol` skill. This file records only what is true of **this**
repository.

> **This file used to be a 268-line fork of the global skill**, sitting at the path
> the adoption pass reserves for a profile. Because a project skill shadows a user
> skill, `/changelog-protocol` resolved to the fork, and the global skill's checker,
> references and adoption pass were never reachable. Replaced 2026-09-20 with the
> answers below; everything it argued is in the global skill already, and one thing
> it argued was a re-derivation the global skill had stated better — see *What did
> not transfer*.

## Version of record

`Cargo.toml` — `[package] version`. Single source; nothing else declares a version.

`Cargo.lock` must move with it, **in the same commit**:
`cargo update --offline -p odf-crypto`. A bump alone leaves the lock naming the old
version and `cargo package --locked` refuses — this repo hit that for real at
`0.1.0` → `0.1.0-rc.1`. `--offline` holds the diff to one line so nothing else moves
underneath.

## Heading format

Global format, `## [0.1.0-rc.5] - 2026-09-20`, with an **ASCII hyphen**.

Legacy deviations, both normalized rather than tolerated:

- `rc.1` and `rc.2` originally used `## v0.1.0-rc.N` with no brackets.
- Every heading used an **em dash** (`—`) until 2026-09-20. The global checker's
  `HEADING` regex takes an ASCII hyphen, so it matched nothing and reported
  *"no version heading found"* as a violation — a false one, on a compliant file.
  Normalized rather than making the checker tolerant of two spellings, for the same
  reason the bracket normalization happened: a check that must accept two spellings
  is one nobody can run mechanically.

Prose inside entries still uses em dashes. Only the headings are constrained.

## Release marker

Annotated tag `v<version>`. No non-release tags exist in this repo.

## Registry

crates.io, package `odf-crypto`. Existence query:

```bash
curl -s https://crates.io/api/v1/crates/odf-crypto/versions \
  | python -c "import sys,json;print(' '.join(v['num'] for v in json.load(sys.stdin)['versions']))"
```

Published through `0.1.0-rc.4`. `rc.5` is cut but unpublished, which is the expected
transient state the global skill describes, not a violation.

## What a bump touches

One commit, first change after a tagged state:

- `Cargo.toml` — `version`
- `Cargo.lock` — via `cargo update --offline -p odf-crypto`
- `README.md` — **four** references: the pre-release note, both install snippets, and
  the feature table near the bottom. The last is the one that gets missed.
- `CHANGELOG.md` — the new `## [x] - Unreleased` heading

The README moves at **open**, not at cut. Accepted cost: GitHub then advertises a
version not yet on crates.io, so its install snippet is wrong for anyone copying it
that day. The alternative leaves `Cargo.toml` and `README.md` disagreeing about what
the tree is, which is worse and harder to notice — a reader can tell an unreleased
version from `- Unreleased` and a missing tag, but cannot tell which of two
disagreeing files to believe.

Crate counts in `README.md` and `CLAUDE.md` are **re-measured at cut**, never carried
forward: `61 crates` once shipped as `62` in three places.

```bash
cargo tree --locked -e no-dev --prefix none [--features crypto-ops] \
  | grep -v '(\*)' | sort -u | wc -l
```

## Enforcement

**Deliberately none automated.** Run the global skill's checker by hand when cutting:

```bash
python ~/.claude/skills/changelog-protocol/scripts/check_changelog.py
```

Measured 2026-09-20 against the normalized headings: passes, reporting
`[0.1.0-rc.5] - Unreleased` ok with `v0.1.0-rc.5` absent.

Reconsider adding a CI job if a release is ever cut without the check being run. Note
the checker needs tags: in CI that means `fetch-depth: 0` or `fetch-tags: true`, or
every dated section looks untagged — it refuses to judge rather than reporting false
violations, which is how this was confirmed.

## Exempt history

Everything below the first version heading is a dated development record from before
the crate was published — entries keyed by date, newest first, the opposite of what
the protocol says. `CHANGELOG.md`'s own header says so. Those dates are where the
reasoning for a behaviour lives; a release heading summarising them would lose it.

**This needs no engineering.** The checker inspects only the newest section, so it
never reaches the record. Recorded as context, not as an exemption anyone must
implement.

## What did not transfer

- **The old local file's "The pre-publication record is exempt" section**, which
  argued the dated record must be protected from the checks. It was re-deriving the
  global skill's *scope every check to the newest section*, and arriving at a weaker
  version of it — a rule about one repo's history instead of a rule about every
  repo's. Kept above as a fact, dropped as a rule.
- **The local restatement of the two invariants, the registry axis, the release flow
  and the tag mechanics.** All present in the global skill, most of them in more
  detail, and the registry axis there covers the publish-existence question this repo
  raised.
- **`msoffice-crypto`'s heading style and its CI enforcement.** Style differs; its
  enforcement is real and this repo's is not, and claiming otherwise would be a false
  claim in a repo whose first rule is that a claim carries its proof.
