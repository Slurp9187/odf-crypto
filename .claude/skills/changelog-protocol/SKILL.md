---
name: changelog-protocol
description: Keep CHANGELOG.md's release claims checkable, and run the two-commit release flow. Use when adding a changelog entry, opening or cutting a release line, bumping the version in Cargo.toml, tagging, or when a version heading looks out of step with the manifest or the tags.
---

# Changelog protocol

A changelog is a set of claims about what shipped and when. The failure mode is
silent: `## [0.1.0-rc.9] — 2026-09-20` for a version never tagged looks released
forever and nothing complains.

Adapted from `msoffice-crypto`'s skill of the same name. The two invariants and
the tag-pushing trap are theirs and transfer intact. The release flow, the
evidence-dating section and the enforcement status below are this repository's,
and they differ — see *What did not transfer*.

## The two invariants

**1. The top version heading matches `Cargo.toml`'s `version`.** Exact string,
`-rc.N` included.

**2. A heading carries a date if and only if that tag exists.**

```
## [0.1.0-rc.5] — Unreleased      while the work is in flight
## [0.1.0-rc.5] — 2026-09-20      the moment v0.1.0-rc.5 is tagged
```

The date is the release marker. It is not decoration and it is not the date the
work happened.

Check both at once — this is a manual check today, see *Enforcement*:

```bash
grep -nE "^## \[0\.1\.0" CHANGELOG.md | while IFS=: read -r ln rest; do
  ver=$(echo "$rest" | grep -oE "0\.1\.0-rc\.[0-9]+")
  dated=$(echo "$rest" | grep -qE "— [0-9]{4}-" && echo dated || echo undated)
  tag=$(git tag -l "v$ver")
  [ "$dated" = dated ] && [ -z "$tag" ] && echo "DATED BUT UNTAGGED: $ver"
  [ "$dated" = undated ] && [ -n "$tag" ] && echo "TAGGED BUT UNDATED: $ver"
done
[ "$(grep -m1 -oE '0\.1\.0-rc\.[0-9]+' CHANGELOG.md)" = \
  "$(grep -m1 -oE '0\.1\.0-rc\.[0-9]+' Cargo.toml)" ] || echo "TOP HEADING != Cargo.toml"
```

## The third axis: the registry

The two invariants above are about the *tree*. A dated, tagged heading can still
describe a release nobody can install, because `cargo publish` is a separate
step from tagging.

**3. A dated heading should have a matching version on crates.io — eventually.**

Unlike the first two, this is **not** a violation on sight. There is a
legitimate window between cutting a line and publishing it, and `0.1.0-rc.4`
sat in it for hours: dated, tagged, CI green, waiting on a human's explicit
go-ahead. The state is expected and transient.

It becomes a defect when it *persists*. Then the changelog announces a release
that does not exist, which is the same silent failure as invariant 2 wearing a
different hat — it looks shipped forever and nothing complains.

**Scope it to the newest line.** A publish missed long ago is a historical fact,
not a defect to fix: republishing means shipping a stale tree, and un-releasing
means rewriting a record for no one's benefit. Let it go, and if it matters,
say so once in that section rather than leaving a check red forever. This is the
same rule the *Enforcement* section states for the other two — a check that
fails on something nobody can act on is a check somebody disables, and then it
catches nothing.

For the newest line, where action is still possible: **resolving it is the
maintainer's call, not an agent's.** There are exactly two ways out and an agent
may take neither on its own initiative:

- **Publish it**, making the claim true. `cargo publish` is irreversible and
  outward-facing; it needs an explicit go-ahead every time, and approval for one
  release is not approval for the next.
- **Un-release it**, putting `— Unreleased` back and removing the tag, making the
  claim withdrawn rather than false.

Both change what the world is told. An agent detects the state, reports it with
the evidence, and stops — the same way it stops before publishing. Do not
"tidy" a dated heading back to `— Unreleased` because a check went red; that is
silently withdrawing a release announcement, and whether the release is late or
abandoned is not something a checker can tell.

**The inverse is worse and always wrong:** a version on crates.io with no dated
heading means something shipped that the changelog does not describe. A consumer
reading the changelog to decide whether to upgrade is then reading about a
different release than the one they would get.

**Compare existence, never dates.** The obvious extension — "and the heading's
date matches when it was published" — is wrong and will fire on roughly a third
of evening releases. Registry timestamps are UTC; heading dates are stamped
locally. `msoffice-crypto`'s `rc.2` heading reads `2026-09-15` while its
`created_at` is `2026-09-16T03:04:16Z`, which is the same moment on a UTC-7
machine. There is no discrepancy and no way for a checker to know that, because
the changelog does not record a timezone. Ask whether a matching version
*exists*; that is answerable.

This check needs the network, where the other two are offline — so it is a
different class and cannot join the snippet above or an offline CI job:

```bash
PUB=$(curl -s https://crates.io/api/v1/crates/odf-crypto/versions \
      | python -c "import sys,json;print(' '.join(v['num'] for v in json.load(sys.stdin)['versions']))")
grep -oE "^## \[0\.1\.0-rc\.[0-9]+\] — [^ ]+" CHANGELOG.md | while read -r _ ver _ date; do
  v=${ver//[\[\]]/}
  case "$date:$(echo "$PUB" | grep -qw "$v" && echo pub || echo nopub)" in
    [0-9]*:nopub) echo "DATED BUT UNPUBLISHED (fine if just cut): $v" ;;
    Unreleased:pub) echo "PUBLISHED BUT UNDATED: $v" ;;
  esac
done
for v in $PUB; do grep -q "^## \[$v\]" CHANGELOG.md || echo "PUBLISHED, NO HEADING AT ALL: $v"; done
```

**Heading style is `## [0.1.0-rc.N] — …`**, brackets included. `rc.1` and `rc.2`
originally used `## v0.1.0-rc.N` and were normalised so the check above can be
mechanical rather than tolerant of two spellings.

**No standing `## [Unreleased]` heading.** The versioned-but-undated section *is*
the unreleased one. Both at once leaves a reader unable to tell which section
describes the code they hold.

## The release flow

Two commits, and the split is deliberate: a version is in development long
before it is released, and the tree should say which it is.

**Open the line** when the first commit lands **past the release tag** — not
when the previous version publishes. While `HEAD` *is* the tag its version
string is accurate and is left alone; bumping at publish time invents a version
whose only content is its own number, and makes `— Unreleased` mean "nothing has
happened yet" rather than "here is what has happened so far". **The trigger is a
commit, not a release.**

1. `version` in `Cargo.toml` → the next `rc`.
2. `cargo update --offline -p odf-crypto`, **in the same commit**. A bump alone
   leaves the lock naming the old version and `cargo package --locked` refuses.
   `--offline` holds the diff to one line so nothing else moves underneath.
3. `README.md`'s version references — **all** of them, including the feature
   table near the bottom.
4. `CHANGELOG.md`: a `## [0.1.0-rc.N] — Unreleased` heading.

**Cut it** when the release is ready: replace `— Unreleased` with the ISO date,
re-measure the crate counts rather than carrying them forward, verify every
configuration CI runs **including both doc builds**, commit, then tag *that*
commit. Publishing is a separate, explicit decision.

**Why the README moves at open**, since it is the one step with a real cost: the
README on GitHub then advertises a version not yet on crates.io, so its install
snippet is wrong for anyone copying it that day. Accepted deliberately. The
alternative leaves `Cargo.toml` and `README.md` disagreeing about what the tree
is, which is worse and harder to notice — a reader can tell an unreleased
version from `— Unreleased` and a missing tag, but cannot tell which of two
disagreeing files to believe.

## Dates inside entries: bookkeeping versus evidence

**Do not date an entry as bookkeeping.** Git records when a change landed,
precisely. A typed date is a lossy copy that can drift, costs a decision per
entry, and answers a question no reader asks.

**Do bound an observation whose staleness matters.** The test: *does the reader
need to know how stale this measurement is?*

```markdown
<!-- KEEP — names what the measurement was taken against -->
opened by LibreOffice 26.2.1.2 with the correct text recovered
across the four versions in the registry cache — 1.1.4, 2.4.2, 6.0.0, 8.6.0

<!-- DROP — git already knows -->
- Renamed the error type (2026-09-20).
```

**This matters less here than in the sibling, and the reason is structural.**
Every measurement in this changelog sits inside a version section that gets an
ISO date when the line is cut, so the section already bounds it. The sibling
keeps a standing Evidence section outside any version heading, where nothing
else supplies the bound. What still applies here is naming the **external
version** a measurement was taken against — `LibreOffice 26.2.1.2`,
`zip-8.6.0`, `argon2-0.5` — because that is a sharper staleness bound than a
date, and it is what a reader re-running the check actually needs.

## Tags

Annotated, always:

```sh
git tag -a v0.1.0-rc.5 -m "0.1.0-rc.5"
git push origin main
git push origin v0.1.0-rc.5
```

**Moving a tag is by name and forced**, and only before it is published:

```sh
git tag -f -a v0.1.0-rc.5 <commit> -m "…"
git push --force origin v0.1.0-rc.5
```

**The trap, inherited intact from the sibling because it bites identically
here:** `git push --follow-tags` pushes only tags **missing** on the remote. It
will not move one that already exists, and reports `Everything up-to-date` while
the remote keeps the old commit. A no-op reported as success is the worst shape
a failure takes. This session moved the `v0.1.0-rc.4` tag six times before
publishing; every one used the explicit forced form above.

Do not use `git push --tags` without auditing what would go:

```bash
comm -23 <(git tag -l | sort) \
         <(git ls-remote --tags origin | grep -v '\^{}' | sed 's|.*refs/tags/||' | sort)
```

**After publishing, a tag never moves.** The `.crate` is immutable and the tag
is what ties it to a tree.

## The pre-publication record is exempt

Everything below the first version heading is the dated development record from
before the crate was published — entries keyed by date, newest first, which is
the opposite of what this protocol says. `CHANGELOG.md`'s own header says so.

That record is **not** a violation to be tidied. Those dates are where the
reasoning for a behaviour lives, and a release heading summarising them would
lose it. This protocol governs what is written from here on.

## Enforcement

**None automated.** The check above is a shell snippet a human runs; there is no
CI job and no audit tool, unlike the sibling's `tools/audit_claims.py` and its
`prose` job.

Saying so is the point. This repository's rule is that a claim carries its proof,
and "the changelog is checked" would be a claim with no proof behind it. Both
invariants held when this skill was written — verified by running the snippet,
not by assuming — and keeping them true is currently a human's job.

Automating it is worth doing and is not done. If you automate it, check **only
the newest section**: historical sections are frozen, and a check that fails on
something nobody can act on gets disabled.

## What did not transfer

Recorded because inheriting a sibling's method without re-deriving it is the
defect that produced the sibling's own read-path bug.

- **Their heading style** (`## v0.1.0 — unreleased`, no brackets). This repo had
  brackets in three of five headings already; normalising to the majority was
  cheaper than churning them all.
- **Their enforcement.** They have a checker and a CI job. Claiming the same here
  would be a false claim in the file that forbids them.
- **Their evidence-dating emphasis**, weakened for the structural reason above:
  our measurements already sit under a dated version heading.
