Status: **Shipped (2026-09-15)** — `secure-gate` 0.9.0-rc.7 → 0.9.0-rc.12 (planned as rc.11; see §11); `dynamic_newtype!` adoption is a later arc · Authored 2026-09-15 against `296fa85` · Landed on `claude/secure-gate-rc11`: `7f47cd9` (upgrade and pin), `a92ee54` (crate counts), `a0b48f7` (skill rewrite), `d3db786` (changelog and plan), `2efa775` (rc.12), `6533809` (inflate into slot)

# Upgrade `secure-gate` to 0.9.0-rc.11

## 1. Context

`src/sensitive.rs` declares this crate's four wrappers with `dynamic_alias!`.
**That macro no longer exists.** Upstream deleted `fixed_alias!`,
`dynamic_alias!`, `fixed_generic_alias!` and `dynamic_generic_alias!` in
0.9.0-rc.9, on the grounds that a macro exported by a crate whose pitch is
"accidents must not compile" reads as a guarantee, and these guaranteed only a
name. The file will not compile against anything past rc.8.

The upgrade is not optional in the way it looks, because of how the requirement
is written today:

```toml
secure-gate = { version = "0.9.0-rc.7", ... }
```

A caret requirement over a pre-release matches **later pre-releases of the same
version**. `"0.9.0-rc.7"` already resolves to rc.11. A bare `cargo update` —
not a manifest edit, not a review — drops four deleted macros on this crate with
no warning. The lockfile is the only thing currently holding rc.7 in place. So
this arc does two things: it moves deliberately to rc.11, and it replaces the
requirement with `=0.9.0-rc.11` so the next move is an edit somebody reads.

Nineteen breaking changes separate rc.7 from rc.11. **One reaches this crate.**
That claim is the substance of §2, and it is what makes this a small arc rather
than a large one.

Evidence for everything below: rc.7's and rc.11's extracted registry sources
under `~/.cargo/registry/src/index.crates.io-*/`, the upstream `CHANGELOG.md`
carried inside rc.11's own tarball, and `cargo tree` runs against this
repository at `296fa85`. Nothing here is reconstructed from a summary.

## 2. What actually reaches this crate

| Upstream change | Version | Reaches us? |
|---|---|---|
| `*_alias!` macros deleted | rc.9 | **Yes** — 4 invocations, `src/sensitive.rs` |
| `zeroize_derive` → `[dev-dependencies]` | rc.9 | **Yes** — dependency graph shrinks |
| `SecretLen` split out of `RevealSecret` | rc.8 | No — see below |
| `into_inner()` returns `T`, not `InnerSecret<T>` | rc.9 | No — see below |
| `Fixed::new_with` inference (E0282) | rc.10 | No — this crate has no `Fixed` |
| `Fixed::new` requires `FixedStorage` | rc.9 | No — no `Fixed` |
| Encoders return `EncodedSecret`; `_zeroizing` gone | rc.9 | No — no `encoding` feature |
| bech32 `Case`, `Bech32Large`, `encoding-bech32m` | rc.9 | No — no `encoding` feature |
| `DecodingError`, `SecureEncoding`/`SecureDecoding` | rc.9 | No — never imported |
| `Display`/`AsRef` on `EncodedSecret` | rc.8/9 | No — type never used |
| `fixed_newtype!` / `dynamic_newtype!` changes | rc.8–11 | No — newtypes unused |
| base32ct floor (security) | rc.10 | No — `encoding-base32` off |

The two "No"s worth justifying, because they are the ones that could be wrong:

**`SecretLen`.** `len()`/`byte_len()`/`is_empty()` moved to a new trait, and the
upstream migration note says call sites add one import. This crate calls `.len()`
on a wrapper **nowhere**. The two hits that look like it — `src/decrypt.rs:360`
and `:404` — are `key.len()` where `key: &[u8]` is a function parameter the
caller already revealed through `with_secret`. That is the slice's own inherent
method and is unaffected by any trait move.

**`into_inner()`.** This is the dangerous one upstream, because it still compiles
and silently stops zeroizing — `InnerSecret<T>` used to keep wiping, and now
there is no such type. Six `into_inner` call sites exist here
(`decrypt.rs:561`, `:615`, `encrypt.rs:493`, `:535`, `test_support.rs:105`,
`:132`) and **all six are `ZipWriter`/`Cursor::into_inner`**, verified in
context. Zero secure-gate wrappers. For a crate whose claim is that key material
zeroizes, this is worth stating explicitly rather than leaving as an absence.

## 3. The migration

`src/sensitive.rs` is the only source file that changes. The macro expanded to
exactly one `type` line plus a doc attribute — rc.7's own definition:

```rust
($vis:vis $name:ident, $inner:ty, $doc:literal) => {
    #[doc = $doc]
    $vis type $name = $crate::Dynamic<$inner>;
};
```

So the replacement is mechanically exact and **no call site moves**. All 10
`with_secret`, 5 `with_secret_mut` and 1 `new_with` sites are untouched, as are
both `use secure_gate::{RevealSecret, RevealSecretMut};` imports.

Line 20 changes from importing the macro to importing the type:

```rust
-use secure_gate::dynamic_alias;
+use secure_gate::Dynamic;
```

and each of the four invocations becomes a documented alias — the doc string
moves from the macro's third argument to an ordinary `///` comment above the
`type`, preserving the prose verbatim:

```rust
-dynamic_alias!(
-    pub(crate) PasswordDigest,
-    Vec<u8>,
-    "SHA-1 or SHA-256 digest of the user's password (`start_key`'s output), \
-     before KDF stretching. Length depends on the digest algorithm (20 or 32 \
-     bytes), so this wraps `Vec<u8>`, not a fixed-size array."
-);
+/// SHA-1 or SHA-256 digest of the user's password (`start_key`'s output),
+/// before KDF stretching. Length depends on the digest algorithm (20 or 32
+/// bytes), so this wraps `Vec<u8>`, not a fixed-size array.
+pub(crate) type PasswordDigest = Dynamic<Vec<u8>>;
```

Same shape for `DerivedKey`, `DeflatedPlaintext` and `MemberPlaintext`.

**Write these by hand, not with the upstream `sed` script.** The script exists
for a tree with many aliases; there are four here, all using the doc-string
form, and the `dynamic_alias!` doc-string pattern is the one that eats the doc
into the type position and yields `Dynamic<Vec<u8>, "doc">` if run out of order.
Four hand edits carry none of that risk.

`sensitive` is declared `#[cfg(feature = "crypto-ops")] mod sensitive;`
(`src/lib.rs:76-77`), so the new `use secure_gate::Dynamic;` is compiled only
under `crypto-ops` and needs no `cfg` of its own. This is the one place the
msoffice-crypto session hit an unused-import clippy failure; it does not
reproduce here because the module, not the alias, carries the gate. Verify it
anyway — that is what the detect-only clippy job is for.

**Do not take this opportunity to move to `dynamic_newtype!`.** It is the
upstream-recommended spelling and it would make the four wrappers distinct types
rather than four names for `Dynamic<Vec<u8>>`. It is also a different change
with its own design argument — `DerivedKey` and `PasswordDigest` becoming
non-interchangeable would be a real improvement, and `rc.11` is still actively
churning that macro surface. Keep this arc to the mechanical move; §7 records
the newtype question as deliberately deferred, not overlooked.

## 4. The dependency graph, measured

rc.11's manifest carries `zeroize = { version = "1.8", default-features = false }`
as its only non-optional dependency, with `zeroize_derive` deliberately moved to
`[dev-dependencies]`. rc.7 enabled the derive feature, and in the **default,
detection-only** build `secure-gate` is the sole reverse dependency of `zeroize`:

```
zeroize_derive v1.5.0 → zeroize v1.9.0 → secure-gate v0.9.0-rc.7 → odf-crypto
syn v2.0.119          → zeroize_derive v1.5.0   (its only reverse dependency)
```

So **two** crates leave, not one: `zeroize_derive` and the duplicate `syn v2`
that only it pulled. `thiserror-impl` keeps `syn v3.0.4`, so `syn`/`quote`/
`proc-macro2`/`unicode-ident` remain present — this is a change in *count*, not
in presence, and reasoning from presence is exactly how the wrong number gets
shipped.

Measured at `296fa85`, before the upgrade: **27** default, **61** `crypto-ops`,
74 `cli`. Predicted after: **25** and **59**. The 34-crate delta between the two
configurations is arithmetically unchanged (59 − 25 = 34), so that claim in
`Cargo.toml` should survive — but re-run it rather than reasoning it.

> **Outcome.** Measured after the upgrade: **25** default, **59** `crypto-ops`,
> **72** `cli`. The prediction held, and the 34-crate delta survived as
> expected. The one loose end in this section resolved benignly: `syn 2.0.119`
> does remain in `Cargo.lock`, but for `derive_arbitrary` — a dev-only path that
> `-e no-dev` excludes — so it was never the reason the *tree* carried two, and
> the orphan question was a false alarm. `base32ct 0.3.1` entered the lock as
> predicted and is absent from all three resolved trees, above rc.10's floor.

`thiserror` also leaves *secure-gate's* dependency list in rc.9. It does **not**
leave ours: `thiserror = "2"` is a direct dependency of this crate for its own
error types. Do not count it as a saving.

Nothing is committed until this has actually been run, per CLAUDE.md:

```bash
cargo tree --locked -e no-dev --prefix none                        | grep -v '(\*)' | sort -u | wc -l
cargo tree --locked -e no-dev --prefix none --features crypto-ops  | grep -v '(\*)' | sort -u | wc -l
cargo tree --locked -e no-dev --prefix none --features cli         | grep -v '(\*)' | sort -u | wc -l
```

**The trapdoor is demonstrated, not theorised.** `cargo update --dry-run -p
secure-gate` against the current manifest at `296fa85`:

```
Locking 2 packages to latest compatible versions
  Adding base32ct v0.3.1
  Updating secure-gate v0.9.0-rc.7 -> v0.9.0-rc.11
  Removing zeroize_derive v1.5.0
```

The existing `"0.9.0-rc.7"` resolves to **rc.11 today**. One `cargo update`, no
manifest edit, no review, and `src/sensitive.rs` stops compiling. This is the
concrete justification for the `=` pin in §5, and it is why the pin belongs in
the same commit as the migration rather than a follow-up.

**`base32ct` is a new lockfile entry, and it needs checking rather than
assuming.** rc.11 added `encoding-base32`, whose optional dependency is
`base32ct`. `Cargo.lock` records optional dependencies whether or not a feature
activates them, so the lock gains a package this crate does not build —
`default-features = false, features = ["alloc"]` leaves `encoding-base32` off.
`cargo tree` is feature-resolved and should therefore not show it, leaving the
counts at 25 / 59. **Verify that rather than trusting it**, because the crate
count is a published claim and the lockfile and the tree disagreeing is exactly
the kind of gap that ships a wrong number:

```bash
cargo tree --locked -e no-dev --prefix none --features cli | grep -c base32ct   # expect 0
grep -c 'name = "base32ct"' Cargo.lock                                         # expect 1
```

Note also that the dry run reported removing `zeroize_derive` but said nothing
about `syn v2.0.119`, while `cargo tree -i syn@2.0.119` shows `zeroize_derive`
as its only reverse dependency. Either the summary is abbreviated or the orphan
is not pruned. **This is the single number most likely to be wrong** — it is the
difference between 25 and 26 — so the count comes from the command, never from
this paragraph.

## 5. Files to change

**Manifest and lock**

- `Cargo.toml:133-135` — `version = "=0.9.0-rc.11"`, with a comment saying why
  this one dependency is pinned when every other is a caret range. Feature set is
  unchanged: `default-features = false, features = ["alloc"]` still names real
  features in rc.11, and `rand` / `ct-eq` / `encoding` still exist, so the skill's
  "no rand, ct-eq, or encoding" phrasing stays accurate.
- `Cargo.toml:3` — `version = "0.1.0-rc.3"`. Required by §6.
- `Cargo.lock` — regenerated and committed. Every CI job passes `--locked`, so a
  stale lock is a hard failure, not a warning.

**Measured claims (only after §4 has been run)**

- `README.md:214-215` — the 27 / 61 figures.
- `CLAUDE.md:52-53` — the same two figures in the feature table.
- `Cargo.toml:74-76`, `:91-92`, `:174-175` — 27, the derived 34, and 27 again.

Leave `CLAUDE.md:102-105` alone. Its "61 crates shipped as 62" is a deliberate
record of a past error, not a live claim.

**`.claude/skills/odf-crypto-secure-gate/SKILL.md` — full rewrite against rc.11**

This file declares itself the sole authority on the topic and says that where it
and `CLAUDE.md` disagree, it wins. It is therefore the file where a stale claim
does the most damage, and several of its claims are now false or unverified:

- L22-23 — the version string and feature list.
- L231-234 — instructs the next contributor to reach for `fixed_alias!` or
  `dynamic_alias!`. Both are deleted. `fixed_alias!` has **zero call sites**, so
  nothing compile-fails; this sentence is the whole of its existence and would
  silently mislead. Replace with the `type` spellings, and record the
  `dynamic_newtype!` option deferred in §3 so the choice is visible.
- L207-212 — quotes secure-gate's own docs verbatim on `Dynamic::new_with`
  ("for consistent API idiom, not for stack-residue avoidance"). Re-verify
  against rc.11's rustdoc; a quotation that has drifted is worse than none.
- L12-20, L97-103 — the zeroize-subsumption claim. Still true in rc.11
  (`zeroize` remains secure-gate's one non-optional dependency) but re-verify,
  because `Cargo.toml:155-160` leans on it to justify `aes-gcm`'s `zeroize`
  feature costing no crate.
- L120-174 — the hand-maintained ```rust pattern block. Nothing compiles it, so
  nothing has ever verified it. Check it against the post-migration source.
- L57-72 — the "What is wrapped" table. Its `file:line` citations have **drifted
  a third time** (`decrypt.rs:200` → `:281`, `:244` → `:327`, `:252` → `:340`,
  `:290` → `:378`, `:476` → `:564`, and nine more). `CHANGELOG.md:203-205`
  records this being fixed once already.

The line-number drift is pre-existing and not caused by this upgrade. It is in
scope because the user asked for the full rewrite, and because a table that is
wrong in most of its rows is worse than no table — if it drifts a fourth time,
consider naming functions rather than lines.

**Do not convert the `new(...)` sites to `new_with(...)` during the rewrite.**
The skill's "Construction" section (L196-212) already gets this right. The
msoffice-crypto session had broader `new_with` adoption as an *approved* plan
item, checked every candidate against the discriminator, and cancelled the item
outright — converting nothing. The discriminator is whether the producer *writes
into a caller-provided buffer* or *returns an owned value*. An owned return means
`new` is already a move, and `new_with` would wrap a closure around a copy from a
source that stays unprotected — strictly worse. Here
`out.map(DeflatedPlaintext::new)` and `MemberPlaintext::new(inflated)` take owned
`Vec`s and are correct as they stand; `PasswordDigest::new_with` is correct
*because* `finalize_into` writes into the buffer it is handed. Leave the
distinction as written and keep the reasoning visible.

**The related check that is not about churn.** `Dynamic::new_with` hands the
closure an **empty** buffer, so a closure that *grows* rather than *fills* can
reallocate — and `Vec`'s realloc frees the old block **unwiped**, leaving a copy
of the secret outside the wrapper while the wrapper reports doing its job. This
has no symptom and no test will catch it. It was msoffice-crypto's one genuine
defect this arc, and it was not caused by the upgrade: a key built with
`extend_from_slice` + `resize` inside `new_with`.

This crate's single `new_with` is the safe shape — `kdf.rs:42-45` does
`v.resize(N, 0)` on a fresh empty buffer (one allocation, nothing to copy
forward) and then `finalize_into` writes in place, so the length is fixed before
the write. Confirm that during S3 rather than assuming it, and if a future
`new_with` ever grows, `reserve_exact` first.

**`docs/plans/secure-gate-rc11-2026-09-15.md`** — this document, landed in the
repo as the design record.

## 6. Changelog and version identity

There is no `[Unreleased]` section in `CHANGELOG.md`, and `0.1.0-rc.2` **is
published** — verified against crates.io, created 2026-09-04. CLAUDE.md is
explicit that a published version is immutable and a tag moves freely only
before publishing, so this cannot land in rc.2. Note that `main` is already
three commits past the `v0.1.0-rc.2` tag, so the line needs opening regardless.

Adopting the peer repository's changelog protocol, which the same person
maintains: the versioned-but-undated section *is* the unreleased one, and a
standing bare `[Unreleased]` is what that protocol exists to avoid. Its release
flow opens the line by bumping the manifest and adding the heading **in the same
commit**, so the top heading always matches `Cargo.toml`.

So this arc adds, at the top of `CHANGELOG.md`:

```markdown
## [0.1.0-rc.3] — Unreleased
```

and bumps `Cargo.toml` to match. At release time the **same heading is rewritten
in place** — `— Unreleased` becomes the ISO date, commit, then tag that commit.
A second heading is never added.

The two invariants that carry the value, independent of punctuation:

1. The top heading's version matches `Cargo.toml` exactly, `-rc.N` included.
2. A heading carries a date **if and only if that tag exists**.

Two judgement calls, flagged rather than buried:

- **Heading style.** Every existing heading here is `## v0.1.0-rc.2 — 2026-09-04`
  — `v` prefix, em-dash. The bracket form above is what you asked for; it is the
  file's first, and it is Keep-a-Changelog's spelling rather than this file's.
  The peer's protocol notes that the spelling is coupled to whatever enforces it
  — theirs compares the heading against `"v" + version` in a checker. odf-crypto
  has no such check today, so either parses; but if one is ever written it will
  be written against the file's majority shape. On that reasoning I would use
  `## v0.1.0-rc.3 — Unreleased`. Your call — the invariants above hold either way,
  and they are the part that matters.
- **`README.md:214`'s `odf-crypto = "0.1.0-rc.2"` install snippet stays at rc.2
  until publish.** The peer protocol moves install snippets at bump time, but it
  also records a defect where pointing a versioned URL at an unpublished version
  produced a 404, and fixes it by moving such references at *publish* time. A
  reader copying `= "0.1.0-rc.3"` before publication gets an unresolvable
  dependency, which is the same failure. The crate-count figures in that table
  *do* change now — they describe the code, not the release.

**What the entry is actually about.** A dependency bump with nothing
consumer-observable earns no entry — "bumped secure-gate rc.7 to rc.11" is
bookkeeping and git already has it. This one earns an entry because the
**crate count is consumer-observable and pinned in the README**: 27 and 61
become 25 and 59, facts a reader can check and would otherwise find wrong. So
the entry leads with the count, in the file's house style — prose-first, bolded
lead, the change written as a behavioural consequence with a measured number.

**Do not date the entry.** The date rule is whether a reader needs it to judge
how stale an *observation* is. A crate count is deterministic from the lockfile,
so the lockfile pins it and git dates it.

The three commits already sitting unreleased on `main` have no entries;
completing rc.3's section is the release commit's job, not this one's.

**At tag time:** `git push --follow-tags` only pushes tags *missing* on the
remote. It will not move one that already exists — it reports
`Everything up-to-date` while the remote keeps the old commit. Move a tag by
name with `git push -f origin <tag>`.

## 7. Slices

No GitHub issues: the PR is the paperwork for this arc, per your call. The
slices below are execution order, not filed work.

| Slice | Work | Done when |
|---|---|---|
| **S1** | Pin `=0.9.0-rc.11`; migrate the four aliases in `src/sensitive.rs`; regenerate `Cargo.lock` | All five CI configurations green at the recorded baseline (107 lib + 9 doctests) |
| **S2** | Re-measure all three crate counts; update `README.md`, `CLAUDE.md`, `Cargo.toml` comments | Each figure in the repo is one the command in §4 actually printed |
| **S3** | Rewrite `.claude/skills/odf-crypto-secure-gate/SKILL.md` against rc.11 | No false claim survives; every `file:line` re-verified; the deferred `dynamic_newtype!` decision recorded |
| **S4** | Bump to `0.1.0-rc.3`; open the changelog line; land the plan file | Top heading matches the manifest; `v0.1.0-rc.3` tag absent and the date slot reads `Unreleased` |

S2 blocks on S1 — the counts cannot be measured until the lock resolves rc.11.
S3 blocks on S1 for the `file:line` pass. S4 is last so the changelog entry can
quote the numbers S2 measured.

**Step 0, before editing anything:** capture the feature-resolved baseline. It
cannot be reconstructed afterwards, and it is the only evidence the dependency
claim in §4 is true.

```bash
cargo tree --locked -e no-dev --prefix none -f '{p} {f}' > before-default.txt
cargo tree --locked -e no-dev --prefix none -f '{p} {f}' --features crypto-ops > before-crypto.txt
grep -rn "into_inner" src/          # know the shape of the migration before starting it
```

The `into_inner` grep goes first deliberately: it is the **only** break in the
nineteen that compiles silently, it takes five seconds, and doing it first means
the migration's shape is known rather than discovered. (Already run here — six
hits, all `ZipWriter`/`Cursor`.)

One commit per slice, verified between, so bisect boundaries stay clean. The pin
and the four alias lines belong in the **same** commit: they are one change, and
splitting them leaves a commit where the manifest and the source disagree.

## 8. Verification

Baseline recorded at `296fa85` before any change: **107 library + 9 doctests**
green under `--no-default-features --features crypto-ops`; `tests/cli.rs`
reports 0 because it is `#![cfg(feature = "cli")]` throughout.

The full CI surface, which must pass in every configuration:

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo clippy --locked --all-targets --no-default-features --features crypto-ops -- -D warnings
cargo test   --locked --no-default-features
cargo test   --locked --no-default-features --features crypto-ops
cargo doc    --locked --all-features --no-deps          # RUSTDOCFLAGS='-D warnings'
cargo doc    --locked --all-features --no-deps          # nightly, RUSTDOCFLAGS='--cfg docsrs -D warnings'
cargo package --locked --features crypto-ops
```

Two jobs deserve attention beyond "it passed":

- **MSRV.** `cargo build --locked --no-default-features --features crypto-ops`
  on a pinned 1.85.0. rc.11 declares `rust-version = "1.85"` and
  **`edition = "2024"`**, which requires exactly 1.85 — zero margin. This is the
  job a dependency bump is most likely to break, and the one that cannot be
  checked by reading.
- **`docsrs`.** Nightly with `--cfg docsrs`. rc.1 shipped broken documentation
  because only that configuration fails and nothing built it.

Also confirm, specifically:

```bash
cargo tree --locked -e no-dev --prefix none | grep -E '^(syn|zeroize)'   # zeroize_derive and syn v2 gone
grep -rn "into_inner" src/                                              # still six, still all Zip/Cursor
```

Round-trip behaviour is covered by the existing suite; `encrypt`'s salt and IV
are fresh per call, so nothing here asserts on its output bytes.

**The test counts must be identical, not merely green — 107 + 9, 0 ignored.**
This is the real acceptance criterion. The goldens are real LibreOffice and
Apache OpenOffice output and the decrypt paths run every KDF and cipher arm over
them, so an identical pass at an identical count is evidence that no key
schedule moved underneath the upgrade. A count that *changes* is a finding, even
if everything still passes. msoffice-crypto held all five of its configurations
at the identical pre-upgrade baseline across this same move, which is the
outcome to expect.

The `ct_eq` property greps that session recommends do not apply here: this crate
does not enable `ct-eq` and has no constant-time comparison surface.

## 9. Out of scope

- **`dynamic_newtype!` adoption.** Deferred deliberately, per §3 — a real
  improvement with its own design argument, on a macro surface rc.11 is still
  changing. State the limitation in `sensitive.rs` rather than leaving it to be
  rediscovered: **the four aliases are the same nominal type.** `PasswordDigest`,
  `DerivedKey`, `DeflatedPlaintext` and `MemberPlaintext` are all
  `Dynamic<Vec<u8>>` and are freely substitutable for one another — passing a
  digest where a derived key belongs compiles. The aliases buy greppable names
  and zeroize-on-drop, not type safety. That is precisely the case upstream
  deleted the alias macros over, and precisely the case where a newtype would buy
  something real, so the deferral should be visible rather than implied.

  The question to settle before that arc, per msoffice-crypto's suggestion, goes
  to the `[WS-AESC] AESCRYPT-RS SG UPGRADE` session, who have already migrated to
  newtypes: not "is it worth it" but **whether the nominal separation earns its
  keep when every wrapper has the same shape**, and whether the `derive:` surface
  is settled enough to build on while rc.11 is still moving it.
- **Completing rc.3's changelog section.** The three commits already unreleased
  on `main` get their entries from the release commit.
- **`cargo deny` / license re-verification.** `docs/LICENSING.md:112-114` asks
  for this after any dependency change. The graph here strictly shrinks by two
  crates and adds none, so no new licence enters; there is no `deny.toml` or
  audit job in this repo to run, and adding one is its own arc.
- **Re-splitting `crypto-ops`**, and anything else CLAUDE.md already settles.

## 10. Borrow / do not copy

**Borrow:** the shape of the exposure table in §2. Nineteen upstream breaking
changes, one that lands, and each "No" carrying the reason it is a No — that is
what made this arc small enough to do in one PR, and it is reusable for the next
dependency that moves fast.

**Borrow:** measuring the crate count before reasoning about it. The first
estimate here was 27 → 26, from "`syn` survives via `thiserror-impl`". That is
true about *presence* and wrong about *count*: there were two `syn` majors and
the upgrade removes one. The README pins the figure.

**Do not copy:** the caret-over-a-pre-release requirement this arc replaces. It
looked like a pin for months and was not one. If a future dependency is tracked
through release candidates, pin it with `=` from the first commit.

**Do not copy:** letting a `file:line` table drift three times. It has been
fixed twice and is wrong again; the third repair should probably be the last
before it becomes function names instead.

## 11. Amendment — the arc extended to rc.12 and to the inflate path

**Recorded rather than quietly folded in, because the plan above argued for a
narrow scope and the work did not stay in it.**

### What changed

secure-gate `0.9.0-rc.12` published roughly four hours after rc.11, while this
branch was finished and unpushed. It changes `Dynamic::new_with` from `(f)` to
`(len, f)` — a sized, pre-zeroed `&mut [u8]` instead of a zero-capacity `Vec`.
The user's call was to fold it in along with the inflate work rather than ship
rc.11 and follow up.

### Why the original reasoning did not survive

§3 said "keep this arc to the mechanical move" and treated anything touching the
decode path as a separate arc. That was right for `dynamic_newtype!`, which is
still deferred, and wrong here — for a reason §4 of this plan half-saw and did
not follow through.

This plan's §3 recorded that `Dynamic::new_with` hands its closure an empty
buffer, and the skill rewrite turned that into a warning: *do not write a
`new_with` closure that grows.* Both stopped at the wrapper's own constructors.
Neither asked the next question — **what about the buffers that were already
grown before we wrapped them?** `MemberPlaintext::new(inflated)` moves an owned
`Vec` that `decompress_to_vec_with_limit` reallocated several times while
decoding, and each of those reallocations freed a block of the user's document
unwiped. The residue rule was written down and then not applied to the largest
secret this crate handles.

What exposed it was not review of this plan but a question from the secure-gate
maintainer, answered by reading the code: ODF is deflate-then-encrypt, so *every*
decrypted member goes through a growing inflate. The fix needed `(len, f)`, which
did not exist when this plan was written — so the omission was not avoidable at
authoring time, but the reasoning that would have found it was already on the
page.

### What that is worth keeping

**A hazard stated as a rule about one constructor is a hazard half-understood.**
"Do not grow inside `new_with`" is true and was not the whole shape; the general
form is *any* secret that reached its wrapper by growing. Written as the narrow
rule, it passed review here twice.

### Where the scope did hold

`dynamic_newtype!` is still deferred, on the reasoning in §3 unchanged: it is a
separate design question, and rc.12 has not settled the `derive:` surface. The
encrypt-side deflate residue is also left open and named in the skill — deflate
has no declared output length to size a slot from, so closing it needs a bound
and a truncate rather than the same fix, and that is its own arc.
