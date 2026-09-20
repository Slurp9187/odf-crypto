# Project Rules — odf-crypto

## What this crate is for

> **LibreOffice's behaviour is the specification. The ODF spec is a secondary source.**

Where the two disagree, follow LibreOffice. Where LibreOffice is wrong on
purpose — `rtl_digest_SHA1` is a knowingly broken SHA-1 it keeps for
compatibility (`tdf#114939`) — reproduce the wrongness, and cite the upstream
line that proves it is deliberate.

This is not pedantry. A package this crate calls encrypted must be one
LibreOffice would prompt for, and one it refuses must be one LibreOffice would
refuse to open. Anything else produces files real users cannot open, which is
the only failure mode that actually matters here.

### Authority is per field, not per format

The rule above is right in effect and hides a split worth knowing before you
argue from "the spec". Derived from the normative RELAX NG schemas in a
LibreOffice checkout (`core/schema/`), not from prose:

| field | defined by | so a LibreOffice refusal is |
| --- | --- | --- |
| `iteration-count`, `key-size`, `checksum-type` | **OASIS** (`odf1.2/1.3/1.4/…-manifest-schema.rng`) | evidence about one implementation |
| `manifest:algorithm-name` | OASIS, but **open**: `"Blowfish CFB" \| anyURI` | not adjudicable by the schema at all |
| `loext:argon2-iterations` / `-memory` / `-lanes` | **LibreOffice alone** (`libreoffice/OpenDocument-v1.4+libreoffice-manifest-schema.rng`); `argon2` appears in no OASIS schema | **a conformance failure** |

Two consequences that change what an argument has to prove:

- **For the profile `encrypt` writes — AES-256-GCM with Argon2id — there is no
  OASIS specification to be compliant with.** Those attributes exist only in
  LibreOffice's extension schema, and the cipher is named through an open
  `anyURI` that would equally admit nonsense. There LibreOffice *is* the
  specifying authority, and "follow LibreOffice" is not a pragmatic compromise
  but the only available reading of correct.
- **Where OASIS does specify, it specifies structure and no ranges.**
  `iteration-count` and `key-size` are unbounded `nonNegativeInteger` with no
  `minInclusive`/`maxInclusive` facet, and LibreOffice bounds neither on read.
  So a numeric bound in `limits.rs` answers to nobody but us. Say so when you
  write one; do not dress a policy cap as a format rule.

The one thing this table cannot tell you is whether a *bound* is right. It tells
you whose rule you are quoting, which is the question that keeps getting
answered wrong.

`classify` therefore re-runs LibreOffice's own two machines — `ManifestImport`,
then `ZipPackage::parseManifest` — rather than evaluating manifest rows
independently. State leaks across rows upstream in ways a tidy per-row
implementation gets wrong on constructible input: a sticky `key_info` pointer,
an order-dependent derived key size, a lookup cache that resolves a row onto a
stream its path does not name. Do not "simplify" that into a row filter.

### The corollary: some ugly code is load-bearing

`manifest::decode_b64` is **not** RFC 4648 and must never be replaced with a
conforming decoder. It reproduces `Base64::decodeSomeChars`, which skips any
character outside the alphabet. A correct decoder rejects manifest values
LibreOffice accepts, which changes which packages classify as encrypted.

Before replacing any hand-rolled primitive with a crate, check whether it exists
to reproduce a quirk. If its doc comment names an upstream function, it does.

## Where the other rules live

Nothing here restates these. Read them where they live.

| Topic | Authority |
| --- | --- |
| Secret handling, `secure-gate`, what is and is not wrapped | [`.claude/skills/odf-crypto-secure-gate/SKILL.md`](.claude/skills/odf-crypto-secure-gate/SKILL.md) |
| Plans, parent/slice issues, closing keywords | [`docs/plan-workflow.md`](docs/plan-workflow.md) and the `file-plan-issues` skill |
| Why `MIT OR Apache-2.0` is sound against LibreOffice and odfdecrypt | [`docs/LICENSING.md`](docs/LICENSING.md) |
| Design record for each arc | `docs/plans/<feature>-<yyyy-mm-dd>.md` |
| The 54 detection findings, including the 2 refuted | [`docs/audits/classify-lo-fidelity-2026-09-01.md`](docs/audits/classify-lo-fidelity-2026-09-01.md) |

## Features

Three configurations, and every change must hold in all of them.

| Feature | Default | What it adds |
| --- | --- | --- |
| *(none)* | **yes** | `classify` only. 25 crates, no cryptographic dependency. |
| `crypto-ops` | opt-in | `decrypt` and `encrypt`. 59 crates. |
| `cli` | opt-in | The `odf-crypto` binary. Implies `crypto-ops`; adds `clap`, `serde_json`, `rpassword`. |

**Detection-only is the default on purpose.** Nobody should resolve a cipher
stack to ask whether a file is encrypted, and it makes the crate cheap for a
consumer like `calamine`, whose ODS path detects password protection and stops.

`decrypt` and `encrypt` were once separate features. They were collapsed because
the split bought nothing — identical dependency graphs — while producing a third
build configuration in which a bound could be dead in neither of the others.
Do not re-split them.

### Gate; do not allow

A `#[cfg]` states a fact. An `allow(dead_code)` silences a symptom and hides the
next one. If an item has no caller in a configuration, gate it:

```rust
#[cfg(any(feature = "crypto-ops", test))]   // the `test` arm when in-module tests use it
pub(crate) fn encode_b64(..) { .. }
```

The one standing exception is `src/test_support.rs`, whose helpers genuinely do
not partition by feature — `load_golden` is used by the classify tests and calls
helpers only `encrypt_tests` reaches directly. It is `cfg(test)` throughout and
cannot reach the published artifact.

## The library does not panic

There is no `panic!`, `unwrap`, `expect`, `unreachable!` or `todo!` in any
non-test path. Keep it that way — a library must not abort its caller's process
to report something it could return.

**That sentence, not the list, is the rule.** The list names the mechanisms this
crate controls; it is not the set of ways a process dies. The known gap is
**allocation failure**, which calls `handle_alloc_error` and *aborts* — whatever
the panic strategy, because an abort is not a panic. Nothing in the list above
fires, and the crate is clean by its own measure, while the caller's process is
gone.

The consequence is worse here than a crash. An abort skips unwinding, so `Drop`
never runs, so `secure-gate`'s zeroize-on-drop does not happen — and the crate's
only zeroizing primitive is `Drop`. A path that aborts mid-decrypt leaves the
password digest and derived key in memory, unwiped. `kdf.rs`'s Argon2 call is a
live instance, open as of `0.1.0-rc.4`: `argon2`'s `hash_password_into` does
`vec![Block::default(); block_count()]` sized from a manifest field
(`argon2-0.5/src/lib.rs:230`), while `PasswordDigest` and `DerivedKey` are both
alive inside `with_secret`/`with_secret_mut`. `ARGON2_MAX_M_COST_KIB` bounds how
far it can be pushed; it does not close it.

**So: an allocation whose size comes from untrusted input must be fallible.**
Reach for `Vec::try_reserve` and an API that accepts caller-provided storage
(`argon2`'s `hash_password_into_with_memory` is the pattern) rather than a
constant chosen to keep the infallible one from failing. A guessed ceiling is
wrong in both directions — it refuses a host that could have coped and still
aborts one that could not.

Two shapes, and the second is better:

- **Return it.** `DecryptError::Internal` / `EncryptError::Internal` report an
  invariant of ours that something upstream should have enforced. Deliberately
  *not* the `BadParameters` analogue: that reports an untrusted manifest field.
- **Make it impossible.** `classify` once had six panics because
  `password_complete` returned a bool and the builder then re-read the same
  fields and unwrapped them. Folding the guard into the builder made the
  completeness test and the extraction the same code. Prefer this: it removes
  the case rather than reporting it.

## Evidence, not assertion

This repo's culture is that a claim carries its proof. Three concrete rules,
each of which has caught a real error here:

**Measure before you argue from a number.** "clap is roughly fifteen crates"
was wrong — `derive` is 21, and the builder API is 5, which the argument had
never considered. "61 crates" shipped as 62 in the README, `Cargo.toml` and a
changelog entry. Run the command:

```bash
cargo tree --locked -e no-dev --prefix none [--features crypto-ops] \
  | grep -v '(\*)' | sort -u | wc -l
```

**Test the guard by breaking the thing it guards.** A test that passes both ways
is decoration. Delete the `cfg`, watch the lint fire, put it back — and record
that you did, in the commit that adds the guard.

**Check the code, not the doc.** Six doc comments were corrected during the
rustdoc sweep because they described behaviour the code no longer had —
`Mode::Plain` documented `package_encrypted`, `kdf.rs` claimed `encrypt` treats
a failure as unreachable when it maps to `Internal`. When a doc and the code
disagree, the code is the fact.

## Tests

187 of them: 124 library, 16 CLI unit, 35 CLI end-to-end, 12 doctests. All must
pass in every feature configuration.

**The goldens are the evidence.** `tests/goldens/*.odt` are real LibreOffice
output — every one, including `aoo-blowfish-pbkdf2.odt`, whose `aoo-` prefix
names the ODF 1.1 Blowfish format family rather than its producer. Check
`meta:generator` before claiming otherwise; all six read LibreOffice 26.2.1.2,
and `make_goldens.py` only ever drives a local LibreOffice. There is no Apache
OpenOffice-produced evidence here, so the corpus proves fidelity to LibreOffice
and to the format, not agreement between two independent writers. They ship
inside the published crate so the tarball can verify its own fidelity claim. Discover them at run time rather than
hardcoding a count — one arc's evidence file became a fifth golden before that
arc even landed — but assert the corpus is not silently empty, because a glob
matching nothing passes every test.

Never assert on `encrypt`'s output bytes. Its salt and IV are fresh per call.
Assert on the round trip.

## Publishing

- **`--locked` everywhere.** It catches a stale `Cargo.lock`, which this repo hit
  for real: bumping `version` alone leaves the lock behind and `cargo package`
  refuses.
- **`include` is an allowlist.** A new directory ships only once a pattern names
  it. The `*_tests.rs` files and the `.odt` goldens are load-bearing — without
  them the published crate fails `cargo test`, because the `#[path]` test modules
  ship in `lib.rs` regardless.
- **A published version is immutable.** rc.1's docs.rs page is permanently broken
  and no amount of fixing repairs it; the fix ships in the next version. Move a
  tag freely before publishing and never after.
- **CI must mirror docs.rs.** The `docs` job runs stable without `--cfg docsrs`;
  the `docsrs` job runs nightly with it. rc.1 shipped broken documentation
  because only the second configuration fails and nothing built it.
- **`cargo package` needs a clean tree.** It refuses a dirty working directory,
  and the refusal prints nothing useful if you are grepping for success. Commit
  first; a silent `cargo package` is almost always this and not a packaging bug.

### Releasing: open the line, then cut it

Two commits, not one, and the split is deliberate — a version is in development
long before it is released, and the repo should say which it is.

**Open the line** when the first commit lands *past the release tag* — not when
the previous version publishes. While `HEAD` is the tag, the version string is
accurate and should be left alone; bumping at publish time invents a version
whose only content is its own number, and makes `— Unreleased` mean "nothing
happened yet" instead of "here is what has happened so far". The trigger is a
commit, not a release.

1. `version` in `Cargo.toml` → the next `rc`.
2. `cargo update --offline -p odf-crypto`, in the **same commit**. A bump alone
   leaves the lock naming the old version and `cargo package --locked` refuses.
   `--offline` keeps the diff to one line so nothing else can move under you.
3. `README.md`'s version references — **all** of them, including the feature
   table near the bottom.
4. `CHANGELOG.md`: a new `## [0.1.0-rc.N] — Unreleased` heading.

**Cut it**, when the release is ready: change `— Unreleased` to the date,
re-measure the crate counts rather than carrying them forward, verify every
configuration CI runs *including both doc builds*, then tag. Publish is a
separate, explicit decision.

**Why the README moves at open rather than at cut**, since it is the one step
with a real cost: it means the README on GitHub advertises a version not yet on
crates.io, so its install snippet is wrong for anyone copying it that day. That
is accepted on purpose. The alternative — `Cargo.toml` at rc.5 while the README
says rc.4 — makes the working tree internally inconsistent, which is worse and
harder to notice. A reader can tell an unreleased version from `— Unreleased` in
the changelog and the absence of a tag; they cannot tell which of two
disagreeing files to believe.

Lints live in `[lints]` in `Cargo.toml`, not `RUSTFLAGS` — `RUSTFLAGS` reaches
every crate Cargo compiles, so a new warning in `quick-xml` would fail the build
over code nobody here can edit. All `warn`; CI escalates with `-D warnings`.

## The CLI

`argv` is world-readable in a process listing. **There is no `--password VALUE`
argument, and adding one is a regression, not a feature.** It is registered as a
hidden argument purely so a caller reaching for it gets the reason rather than
"unexpected argument", and two tests pin its absence from every help output.

Exit codes are a contract: 4 means *wrong password, try again*, 5 means
*refused, you had the wrong file*. A CLI that returns 1 for everything cannot be
scripted.

## Plans record reversals

When implementation contradicts a plan, amend the plan to say what changed and
why the original reasoning failed. Do not quietly correct it to match the code:
the plan is the design record, and a decision that was reversed is more useful
than one that appears never to have been made. The CLI plan's §1 and §4 are the
worked example.
