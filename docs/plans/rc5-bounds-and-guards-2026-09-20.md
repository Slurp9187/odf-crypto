Status: **In flight (`0.1.0-rc.5`)** — every item shipped; §7's human verdict is the one thing outstanding · Authored 2026-09-20 · **Written into the repo late**, after three of its items had already landed; see *How this plan got here* · Shipped so far: [#52](https://github.com/Slurp9187/odf-crypto/pull/52) (§1, §6), `507d8a0` (§2's first half), plus two off-plan items — [#54](https://github.com/Slurp9187/odf-crypto/pull/54) and [#55](https://github.com/Slurp9187/odf-crypto/pull/55)

Consumes [docs/plans/odf-encryption-decrypt-2026-09-02.md](odf-encryption-decrypt-2026-09-02.md) and [docs/plans/odf-encryption-encrypt-2026-09-03.md](odf-encryption-encrypt-2026-09-03.md), both Shipped. §1 and §2 below reverse decisions recorded in the first of those; the reversals are written into *that* file as well, not only here.

# Plan — ground every bound in a real limit, and stop margins looking like format rules

> **Goal.** Every numeric bound in `src/limits.rs` is either a real limit or an
> owned policy, each labelled as such; nothing is refused that LibreOffice
> accepts unless the reason fits in one sentence; and a caller can tell *"this
> file is invalid"* from *"this crate declines to go that far."*

## How this plan got here

This file was written on 2026-09-20, after §1, §6, half of §2 and two off-plan
items had already shipped. Until then the plan governing `0.1.0-rc.5` existed
only in a coding session's scratch directory.

That is a defect in its own right and is recorded rather than tidied away.
`CLAUDE.md`'s authority table says the design record for each arc lives in
`docs/plans/<feature>-<yyyy-mm-dd>.md`, and every previous arc has one. This arc
did not, so for three pull requests the reasoning behind rc.5 was unreviewable,
unlinkable, and invisible to anyone not in that session — including to the only
external consumer, who re-audits on every version move.

The status line is therefore dated honestly rather than flatteringly: the plan
carries the day it entered the repository, not the day its reasoning was first
written down somewhere.

## Authority: answered from our own sources

`msoffice-crypto`, templated off this crate, inherited its method — *a MIN and a
MAX for every attacker-controlled field* — and sent back the principle that *"the
specification is the authority, and no implementation is."* `CLAUDE.md` says the
opposite deliberately: **LibreOffice's behaviour is the specification.**

Both are satisfiable here, because **the spec and LibreOffice agree: neither
bounds these fields at all.**

- The normative RELAX NG manifest schemas
  (`core/schema/odf1.2|1.3|1.4/…-manifest-schema.rng`) type `iteration-count`
  and `key-size` as `nonNegativeInteger` and the Argon2 triple as
  `positiveInteger`, with **no `minInclusive`/`maxInclusive` facet on any of
  them**.
- LibreOffice on read: `iteration-count` has **no check whatsoever**
  (`ManifestImport.cxx:272-274` → `rtl_digest_PBKDF2`, which validates only
  pointers, `sal/rtl/digest.cxx:1825-1838`). `key-size` is checked for `< 0` and
  nothing else (`ZipFile.cxx:155-160`). Argon2 is `0 < t && 0 < m && 0 < p`
  (`ManifestImport.cxx:257`), then delegated (`ZipFile.cxx:192`).

**Four of six bounds are tighter than both**, enforced on the read path. The
floors diverge too: the schema permits `0` for `iteration-count` and `key-size`,
and this crate requires `1`.

The authority split this produced — ODF's authority is **per field**, and for the
AES-256-GCM/Argon2id profile `encrypt` writes there is no OASIS specification to
be compliant with — now lives in `CLAUDE.md` rather than here, because it governs
more than this arc.

## The governing idea: hard limits are the reality check — where they exist

Grounding bounds in physics rather than in taste is possible for **memory** and
impossible for **time**, and separating the two is most of the work.

**Memory bounds can be made real.** `argon2`'s default path does
`vec![Block::default(); params.block_count()]` (`argon2-0.5/src/lib.rs:230`) and
Rust **aborts** on allocation failure — it cannot be caught. But
`hash_password_into_with_memory` (`:243`) takes caller-provided blocks.
Allocating those with `Vec::try_reserve` turns an abort into a recoverable `Err`,
and the bound stops being a number we guessed and becomes *the machine actually
running it*.

**Time bounds cannot.** `iteration-count` allocates nothing; there is no failure
to catch. PBKDF2 at 10,000,000 iterations is slow, not impossible, and
LibreOffice simply spins. So it is either uncapped or an explicit policy cap with
a measured budget — and it must be **labelled** policy, never presented as a
format rule.

That asymmetry is the plan.

## No deprecations, migrations or workarounds

Owner's standing constraint for this line: **breaking changes are the expected
move, not a cost to be justified.** No `#[deprecated]` shims, no parallel
old/new APIs, no documenting around a bad shape when the shape is the defect, no
migration paths. The one known consumer pins exact versions and re-audits on
every move; that is what the pin is for.

This was drafted against the wrong constraint at first, and the corrections are
the more valuable half:

| shape | was going to | should |
| --- | --- | --- |
| `EncryptError::Params(String)` | add a typed reason beside the string | **replace** the payload — done in rc.4 |
| `DecryptError::Zip` carrying quick-xml failures, its own doc admitting *"despite the name"* | note it in the troubleshooting guide | **split the variant** ([#48](https://github.com/Slurp9187/odf-crypto/issues/48)) |
| `EncryptError::AlreadyEncrypted`, which fires on a `PerEntry` package with `package_encrypted == false` — one LibreOffice opens **without prompting** | document the edge case | **rename or split** so it states what it detects |

Checked rather than assumed: `encrypt` alongside `encrypt_with_params` is **not**
a workaround. It was partly motivated by not breaking `encrypt`, which is no
longer a reason, but it survives on its own merits — a caller with no opinion
should not have to name a parameter to say so. `Vec::new` / `Vec::with_capacity`,
not a compatibility shim.

## Guidance, not gates — and where that stops

Owner's ruling, extended from Argon2 to bounds generally: *"Who are we to force
users into a construct? We may consider simply warning, but never block."* Three
tiers, and every bound lands in exactly one:

| tier | what it means | mechanism |
| --- | --- | --- |
| **Refuse** | cannot work at all — the cipher rejects it, the host cannot allocate it, or it produces a file nothing can read | typed error (§3) |
| **Report** | legal, runnable, and a bad idea | query predicate + typed reason; caller decides |
| **Default** | what a caller who expresses no opinion gets | LibreOffice's profile, always |

A library has no terminal, so "warn" concretely means a **predicate the caller
can ask** (`is_weaker_than_libreoffice` is the precedent), a **typed reason**
rather than free text, `#[must_use]` where ignoring the answer is the mistake,
and rustdoc showing both sides as compiled doctests.

**Where this stops, said here rather than discovered later:** a warning reaches
the *developer*, while the cost of a weak choice lands on the *document owner*,
who never sees it. So "warn, never block" is right for a caller choosing their
own trade, and is **not** a reason to soften the other two tiers.
Refuse-what-cannot-work stays hard and the default stays LibreOffice's — those
protect the person who is not in the room.

## Work

### 1. Provenance table in `limits.rs`, and let it force the rest — **SHIPPED** ([#52](https://github.com/Slurp9187/odf-crypto/pull/52))

Label every bound **spec** / **LibreOffice** / **hard** / **policy**. The label
determines the tier above and is not a separate judgement: hard → Refuse,
policy → Report, and *spec* or *LibreOffice* is not ours to have an opinion about.

Shipped with **zero values moved**, deliberately: labelling is what decides which
values should move, and doing both in one pass makes the labels post-hoc
justifications for numbers already chosen.

| bound | finding |
| --- | --- |
| `ARGON2_MAX_M_COST_KIB` `1<<20` | **basis dissolved.** Its only stated reason was that libargon2 errors where Rust's `vec!` aborts, so "the ceilings sit exactly where the two behaviours diverge". §2 closed that divergence. |
| `ARGON2_MAX_T_COST` `1<<16` | never had the memory argument; `t` allocates nothing. `1<<16` is ~21,800× LO's `t=3`, so the plan's "16× anything LO writes" line described `m` and was stretched over `t`. Had no comment at all. |
| `PBKDF2_MAX_ITER` `1<<23` | a **read** ceiling derived from LibreOffice's **write** default (`ZipPackage.cxx:1400`). LO imposes no read ceiling. |
| `DERIVED_KEY_MAX_LEN` `64` | the hard limit is 56, Blowfish's maximum key; 64 rounds it up. Now says so. |
| `PBKDF2_MIN_ITER`, `DERIVED_KEY_MIN_LEN` `1` | the schema permits `0` and LO accepts it. Policy. |

> **Open decision, not taken here.** Widening any of the three unmeasured policy
> caps changes what `decrypt` accepts, which is the owner's call and an
> EFV-notifiable event. The standing recommendation: widen `m` to the host, since
> `try_reserve` is now the real bound; leave `t` and `PBKDF2_MAX_ITER` capped but
> **labelled as the policy they are** until someone takes the time-budget
> measurement. `m` has physics behind it now; the other two have only a wait-time
> opinion, and an opinion is a worse thing to remove than to name.

### 2. Make the memory bounds real — **HALF SHIPPED** (`507d8a0`; remainder is [#51](https://github.com/Slurp9187/odf-crypto/issues/51))

> **Severity was promoted during drafting.** This began as "make a guessed bound
> honest". It is also closing a path on which **secrets are not wiped**, which is
> a different class of item, and it was resequenced first in rc.5 accordingly.
>
> Rust aborts on allocation failure; an abort bypasses unwinding; `Drop` never
> runs — and at that moment `decrypt` is inside
> `start_key.with_secret(|sk| derived_key.with_secret_mut(|key| …))`, so
> `PasswordDigest` and `DerivedKey` are both live. secure-gate's zeroize-on-drop,
> the crate's only zeroizing primitive, does not happen.
>
> **This named a hole in `CLAUDE.md`'s own rule**, which enumerated `panic!`,
> `unwrap`, `expect`, `unreachable!`, `todo!` — mechanisms, not the outcome. The
> crate satisfied the letter of its strictest rule while the sentence explaining
> it was false on this path. The rule now says the sentence is the rule.

**Shipped:** `kdf::derive_argon2id` allocates its block buffer with
`try_reserve_exact` and passes it to `hash_password_into_with_memory`; an
unaffordable `m` returns `HostCannotAllocate`. Verified the abort **closed rather
than moved** — everything beneath that entry point in argon2 0.5.3 is heap-free.
Had any of it allocated, the fix would have compiled, passed, and changed
nothing.

**Not shipped:** the same treatment where a manifest field sizes an allocation —
`key-size` → derived-key buffer, and `decrypt.rs`'s inflate slots and cipher
buffers, each bounded at 1 GiB but summing across up to `MAX_ENCRYPTED_ENTRIES`
rows with wrapped plaintext live throughout. `MemberPlaintext::try_new_with`'s
`try_` names the *fill*, not the allocation, and is the site most likely to be
mistaken for already-safe.

**Do not** remove `PAYLOAD_CEILING` — but honour the encrypt plan's explicit
instruction (`odf-encryption-encrypt-2026-09-03.md:169`) that `DEFLATE_CEILING`
is *hygiene, not a security boundary*, which the current shared-constant comment
contradicts.

### 3. Error taxonomy: add the missing fourth case — **SHIPPED**

A consumer could not distinguish: (1) the format forbids it, (2) the cipher/KDF
cannot run it, (3) this host cannot afford it, (4) **spec-legal, implementable,
and this crate declines anyway**. Case 4 was the missing one, and reporting a
policy cap as case 1 is a *typed* lie — a consumer renders it as authoritative.

**Shipped in rc.4:** `EncryptError::Params(String)` → `Params(ParamsReason)`,
`#[non_exhaustive]`, carrying `OutOfRange` (our policy bound) and `CipherRejects`
(argon2's own requirement). Moved before rc.4 published specifically so no
released version ever carried the wrong shape and no migration was manufactured.

**Shipped in rc.5:** `HostCannotAllocate` on both error types, and CLI exit code
8. Non-breaking, because the reason type was `#[non_exhaustive]` from the start —
which is what held this to one break rather than two.

**Shipped in rc.5, second half:** [#48](https://github.com/Slurp9187/odf-crypto/issues/48)'s
`DecryptError::Zip`. The rewrite's **serialization** failures are `Internal` now,
matching `encrypt::build_manifest`, which had it right. Its **parse** failure
stays `Zip` and un-elided, on a measured argument that the path is unreachable
rather than on an elision implying a live threat — three independent adversarial
searches found no input `classify` accepts and the rewrite refuses, and because
the argument is scoped to quick-xml 0.38.4 a test pins it rather than prose.

The split §1 surfaced between *the format forbids it* and *we decline* is carried
by `limits.rs`'s labelling and `ParamsReason`, not by a further error variant: a
consumer needing to know whose rule refused a value reads it there, and
`BadParameters` stays one verdict about the manifest. §5's first section is the
decision tree for exactly that question.

### 4. Fix the scope justifications; change no behaviour — **SHIPPED**

The audit found the reasoning weak in five places and the decisions mostly sound.
All five are re-argued. **Two of the five turned out to be more than a wording
fix**, which is the argument for doing this item at all rather than treating it
as tidying:

- `m_bHasNonEncryptedEntries`'s circular justification was not just circular, it
  reached the **wrong conclusion** — see below.
- `AlreadyEncrypted` could not be fixed by rewording, because the name was a
  claim about the file. It was **split**, which is a breaking API change.

Filed out of this item: [#59](https://github.com/Slurp9187/odf-crypto/issues/59)
(the read/write profile asymmetry) and
[#60](https://github.com/Slurp9187/odf-crypto/issues/60) (the flag a consumer
cannot see). The original five:

- **PGP refusal** (`decrypt.rs:61-65`) says *"later arc"*. The real argument is
  infeasibility and it is unstated: `decrypt(bytes, password)` has no surface
  through which a private key, passphrase or agent socket could arrive, and an
  OpenPGP stack contradicts "25 crates by default". Cheapest high-value fix in
  the audit.
- **Per-entry write** (encrypt plan `:215`) closes on *"no concrete reason to
  target an older ODF version"* — that is demand, asserted, and the crate ships
  goldens it can read and cannot write. Replaced with an effort/gap statement
  naming what exists (every primitive, since `decrypt` uses them) and what does
  not (per-member salt/IV, one `encryption-data` per member, `manifest:size` on
  each). Filed as #59, and stated on the README so the asymmetry is visible to a
  reader rather than only to the tracker.
- **`m_bHasNonEncryptedEntries`** (detection plan `:270`) is circular: it cites
  *our own* `decrypt`'s copy-through as evidence nobody needs the flag. **Re-argued
  from LibreOffice, and the conclusion flipped.** The flag is live upstream:
  `ZipPackage.cxx:446` sets it, and `SfxObjectShell::CheckEncryption_Impl`
  (`sfx2/source/doc/objmisc.cxx:1028-1063`) reads it — on ODF >= 1.2, when
  `HasEncryptedEntries && HasNonEncryptedEntries`, LibreOffice raises
  `ERRCODE_SFX_INCOMPLETE_ENCRYPTION` and calls `disallowMacroExecution()`. A
  security decision, not bookkeeping. `Classification` exposes one half of that
  predicate and not the other, so a consumer cannot tell whether LibreOffice
  would warn. Recorded as a known limitation and filed as #60.
- **`AlreadyEncrypted`** (`encrypt.rs:260-263`) restates its condition instead of
  justifying it, and over-claims. Verified: `Mode::PerEntry` is
  `!encrypted_entries.is_empty()` (`classify.rs:319`), wholly independent of
  `package_encrypted`, so a package with complete rows and no latch row is
  refused as *"already encrypted"* while LibreOffice opens it **without
  prompting**. **Split** into `AlreadyEncrypted` (the latch is set; LO would
  prompt) and `PartiallyEncrypted` (rows but no latch; LO would not). Both still
  refuse, and both still map to exit 5 — what changed is which claim is made
  about the file, not what a script does about it.
- `lib.rs:32` / `README.md:255` assert scope with no reason on the public surface.

### 5. A troubleshooting guide, organised by symptom — **SHIPPED**

The typed reasons in §3 tell a caller *which* case they hit, not what to do about
it. That belongs on one page organised by **symptom** — how a stuck developer
actually arrives — rather than by API, which is how you arrive only if you
already know what is wrong.

Ships as a doc-only module (`src/troubleshooting.rs`, `pub mod` with `//!` docs
and no items), not a file under `docs/`: it appears on docs.rs where a consumer
is already looking, `src/**/*.rs` already covers it in the `include` allowlist,
and **its examples compile as doctests, so the advice cannot rot.**

Symptoms, each drawn from something that has actually confused someone here:
`BadParameters` as a decision tree over §3's taxonomy; `WrongPassword` when the
password is right (it cannot distinguish a wrong password from tampered
ciphertext, and on AES-CBC/Blowfish the checksum covers only the first 1 KiB, so
damage past that surfaces as `Inflate`); LibreOffice refusing what `encrypt`
wrote; which Argon2 cost to pick, and that the cost is stored in the file and
binds every future reader; error text the caller did not write (#48/#49); and
`AlreadyEncrypted` on a file LibreOffice opens without prompting.

### 6. Record the reversal — **SHIPPED** ([#52](https://github.com/Slurp9187/odf-crypto/pull/52))

`odf-encryption-decrypt-2026-09-02.md:101` said *"No iteration or memory cap:
match LO's absence. An attacker-complete row can make Argon2 expensive; that is
accepted, not a slice."* `limits.rs` capped both and the plan was never amended,
so the caps were not an oversight but a silent reversal of a written decision.

It now records **both** reversals — the 2026-09-03 capping, and rc.5 removing
that capping's basis — rather than correcting either away. The original paragraph
was wrong when written, because it assumed both implementations failed the same
way. Its instinct is available again for `m`, and not for `t`.

### 7. Human-openable artifact set — **NOT STARTED, AND IT GATES THE RELEASE**

`tests/goldens/validate_encrypt.py` drives UNO, which is **not** the path a
double-click takes — no password dialog, no recovery prompt. Produce a durable
`tests/artifacts/` directory plus a manifest (tuple, password, sha256, expected
text, what a failure would mean) covering each profile and each boundary tuple,
for a human to open in LibreOffice. That verdict outranks the harness.

## Off-plan work that landed in this line

Recorded because it is real work in rc.5 that this plan did not call for, and a
plan that quietly absorbs what happened is not a design record.

**[#54](https://github.com/Slurp9187/odf-crypto/pull/54) — the `cli`
configuration ran in no CI job.** Found while reading CI for an unrelated reason.
`grep -rn 'cli' .github/workflows/` matched only the word "clippy": 52 tests had
never run on a runner, including the two pinning `--password`'s absence and the
one pinning exit code 4, and the binary was never linted. `cargo package` also
ran with `crypto-ops`, whose comment claimed "the largest source set" while
`required-features = ["cli"]` meant it never compiled `src/bin/` at all.

**[#55](https://github.com/Slurp9187/odf-crypto/pull/55) — the exit-code contract
had no guard.** Closes #40, and the issue's specified mechanism did not work: the
binary is a *separate crate*, so `#[non_exhaustive]` binds it and rustc requires
the very `_` arm a canary there was meant to catch. Completeness therefore lives
in the library and correctness in the binary.

Both are the same class as §1 — a claim in `CLAUDE.md` that nothing checked — and
neither was foreseen here. **They were sequenced correctly by accident:** #54 had
to precede #55, because a guard in a suite no CI job runs reads as coverage and
is not.

## Verification

- Every configuration as CI runs them: `cargo test --locked` ×3, clippy
  `-D warnings` ×3, `fmt`, **both** doc builds (stable, and nightly with
  `--cfg docsrs`), MSRV 1.85, `cargo package`.
- **A widened bound needs a test proving the widening**, not just that nothing
  broke: construct a manifest at each new boundary, assert `decrypt` accepts what
  LibreOffice accepts and still refuses what it cannot run.
- **The `try_reserve` path needs its failure exercised.** Honestly unmet today:
  the only test driving a real 1 GiB request is `#[ignore]`d and returned `Ok` on
  the machine that wrote it. A deterministic test needs a `#[global_allocator]`
  shim, and `unsafe_code = "forbid"` makes one impossible — `forbid` cannot be
  lifted by `allow`. What is pinned deterministically is everything downstream.
  By this repo's own standard the guard is untested, and saying so is better than
  implying otherwise.
- Round-trip the goldens and confirm byte-identical output, as rc.4 did.
- Open the §7 artifacts by hand in LibreOffice before release.

## Sequencing

**rc.4 published first; this is rc.5.** An earlier call was to hold rc.4 and fold
this in; reversed, and the reasoning is kept rather than overwritten. rc.4 was
finished and externally validated — the EFV integration built against it and ran
21/21 — and it was additive. This arc is not: §2 changes *what `decrypt`
accepts*, a wider blast radius than anything in rc.4, and §1 surfaced divergences
the audit had not reached. Combining them would have thrown away rc.4's
validation and left a consumer unable to tell which half caused trouble.

> Approving this plan is **not** authorisation to publish. `cargo publish` is
> irreversible and stays a separate, explicit go-ahead every time.

**Nothing in rc.5 ships until the §7 artifact set has been opened by a human in a
real LibreOffice.**
