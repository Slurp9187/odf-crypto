Status: Released — version headings, newest first

# Changelog

Releases lead. Everything below the first version heading is the dated development
record from before the crate was published: entries keyed by date rather than release,
organized by arc, kept as written. Those dates stay — they are where the reasoning for a
behaviour actually lives, and a release heading summarizing them would lose it.

Finding ids (`A1`–`A10`, `B1`–`B7`, `C1`–`C7`, `D1`–`D7`) index into
[the audit](docs/audits/classify-lo-fidelity-2026-09-01.md), which carries the
LibreOffice citation and a reproduction for each.

## [0.1.0-rc.5] — Unreleased

### Fixed

**The Argon2 key derivation no longer aborts the process when the host cannot
supply the memory a manifest asks for.** `argon2`'s `hash_password_into`
allocates its working blocks as `vec![Block::default(); block_count()]`
(`argon2-0.5.3/src/lib.rs:230`), sized from `manifest:argon2-memory`. Rust
**aborts** on allocation failure whatever the panic strategy, an abort skips
unwinding, `Drop` never runs — and `Drop` is this crate's only zeroizing
primitive. The allocation happens inside
`start_key.with_secret(|sk| derived_key.with_secret_mut(|key| …))`, so the
process died with the password digest and derived key in memory, unwiped.

`kdf::derive_argon2id` now allocates the blocks itself with
`Vec::try_reserve_exact` and passes them to `hash_password_into_with_memory`.
An unaffordable request returns `DecryptError::HostCannotAllocate` or
`EncryptError::HostCannotAllocate` instead.

**The abort closed rather than moved**, which is the only thing that makes this
more than theatre: everything beneath `hash_password_into_with_memory` in argon2
0.5.3 — `initial_hash`, `verify_inputs`, `fill_blocks`, `finalize`,
`blake2b_long` — is heap-free, stack `Block` locals and fixed buffers only. If
any of it had allocated, the fix would have compiled, passed, and changed
nothing.

**Nothing about which inputs are accepted changed.** No bound in `limits.rs`
moved. That is the separate provenance arc, and this had to land first: widening
a memory ceiling before the allocation is fallible would make the abort *easier*
to reach.

**The CLI gains exit code 8, `host-capacity`.** Both new variants first landed
in `decrypt_exit`/`encrypt_exit`'s trailing `_ => EX_MALFORMED`, so the binary
announced exit 6 — "malformed or hostile package" — for a memory failure, which
is precisely the "your file is bad" rendering the change exists to prevent. That
is the **third** variant to fall through that wildcard after
`EncryptError::Params`; [#40] remains open and is now overdue.

**What is honestly not proven.** The `try_reserve_exact` failure itself is
exercised only by an `#[ignore]`d test that drives a real 1 GiB request, and it
returned `Ok` on the 16 GiB machine that wrote it. A deterministic test needs a
`#[global_allocator]` shim, and `unsafe_code = "forbid"` in `Cargo.toml` makes
one impossible — `forbid` cannot be lifted by `allow`. What *is* pinned
deterministically is everything downstream: the `KdfError` → `DecryptError`
split, and that neither variant maps to `EX_MALFORMED`. By this repo's own
standard the guard itself is untested, and saying so is better than implying
otherwise.

**The other aborting allocations are recorded, not fixed** — the inflate slots
and cipher buffers in `decrypt.rs`, each bounded at 1 GiB but summing across up
to 4096 rows with wrapped plaintext live throughout. Filed as [#51]. Note
`MemberPlaintext::try_new_with`'s `try_` names the *fill*, not the allocation;
it is the site most likely to be mistaken for already-safe.

[#40]: https://github.com/Slurp9187/odf-crypto/issues/40
[#51]: https://github.com/Slurp9187/odf-crypto/issues/51

### Documentation

**`CLAUDE.md` gains a fourth "Evidence, not assertion" rule: name the proxy when
a rule tests one.** The recurring defect across this crate and its sibling is not
a wrong check but one that silently swapped the property it cares about for a
proxy it can observe, then took the proxy's name — *does not panic* for *does not
abort*, *dated iff tagged* for *dated iff released*, *within our constant* for
*within the format's range*, *`panic = "unwind"` is set* for *`Drop` runs, so
secrets are wiped*. Every substitution was reasonable, because the real property
was not observable from where the check runs; that is also what hides it, since
the check does test what its name says. Four instances, two of them this
repository's, and all four found by someone outside the rule asking what it was
for. The rule cannot close the class — it widens who can catch it from an
outsider to anyone who reads the paragraph. Framing owed to the
`msoffice-crypto` session.

Applied immediately: the `changelog-protocol` skill's second invariant is
restated as *a released version has a dated heading — approximated by the tag*,
naming both the property and why the tag stands in for it.

**Two rules in `CLAUDE.md` were closed against themselves.** Both were found by
applying the repo's own standards to the repo, and neither is a code change.

*The no-panic rule named the mechanism and not the outcome.* It listed `panic!`,
`unwrap`, `expect`, `unreachable!`, `todo!` — and the crate is clean by that
measure. Allocation failure calls `handle_alloc_error` and **aborts**, whatever
the panic strategy, because an abort is not a panic: nothing in the list fires
and the caller's process is gone anyway. Worse here than a plain crash, because
an abort skips unwinding, `Drop` never runs, and `Drop` is this crate's only
zeroizing primitive — so an abort mid-decrypt leaves the password digest and
derived key unwiped. `kdf.rs` is a live instance as of `0.1.0-rc.4`: `argon2`'s
`hash_password_into` does `vec![Block::default(); block_count()]` sized from a
manifest field (`argon2-0.5/src/lib.rs:230`) while both wrappers are alive.
The rule now says the *sentence* is the rule, and requires an allocation sized
from untrusted input to be fallible.

*"LibreOffice's behaviour is the specification" hid a per-field split.* Derived
from the normative RELAX NG schemas in a LibreOffice checkout: `iteration-count`,
`key-size` and `checksum-type` are OASIS; `manifest:algorithm-name` is OASIS but
**open** (`"Blowfish CFB" | anyURI`, adjudicating nothing); and `loext:argon2-*`
is defined by **LibreOffice alone** — `argon2` appears in no OASIS schema. Two
consequences: for the profile `encrypt` writes there is no OASIS specification to
be compliant with, so "follow LibreOffice" is the only available reading of
correct rather than a compromise; and where OASIS does specify, it specifies
structure and **no ranges**, so a numeric bound in `limits.rs` answers to nobody
but us. The original rule is kept verbatim above the refinement — it is correct
in effect, and a reader who stops early is under-informed rather than misled.

**The README's `OutOfRange` paragraph carried the same misattribution** the rc.4
changelog had, and is corrected the same way: the Argon2 attributes are
LibreOffice's extension, not OASIS's.

**The release workflow is now written down** rather than inferred from git
history, and lives in a new `changelog-protocol` skill — adapted from
`msoffice-crypto`'s skill of the same name, not copied. It carries two
invariants about the tree (the top heading matches `Cargo.toml`; a heading is
dated if and only if that tag exists), a third about the registry, the
two-commit open/cut flow, and the tag mechanics.

The registry axis is an addition, not borrowed: a dated, tagged heading can
still describe a release nobody can install, because publishing is a separate
step from tagging. It is deliberately **not** a violation on sight — `rc.4` sat
dated-and-unpublished for hours waiting on a go-ahead, which is expected and
transient. It is a defect when it persists, and the inverse is always one: a
version on crates.io with no dated heading means something shipped that the
changelog does not describe, so a consumer reading it to decide whether to
upgrade is reading about a different release than the one they would get. That
check needs the network where the other two are offline, so it cannot join them
in an offline job.

The axis is **scoped to the newest line**. A publish missed long ago is a
historical fact rather than a defect: republishing ships a stale tree,
un-releasing rewrites a record for nobody's benefit, and a check that stays red
on something nobody can act on is a check somebody disables. That is the same
rule the skill already stated for the other two invariants; it just had not been
applied to this one.

It also compares **existence, never dates**. The obvious extension — does the
heading's date match when it was published — fires on roughly a third of evening
releases, because registry timestamps are UTC and heading dates are stamped
locally, and the changelog records no timezone to reconcile them. Raised by the
`msoffice-crypto` session from a real pair in their own repo: a heading reading
`2026-09-15` against a `created_at` of `2026-09-16T03:04:16Z`, which is the same
moment on a UTC-7 machine.

For the newest line, where action is still possible, resolving the state is
recorded as the **maintainer's call, not an agent's**.
There are two ways out — publish it, making the claim true, or un-release it,
putting `— Unreleased` back and removing the tag — and both change what the
world is told. An agent detects, reports, and stops. In particular it must not
"tidy" a dated heading back to `— Unreleased` because a check went red: that
silently withdraws a release announcement, and whether a release is late or
abandoned is not something a checker can know.
`CLAUDE.md` points at it rather than restating it, which is that file's own rule
and one the first draft of this entry broke by putting the flow there.

The trigger for opening is **a commit landing past the release tag, not the
previous version publishing**. While `HEAD` is the tag its version string is
accurate and is left alone; bumping at publish time would invent a version whose
only content is its own number, and would make `— Unreleased` mean "nothing has
happened yet" rather than "here is what has happened so far".

Three things were re-derived rather than inherited, and are recorded in the
skill as *what did not transfer*: the sibling's heading style (this repo already
had brackets in three of five headings), its CI enforcement (we have none, and
claiming otherwise would be a false claim in the file that forbids them), and its
emphasis on dating individual entries — weaker here, because every measurement in
this changelog already sits under a version heading that gets dated at cut. What
does carry is naming the external version a measurement was taken against.

`rc.1` and `rc.2`'s headings were normalised from `## v0.1.0-rc.N` to the
bracketed form so the invariant check can be mechanical rather than tolerant of
two spellings.

It also records the one step with a real cost: the README moves at *open*, so GitHub advertises a version not yet on
crates.io and its install snippet is wrong for anyone copying it that day. That
is accepted deliberately. The alternative leaves `Cargo.toml` and `README.md`
disagreeing, which is worse and harder to notice; a reader can tell an unreleased
version from `— Unreleased` and the missing tag, but cannot tell which of two
disagreeing files to believe. Also recorded: `cargo package` refuses a dirty tree
and says nothing useful about why, which has now cost two debugging detours.

Neither `CLAUDE.md` nor this changelog ships in the crate — `include` is an
allowlist and names neither — so the documentation items above change nothing a
consumer compiles. The Fixed section does: two new public error variants and a
new CLI exit code.

## [0.1.0-rc.4] — 2026-09-20

One addition and two hardening fixes. The fixes are both about the same thing —
what an untrusted package can get this crate to *say*; the addition is about
what a caller is allowed to *choose*.

`classify`, `decrypt` and `encrypt` all keep the signatures `0.1.0-rc.3`
shipped: `encrypt_with_params` is a new entry point beside `encrypt`, not a
change to it, so nothing existing has to move. The dependency graph is unchanged
at 25 crates for detection-only and 59 with `crypto-ops`, re-measured rather
than carried forward.

### Added

**The Argon2id cost is now a caller's choice**, through `encrypt_with_params`
and `Argon2Params`. `encrypt` is unchanged and still writes LibreOffice's
`(t=3, m=65536, p=4)`, available to a caller as
`Argon2Params::LIBREOFFICE_DEFAULT`; the new entry point is opt-in and the
weaker choice has to be typed out.

The driver is hardware, not testing. `m=65536` is **64 MiB of working memory per
call**, which on an older phone or a 2 GB laptop is a meaningful share of what
exists — and because the parameters travel with the file, a device that cannot
spend 64 MiB to write also cannot spend it to read the document back. Lowering
the write cost is the only thing that helps such a device, and it helps on both
paths.

**Weak tuples are accepted, not refused.** `Argon2Params::new` rejects two
things and neither of them is *cheap*: a value outside the range this crate acts
on, and a tuple `argon2` cannot run (`m < 8p`, or `p` above its `MAX_P_COST`).
Those are different authorities and the error says which — see `ParamsReason`
below; an earlier draft of this entry attributed both to `argon2`, which is the
mistake the type exists to prevent. Who a document belongs to,
and what its owner can afford to run, is not this crate's call to make. What the
crate does instead is *say so*: `Argon2Params::is_weaker_than_libreoffice`
reports the comparison, the CLI prints a warning on stderr and writes the file
anyway, and the rustdoc states the trade at the type.

**Real LibreOffice reads these back**, established twice over — by measurement
and from its source, because the whole feature is worthless if it is not true:
a lower-cost file that only this crate could open would be exactly the outcome
the crate exists to prevent.

Measured: packages written at `(3, 65536, 4)`, `(2, 8192, 2)` and `(1, 1024, 1)`
were each opened by LibreOffice 26.2.1.2 with the correct text recovered; the
last is one sixty-fourth of the default memory.

From source, which is the stronger half because it bounds every tuple rather
than the three that were sampled. `ManifestImport.cxx:257` validates the three
attributes for positivity and nothing else — `if (0 < t && 0 < m && 0 < p)`,
with the `else` branch setting `bIgnoreEncryptData`; there is no floor, no
ceiling and no clamp. `ZipFile.cxx:184-186` then passes the file's own values
straight into `argon2_context`'s `t_cost`, `m_cost` and `lanes`, and `:192`
states the policy outright: *"libargon2 validates all the arguments so don't
need to do it here."*

So LibreOffice's accepted range **is** libargon2's, and what this crate will
write is a strict subset of it — `t` to `1 << 16` against libargon2's
`u32::MAX`, `m` to `1 << 20` KiB against `u32::MAX`, `p` sharing argon2's own
`MAX_P_COST`, and `m >= 8p` enforced on both sides. Nothing `encrypt_with_params`
can produce is refusable by LibreOffice on parameter grounds. (LibreOffice links
`phc-winner-argon2-20190702`, fetched at build time; the comparison above is
against the Rust `argon2` crate's constants, which mirror the same PHC
reference.)

A struct rather than three integers, because two orderings of the same three
`i32`s are already in play: the manifest writes `(t, m, p)` and `argon2::Params`
orders them `(m, t, p)`. A tuple makes transposing them type-check, look
plausible and still produce a file.

`EncryptError::Params` is new. It is distinct from `Internal` on purpose —
`Internal` reports an invariant of ours, this reports a value the caller can
correct — and the CLI maps it to exit **1 (usage)**, not 6 (malformed): the flag
was wrong, the document was fine. It reached the `_` catch-all arm when first
added, which is exactly the silent fall-through [#40] exists to catch.

The CLI gains `--argon2-t`, `--argon2-m` and `--argon2-p`, each defaulting
independently so `--argon2-m 8192` alone keeps LibreOffice's `t` and `p`.

`EncryptError::Params` carries a typed [`ParamsReason`], not a string, and the
distinction it draws is **whose rule was broken**:

- `OutOfRange` — *this crate declined.* A policy bound of ours, and nobody
  else's: the Argon2 attributes are defined by **LibreOffice's own extension
  schema** (`libreoffice/OpenDocument-v1.4+libreoffice-manifest-schema.rng`) and
  appear in no OASIS schema at all, where they are typed as unbounded
  `positiveInteger`; LibreOffice then validates the triple only as
  `0 < t && 0 < m && 0 < p` (`ManifestImport.cxx:257`). So the only authority
  that defines these attributes imposes no ceiling, and a tuple refused here may
  be entirely legal and openable elsewhere.
- `CipherRejects` — *`argon2` cannot run it.* `m >= 8 * p`, or `p` above
  `argon2::Params::MAX_P_COST`. Widening our own bounds would not help.

A string could not carry that difference, and a consumer told "the format does
not allow this" when the truth is "this crate declined" has been handed a lie it
will render as authoritative. Both the typed variant and the `Display` text now
name the authority, and a test asserts the attribution rather than the wording.

`ParamsReason` and `Argon2Axis` are both `#[non_exhaustive]`: a host that cannot
allocate the requested memory is the next reason expected, and adding it will not
be a breaking change. Inside the crate the `Argon2Axis` `Display` match is
deliberately exhaustive with no `_` arm, so a new axis fails to compile until it
is named rather than silently rendering as something else.

Validated before release by the `encrypted-file-vault` integration, which built
against the release commit as a git dependency and ran its own suite — 0 compile
errors, 21 of 21 passing. Two refinements came back and are in this release.
`is_weaker_than_libreoffice` now documents that it is **any axis below the
reference, not a strength ordering**: a tuple with one fewer pass but twice the
memory reports weaker, which is right for deciding whether to warn and wrong as
a claim about strength. And `EncryptError::Params` now says outright that it is
a *usage* error — the tuple was wrong and the document was never examined — so a
consumer does not render "this file is damaged" for it.

(The integration's worked example for the first point, `(4, 65536, 4)`, turned
out not to reproduce: it reports `false`, correctly. The concern underneath it
did reproduce, on a different tuple, which is now the one the test pins.)

[#40]: https://github.com/Slurp9187/odf-crypto/issues/40

### Changed

**Every conversion of a `zip::result::ZipError` into one of the three `Zip(String)`
payloads now goes through one helper, `crate::zip_err::message`, instead of calling
`e.to_string()` directly.** `ZipError` is `#[non_exhaustive]`
(`zip-2.4.2/src/result.rs:19`) — semver protects the shape of the variants already
enumerated; it does not promise the enumeration stays complete. A new variant landing in
a `zip` 2.x *minor* release would flow its `Display` straight into a public error payload
on a plain `cargo update`, with no compile error anywhere to catch it.

How likely that is, measured rather than asserted, because this repo's rule is to measure
before arguing from a number: across the four versions in the local registry cache —
1.1.4, 2.4.2, 6.0.0, 8.6.0 — `ZipError` gained a variant exactly once, and at a *major*
(`CompressionMethodNotSupported(u16)`, `zip-8.6.0/src/result.rs:32`; 6.0.0 and 2.4.2 both
declare the same five). So the history does **not** show zip adding variants in minors,
and this change is a cheap guard against something `#[non_exhaustive]` permits rather
than a response to something zip has done. The honest case for it is that the cost is one
no-op helper and the failure mode is silent.

What zip *has* done, at a major, is widen a payload: 6.0.0 changed
`InvalidArchive(&'static str)` to `InvalidArchive(Cow<'static, str>)` and began
interpolating an archive entry name (`"Duplicate filename: {}"`,
`zip-6.0.0/src/write.rs:1061`; still there at `zip-8.6.0/src/write.rs:1382`). That is the
only attacker-controlled *free text* among the runtime-interpolated archive errors in
either version. 6.0.0 has just that one; 8.6.0 has two more, and both are bounded —
`zip-8.6.0/src/read.rs:642` interpolates a numeric extra-field id
(`"Extra field {} header truncated"`) and `zip-8.6.0/src/spec.rs:236` a compile-time
`type_name::<Self>()` (`"Unexpected end of {}"`).

No behaviour change: the helper reproduces 2.4.2's `displaydoc` strings byte for byte,
and a test asserts `message(&e) == e.to_string()` for every known variant — the same
test that fires the day a `zip` minor changes its `Display` wording. Two guards ride
along: `InvalidArchive` and `UnsupportedArchive` are matched with their payload bound as
`&'static str`, so a future widening to `Cow` — the exact move 6.0.0 already made once —
is a compile error rather than a silent quote of package text, and the wildcard arm
contributes no text of its own.

Scope, stated honestly: only the 18 genuine `ZipError` sites moved. The 16
`std::io::Error` conversions are untouched on purpose — `io::Error`'s text is
OS-generated, not package-controlled, and `io::Error` is not the `#[non_exhaustive]`
risk this closes. Two adjacent items are recorded, not fixed: `decrypt.rs` still
converts a `quick_xml::Error` into `DecryptError::Zip`, and `quick-xml`'s
`IllFormedError::UnmatchedEndTag(String)` holds a document-derived element name that its
`Display` writes (`quick-xml-0.38.4/src/errors.rs:98`), so manifest-controlled text can
in principle reach that payload unelided. Reachability is doubtful, since `decrypt` runs
`classify` first and a manifest that fails to parse classifies `Plain` and is refused.
(An earlier draft of this entry cited `MissingEndTag` instead. That was wrong and is
worth recording rather than quietly correcting: `MissingEndTag` is constructed only by
`Error::missed_end`, whose callers all live in `quick-xml`'s `src/de/` serde
deserializer, which this crate does not use — so the rewrite path cannot emit it.
`DecryptError::Zip`'s own rustdoc now carries the warning.)
And `encrypt.rs`'s `read_input_mimetype_member` still swallows every `ZipError` via
`let Ok(..) else`, so a corrupt entry is indistinguishable from an absent `mimetype`
member.

`EncryptError::Zip` also gains the "diagnostic, do not match on its content" sentence
its two siblings already carried.

### Fixed

**`DetectError::Inconsistent` no longer interpolates an unbounded
package-controlled string.** The mimetype-conflict message quotes both the
`mimetype` member and `manifest:media-type`. Only the first was bounded — it is
capped at `MIMETYPE_CEILING` — while nothing caps an individual manifest
attribute, so the second was limited only by the 8 MiB `MANIFEST_READ_CAP`.
Measured: padding that attribute by 512 KiB produced a 524,447-character
`Display`, growing linearly to the cap.

Both quoted values are now elided at `DIAGNOSTIC_ELISION` (96 bytes), on a
character boundary — `manifest:media-type` is arbitrary UTF-8 and slicing a
`&str` at an arbitrary byte index would panic, which this crate does not do. The
elided form reports how much was cut (`… [+524231 bytes elided]`): that count is
the part of an anomalous value actually worth having, and it is ours rather than
the package's. A 512 KiB attribute now yields a 243-character message.

This bounds the message's **volume**, not the trustworthiness of its content. A
short hostile value is still reproduced verbatim, because no escaping can tell
`wrong password` from a media type — both are ordinary letters. That half is
addressed by the doc note below telling consumers not to present the string as
the library's own words.

Two tests cover it, and the guard was broken to check they are not decoration:
with the `elide` calls removed the length assertion fails at 524,435 characters.

`Inconsistent` also gains the diagnostic note `BadParameters` already carried —
do not match on its content — plus a warning that it may quote untrusted text.
Severity is low: no memory-safety or cryptographic consequence. It is a
log-flood and UI hazard, and a consumer rendering `DetectError` in a dialog got
whatever the package author wrote. Found jointly with the `encrypted-file-vault`
integration, whose own sibling crate had the same shape bite harder: a crafted
`.docx` declaring `hashAlgorithm="wrong password"` made that consumer's refusal
message say *wrong password*.

### Documentation

- **The goldens are LibreOffice output — all six.** `CLAUDE.md` said "real
  LibreOffice and Apache OpenOffice output"; `meta:generator` inside every
  golden reads LibreOffice 26.2.1.2, `aoo-blowfish-pbkdf2.odt` included, where
  the `aoo-` prefix names the ODF 1.1 Blowfish format family and not a producer.
  `make_goldens.py` only ever drives a local LibreOffice, and `LICENSING.md` §4
  already said so. The corpus proves fidelity to LibreOffice and to the format,
  not agreement between two independent writers.
- **Not every Python helper needs LibreOffice.** `LICENSING.md` §5 and a
  `Cargo.toml` comment both claimed each helper "needs a local LibreOffice over
  UNO to do anything". `ref_decrypt.py` does not: it needs `cryptography` and
  `argon2-cffi`, and its sweep — S5 negatives included — runs offline. That is
  what makes it runnable in CI, which the old wording argued against.

## [0.1.0-rc.3] — 2026-09-15

A dependency upgrade that turned out to carry a confidentiality fix. No public
API moved: `classify`, `decrypt` and `encrypt` have the signatures `0.1.0-rc.2`
shipped.

### Changed

**The dependency graph is two crates smaller in every configuration** —
detection-only goes from 27 crates to **25**, and `crypto-ops` from 61 to
**59**. `secure-gate` moved to `0.9.0-rc.11`, which stopped enabling `zeroize`'s
`zeroize_derive` feature; the derive macro left the graph and took `syn 2` with
it, having had no other reverse dependency that a non-dev build reaches. The
34-crate gap between the two configurations is unchanged. Nothing on the public
API moved: `decrypt` and `encrypt` have the same signatures, and the goldens
decrypt to the same bytes — 107 library tests and 9 doctests pass at the
identical count.

**`secure-gate` is pinned with `=` rather than a caret range**, which is a
departure from every other dependency here and is deliberate. A caret
requirement over a *pre-release* matches later pre-releases of the same version,
and a release candidate promises no compatibility: the previous
`"0.9.0-rc.7"` already resolved to rc.11, so `Cargo.lock` was the only thing
holding the old version in place. rc.9 deleted the `dynamic_alias!` macro this
crate's `sensitive.rs` was built on, which means a bare `cargo update` — no
manifest edit, no review — would have broken the build. The four wrappers are
now plain `type` aliases, which is exactly what the macro expanded to, so no
call site moved.

The pin earned itself the same day: rc.12 published hours later and changed
`Dynamic::new_with` from `(f)` to `(len, f)`. The crate is now on
**`=0.9.0-rc.12`**, and the graph is unchanged by that move.

### Fixed

**Decrypting no longer leaves copies of the document on the heap.** ODF is
deflate-then-encrypt, so every decrypted member is inflated on its way out. That
inflate grew its output buffer as it decoded, and a `Vec` that reallocates frees
the old block *without wiping it* — so each decrypt abandoned partial copies of
the plaintext outside any wrapper, before there was a wrapper to put them in.
Moving the finished buffer into a zeroizing wrapper never addressed it: the
reallocations had already happened.

`manifest:size` declares the inflated length, so the destination can now be
sized before the decode rather than discovered by growing into it, and the
inflate writes directly into the wrapper's own storage. The plaintext never
exists in an unwrapped buffer, and a failed inflate is wiped rather than left
behind.

Two guards came with it, because a sized destination makes `manifest:size` an
allocation length rather than a value checked afterwards. A hostile size is now
refused before any key derivation, and a size that *overstates* the real length
is rejected rather than accepted as a document with a tail of zeros — which is
what a zero-filled destination would otherwise hand back. Suite 107 → 109.

## [0.1.0-rc.2] — 2026-09-04

Adds a command-line front end, and fixes the docs.rs build — which was broken in
`0.1.0-rc.1` and cannot be repaired there, because a published version is
immutable.

### Fixed

**The docs.rs build.** `0.1.0-rc.1` reports `doc_status: false`. Its
`#![cfg_attr(docsrs, feature(doc_auto_cfg))]` is a hard `E0557`: `doc_auto_cfg`
was removed in Rust 1.92 and merged into `doc_cfg`, so the attribute fails on
stable *and* nightly whenever `docsrs` is set — which is exactly and only what
docs.rs does, via this crate's own `rustdoc-args`. Now `feature(doc_cfg)`, which
builds and emits the intended badge, *"Available on crate feature `crypto-ops`
only"*, on the gated items.

CI could not have caught it: the `docs` job runs stable and does not pass
`--cfg docsrs`, so the only configuration that broke was the one nothing built.
A `docsrs` job now mirrors docs.rs — nightly, `--all-features`, `--cfg docsrs`,
`-D warnings` — and was verified by reintroducing the removed feature and
watching the new job fail while the old one passed.

### Added

**A CLI**, behind a `cli` feature that is off by default.

```sh
cargo install odf-crypto --features cli

odf-crypto classify report.odt          # and --json
odf-crypto decrypt  locked.odt -o plain.odt --password-env ODF_PW
odf-crypto encrypt  plain.odt  -o locked.odt --password-stdin
```

A library consumer is unaffected, and that is measured rather than asserted:
the default build still resolves 27 crates with no `rpassword`.

**Passwords never come from `argv`.** There is deliberately no `--password
VALUE` flag — `argv` is world-readable in a process listing for the lifetime of
the run. Four sources instead: `--password-env`, `--password-file`,
`--password-stdin`, or a non-echoing prompt. Two together is an error rather
than a silent precedence win; none with no terminal is an error naming the flags
rather than a prompt nobody can see.

**Exit codes are scriptable**, and 4 is distinct from 5 on purpose: *wrong
password* means try again, *refused* means you had the wrong file. An
unencrypted package passed to `classify` is exit 0 with `encrypted: no` — an
answer, not a failure.

Writes go to a temporary in the destination directory and are renamed over the
target, and never overwrite without `--force`: a decrypt that silently replaced
the encrypted original would be unrecoverable.

Argument parsing is `clap`'s builder API — not `derive`, which is 21 crates
against the builder's 5 — and `--json` is built as a `serde_json::Value`. Both
were hand-rolled first and both were changed after measuring: the hand-rolled
parser rejected `--output=x.odt`, the GNU `--flag=value` form, and offered no
suggestion on a near-miss like `--password-en`. The JSON had no defect; it was
replaced so that a field added later without escaping cannot silently emit
broken output.

## [0.1.0-rc.1] — 2026-09-04

First published release, and a pre-release: the API may change before `0.1.0`. Cargo
does not match a pre-release from an ordinary requirement, so name the full version —
`"0.1"` will not resolve to this.

```toml
odf-crypto = "0.1.0-rc.1"                                    # detection only
odf-crypto = { version = "0.1.0-rc.1", features = ["crypto-ops"] }
```

### Added

- **`classify`** — whether a file is an ODF package, whether it is encrypted, in which
  zip shape (`Plain` / `PerEntry` / `Wholesome`), and with which algorithm tuple. Follows
  LibreOffice's `package/` accept predicates rather than a spec-literal reading, and
  refuses what LibreOffice itself will not open (`odf12_fatal`).
- **`decrypt`** — an LO-encrypted package to the plaintext ODF zip LibreOffice would open
  after a correct password. AES-GCM + Argon2id, AES-CBC + PBKDF2, and Blowfish-CFB +
  PBKDF2, including LibreOffice's four-candidate SHA-1 start-key ladder and the
  deliberately non-conforming `rtl_digest_SHA1` it keeps for compatibility (`tdf#114939`).
- **`encrypt`** — a plaintext `Mode::Plain` package to what current LibreOffice writes
  for that input under a password, backed by a golden that real LibreOffice opens.
- Six LibreOffice- and Apache OpenOffice-produced goldens ship inside the crate, so the
  published tarball verifies its own fidelity claim under `cargo test` rather than
  asking to be believed.

### Features

Detection is the default build and carries no cryptographic dependency — 27 crates.
`crypto-ops` adds `decrypt` and `encrypt`, and takes that to 61. Nobody pays for a
cipher stack to ask whether a file is encrypted.

### Not supported

PGP-encrypted packages are detected (`Classification::pgp_keys`) and refused
(`DecryptError::UnsupportedPgp`), never decrypted.

### Documentation

Every public item is documented, and nine doctests execute against the
LibreOffice goldens shipped inside the crate — so the published tarball verifies
its own fidelity claim rather than asking to be believed. `missing_docs`, seven
`rustdoc::*` lints and three `clippy::*` lints are declared in `Cargo.toml` and
enforced by CI in both feature configurations.

`decrypt` and `encrypt` document their refusal **order**, which is load-bearing
rather than decorative: every ineligible input is rejected before any key
derivation, so no caller pays for PBKDF2 or a 64 MiB Argon2id to learn the
package was never eligible.

### Robustness

No `panic!`, `unwrap`, `expect`, `unreachable!` or `todo!` remains in any
non-test path of the library.

A violated internal invariant returns `DecryptError::Internal` or
`EncryptError::Internal` instead of aborting the caller's process — a library
must not take a process down to report something it could return. `classify`'s
six remaining panics were removed differently: its `pgp_complete` /
`password_complete` guards returned a bool and its builders then re-read the
same fields and unwrapped them, so the guards were folded into the builders.
The completeness test and the extraction are now the same code and cannot
drift, which removes the possibility rather than reporting it.

`DetectError` gains `#[non_exhaustive]`, matching the other two error enums.
None of the three implements `PartialEq`; match with `matches!`.

`DetectError::Manifest` is removed. No code ever constructed it — every
`parse_manifest` failure path discards the rows and returns an empty list,
because LibreOffice does the same and still opens the package. Its
`"failed to parse manifest.xml"` display advertised behaviour the crate
deliberately refuses.

### Licensing

Dual MIT OR Apache-2.0. LibreOffice (MPL-2.0) is the behavioural reference and
[Horsmann/odfdecrypt](https://github.com/Horsmann/odfdecrypt) (Apache-2.0) is prior art;
neither imposes an obligation here. [docs/LICENSING.md](docs/LICENSING.md) records the
evidence for that rather than only the conclusion.

### Requires

Rust 1.85.

## 2026-09-04

Follow-up review of the encrypt arc ([#24](https://github.com/Slurp9187/odf-crypto/pull/24))
and the secure-gate adoption ([#25](https://github.com/Slurp9187/odf-crypto/pull/25)),
taken together now that both have landed. Suite 97 -> 100. Two of the reported
findings were checked against LibreOffice's own source and behaviour rather than
accepted, and one of those turned out to be wrong.

### Measured, not assumed

- **`encrypt` writing a zero-length `mimetype` member is correct, not a bug.** The
  report called it an oversight of `unwrap_or(&[])`. `ZipPackage::WriteMimetypeMagicFile`
  (`ZipPackage.cxx:1125-1160`) is called unconditionally for the ZIP format and writes
  `GetMediaType().getLength()` bytes -- zero when the root folder has no media type. So
  LibreOffice writes the empty member too, and omitting it would be the divergence. The
  call site now carries that citation so it does not get "fixed" later.
- **A whitespace-bearing `mimetype` really can make two things we write disagree**, and
  is now refused. XML 1.0 attribute-value normalization turns a tab/CR/LF in
  `manifest:media-type` into a space, while the `mimetype` zip member is copied verbatim
  -- so the attribute and the member diverge. Confirmed by round-tripping one through a
  real parser. What the report did *not* establish, and what testing showed, is that the
  divergence is unreachable for any loadable file: such an input only passes `classify`
  when its manifest declares no root media type, and real LibreOffice cannot open a
  document of that shape *before* encryption either. Refused anyway, because the previous
  test asserted the divergence was correct -- a wrong claim pinned in place is worse than
  no test.

### Fixed

- **`encrypt()` no longer panics.** Three `.expect()` calls and a `Nonce::from_slice`
  were unreachable under the wholesome profile's `const` asserts, but a dependency bump
  that narrowed what `argon2` or `aes-gcm` accepts would have turned them into an abort
  inside a library. They map onto a new `EncryptError::Internal` instead -- explicitly
  *not* the `BadParameters` analogue plan §4 rules out, since that would report an
  untrusted manifest field and this reports an internal invariant.
- **Every cipher now wipes its key schedule.** `aes-gcm` had `zeroize` on; `aes`, `cbc`,
  `blowfish` and `cfb-mode` did not, so the per-entry AES-CBC and Blowfish read paths
  left an expanded schedule behind where the GCM path did not. secure-gate wraps the
  derived key, but each cipher expands its own copy beyond the wrapper's reach.
- **The per-entry inflate wraps inside the closure that produces it**, not on the next
  line, per the secure-gate skill's own rule that the producer hands back the wrapper.
- **The skill's `file:line` table is re-grepped.** Extracting `kdf.rs` in #24 moved
  `start_key` out of `decrypt.rs` and shifted most of the cited lines; the table had
  drifted again after being fixed once on the #25 branch.
- The S5 shim takes its password from `ODF_ENCRYPT_PASSWORD` rather than argv, which is
  world-readable in a process listing; `build_manifest` uses `from_utf8` rather than a
  second, weaker lossy path; and the plan's "borrow decrypt's `Zeroizing` handling"
  pointer now names secure-gate.

### Newly covered

Non-ASCII password round trip (this arc's start key is SHA-256 over UTF-8 and nothing
exercised it); `DEFLATE_CEILING`'s rejection, via a ceiling parameter so the test costs
no gigabyte; and `odf_version` / `has_unexpected_streams` on encrypt's own output, the
two properties the LibreOffice wholesome golden was already pinned on.

## 2026-09-03

Two arcs, in the order they landed: the secure-gate adoption
([#25](https://github.com/Slurp9187/odf-crypto/pull/25)), then password encryption
([#24](https://github.com/Slurp9187/odf-crypto/pull/24)), which was written against the
zeroize-era code and adopted secure-gate on the way in.

### secure-gate adoption

**secure-gate is now the crate's only zeroizing primitive.** `secure-gate = "0.9.0-rc.7"`
(`alloc` only, unconditional — not gated on `decrypt` like the algorithm crates) replaces the
direct `zeroize` dependency. Nothing on the public API moved: `decrypt(bytes: &[u8],
password: &str) -> Result<Vec<u8>, DecryptError>` is byte-for-byte unchanged, and the
returned zip is still a plain `Vec<u8>`. Everything between those two ends is wrapped:

- `PasswordDigest` and `DerivedKey` (`src/sensitive.rs`) replace the two `Zeroizing<Vec<u8>>`
  values in `derive_key`. `start_key` now writes the digest straight into the wrapper via
  `finalize_into` instead of returning it through a stack `GenericArray` and copying.
- `DeflatedPlaintext` and `MemberPlaintext` wrap every decrypted member from the cipher
  call to the zip writer. The in-place ciphers (CBC, Blowfish) wrap the buffer before the
  first block is decrypted, so stripped CBC padding lands in zeroized spare capacity;
  `rebuild_zip` writes each member from its wrapper rather than cloning it into a plain
  buffer.
- `MAX_DERIVED_KEY_LEN = 64` bounds `manifest:key-size` before the key buffer is allocated.
  `derived_key_len` is an `i32` the manifest controls; a value near `i32::MAX` used to
  allocate ~2 GiB and then run PBKDF2 over all of it before any cipher rejected the length.
  AES-256 needs 32 and Blowfish takes at most 56, so nothing LibreOffice opens is refused.
  New test: `hostile_derived_key_len_is_refused_before_allocating`.

Documented, not fixed: the `Sha1`/`Sha256` hasher buffers the raw password bytes until
`finalize` and `compress` spills its schedule on the stack; the 0.10 digest crates offer no
`zeroize` feature and hand-rolling the hash would remove one copy and leave the other.

Suite: 79 passing. Policy lives in `.claude/skills/odf-crypto-secure-gate/SKILL.md`, the
first repo-specific skill here (the repo has no CLAUDE.md yet).

### The encrypt arc

The crate writes as well as reads. `encrypt(&[u8], &str)` turns a `Mode::Plain` ODF
package into what current LibreOffice writes for it under a password — wholesome
Argon2id + AES-256-GCM, one `encrypted-package` member, no checksum,
`manifest:version="1.4"` — closing arc
[#18](https://github.com/Slurp9187/odf-crypto/issues/18) and its five slices
([#19](https://github.com/Slurp9187/odf-crypto/issues/19)–[#23](https://github.com/Slurp9187/odf-crypto/issues/23)).
Per-entry write (Blowfish CFB / AES-CBC) and PGP wrap stay later arcs, cited in the plan
so neither has to re-derive its primitives. The suite went 79 → 97 (the secure-gate arc had taken it 78 → 79 first).

#### Evidence, in three independent directions

- **Against ourselves.** `decrypt(encrypt(p, pw)?, pw)? == p`, byte-for-byte — for the
  golden and for a constructed package with non-ASCII text and a binary member, each
  asserted `Mode::Plain` first so the round trip cannot pass vacuously.
- **Against LibreOffice.** Real LO 26.2.1.2, which has never seen a line of this crate,
  opens `encrypt()`'s own output and recovers the exact text
  (`tests/goldens/validate_encrypt.py`). The file it validated is checked in as
  `tests/goldens/lo-opens-our-encrypt-output.odt`, and a test now decrypts that artifact
  back to its source golden so it stays live between LibreOffice runs — CI will never
  have LO, but it can still catch a framing change that `encrypt` and `decrypt` mirror.
- **Against a third implementation.** The Python oracle from the decrypt arc
  (`ref_decrypt.py`, which shares no code with either direction) decrypts that same file
  byte-identically, and now sweeps it as a fifth entry.

#### What review changed

Fifteen findings from a three-lens adversarial pass, all before merge. The two that were
bugs rather than hardening:

- **`cargo test --no-default-features` did not compile.** `cargo test` builds example
  targets, and the new validation example calls `encrypt` unconditionally — so the
  standing check every slice names as a done-when was broken by the slice that added the
  example. `required-features` fixes it.
- **Key derivation could panic or abort inside a public `decrypt()`.** `argon2`'s
  `Params::new` tests `m_cost < p_cost * 8` *before* range-checking `p_cost`, so a
  manifest claiming 2^29 lanes overflowed `u32`; and an `argon2-memory` of 2 GiB (KiB)
  asked `vec!` for ~2 TiB, which aborts the process rather than returning an error. Both
  pre-existed this arc — relocating derivation into the shared `src/kdf.rs` is what put
  them in one place to fix. LibreOffice's own libargon2 returns
  `ARGON2_MEMORY_ALLOCATION_ERROR` here, so a ceiling is what *matches* LO, not a
  divergence from it; the decrypt plan's "no cap" note now carries that carve-out.

Also: the input's `mimetype` member is bounded and checked for XML-1.0-legal characters
before being copied verbatim (`classify` admits a package on its first 1024 bytes, so an
unbounded copy was a side door around `DEFLATE_CEILING`, and a NUL would emit a manifest
expat rejects — a package that classifies here and will not open there); the wholesome
profile is one `const` consumed by both the KDF call and the manifest emit, so the two
cannot drift; `derive_key` no longer allocates a key buffer it discards; the AES-GCM seal
is one `Aes256Gcm` call rather than a duplicated three-way dispatch whose 128/192 arms
were unreachable; the payload is encrypted in place instead of copied four times; and
`src/test_support.rs` replaces three drifted copies of the test helpers.


## 2026-09-02

No `src/` change and the suite stayed at 66 passing. `tests/goldens/` gained one
probe file, and the decrypt arc was planned — both at the end of this entry.

**All four plan open questions are now closed, and with them arc
[#1](https://github.com/Slurp9187/odf-crypto/issues/1).** The last two were settled from
the LibreOffice source at the pin rather than from a corpus, because the corpus that
gated them does not exist and was not coming:

- **The nested `content.xml` latch stays keyed on the short name** ([#8](https://github.com/Slurp9187/odf-crypto/issues/8)).
  No LibreOffice or Apache OpenOffice save path emits a package whose *only* complete
  latch row is a nested `content.xml` — a per-entry save always writes and encrypts a
  root one, and in a wholesome package the nested copy is sealed inside the
  `encrypted-package` blob where `classify` never sees it. More decisively, no corpus
  evidence *could* change the implementation: a third-party file shaped that way would
  still be latched by LibreOffice, so matching it stays correct.
- **SHA512-1K cannot reach a written manifest** ([#9](https://github.com/Slurp9187/odf-crypto/issues/9)).
  The GPG path does briefly default the checksum to SHA512-1K, but `ManifestExport`
  throws on any digest id other than SHA1-1K and SHA256-1K, unconditionally — so the
  default is unreachable whether or not the save path overrides it first. `Checksum`
  gains no variant and the URI table is complete.

Three things were also moved from "undecided" to decided, which matters mostly to
whoever builds the decrypt arc on top of this:

- **`classify` is normal-load-only.** LibreOffice suppresses about a dozen of the
  refusals below under Repair; reproducing that is out of scope. Every refusal this
  crate makes assumes a normal load.
- **`Classification` will not grow LibreOffice's internal storage flags** — with one
  named limitation: `media_type` carries no provenance, so a consumer cannot tell a
  manifest-declared type from one sniffed off the `mimetype` stream.
- **The unaudited remainder of LibreOffice's zip structural checks** (overlapping
  entries, STORED size mismatch, data-descriptor holes, `Count != Total`, name length)
  is recorded as *unquantified* risk rather than low risk. Two members of that family
  turned out to be major bugs; the rest simply were not looked at.

### The decrypt arc, and its first open question closed the same day

[The decrypt plan](docs/plans/odf-encryption-decrypt-2026-09-02.md) is written: password
decrypt only, consuming `classify` rather than re-parsing the manifest, in five slices.
Review against the LibreOffice pin caught two errors that would each have sunk a slice.

**Blowfish is 64-bit-segment CFB on the wire, not CFB-8.** `BlowfishCFB8CipherContext` is
a misleading name — it asks sal for `rtl_Cipher_ModeStream`, and both sal backends
implement that as CFB-64: the in-tree `BF_updateCFB` re-encrypts its register every 8
bytes, and the OpenSSL backend calls `EVP_bf_cfb()`, which is `bf_cfb64`. Decrypting the
Blowfish golden confirms it — CFB-64 reproduces the stored SHA1-1K checksum, CFB-8 does
not. Horsmann's odfdecrypt has this backwards too, and only works on LibreOffice files
because its origin detector misroutes them to its Apache decryptor, which uses CFB-64.
There is one Blowfish wire format; the planned “AOO CFB-64” arc was deleted as vacuous.

**A wholesome `encrypted-package` is deflated before it is encrypted.** The plan had said
the decrypted blob *is* the inner package; it is the inner package **compressed**. The
golden's member is 6530 bytes — 12 IV + 6502 ciphertext + 16 tag — against a
`manifest:size` of 6977.

**OQ1 is closed with a measurement, not an argument** —
`tests/goldens/lo-odf11-nonascii-password.odt`. LibreOffice keeps a four-rung fallback
ladder for SHA-1 start keys, and its own comment says the ladder applies to “ODF
1.1/OOoXML files written by any version”, which is precisely the shape of our Blowfish
golden — so it could not be waved away as legacy-only. The new golden's password is
built so all four candidates are distinguishable: one non-ASCII character separates UTF-8
from MS-1252, and its length (53 and 52 bytes in those two encodings) lands both inside
the window where `rtl_digest_SHA1` diverges from real SHA-1 (tdf#114939 — a comparison
LibreOffice documents as wrong and keeps for compatibility). Only the **correct UTF-8
SHA-1** start key decrypts the file, which `tests/goldens/sha1_star.py` re-derives on
demand rather than asking anyone to take it on trust. Current LibreOffice writes the correct digest even
where it still tolerates the buggy one on read, so the decrypt arc implements one start
key per algorithm and treats the ladder as read-compat it does not provide.

`make_goldens.py` also gained a longer bootstrap wait: a cold UNO profile took 37s here
against a 30s limit, which fails as “could not connect”.

## 2026-09-01

The crate was written, adversarially audited against LibreOffice `package/` at
`07047a02f94d`, and repaired — all on the same day. If you are picking this up cold,
this is the entry that matters.

### What it does

`classify(&[u8]) -> Result<Classification, DetectError>` is the only entry point. It
answers whether a file is an ODF package, whether it is encrypted, in which zip shape
(`Plain` / `PerEntry` / `Wholesome`), and with which algorithm tuple. **It does not
derive keys and does not decrypt** — there is no crypto dependency in `Cargo.toml`, so
that is structurally guaranteed rather than merely intended.

It is not a port. It re-derives LibreOffice's accept predicates by running the same two
machines — `ManifestImport`, then `ZipPackage::parseManifest` — because LibreOffice's
answer is not a pure function of independent manifest rows. State leaks across rows in
ways a tidy per-row implementation gets wrong on constructible input: a sticky
`key_info` pointer, an order-dependent derived key size, a lookup cache that can resolve
a row onto a stream its path does not name.

`classify` also **refuses archives LibreOffice refuses to open** — invalid entry names,
duplicate names, stream/folder collisions, STORED-with-data-descriptor entries the
manifest never accepted as encrypted. Before that, it answered confidently for files
LibreOffice will not open at all, which let a crafted archive pick its own verdict.

Four real LibreOffice files back this up in `tests/goldens/` — wholesome GCM+Argon2id,
per-entry AES-CBC, Blowfish+PBKDF2, and an unencrypted document — with every URI they
contain recorded in `URIS.md`. All of them match the plan's predictions, which is the
strongest evidence the URI tables have.

### If you used an earlier build

- The crate was **renamed from `odf-decrypt` to `odf-crypto`**; the lib target is now
  `odf_crypto`.
- **`derived_key_len` is `i32`, not `u8`.** LibreOffice keeps `manifest:key-size` as a
  `sal_Int32` with no floor or ceiling; the old type silently clamped `key-size="256"`
  to 255 and `"-8"` to 0 (`C2`).
- **`EntryEncryption::path` is the resolved tree path**, not the manifest's `full-path`.
  These differ only when LibreOffice's own lookup lands a row on a different stream than
  its path names (`A10`).
- **A malformed `manifest.xml` now yields `Plain` with zero rows** instead of an error —
  or, worse than an error, a package reported as encrypted from half-parsed rows.
  LibreOffice swallows the parse failure and opens the file (`A3`).
- **The `base64` dependency is gone.** Its strict decoder rejected input LibreOffice
  accepts, silently handing back an empty salt or IV on a row still reported as
  encrypted (`C1`).

### Corrected behaviour

Ten divergences changed the answer `classify` gives. The ones most likely to bite a real
file:

- Integer parsing did not match `OUString::toInt`: a leading `+` read as 0, flipping an
  Argon2-encrypted file to `Plain` (`A1`).
- A mistyped root element dropped every `file-entry`, because level-2 elements were
  gated on the root's validity where LibreOffice has no such check (`A2`).
- `Mode::Wholesome` keyed on any row whose short name matched, so a nested
  `Object 1/encrypted-package` could force it (`A4`).
- Root-membership lookups consulted the flat zip namelist instead of the folder tree —
  the one anti-pattern the plan names outright (`A6`, `A7`).
- Folder rows could not clear a media-type or version that an earlier row had set (`A5`).
- Leading-slash and doubled-slash paths resolved differently than
  `hasByHierarchicalName` (`A8`, `A9`, `A10`).
- Manifest parsing was quadratic in nesting depth: an 854-byte zip occupied `classify`
  for 12–25 seconds. It now takes 23 ms (`B7`).
- Entity references in element text were silently deleted, attribute values were not
  whitespace-normalized, and a second `encryption-data` element read its checksum from
  the wrong place (`C3`, `C4`, `C5`).

Seven behaviours were already correct but had no test holding them there — each survived
being deliberately broken with the suite still green, including the one the plan calls
its marquee quirk. They have fixtures now (`D1`–`D7`).

### Where the reasoning lives

- [The plan](docs/plans/odf-encryption-detection-2026-09-01.md) is the design record:
  predicates, URI tables, the two-stage machine, and the LibreOffice quirks that make a
  row-independent implementation wrong. Stamped `Shipped (2026-09-01)`.
- [The audit](docs/audits/classify-lo-fidelity-2026-09-01.md) records all 54 findings —
  including the 2 that were refuted and the 13 narrowed under challenge — and, at the
  end, what was deliberately left uncovered.
- [The plan/slice workflow](docs/plan-workflow.md) is how arcs get filed and closed here.
