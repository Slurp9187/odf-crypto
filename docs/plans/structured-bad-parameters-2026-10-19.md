Status: **Planned.** Authored 2026-10-19 by the encrypted-file-vault session that consumes this crate (EFV #1064, the #309 line). The owner decided the shape (below). Five scope points went to the owner with recommendations on 2026-10-19 UTC, and this plan follows those recommendations until the answers arrive (§ Open points). No code has landed.

# Plan — a decrypt refusal carries no text from the file

> **Goal.** `DecryptError::BadParameters` reports *which* manifest setting is
> wrong, the value the file declares, and the range that was allowed, as closed
> enums and integers. Nothing the file chose (a path, a name, a third-party
> crate's message picked by the file) reaches the error or its `Display`. A
> consumer can then write its own sentence: *"This file declares 20 Argon2
> passes; the most this app reads is 10."*

## Why

The owner's decision (2026-10-19 UTC, relayed through EFV's coordinator):
structure the decrypt-side refusal like the write side's
`ParamsReason::OutOfRange { axis, got, min, max }`. That means a closed enum of
which setting, the value the file declares and the allowed range, with **no free
text from the file anywhere in the error or its Display**.

Two facts from the survey (read-only, at `ffe80bf`) make this more than tidiness:

- **`decrypt.rs:598` prints `manifest:full-path` with no bound.**
  `format!("row path {path:?} has no zip member")` can carry up to
  `MANIFEST_READ_CAP` (8 MiB) of file-chosen text. `DIAGNOSTIC_ELISION`
  (`limits.rs`) was added to bound exactly this for `DetectError::Inconsistent`,
  but nothing bounds this site, and the CLI's `report()` prints it to stderr. It
  is reached from `decrypt_entries.rs`, `decrypt_stream.rs` and `reencrypt.rs`.
- **The file chooses which `argon2` message appears** (`kdf.rs`'s
  `"argon2 params: {e}"` and `"argon2: {e}"`). In argon2 0.5.3 each one is a
  fixed `&'static str`, so this is not file text. It is still a third party's
  wording passed through untyped, and `SaltTooShort` is reachable because
  nothing screens the decoded salt length before the KDF runs.

Every other site already renders only fixed text, integers from the file and our
own enum names. The string type is what makes the next site free to break that.

## The shape

`DecryptError::BadParameters(BadParameter)`, where `BadParameter` is
`#[non_exhaustive]`, `Copy + Eq`, derives `thiserror::Error`, and has a
hand-written exhaustive `Display` in its supporting enums (no `_` arm, the same
discipline as `Argon2Axis` and `AllocationSite`). It sits under `crypto-ops`,
like `decrypt`.

```rust
#[non_exhaustive]
pub enum ManifestField {
    IterationCount,       // manifest:iteration-count (PBKDF2)
    Argon2(Argon2Axis),   // loext:argon2-iterations / -memory / -lanes (reused as is)
    KeySize,              // manifest:key-size
    Size,                 // manifest:size
    IvLen,                // manifest:initialisation-vector, decoded length
    SaltLen,              // manifest:salt, decoded length
    EncryptedEntries,     // how many encrypted rows
}

#[non_exhaustive]
pub enum BadParameter {
    /// Outside the range this crate acts on (limits.rs, DecryptLimits).
    OutOfRange { field: ManifestField, got: i64, min: i64, max: i64 },
    /// A primitive cannot run it: argon2's m >= 8p and p <= MAX_P_COST, a salt
    /// of at least 8 bytes, a cipher's IV length.
    CipherRejects { field: ManifestField, by: Primitive, got: i64, min: i64, max: i64 },
    /// key-size not usable with the row's cipher: AES takes the set {16, 24, 32}.
    KeySizeForCipher { got: i32, cipher: Cipher },
    /// A member's shape disagrees with its manifest row.
    Member(MemberFault),
    /// A manifest row names no zip member, given as its index, never its path.
    NoMember { row: usize },
}
```

- **`i64` for `got`, `min` and `max`** holds every value exactly: `i32` costs and
  key size, `i64` size, `u32` counts. A `usize` count saturates through
  `i64::try_from(..).unwrap_or(i64::MAX)`, which cannot panic.
- **The write side's type is not reused.** `ParamsReason` is about a caller's own
  tuple and maps to exit 1 (usage); `BadParameters` maps to exit 6. One type with
  two exit codes would read wrong.
- **The variant is chosen by which bound failed.** Below a floor the format sets
  is `OutOfRange` (as `ParamsReason::OutOfRange` folds format floors in). Above
  this crate's `DecryptLimits` is `OutOfRange`. Above what argon2 or the cipher
  can run is `CipherRejects`. Today `kdf.rs`'s lanes message names no range at
  all.
- **`argon2::Error` is matched, never formatted.** `m >= 8p` and the salt length
  are checked before `Params::new`, so the KDF never starts on a tuple that
  cannot run. Any other argon2 error is `Internal`, because nothing reaches it
  past those checks.
- **`KdfError::Params` and `stream::Fault::BadParameters` carry the same
  `BadParameter`.** The two pass-throughs stay one line each. The encrypt side's
  `KdfError::Params(s) => EncryptError::Internal(s)` renders the structured value.

## The sites

There are 28 production construction sites, with a file:line table in the survey
that seeded this plan. By outcome:

- **Range checks become `OutOfRange` or `CipherRejects`:** the encrypted-entry
  count, PBKDF2 iterations (negative too), the Argon2 `t`, `m` and `p` (negative
  too), `manifest:size` on both paths, the IV lengths and the salt length.
- **Shape faults become `Member(MemberFault)`:** shorter than IV plus tag,
  inconsistent IV, not a block multiple (the streamed form reports no `got`,
  because it sees a chunk, not the total), and longer than its zip header says.
- **`decrypt.rs:598` becomes `NoMember { row }`.** The path is dropped. `row`
  plus `odf-crypto inspect`'s row list gets it back.
- **About nine invariant sites move to `Internal`** (§ Open points, 1). Each is
  unreachable past `screen_shape`, or is our own dispatch: the derived-key length
  guard, the AES-GCM, AES-CBC and Blowfish key/IV setup failures, and
  `decrypt_entries.rs`'s "GCM member reached the checksum path".
- **Two sites wait on a fact.** Whether Wholesome mode guarantees the
  `encrypted-package` row (`decrypt_stream.rs`, `reencrypt.rs`) decides
  `Internal` versus `Member(NoPackageRow)`; it is checked against `classify`
  first. `decrypt_stream.rs`'s 32-bit "rebuild of {bound} bytes" is a host limit,
  so it moves to `HostCannotAllocate`, which is exit 7.

## What else moves

- **CLI.** `bin/odf-crypto.rs`'s exit map keeps `BadParameters` at 6, with the
  pattern's shape changed. Every site that moves to `Internal` changes 6 to 5.
  The CHANGELOG lists each one.
- **Tests.** Seven assertions in `decrypt_tests.rs` read the string. They become
  variant matches. The negative guard (`!matches!(.. m.contains("shorter than
  IV+tag"))`) is rewritten so it cannot pass both ways, and is broken once to
  prove it. There are two new tests: a 1 MiB hostile `manifest:full-path` never
  appears in `Display` or `Debug`, and a salt under 8 bytes is refused before the
  KDF runs.
- **Docs.** `troubleshooting.rs`'s doctest matches `BadParameters(msg)` and its
  table says the variant "quotes manifest field values". Both are rewritten. Also
  updated: the variant doc, the `kdf_error`/`KdfError` docs, `screen_shape`'s
  "messages are unchanged, deliberately", and the README, which gains a read-side
  companion to the `ParamsReason` table.
- **CHANGELOG.** Open `## [0.1.0-rc.13] - Unreleased`. The breaking change is
  `DecryptError::BadParameters(String)` becoming `BadParameters(BadParameter)`.
  Every exit-code move and the closed path leak are listed.
- **Every feature configuration** builds and tests: detect-only, `crypto-ops`
  and `cli`.

## Open points (sent to the owner 2026-10-19 UTC, with recommendations)

1. Invariant sites leave `BadParameters` for `Internal` (exit 6 → 5).
   Recommended: yes.
2. The row is named by its index instead of its path. Recommended: yes.
3. (msoffice-crypto's companion arc) `UnsupportedAlgorithm.name` closes too.
4. The shape above; one PR, because the tree cannot build half converted.
   Recommended: yes.
5. (msoffice-crypto only) the four-reader gate is rerun once on the final tree.

## Slices

One branch, one PR. The commits follow these slices, and each slice is a
sub-issue under the parent.

| slice | what | done when |
| --- | --- | --- |
| S1 | `BadParameter`, `ManifestField`, `MemberFault`, `Primitive`; `KdfError`/`Fault` carry it; argon2's tuple and salt checked before the KDF | every site compiles against the new types in all three configurations |
| S2 | the 28 sites converted; invariants to `Internal`; the row path to `NoMember { row }` | the new hostile-path and short-salt tests pass and each is broken once to prove it |
| S3 | CLI exit map, tests rewritten from strings to variants, troubleshooting doctest, docs, README, CHANGELOG `rc.13 - Unreleased` | the full test count (`--list`) is unchanged or higher in every configuration; CI green |

## Release

The owner publishes. This arc bumps `version` to `0.1.0-rc.13` with a `--locked`
lock refresh and opens the CHANGELOG section. It does not tag, cut or publish.
EFV moves its exact pin only after the owner publishes, in its own PR, and
rewrites its sentence from the structured value (EFV's
`file_controlled_text_cannot_impersonate_our_prose` stays green).
