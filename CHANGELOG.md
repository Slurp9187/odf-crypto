Status: Living — dated entries, newest first

# Changelog

Keyed by **date, not release**. Nothing is published, the version has stayed `0.1.0`
throughout, and the work is organized by arc — a release-style changelog would have one
heading and tell you nothing. When the crate is first published this file gains version
headings above the dates; the dates stay.

Finding ids (`A1`–`A10`, `B1`–`B7`, `C1`–`C7`, `D1`–`D7`) index into
[the audit](docs/audits/classify-lo-fidelity-2026-09-01.md), which carries the
LibreOffice citation and a reproduction for each.

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
