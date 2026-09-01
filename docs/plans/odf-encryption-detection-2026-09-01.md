Status: Planned — detection-only crate; decrypt is a later arc · Authored 2026-09-01

# Plan — ODF package encryption detection

> **Goal.** A Rust `classify` that answers *is this an ODF package, is it encrypted,
> in which mode, and with which independent algorithm tuple* — following
> LibreOffice’s `package/` predicates, not Horsmann’s Python origin detector.
>
> **This crate does not derive keys and does not decrypt.** Those fields exist so a
> later crypto crate can consume a typed description. Detection is the whole
> deliverable.

This is **not** MS-OFFCRYPTO / OOXML `EncryptedPackage` inside OLE.

## Authority

Verified 2026-09-01 against two local trees. Do not re-download LibreOffice.

| Tree | Path | Pin |
|---|---|---|
| LibreOffice core | `O:\projects-github-clones\LibreOffice\core` | `95e83feb2e85` (30 Aug) through `07047a02f94d` (pull 2026-09-01). **`package/` is identical across that range.** Re-check `package/` + `sfx2/source/doc/objstor.cxx` + `comphelper/source/misc/storagehelper.cxx` before changing this plan. |
| Horsmann odfdecrypt | `O:\projects-github-clones\odfdecrypt` | Read for interop quirks and *negative* examples. Never the detector. |

Primary LO files:

- `package/source/manifest/ManifestDefines.hxx` — URI and name aliases
- `package/source/manifest/ManifestImport.cxx` — XML → property bag; `bIgnoreEncryptData`; Argon2 `manifest:` vs `loext:`
- `package/source/manifest/ManifestExport.cxx` — what LO *writes* (wholesome omits `/`)
- `package/source/zippackage/ZipPackage.cxx` — accept predicates, package latch, ODF ≥ 1.2 inconsistency
- `package/source/zippackage/ZipPackageFolder.cxx` — `LookForUnexpectedODF12Streams`
- `include/comphelper/documentconstants.hxx` — `ODFVER_012_TEXT = "1.2"`, `ODFVER_013_TEXT = "1.3"`

Save-side only (do not use on read): `sfx2::UseODFWholesomeEncryption`, `SfxObjectShell::SetupStorage`.

There is **no** `detectEncryptionVersion()`. Mode is not chosen from ODF version. ODF version `>= "1.2"` only tightens extra-stream consistency (and, on save, whether `start-key-generation` is written). `"1.3"` only switches PGP element names `loext:` → `manifest:`.

LibreOffice does **not** use HPKE / DHKEM (`package/` has zero matches). Combinations are independent manifest fields applied in a pipeline:

```
UTF-8(password)
  → start key (SHA-1 or SHA-256)
  → KDF (PBKDF2-HMAC-SHA1 or Argon2id; PGP wrap is a third path)
  → cipher (Blowfish-CFB-8, AES-CBC, or AES-GCM)
  → optional checksum (SHA-1-1K / SHA-256-1K); omitted for GCM
```

## Out of scope

- Key derivation, password checks, inflate, writing a decrypted zip
- OOXML / OLE `EncryptedPackage`
- Guessing LibreOffice vs Apache OpenOffice from `meta:generator`, Thumbnails, Configurations2, or “mixed algorithms”
- Substring `is_encrypted` (`"encryption-data" in manifest`)
- Implementing PGP unwrap (detect and type it; do not decrypt)

## 1. Modes and the package latch

Four outcomes. The first three are password-or-PGP *shapes*; PGP can sit on either zip shape.

| Mode | Zip | Manifest | Package latch |
|---|---|---|---|
| `Plain` | anything without a complete latch row | no complete encryption-data on `content.xml` / `encrypted-package` | `HasEncryptedEntries = false` |
| `PerEntry` | ordinary members (`content.xml`, `styles.xml`, …) carry encryption-data | no `encrypted-package` zip member | latch if a complete tuple is on a member whose **short name** is `content.xml` |
| `Wholesome` | zip **has** a root member named `encrypted-package` | that member’s file-entry has a complete tuple; `/` is usually omitted | latch if the short name is `encrypted-package` |
| `Pgp` | either shape | `KeyInfo` + KDF name `PGP` + wrap `xmlenc#rsa-oaep-mgf1p` | same latch names |

**Wholesome is a zip check.** `ZipPackage::parseManifest` passes `m_xRootFolder->hasByName("encrypted-package")` into `LookForUnexpectedODF12Streams`. A manifest row whose `full-path` is `encrypted-package` but whose zip member is missing is **not** wholesome and is not applied (`hasByHierarchicalName` fails).

**Package-level “this file is encrypted”** (`m_bHasEncryptedEntries`, `ZipPackage.cxx` ~349–353 and ~434–438):

```
complete encryption-data tuple
  AND ZipPackageStream::getName() ∈ { "content.xml", "encrypted-package" }
```

`getName()` is the last path component (`ZipPackageEntry.cxx` 53–55). Other encrypted members are still marked encrypted (`SetIsEncrypted(true)`) but do **not** flip the latch; they set `m_bHasNonEncryptedEntries` when the tuple is incomplete.

⚠️ Nested `foo/content.xml` would also latch. Treat that as specified-by-LO until open question 2 is closed.

## 2. Complete-row predicates

Apply a row only if `full-path` is nonempty **and** that path exists in the zip.

**Password** (`ZipPackage.cxx` ~360–367):

```
salt && iv && size && enc_alg && kdf
&& ( (kdf == PBKDF2 && iteration_count_present) || (kdf == Argon2id && argon2_args) )
&& ( enc_alg == AES_GCM || (digest && digest_alg) )
```

**PGP** (`ZipPackage.cxx` ~297–302):

```
key_info && iv && size && enc_alg
&& kdf == PGP_RSA_OAEP_MGF1P
&& ( enc_alg == AES_GCM || (digest && digest_alg) )
```

Implications, all from those predicates plus `ManifestImport.cxx`:

- `manifest:size` is **required**. Missing size → not encrypted.
- GCM: checksum optional. CBC / Blowfish: checksum **and** checksum-type required.
- PBKDF2: `iteration-count` property must exist. Empty attribute becomes `0` (`toInt32`) and still counts. Detect does **not** require `> 0`.
- Argon2: `t, m, p > 0` at import (`ManifestImport.cxx` 257–266). Otherwise drop that encryption-data.
- `start-key-generation` is **optional**. Default SHA-1 (`ZipPackage.cxx` 376).
- Unknown cipher / KDF / start-key URI sets `bIgnoreEncryptData`. That flag is **not** visible to `ZipPackage` and already-parsed fields are **not** stripped. Typical LO element order is algorithm → start-key → KDF, so an unknown start-key usually also skips KDF and the row fails. If KDF appears first, an unknown start-key can still accept with default SHA-1.

## 3. Version

| Field | Effect on detect |
|---|---|
| `manifest:manifest/@manifest:version` | `m_PackageVersion`. Copied onto the **first** file-entry if that entry has no version (`ManifestImport.cxx` 455–466). Needed because wholesome omits `/`. |
| `file-entry/@manifest:version` on `/` | Root folder version. |
| First-entry / package version when `/` is missing | Becomes `oFirstVersion`; copied onto the root in the mimetype-fallback branch when root media-type is empty (`ZipPackage.cxx` 504–507). |
| `version >= "1.2"` | Unexpected streams are fatal (unless recovery). META-INF hidden from the user. Start-key uniformity is a TODO in LO, **not enforced**. |
| `version >= "1.3"` | PGP children use `manifest:` names instead of `loext:`. No password-tuple change. |
| Empty version | Treat as pre-1.2 for consistency rules (`compareTo("1.2")` is negative). |

Wholesome unexpected-member rule (`ZipPackageFolder.cxx` 67–117): only `mimetype`, `encrypted-package`, `META-INF/manifest.xml`, and `META-INF/*signatures*` (substring `signatures`). Any other root file or any folder other than `META-INF` is unexpected.

Non-wholesome ODF ≥ 1.2: every non-`mimetype` stream outside those META-INF exceptions must be listed in the manifest (`IsFromManifest()`).

Document media-type when wholesome: the `encrypted-package` file-entry’s media-type, and it must match the `mimetype` stream when both exist (`ZipPackage.cxx` 520–528).

## 4. URI aliases

Namespaces rewritten to a `manifest:` prefix: `http://openoffice.org/2001/manifest` and `urn:oasis:names:tc:opendocument:xmlns:manifest:1.0`. `loext:` (`urn:org:documentfoundation:names:experimental:office:xmlns:loext:1.0`) is **not** rewritten.

LO **reads** both names and URLs. LO **writes** the emit column. Implement **read** aliases. Do not implement odfdecrypt’s extra URLs as if they were LO.

| Role | Accept (LO) | LO emit | Do not treat as LO |
|---|---|---|---|
| Blowfish | `"Blowfish CFB"` or `urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#blowfish` | `"Blowfish CFB"` | `#blowfish-cfb8` (Python only; LO drops the row) |
| AES-CBC | xmlenc `aes128-cbc` / `aes192-cbc` / `aes256-cbc` | `aes256-cbc` only (export requires key size 32) | — |
| AES-GCM | xmlenc11 `aes128-gcm` / `aes192-gcm` / `aes256-gcm` → all `AesGcm` | `aes256-gcm` only | — |
| PBKDF2 | `"PBKDF2"` or oasis `#pbkdf2` | `"PBKDF2"` | `http://www.w3.org/2001/04/xmlenc#pbkdf2` |
| Argon2id | oasis `…manifest:1.5#argon2id` **or** `urn:org:documentfoundation:names:experimental:office:manifest:argon2id` | experimental URN | Python accepts only the experimental URN |
| Argon2 params | `manifest:argon2-{iterations,memory,lanes}` **or** `loext:…` (prefer `manifest:` if both) | `loext:…` | Hardcoded defaults when attrs missing — LO rejects t/m/p ≤ 0 |
| Start SHA-256 | `http://www.w3.org/2001/04/xmlenc#sha256` **or** `http://www.w3.org/2000/09/xmldsig#sha256` (OFFICE-3708) | GCM → xmlenc; AES-CBC → **xmldsig** | Python accepts only xmlenc |
| Start SHA-1 | `"SHA1"` or `http://www.w3.org/2000/09/xmldsig#sha1` | `"SHA1"` | `http://www.w3.org/2001/04/xmlenc#sha1` |
| Checksum SHA-1-1K | `"SHA1/1K"` or oasis `#sha1-1k` | `"SHA1/1K"` | — |
| Checksum SHA-256-1K | oasis `#sha256-1k` | that URL | Python does not parse it |
| PGP KDF | `"PGP"` and only after a valid encrypted-key | `"PGP"` | — |
| PGP wrap | `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p` | that URI | — |

Derived-key-size default: Blowfish 16; AES-CBC/GCM implied 32/24/16 from the cipher URI if `key-size` is missing; else 16 (`ManifestImport.cxx` 283–291, `GetDefaultDerivedKeySize` in `ZipPackage.cxx` 137–148).

## 5. Types

One crate, no key-derivation dependency.

```rust
enum Mode { Plain, PerEntry, Wholesome, Pgp }

enum StartKeyAlg { Sha1, Sha256 } // default Sha1 if the element is omitted

enum Cipher {
    BlowfishCfb8,
    AesCbcW3c { key_len: u8 }, // 16 | 24 | 32
    AesGcmW3c { key_len: u8 },
}

enum Kdf {
    Pbkdf2 { iterations: u32, salt: Vec<u8>, derived_key_len: u8 },
    Argon2id { t: u32, m: u32, p: u32, salt: Vec<u8>, derived_key_len: u8 },
    PgpRsaOaepMgf1p,
}

enum Checksum {
    None, // GCM, or PGP+GCM
    Sha1_1K(Vec<u8>),
    Sha256_1K(Vec<u8>),
}

struct EntryEncryption {
    path: String,
    cipher: Cipher,
    kdf: Kdf,
    start_key: StartKeyAlg,
    checksum: Checksum,
    iv: Vec<u8>,
    size: u64, // manifest:size, uncompressed
}

struct Classification {
    mode: Mode,
    package_encrypted: bool,           // LO HasEncryptedEntries
    odf_version: Option<String>,
    zip_has_encrypted_package: bool,   // zip member, not XML-only
    media_type: Option<String>,
    common: Option<EntryEncryption>,   // the latch member, if any
    encrypted_entries: Vec<EntryEncryption>,
    inconsistent_odf12: bool,
}

fn classify(bytes: &[u8]) -> Result<Classification, DetectError>;
```

`package_encrypted` is the latch, **not** “any encryption-data substring.” A file with only `styles.xml` encrypted is `package_encrypted == false` and still lists that entry.

Keep URI tables in one module that matches `ManifestDefines.hxx`. No `OpenOfficeOrigin` enum.

## 6. `classify` — implement against these steps

1. Open as zip. If the archive is not zip, fail. If `META-INF/manifest.xml` is missing, this is not an ODF package (LO throws unless recovery).
2. `zip_has_encrypted_package =` root member named `encrypted-package`.
3. Parse the manifest. Store `@manifest:version`. Rewrite oasis / OOo manifest namespaces to `manifest:`; leave `loext:` as-is.
4. Collect PGP `encrypted-key` blocks (`loext:` or `manifest:`). Wrap algorithm must be `xmlenc#rsa-oaep-mgf1p`; else discard that key.
5. For each `file-entry` with nonempty `full-path`: record media-type, version, optional size. If this is the first entry, it has no version, and the package version is set → copy the package version onto it.
6. If `encryption-data` is present, decode checksum-type, algorithm-name, IV, optional start-key, KDF (including Argon2 attrs). Unknown URI → incomplete row, not a package-level error.
7. A row is **complete** iff the zip has that full-path **and** the password or PGP predicate in §2 holds. Incomplete → not encrypted.
8. If complete, push `EntryEncryption`. If the short name is `content.xml` or `encrypted-package`, set `package_encrypted` and store `common`.
9. Mode:
   - `Wholesome` if `zip_has_encrypted_package` **and** that member’s row is complete (PGP wholesome is still `Wholesome` with `Kdf::Pgp…` on the entry; or expose `Pgp` when KDF is PGP — pick one in S1 and keep it).
   - else `PerEntry` if any complete ordinary member exists.
   - else `Plain`.
10. Resolve `odf_version`: `/` folder version if present; else first-entry / package version; else `None`.
11. If `odf_version >= "1.2"`, run the unexpected-member rule in §3. Set `inconsistent_odf12`.
12. Media-type: wholesome → encrypted-package file-entry; else root `/` or the `mimetype` stream. If both mimetype and XML exist and differ, that is an error in LO when not recovering.
13. Stop. No generator strings, no try-LO-then-AOO, no key derivation.

**Mode vs PGP.** Prefer recording PGP on the `Kdf` of the latch entry and keeping `Mode` as the zip shape (`Plain` / `PerEntry` / `Wholesome`). A separate `Mode::Pgp` is only useful as a convenience alias when the latch KDF is PGP. Decide in S1; do not have both meanings.

## 7. Slices

| Slice | Work | Done when |
|---|---|---|
| **S1** | Types in §5, URI tables in §4, `classify` for zip + manifest walk with no crypto. Fixture: unencrypted ODF → `Plain`. | `classify` returns `Mode::Plain`, `package_encrypted == false` on a real unencrypted odt/ods. |
| **S2** | Accept predicates + latch. Table-driven tests: missing size, GCM without checksum (accept), CBC without checksum (reject), Argon2 t=0 (reject), missing start-key (SHA-1), unknown cipher (incomplete). | Each row of the predicate table has a constructed zip+manifest fixture. |
| **S3** | Wholesome: zip `hasByName` required; XML-only `encrypted-package` is not wholesome. Media-type from that member. Version copied from package onto first entry when `/` is missing. | Two fixtures: member present vs manifest-only. |
| **S4** | ODF ≥ 1.2 unexpected-member flag. Wholesome allow-list vs per-entry “must be in manifest.” | Fixtures with an extra root stream. |
| **S5** | PGP row shape typed, not decrypted. Both `loext:` and `manifest:` trees. | A constructed PGP manifest classifies; no gpg. |
| **S6** | Golden fixtures from real LO/AOO files once `odfdecrypt/tests/resources/` (or a local corpus) is available. Record exact written URIs. | At least one wholesome GCM+Argon2, one legacy AES-CBC, one Blowfish+PBKDF2. |

S6 is gated on sample files. The odfdecrypt clone’s `tests/resources/` was **empty** on 2026-09-01.

## 8. Borrow / do not copy

**Borrow from odfdecrypt** (as notes, not detector logic):

- Modern LO files are one `encrypted-package` member, typically Argon2id + AES-256-GCM, `loext:` argon2 attrs, experimental Argon2 URN.
- AOO Blowfish is CFB-64; LO is CFB-8 — decrypt-arc only.
- Raw DEFLATE after decrypt; GCM IV is prepended (W3C).

**Do not copy:**

- `ODFOriginDetector`
- `api.decrypt` try-LO-then-AOO
- substring `is_encrypted`
- `#blowfish-cfb8`, `xmlenc#pbkdf2`, `xmlenc#sha1`
- Requiring `start-key-generation` to exist
- XML `full-path="encrypted-package"` without a zip member
- Hardcoded Argon2 defaults
- PKCS#7 unpadding (LO is ISO 10126 / W3C)
- AES-256-only on read

## 9. Decrypt notes (interpret fields; do not implement)

Needed later so checksum / IV / start-key fields are not misread.

- Start key = hash(UTF-8 password). That digest is the PBKDF2 / Argon2 **password** (`KDFID.idl`; `OStorageHelper::CreatePackageEncryptionData`). LO does not truncate via start-key `key-size`.
- Compress with raw DEFLATE, **then** encrypt. Checksum is the first 1024 bytes of **compressed** plaintext (`n_ConstDigestLength`, `ZipOutputEntry.cxx` 129–136).
- AES-CBC padding is ISO 10126 / W3C (`ciphercontext.cxx` 314–383): random bytes, last byte = pad length.
- AES-GCM: 12-byte IV, 16-byte tag, IV prepended to ciphertext (`CipherID.idl` `AES_GCM_W3C`).
- Save defaults (not detect): PBKDF2 600000 wholesome / 100000 per-entry; Argon2 `(3, 65536, 4)`.

## 10. Open questions

Close these in the plan (amend in place) when evidence lands. Do not guess.

1. **Unknown start-key URI vs element order.** `doStartKeyAlg` does not early-return on `bIgnoreEncryptData` (`ManifestImport.cxx` 306–317); `doKeyDerivation` does (232–234). A file that puts `key-derivation` before a bogus start-key URI may still accept with default SHA-1. No sample in either tree.
2. **Nested `content.xml` latch.** Specified as short name. Confirm whether any real producer writes `…/content.xml` encrypted without a root `content.xml`.
3. **PGP + SHA512-1K.** `ZipPackage::setPropertyValue` defaults PGP checksum to `SHA512_1K` (`ZipPackage.cxx` 1920–1923) but `ManifestExport` only writes SHA1-1K / SHA256-1K. Unknown checksum-type ⇒ no digest-alg ⇒ non-GCM PGP fails the accept predicate. Likely the save path overrides to GCM before export; not fully traced.
4. **Sample corpus.** Restore or collect real LO/AOO files before S6. Until then, constructed fixtures are the authority.
5. **`Mode::Pgp` vs `Kdf::Pgp`.** Decide in S1 (see §6 step 9).

## 11. Why this shape

odfdecrypt answers “which app probably wrote this” so it can pick a decryptor. LibreOffice answers “does this package have a complete encryption-data tuple on the latch member, and is the inner payload one stream or many.” Those are different questions. A detector that follows the Python origin heuristic will reject LO-valid URIs (`#blowfish`, oasis `#pbkdf2`, OASIS Argon2id, xmldsig SHA-256) and accept XML-only wholesome rows LO would ignore.

This crate exists so later work can port crypto against a classification that already matches LO.
