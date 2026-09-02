Status: Planned — detection-only crate; decrypt is a later arc · Authored 2026-09-01 · Reviewed 2026-09-01 against `07047a02f94d` (F1–F12 applied)

# Plan — ODF package encryption detection

> **Goal.** A Rust `classify` that answers *is this an ODF package, is it encrypted,
> in which mode, and with which independent algorithm tuple* — following
> LibreOffice’s `package/` predicates, not Horsmann’s Python origin detector.
>
> **This crate does not derive keys and does not decrypt.** Those fields exist so a
> later crypto crate can consume a typed description. Detection is the whole
> deliverable.
>
> **This is not a port of `package/`.** It re-derives LO’s *accept predicates*.
> That is the right call. It is **not** a pure function of independent manifest
> rows. LO’s answer is a stateful SAX pass (`ManifestImport`) feeding a row loop
> that leaks state across iterations (`ZipPackage::parseManifest`). `classify`
> must reproduce those two stages. On constructible input a row-independent
> walk disagrees with LO; that is F1 and F2.

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

There is **no** `detectEncryptionVersion()`. Mode is not chosen from ODF version. ODF version `>= "1.2"` only decides whether unexpected streams are *fatal* (and, on save, whether `start-key-generation` is written). `"1.3"` switches PGP element names `loext:` → `manifest:` **on write only**. On read, `endElement` accepts both names with no version test (`ManifestImport.cxx` 480–482).

LibreOffice does **not** use HPKE / DHKEM (`package/` has zero matches). Combinations are independent manifest *fields* applied in a pipeline — but the *import* of those fields is stateful (see §6):

```
UTF-8(password)
  → start key (SHA-1 or SHA-256)
  → KDF (PBKDF2-HMAC-SHA1 or Argon2id; PGP wrap is a third path)
  → cipher (Blowfish-CFB-8, AES-CBC, or AES-GCM)
  → optional checksum (SHA-1-1K / SHA-256-1K); omitted for GCM
```

Version strings compare with `OUString::compareTo` — **byte-lexicographic, not semver.** `"1.10" < "1.2"`. Real ODF versions are `"1.0"` … `"1.4"`, so this does not bite produced files; constructed fixtures must not invent dotted tails.

## Out of scope

- Key derivation, password checks, inflate, writing a decrypted zip
- OOXML / OLE `EncryptedPackage`
- Guessing LibreOffice vs Apache OpenOffice from `meta:generator`, Thumbnails, Configurations2, or “mixed algorithms”
- Substring `is_encrypted` (`"encryption-data" in manifest`)
- Implementing PGP unwrap (detect and type it; do not decrypt)

## 1. Modes and the package latch

Three zip-shape outcomes. PGP is a `Kdf`, not a mode.

| Mode | Zip | Manifest | Package latch |
|---|---|---|---|
| `Plain` | anything without a complete latch row | no complete encryption-data on `content.xml` / `encrypted-package` | `HasEncryptedEntries = false` |
| `PerEntry` | ordinary members (`content.xml`, `styles.xml`, …) carry encryption-data | no `encrypted-package` zip member | latch if a complete tuple is on a member whose **short name** is `content.xml` |
| `Wholesome` | zip **has** a root member named `encrypted-package` | that member’s file-entry has a complete tuple; `/` is usually omitted | latch if the short name is `encrypted-package` |

**Wholesome is a zip check.** `ZipPackage::parseManifest` passes `m_xRootFolder->hasByName("encrypted-package")` into `LookForUnexpectedODF12Streams`. A manifest row whose `full-path` is `encrypted-package` but whose zip member is missing is **not** wholesome and is not applied (`hasByHierarchicalName` fails for that path).

**Path existence is a folder-tree lookup, not a namelist.** `ZipPackage::hasByHierarchicalName` returns `true` unconditionally for `"/"` (`ZipPackage.cxx` 1012–1016). Every other lookup resolves against the folder tree `getZipFileContents` builds, and that tree **synthesizes implicit folders** from member paths (`if (!pCurrent->hasByName(sTemp))` → create). So `Pictures/` resolves even when the zip carries no explicit directory entry. The root row is how non-wholesome files get folder version and media-type; other folder rows carry theirs the same way. Build the tree first, then resolve. Do **not** implement “path exists in the zip” as `zip.namelist().contains(path)`.

**Package-level “this file is encrypted”** (`m_bHasEncryptedEntries`, `ZipPackage.cxx` 349–353 and 434–438):

```
complete encryption-data tuple
  AND ZipPackageStream::getName() ∈ { "content.xml", "encrypted-package" }
```

`getName()` is the last path component (`ZipPackageEntry.cxx` 53–55). Other encrypted members are still marked encrypted (`SetIsEncrypted(true)`) but do **not** flip the latch; they set `m_bHasNonEncryptedEntries` when the tuple is incomplete.

**First-wins.** Both latch sites are `if (!m_bHasEncryptedEntries && …)`. If both `content.xml` and `encrypted-package` qualify, `common` is the **first complete latch row in manifest order**.

⚠️ Nested `foo/content.xml` would also latch. Treat that as specified-by-LO until open question 2 is closed.

## 2. Complete-row predicates

Apply predicates to **property bags**, not to raw XML. A bag applies only if `full-path` is nonempty **and** the path resolves in the folder tree of §1 — `"/"` always, folders including implicit ones, streams by member path. Not `zip.namelist()`.

**Password** (`ZipPackage.cxx` 360–367):

```
salt && iv && size && enc_alg && kdf
&& ( (kdf == PBKDF2 && pCount) || (kdf == Argon2id && argon2_args) )
&& ( enc_alg == AES_GCM || (digest && digest_alg) )
```

**PGP** (`ZipPackage.cxx` 297–302):

```
key_info && iv && size && enc_alg
&& kdf == PGP_RSA_OAEP_MGF1P
&& ( enc_alg == AES_GCM || (digest && digest_alg) )
```

⚠️ **`key_info` is not per-row.** `const Any *pKeyInfo` is declared **outside** the row loop (`ZipPackage.cxx` 233) and never reset. `ManifestImport` attaches `KeyInfo` **only to the first file-entry** (`ManifestImport.cxx` 468, `rManVector.empty()`). Net rule: `key_info` is present for row *N* iff the **first** file-entry carried a valid `encrypted-key` — later rows inherit that pointer. Per-entry PGP (`styles.xml`, …) passes **because of this leak**. Stage 2 of `classify` must keep a sticky `key_info` the same way.

Implications:

- `manifest:size` is **required** (`sal_Int64` → `i64`, not `u64`). Missing size → not encrypted.
- GCM: checksum optional. CBC / Blowfish: checksum **and** checksum-type required.
- PBKDF2: `doKeyDerivation` always writes `IterationCount` from `operator[]` on the attrib map. A missing attribute yields `""` → `toInt32()` → `0`, so `pCount` is **never null** in the PBKDF2 branch. The `pCount` conjunct is dead. Detect still does not require `> 0`.
- Argon2: `t, m, p > 0` at import (`ManifestImport.cxx` 257–266). On failure the flag is set but the function **falls through**: salt, key-size, and `KDF=Argon2id` are still recorded. The bag is “Argon2id with no args,” which then fails the `pArgon2Args` conjunct. Same accept verdict; different bag shape.
- `start-key-generation` is **optional**. Default SHA-1 (`ZipPackage.cxx` 376).
- Unknown cipher / KDF / start-key URI sets `bIgnoreEncryptData`. That flag is **not** visible to `ZipPackage` and already-parsed fields are **not** stripped. It clears only at end-of-file-entry (`ManifestImport.cxx` 475). A malformed `encrypted-key` poisons **exactly one** entry and suppresses `KeyInfo` for the package (`:468` also requires `!bIgnoreEncryptData`).
- Typical LO element order is algorithm → start-key → KDF, so an unknown start-key usually also skips KDF and the row fails. If KDF appears first, an unknown start-key can still accept with default SHA-1. **Cipher-implied derived-key-size is the same order dependence** (open question 1 / F2).

## 3. Version

| Field | Effect on detect |
|---|---|
| `manifest:manifest/@manifest:version` | `m_PackageVersion`. Copied onto the **first** file-entry if that entry has no version (`ManifestImport.cxx` 455–466). Needed because wholesome omits `/`. |
| `file-entry/@manifest:version` on `/` | Root folder version. This is the value `bODF12AndNewer` reads. |
| First-entry / package version when `/` is missing | Becomes `oFirstVersion`. Copied onto the **root folder** only in the mimetype-fallback branch, and only if the `mimetype` stream exists **and** its content starts with `application/vnd.` (`ZipPackage.cxx` 496–507). Miss either and root version stays empty → `bODF12AndNewer` is false → unexpected streams are recorded but **not fatal**. |
| `version >= "1.2"` | Unexpected streams become *fatal* (unless recovery). META-INF hidden from the user. Start-key uniformity is a TODO in LO, **not enforced**. The scan itself always runs (see §5 flags). |
| `version >= "1.3"` | **Write-side only** for PGP element names. Read accepts `loext:` and `manifest:` regardless. |
| Empty version | `compareTo("1.2")` is negative → not fatal. |

`LookForUnexpectedODF12Streams` always runs (`ZipPackage.cxx` 535). The version test at 538 only gates whether inconsistency **throws**. A detector wants both bits: `has_unexpected_streams` (the scan) and `odf12_fatal` (scan && root version `>= "1.2"`).

Wholesome unexpected-member rule (`ZipPackageFolder.cxx` 67–117): only `mimetype`, `encrypted-package`, `META-INF/manifest.xml`, and `META-INF/*signatures*` (substring `signatures`). Any other root file or any folder other than `META-INF` is unexpected. Wholesome `isWholesomeEncryption` is zip `hasByName("encrypted-package")`, not “the row was complete.”

Non-wholesome: every non-`mimetype` stream outside those META-INF exceptions must be listed in the manifest (`IsFromManifest()`).

Document media-type when wholesome: the `encrypted-package` file-entry’s media-type, and it must match the `mimetype` stream when both exist **and** the root already had a media-type (`ZipPackage.cxx` 517–528). The fallback branch (empty root media-type) copies mimetype onto the root and, if wholesome, does not set `MediaTypeFallbackUsed`.

## 4. URI aliases

Namespaces rewritten to a `manifest:` prefix: `http://openoffice.org/2001/manifest` and `urn:oasis:names:tc:opendocument:xmlns:manifest:1.0`. `loext:` (`urn:org:documentfoundation:names:experimental:office:xmlns:loext:1.0`) is **not** rewritten.

LO **reads** both names and URLs. LO **writes** the emit column. Implement **read** aliases. Do not implement odfdecrypt’s extra URLs as if they were LO.

| Role | Accept (LO) | LO emit | Do not treat as LO |
|---|---|---|---|
| Blowfish | `"Blowfish CFB"` or `urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#blowfish` | `"Blowfish CFB"` | `#blowfish-cfb8` (Python only; LO drops the row) |
| AES-CBC | xmlenc `aes128-cbc` / `aes192-cbc` / `aes256-cbc` → one `AES_CBC_W3C_PADDING` | `aes256-cbc` only (export requires key size 32) | — |
| AES-GCM | xmlenc11 `aes128-gcm` / `aes192-gcm` / `aes256-gcm` → one `AES_GCM_W3C` | `aes256-gcm` only | — |
| PBKDF2 | `"PBKDF2"` or oasis `#pbkdf2` | `"PBKDF2"` | `http://www.w3.org/2001/04/xmlenc#pbkdf2` |
| Argon2id | oasis `…manifest:1.5#argon2id` **or** `urn:org:documentfoundation:names:experimental:office:manifest:argon2id` | experimental URN | Python accepts only the experimental URN |
| Argon2 params | `manifest:argon2-{iterations,memory,lanes}` **or** `loext:…` (prefer `manifest:` if both) | `loext:…` | Hardcoded defaults when attrs missing — LO rejects t/m/p ≤ 0 (then still writes KDF+salt) |
| Start SHA-256 | `http://www.w3.org/2001/04/xmlenc#sha256` **or** `http://www.w3.org/2000/09/xmldsig#sha256` (OFFICE-3708) | GCM → xmlenc; AES-CBC → **xmldsig** | Python accepts only xmlenc |
| Start SHA-1 | `"SHA1"` or `http://www.w3.org/2000/09/xmldsig#sha1` | `"SHA1"` | `http://www.w3.org/2001/04/xmlenc#sha1` |
| Checksum SHA-1-1K | `"SHA1/1K"` or oasis `#sha1-1k` | `"SHA1/1K"` | — |
| Checksum SHA-256-1K | oasis `#sha256-1k` | that URL | Python does not parse it |
| PGP KDF | `"PGP"` and only after `bPgpEncryption` (a valid encrypted-key already seen) | `"PGP"` | — |
| PGP wrap | `http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p` | that URI | — |

`CipherID` has exactly three values (`BLOWFISH_CFB_8`, `AES_CBC_W3C_PADDING`, `AES_GCM_W3C`). All three CBC URIs collapse to one; all three GCM URIs to one. The 128/192/256 distinction survives **only** as `DerivedKeySize`. Do not store it twice.

**Derived-key-size — two paths, not one function.**

| Path | Who sets it | `manifest:key-size` | Cipher-URI default | Floor |
|---|---|---|---|---|
| Password | `ManifestImport::doKeyDerivation` (`:283–291`), then `ZipPackage.cxx` 376 / 418–419 | used if present | written by `doAlgorithm` into import member `nDerivedKeySize` **only if `<algorithm>` has already run** | `16` if still unset |
| PGP | `GetDefaultDerivedKeySize(nEncryptionAlg)` (`ZipPackage.cxx` 137–148, call site 345) | **ignored** | Blowfish → 16; AES-CBC **and** AES-GCM → **32** (not 16/24) | n/a |

Reverse `<algorithm>` and `<key-derivation>` with no `key-size` on an `aes256-cbc` file and the password path yields **16**. Nothing writes the cipher default back afterward. That is constructible today (S2 fixture); see open question 1.

Optionally keep the cipher URI’s implied length as **provenance** (`cipher_uri_key_len`) if a later decrypt crate wants to warn on mismatch. It is not LO’s accept value.

## 5. Types

One crate, no key-derivation dependency.

```rust
enum Mode { Plain, PerEntry, Wholesome } // zip shape only; PGP is a Kdf

enum StartKeyAlg { Sha1, Sha256 } // default Sha1 if the element is omitted

enum Cipher {
    BlowfishCfb8,
    AesCbcW3c,
    AesGcmW3c,
}

enum Kdf {
    Pbkdf2 { iterations: i32, salt: Vec<u8> },
    Argon2id { t: i32, m: i32, p: i32, salt: Vec<u8> },
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
    size: i64,                 // manifest:size is sal_Int64
    derived_key_len: u8,       // the one LO value; PGP uses GetDefaultDerivedKeySize
}

struct Classification {
    mode: Mode,
    package_encrypted: bool,           // LO HasEncryptedEntries
    odf_version: Option<String>,       // root-folder version after fallback
    zip_has_encrypted_package: bool,   // zip member, not XML-only
    media_type: Option<String>,
    common: Option<EntryEncryption>,   // first-wins latch member
    encrypted_entries: Vec<EntryEncryption>,
    has_unexpected_streams: bool,      // LookForUnexpectedODF12Streams, always
    odf12_fatal: bool,                 // has_unexpected_streams && version >= "1.2"
}

fn classify(bytes: &[u8]) -> Result<Classification, DetectError>;
```

`package_encrypted` is the latch, **not** “any encryption-data substring.” A file with only `styles.xml` encrypted is `package_encrypted == false` and still lists that entry.

Keep URI tables in one module that matches `ManifestDefines.hxx`. No `OpenOfficeOrigin` enum.

## 6. `classify` — two stages, then zip-shape

LO is not a pure function of rows. Implement the same two machines.

### Stage A — streaming manifest reader (`ManifestImport`)

Carry across elements inside one `file-entry`: `derived_key_size`, `ignore_encrypt_data`, `pgp_seen` / collected keys, first-entry flag, package version.

1. Open as zip. If the archive is not zip, fail. If `META-INF/manifest.xml` is missing, this is not an ODF package (LO throws unless recovery).
2. `zip_has_encrypted_package =` root member named `encrypted-package`.
3. Parse `manifest:manifest`. Store `@manifest:version`. Rewrite oasis / OOo manifest namespaces to `manifest:`; leave `loext:` as-is.
4. On each `encrypted-key` (`loext:` or `manifest:`, no version switch): wrap algorithm must be `xmlenc#rsa-oaep-mgf1p`; else set `ignore_encrypt_data` for the current scope and discard that key. A valid key sets `pgp_seen` and is appended to the key list.
5. On `encryption-data` start: reset `derived_key_size` to unset (`ManifestImport.cxx` 157).
6. On `algorithm`: map URI; unknown → `ignore_encrypt_data`. If known AES, **write** `derived_key_size` to 32/24/16. Store IV.
7. On `start-key-generation`: map URI; unknown → `ignore_encrypt_data`. Does **not** check the flag first.
8. On `key-derivation`: if already ignoring, return. Else map KDF. For Argon2, require t,m,p > 0 or set the flag and **fall through** (KDF+salt+key-size still recorded, no args). For PBKDF2, always write `iteration_count` (`""` → 0). Read `key-size` if present; else keep Stage-A `derived_key_size`; else 16.
9. End of `file-entry`: if first entry and no version and package version set → copy version. If first entry and `!ignore && !keys.empty()` → attach `KeyInfo` to **this bag only**. Erase empty props. Reset `ignore_encrypt_data`. Push the bag.

Output of Stage A: an ordered list of property bags.

### Stage B — row loop (`ZipPackage::parseManifest`)

Carry across rows: sticky `key_info` (starts null; set when a bag has `KeyInfo`; **never cleared**), `o_first_version`, first-wins latch.

10. For each bag with nonempty `full-path` that resolves in the folder tree (§1 — `"/"` always true, implicit folders included):
    - If the target is a folder (including `/`): set that folder’s media-type and version. Do not run encryption predicates on folders.
    - If the target is a stream: apply §2 to the bag **plus** sticky `key_info`. Complete → `EntryEncryption`, maybe latch. Incomplete → not encrypted.
11. Latch: if `!package_encrypted` and short name is `content.xml` or `encrypted-package`, set `package_encrypted` and `common =` this entry. First wins.
12. Mode: `Wholesome` if `zip_has_encrypted_package` **and** that member’s bag was complete; else `PerEntry` if any complete ordinary member exists; else `Plain`. PGP does not change the mode.
13. Root version: `/` folder version if a `/` row ran; else, if a `mimetype` stream exists and starts with `application/vnd.` and root media-type was empty, copy `o_first_version` onto the root (and the mimetype onto media-type).
14. Always run the unexpected-member scan (§3) with `isWholesomeEncryption = zip_has_encrypted_package` — the bare zip check, **not** `mode == Wholesome`. A present `encrypted-package` member whose row was *incomplete* is `PerEntry` / `Plain` yet is still scanned under the wholesome allow-list. `has_unexpected_streams =` that result. `odf12_fatal = has_unexpected_streams && root_version >= "1.2"`.
15. Media-type: if root already had one and mimetype exists, LO compares mimetype to (wholesome member media-type or root). Conflict is an error when not recovering.
16. Stop. No generator strings, no try-LO-then-AOO, no key derivation.

## 7. Slices

| Slice | Work | Done when |
|---|---|---|
| **S1** | Stage A + Stage B types. URI tables. Sticky `key_info`. Order-dependent `derived_key_size`. `Mode` is zip shape only. Fixture: unencrypted ODF → `Plain`. | `classify` returns `Mode::Plain`, `package_encrypted == false` on a real unencrypted odt/ods. Constructed two-row PGP manifest: first entry has KeyInfo, second (`styles.xml`) still satisfies the PGP predicate. |
| **S2** | Accept predicates + first-wins latch. Table-driven: missing size, GCM without checksum (accept), CBC without checksum (reject), Argon2 t=0 (KDF set, no args, reject), missing start-key (SHA-1), unknown cipher (incomplete), **algorithm after key-derivation / no key-size / aes256-cbc → derived_key_len 16**, missing `iteration-count` still PBKDF2-complete with 0. `"/"` is not dropped; a `Pictures/` row with no explicit zip directory entry still resolves. | Each row has a constructed zip+manifest fixture. |
| **S3** | Wholesome: zip `hasByName` required; XML-only `encrypted-package` is not wholesome. Media-type from that member. Version on first entry when `/` is missing. Mimetype-fallback gate: no `application/vnd.` prefix → root version stays empty. | Member present vs manifest-only; mimetype present vs missing vs wrong prefix. |
| **S4** | Always compute `has_unexpected_streams`. `odf12_fatal` only when root version `>= "1.2"`. Wholesome allow-list vs per-entry “must be in manifest.” | Extra root stream, with and without a 1.2 root version. Plus `encrypted-package` member present with an *incomplete* row: mode is not `Wholesome`, scan still uses the wholesome allow-list. |
| **S5** | PGP bag shape typed, not decrypted. Both `loext:` and `manifest:` trees, no version switch. Derived key size from `GetDefaultDerivedKeySize`, `key-size` ignored. Malformed encrypted-key poisons one entry and suppresses package KeyInfo. | Constructed PGP manifests classify; no gpg. |
| **S6** | Golden fixtures from real LO/AOO files once a corpus exists. Record exact written URIs. | At least one wholesome GCM+Argon2, one legacy AES-CBC, one Blowfish+PBKDF2. |

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
- A row-independent `classify` that would miss F1/F2

## 9. Decrypt notes (interpret fields; do not implement)

Needed later so checksum / IV / start-key fields are not misread.

- Start key = hash(UTF-8 password). That digest is the PBKDF2 / Argon2 **password** (`KDFID.idl`; `OStorageHelper::CreatePackageEncryptionData`). LO does not truncate via start-key `key-size`.
- Compress with raw DEFLATE, **then** encrypt. Checksum is the first 1024 bytes of **compressed** plaintext (`n_ConstDigestLength`, `ZipOutputEntry.cxx` 129–136).
- AES-CBC padding is ISO 10126 / W3C (`ciphercontext.cxx` 314–383): random bytes, last byte = pad length.
- AES-GCM: 12-byte IV, 16-byte tag, IV prepended to ciphertext (`CipherID.idl` `AES_GCM_W3C`).
- Save defaults (not detect): PBKDF2 600000 wholesome / 100000 per-entry; Argon2 `(3, 65536, 4)`.

## 10. Open questions

Close these in the plan (amend in place) when evidence lands. Do not guess.

1. **Import order is load-bearing (F2 + old Q1).** `nDerivedKeySize` is a `ManifestImport` member, reset per `encryption-data`, written by `doAlgorithm`, read by `doKeyDerivation`. The same flag/`ignore` early-return makes unknown start-key URI order-dependent. LO-written files emit algorithm then start-key then KDF (`ManifestExport.cxx`), so produced files match the “cipher default applies” story. Constructed files can disagree. **S2 must fixture the reversal** (`aes256-cbc`, no `key-size`, KDF first → `derived_key_len == 16`). Whether we *document* that as “LO quirk, we match it” is already decided: we match it. This question is only whether any **producer** emits reversed children; if none do, the fixture stays synthetic.
2. **Nested `content.xml` latch.** Specified as short name. Confirm whether any real producer writes `…/content.xml` encrypted without a root `content.xml`. Tracked as [#8](https://github.com/Slurp9187/odf-decrypt-rs/issues/8), gated on the same corpus as question 4.
3. **PGP + SHA512-1K.** `ZipPackage::setPropertyValue` defaults PGP checksum to `SHA512_1K` (`ZipPackage.cxx` 1920–1923) but `ManifestExport` only writes SHA1-1K / SHA256-1K. Unknown checksum-type ⇒ no digest-alg ⇒ non-GCM PGP fails the accept predicate. Likely the save path overrides to GCM before export; not fully traced.
4. **Sample corpus.** Restore or collect real LO/AOO files before S6. Until then, constructed fixtures are the authority.

Settled 2026-09-01: `Mode` is zip shape only (`Plain` / `PerEntry` / `Wholesome`). PGP lives on `Kdf`.

## 11. Why this shape

odfdecrypt answers “which app probably wrote this” so it can pick a decryptor. LibreOffice answers “does this package have a complete encryption-data tuple on the latch member, and is the inner payload one stream or many.” Those are different questions. A detector that follows the Python origin heuristic will reject LO-valid URIs (`#blowfish`, oasis `#pbkdf2`, OASIS Argon2id, xmldsig SHA-256) and accept XML-only wholesome rows LO would ignore.

Matching LO also means matching its **state leaks**, not only its URI table. A tidy per-row `classify` is simpler and wrong on per-entry PGP and on reversed algorithm/KDF children.

This crate exists so later work can port crypto against a classification that already matches LO.

## 12. Review log (2026-09-01)

Verified against `07047a02f94d`. Line citations in the review landed. Applied:

| Id | Change |
|---|---|
| F1 | Sticky `key_info` outside the row loop; Stage B. S1 fixture. |
| F2 | Order-dependent `derived_key_size`; two defaulting paths; open question 1 widened; S2 fixture. |
| F3 | `"/"` always resolves; row existence is not a namelist check. |
| F4 | `Cipher` is three variants; `derived_key_len` is the one LO value. |
| F5 | Password vs PGP defaulting table. PGP still has a derived key size. |
| F6 | `has_unexpected_streams` + `odf12_fatal`. Scan always runs. |
| F7 | Wholesome root version only via mimetype + `application/vnd.` fallback. |
| F8 | First-wins latch. |
| F9 | ODF 1.3 PGP names are write-side only. |
| F10 | PBKDF2 `pCount` conjunct is dead. |
| F11 | Path existence is a folder-tree lookup; `getZipFileContents` synthesizes implicit folders, so folder rows survive zips without directory entries. S2 fixture. |
| F12 | Unexpected-member scan takes `zip_has_encrypted_package`, not `mode == Wholesome`. S4 fixture. |
| minor | Argon2 fall-through bag; `ignore` clears per file-entry; `size: i64`; `compareTo` is not semver. |
