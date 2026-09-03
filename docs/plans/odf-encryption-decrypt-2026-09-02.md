Status: **Planned (2026-09-02)** — password decrypt against `classify`; PGP unwrap is a later arc · Authored 2026-09-02 against `07047a02f94d` · Review 2026-09-02 (Blowfish is 64-bit-segment CFB on the wire; wholesome `encrypted-package` is deflated then encrypted) · OQ1 closed 2026-09-02 from a probe golden

Consumes [docs/plans/odf-encryption-detection-2026-09-01.md](odf-encryption-detection-2026-09-01.md) (Shipped). Do not re-derive accept predicates.

If `classify` and this pipeline disagree on a complete row, **detection wins: fix `classify`, do not special-case decrypt** — with one carve-out: LO’s SHA-1 *read* ladder (`ZipPackageStream.cxx` 1014–1070) can try `Bugs::WrongSHA1`, then **force SHA-256 despite the manifest saying SHA-1** (rhbz#1013844), then `WinEncodingWrongSHA1`. On that ladder `start_key` is a hint, not a fact. Overriding it there is not a `classify` bug. This arc does not walk the ladder (open question 1, closed).

# Plan — ODF package password decryption

> **Goal.** `decrypt(&[u8], &str) -> Result<Vec<u8>, DecryptError>` that turns an LO-encrypted ODF package into a plaintext ODF zip LibreOffice would open after a successful password, following `package/` crypto — not Horsmann’s origin detector, not a second classifier.
>
> **Password path only.** Blowfish 64-bit-segment CFB, AES-CBC-W3C, AES-GCM-W3C. PBKDF2-HMAC-SHA1 or Argon2id. Start key is SHA-1 or SHA-256 of UTF-8(password).
>
> **Output is a zip.** Wholesome: decrypt **and raw-inflate** the `encrypted-package` member (that blob is compressed plaintext, same as per-entry). Per-entry: rebuild the outer zip with those members decrypted, `encryption-data` stripped, and `manifest:size` dropped, so `classify` returns `Mode::Plain`.

This is **not** OOXML / OLE `EncryptedPackage`.

## Authority

Same pin as detection. Do not re-download LibreOffice.

| Tree | Path | Pin |
|---|---|---|
| LibreOffice core | `O:\projects-github-clones\LibreOffice\core` | `07047a02f94d`. Re-check the files below before changing this plan. |
| Horsmann odfdecrypt | `O:\projects-github-clones\odfdecrypt` | Negative example. Its Blowfish mode is **backwards** (§8). Never the pipeline. |

Primary LO files (crypto, not accept predicates):

- `comphelper/source/misc/storagehelper.cxx` — `CreatePackageEncryptionData` (start keys)
- `package/source/zipapi/ZipFile.cxx` — `StaticGetCipher`, PBKDF2, Argon2id v13, `StaticHasValidPassword` (`n_ConstDigestDecrypt`), GCM whole-stream tag check
- `package/source/zipapi/blowfishcontext.cxx` — `BlowfishCFB8CipherContext` (name is a lie; mode is in sal)
- `sal/rtl/cipher.cxx` — `BF_updateCFB` (`:875`): re-encrypts the register every 8 bytes (`m_offset = (k+1) & 0x07`). OpenSSL backend (`:1071`) is `EVP_bf_cfb()` = `bf_cfb64`. Both backends are 64-bit-segment CFB
- `package/source/zipapi/XUnbufferedStream.cxx` — decrypt then raw inflate (`InflateZlib(true)` → `inflateInit2(..., -MAX_WBITS)`)
- `package/source/zipapi/ZipOutputEntry.cxx` — checksum is first 1024 bytes of **compressed** plaintext
- `package/inc/PackageConstants.hxx` — `n_ConstDigestLength = 1024`, `n_ConstDigestDecrypt = 1056` (1024 + 32)
- `xmlsecurity/source/xmlsec/nss/ciphercontext.cxx` — AES-CBC W3C/ISO 10126 padding; AES-GCM 12-byte IV prepended, 16-byte tag; IV prefix must match (`:277`)
- `package/source/zippackage/ZipPackageStream.cxx` — `GetIVSize`; SHA-1 retry ladder (`:1014-1070`)

Save-side only (do not use as decrypt defaults): PBKDF2 600000/100000, Argon2 `(3, 65536, 4)`. Read `EntryEncryption`.

## Out of scope

- Re-implementing `classify` or URI tables
- PGP unwrap (`Kdf::PgpRsaOaepMgf1p`) — refuse it (`UnsupportedPgp`). Later arc, linked not attached
- StarOffice-not-quite-SHA1 and MS-1252 start keys (`PACKAGE_ENCRYPTIONDATA_SHA1UTF8` / `SHA1MS1252`) and LO’s wrong-SHA1 retry ladder. Correct UTF-8 SHA-1 / SHA-256 only — measured, not assumed (open question 1, closed 2026-09-02)
- `EncryptedDataHeader` / wrapped-raw (`n_ConstHeader = 0x05024d4d`, `ZipFile.cxx` `StaticFillHeader`, `UNBUFF_STREAM_WRAPPEDRAW`). Copy-between-packages path. Goldens are ordinary zip members
- Repair (`m_bForceRecovery`), writing encryption, OOXML
- Guessing origin from `meta:generator`

There is **one Blowfish wire format** (64-bit-segment CFB). There is no “AOO CFB-64 vs LO CFB-8” decrypt arc. AOO-specific leftovers, if any, are start-key quirks (open question 1), not the cipher.

## 1. Consume `classify`, then crypto

```
classify(bytes)?
  Plain            → DecryptError::NotEncrypted
  any Kdf::Pgp…    → DecryptError::UnsupportedPgp
  DetectError      → DecryptError::Classify(…)
  PerEntry|Wholesome + password KDF → decrypt members in encrypted_entries
```

Do **not** decrypt a row `classify` left incomplete. `encrypted_entries` is the complete tuples. Copy-through everything else.

`package_encrypted` is the latch, not a decrypt filter. A file with only `styles.xml` encrypted (`package_encrypted == false`, `Mode::PerEntry`) still decrypts that entry.

Password is `&str`. Encode UTF-8. Empty password → `DecryptError::EmptyPassword` (`CreatePackageEncryptionData` yields an empty sequence).

## 2. Pipeline per complete row

LO (`ZipFile::StaticGetCipher` + `XUnbufferedStream`):

```
UTF-8(password)
  → start key (SHA-1 or SHA-256; `EntryEncryption.start_key`, subject to OQ1)
  → KDF (PBKDF2-HMAC-SHA1 or Argon2id v13; salt / iters / (t,m,p) from the row)
  → cipher (Blowfish 64-bit CFB, AES-CBC-W3C, AES-GCM-W3C; IV from the row)
  → verify (cipher selects the verifier: checksum window, or GCM tag)
  → raw DEFLATE
```

`derived_key_len` is the KDF output size (`sal_Int32`). Do not re-default it. Negative or 0 → `BadParameters` (LO throws `Invalid derived key length!`). `classify` does not validate; decrypt must.

### Start key

`OStorageHelper::CreatePackageEncryptionData` (`storagehelper.cxx` 358–424):

| `StartKeyAlg` | Digest | Length |
|---|---|---|
| `Sha256` | SHA-256(UTF-8(password)) | 32 |
| `Sha1` | **correct** SHA-1(UTF-8(password)) | 20 |

Omitted `start-key-generation` already classified as SHA-1. Do **not** truncate via start-key `manifest:key-size`.

### KDF

| `Kdf` | LO | Notes |
|---|---|---|
| `Pbkdf2 { iterations, salt }` | `rtl_digest_PBKDF2` (`ZipFile.cxx` 200–209) | HMAC-SHA1, output `derived_key_len`. `iterations ≤ 0` → `BadParameters` |
| `Argon2id { t, m, p, salt }` | `argon2id_ctx`, `version = ARGON2_VERSION_13` (`:175-198`) | `pwd` is the **start key**, not the raw password. `.lanes = p` from the manifest; `.threads = getPreferredConcurrency()` — **threads do not affect output**; a single-threaded port is bit-identical. RustCrypto `Params::new` is **`(m_cost, t_cost, p_cost)`**, the reverse of this tuple; `m` is **KiB** (golden `65536` = 64 MiB). `Params::new` failure → `BadParameters` |
| `PgpRsaOaepMgf1p` | session key is already `m_aKey` (`:161-166`) | refuse this arc |

No iteration or memory cap: match LO’s absence. An attacker-complete row can make Argon2 expensive; that is accepted, not a slice.

### Cipher

Keep detection’s type name `Cipher::BlowfishCfb8` (`CipherID::BLOWFISH_CFB_8`). The **wire** is 64-bit-segment CFB.

| `Cipher` | LO | Wire |
|---|---|---|
| `BlowfishCfb8` | `BlowfishCFB8CipherContext` → `rtl_Cipher_ModeStream` → `BF_updateCFB` / `EVP_bf_cfb` | **64-bit-segment CFB** (RustCrypto `cfb-mode` over `blowfish::Blowfish`, **not** `cfb8`). Verified on `aoo-blowfish-pbkdf2.odt`: CFB-64 checksum matches; CFB-8 does not |
| `AesCbcW3c` | NSS AES-CBC + W3C padding (`ciphercontext.cxx` 314–383) | ISO 10126 / XMLENC: last byte is pad length in `1..=block` (read as signed `i8` in LO; treat as `u8` in `1..=16`). Strip that many. IV 16. Ciphertext not a block multiple → `BadParameters` (`:311`) |
| `AesGcmW3c` | NSS AES-GCM (`ciphercontext.cxx` 31–32, 251–288) | 12-byte IV, 16-byte tag. **Zip member is `IV \|\| ciphertext \|\| tag`.** Prefix must match `EntryEncryption.iv` (`:277` “inconsistent IV”). Shorter than IV+tag → `BadParameters` (`:296`). **The cipher selects the verifier, never `Checksum`.** GCM with a digest present still uses the tag only (`StaticHasValidPassword` asserts `m_nEncAlg != AES_GCM_W3C`) |

Wrong IV length for the cipher → `BadParameters`.

Real LO encrypted members are zip **STORED** with a data descriptor (detection Stage 0). The member payload **is** the ciphertext (plus GCM framing). Do not inflate the zip method; inflate **after** decrypt.

LO also runs the zip **CRC over the ciphertext**, not the plaintext: `maCRC.update(maCompBuffer)` before the cipher (`XUnbufferedStream.cxx` 270), checked at `:303-306`. Reading each member through the `zip` crate reproduces that for free. Do not “optimise” into slicing member bytes straight out of the input buffer — that silently drops a check LO makes.

### Verify, then inflate

The cipher chooses the path, not `Checksum::None`.

**CBC / Blowfish** (`StaticHasValidPassword`, `ZipFile.cxx` 482–534): LO reads `n_ConstDigestDecrypt` (**1056**) ciphertext bytes, decrypts, **catches** the finalize exception (partial padding on a short window), then truncates the plaintext to `n_ConstDigestLength` (**1024**) and hashes. Decrypting the whole member, W3C-unpadding, then taking `min(len, 1024)` of the still-compressed plaintext is equivalent in both branches (streams longer than 1056 never hit padding in the window; the digest is what fails). A W3C unpad failure on a full-member decrypt maps to **`WrongPassword`** (corrupt pad is not distinguishable from a wrong key at this layer). Hash SHA-1-1K or SHA-256-1K; compare to `Checksum`. Mismatch → `WrongPassword`. Empty stored digest: LO assumes the password is correct; `classify` would not have accepted a non-GCM row without digest, so this arc never hits it.

**GCM** (`checkValidPassword`, `:542-558`): decrypt the whole member (tag check). Failure → `WrongPassword`. Ignore `Checksum` even if present.

Then raw DEFLATE (`InflateZlib(true)`). **Do not preallocate from `manifest:size`** (`i64`, attacker-controlled); stream inflate with a named ceiling (1 GiB) so a forged size cannot OOM.

Two **post-conditions**, both enforced, neither a password oracle — they run only after the checksum or tag has already passed:

1. The deflate stream must reach its **end marker**. `flate2`, like zlib, returns the partial output it managed on a truncated stream and reports no error.
2. The inflated length must **equal `manifest:size`**.

Measured, not theorised: `tests/goldens/ref_decrypt.py` accepted a Blowfish member truncated *past* the 1 KiB digest window — the checksum still matched — and returned silently short plaintext until both were added. `manifest:size` is a checked post-condition, not a note.

## 3. Zip shape out

**Wholesome** (`Mode::Wholesome`): decrypt **and inflate** the row whose **`path == "encrypted-package"`** — the same condition that set `encrypted_package_complete` (`classify.rs` 241–242). **Not** `common`: with an embedded object, first-wins can latch a nested `content.xml` as `common` while the blob to unwrap is still `encrypted-package`. The member is deflated-then-encrypted (golden: 6530 bytes = 12 IV + 6502 ct + 16 tag; `manifest:size` 6977). The inflated result **is** the inner ODF package. Do not wrap it. Do not rewrite the outer zip. Any other complete row in `encrypted_entries` is **ignored** on this path — LO opens the inner package and never looks at them.

**Per-entry**: rebuild a zip from the **raw zip namelist**, not `collect_members` (that filter drops FAT directory entries such as `Configurations2/`):

1. Enumerate original members in original order. Preserve each unencrypted member’s compression method so `mimetype` stays first and STORED. Copy directory entries that `classify` skipped.
2. For each `encrypted_entries` row, resolve `path` back to a zip member (§6) and replace that member with the inflated plaintext, written **STORED without a data descriptor** (or DEFLATED without one). Emitting STORED-with-DD makes `check_stored_data_descriptors` refuse our own output.
3. Rewrite `META-INF/manifest.xml`: drop every `manifest:encryption-data`. **Drop `manifest:size`** with it — an LO plaintext save emits none (`lo-unencrypted.odt`: zero occurrences). Keeping and updating `size` still classifies `Plain`, so the close-when would not catch it. Keep `file-entry` path / media-type / version.

`classify(decrypt(bytes, password))` is `Ok` with `Mode::Plain` on all four encrypted goldens.

## 4. Types

Same crate `odf-crypto`. Crypto lives behind a **`decrypt` feature**, default **on**. `--no-default-features` is detection-only. Do not add these deps to the default-off graph.

Behind `decrypt`:

- `sha1`, `sha2`, `hmac`, `pbkdf2`
- `argon2` (RustCrypto; `Params::new(m, t, p)`)
- `aes`, `cbc`, `aes-gcm`
- `blowfish` + `cfb-mode` (64-bit segment; **not** `cfb8`)
- `flate2` / `miniz_oxide` **as a direct dep** — `zip`’s `deflate` feature is not reachable for a bare inflate of a decrypted stream
- `zip` writer enabled (rebuild)
- `zeroize` — wipe start key and derived key after use (`rtl_secureZeroMemory` analogue). Do not promise wiping the caller’s `&str` password

```rust
fn decrypt(bytes: &[u8], password: &str) -> Result<Vec<u8>, DecryptError>;

#[non_exhaustive]
enum DecryptError {
    Classify(DetectError),
    NotEncrypted,
    EmptyPassword,
    UnsupportedPgp,
    WrongPassword,
    BadParameters(String), // negative derived_key_len, bad IV length, Argon2 reject, short GCM, CBC length …
    Inflate(String),
    Zip(String),
}
```

`#[non_exhaustive]` so the PGP arc can add variants without a semver break. Complete-but-malformed crypto parameters are **`BadParameters`**, not `WrongPassword`.

**That split is a deliberate divergence in error *granularity*, not in accept/reject.** LO reports wrong-password for all of them: `StaticHasValidPassword` wraps convert+finalize in a try/catch, so “The data should contain complete blocks only” (`ciphercontext.cxx:311`) is swallowed and the digest is what fails; `checkValidPassword` catches every exception on the GCM path, so “incorrect size of input” (`:296`) becomes `WrongPasswordException` too. Both fail closed either way. We tell the caller more than LO does. Do not “fix” this toward LO.

**`pgp_keys` on `Classification` (S1):** refusal only needs `Kdf::PgpRsaOaepMgf1p`, already on the row. Promoting `EncryptedKey` and storing `pgp_keys` (from first-entry KeyInfo; empty otherwise) is **deliberate pre-landing for the PGP arc**, not required to refuse. Keep it; it is cheap (`Classification` is built in one place).

Do **not** add `cipher_uri_key_len`, `m_bMediaTypeFallbackUsed`, or `m_bHasNonEncryptedEntries`. Known limitation: `media_type` has no provenance.

S1 changes `src/lib.rs` crate docs: this crate *does* decrypt when the feature is on.

**Standing check (every slice, not only S1):** `cargo test --offline --no-default-features` still builds and passes the detection suite.

## 5. Goldens

`tests/goldens/`; password **`password`** (`URIS.md`) — except the OQ1 probe, which uses `NONASCII_PASSWORD` from `make_goldens.py`.

| File | Mode | Tuple | Note |
|---|---|---|---|
| `aoo-blowfish-pbkdf2.odt` | PerEntry | SHA-1 (omitted start-key), PBKDF2 100000, Blowfish 64-bit CFB, SHA1/1K | **LO-written** (`make_goldens.py` / UNO, `DefaultVersion=2`). No AOO-produced file is under test. Name is historical |
| `lo-legacy-aes-cbc.odt` | PerEntry | SHA-256 (xmldsig), PBKDF2 100000, AES-256-CBC, SHA256-1K | Five encrypted members including `manifest.rdf` |
| `lo-wholesome-gcm-argon2.odt` | Wholesome | SHA-256 (xmlenc), Argon2id (3, 65536, 4), AES-256-GCM, no checksum | Inflate after GCM |
| `lo-odf11-nonascii-password.odt` | PerEntry | SHA-1 (omitted start-key), PBKDF2 100000, Blowfish 64-bit CFB, SHA1/1K | OQ1 probe, 2026-09-02. Password is 52 chars with one non-ASCII char, **not** `password`. Same shape as the Blowfish golden, so S2 gets a second file for free |
| `lo-unencrypted.odt` | Plain | `NotEncrypted` | |

Both per-entry goldens encrypt **five** members, not only `content.xml`. S2/S3 assert all five decrypt and that the rebuilt zip classifies `Plain`.

Do not regenerate encrypted goldens (salts/IVs/`size` churn). Wrong-password tests use these files with a different password.

**Cross-check oracle.** `tests/goldens/ref_decrypt.py` is an independent Python implementation of this plan (`pip install cryptography argon2-cffi`; not crate deps). Run bare, it sweeps every golden and the §7 S5 negatives. Use it two ways: before writing a slice, to confirm the close-when is reachable; and when a slice disagrees with a golden, to bisect — its steps cite plan sections, so a disagreement points at a paragraph. It is not a port target, and the Rust must not be written by transcribing it.

No golden has an embedded object. Decrypt still walks **all** `encrypted_entries`, not only `common`. Wholesome still selects `path == "encrypted-package"`.

## 6. `decrypt` — steps

1. If `password` is empty, fail.
2. `classify(bytes)`? Map errors as §1.
3. If any `encrypted_entries[].kdf` is PGP, `UnsupportedPgp`.
4. Start key once per `StartKeyAlg` needed (usually one).
5. For each `EntryEncryption`: **`path` is a folder-tree path, not a zip namelist key.** It is `resolved.tree_path` (`classify.rs` 238) — canonical component join, and after A10 it can name a **different** node than the manifest `full-path`. Resolve back to a zip member with the same rule `classify` already uses for mimetype (`classify.rs` 137, 319): first member whose raw name or `collapse_slashes(name)` equals `path`. A row always has one: the tree was built from zip names. Read that member’s payload (STORED ciphertext). KDF with that row’s salt; cipher with that row’s IV; verify; inflate. Members can share a password and still have **per-stream** salt/IV/`size`.
6. Assemble §3.
7. Stop. No origin heuristic, no try-LO-then-AOO.

## 7. Slices

| Slice | Work | Done when |
|---|---|---|
| **S1** | `decrypt` feature (default on), `DecryptError` (`#[non_exhaustive]`, `BadParameters`), public `EncryptedKey`, `pgp_keys` on `Classification`. Crate docs. `decrypt` calls `classify`. Plain → `NotEncrypted`. Constructed PGP zip → `UnsupportedPgp`. Empty password → `EmptyPassword`. No ciphers yet: do not call `decrypt` on the encrypted goldens. | `lo-unencrypted.odt` → `NotEncrypted`. Detection S5 PGP zip → `UnsupportedPgp` and nonempty `pgp_keys`. Every golden has empty `pgp_keys`. `cargo test --offline --no-default-features` green. |
| **S2** | SHA-1 UTF-8 + PBKDF2-HMAC-SHA1 + Blowfish **64-bit CFB** + SHA1-1K + raw inflate + per-entry rebuild (strip `encryption-data` and `manifest:size`; raw namelist copy-through). Both ODF 1.1 goldens: `aoo-blowfish-pbkdf2.odt` under `password`, and `lo-odf11-nonascii-password.odt` under `NONASCII_PASSWORD` — which also proves the start key is UTF-8, not MS-1252 (OQ1). | **Each** ODF 1.1 golden, under its own password → a zip that re-`classify`s **`Plain` with 0 rows, and `odf_version` / `media_type` / member set unchanged from that input’s own `Classification`** (compare against it, never a literal — both legitimately have `odf_version == None` before and after). All five encrypted members are well-formed XML/RDF at `manifest:size` bytes. `"wrong"` → `WrongPassword`. `--no-default-features` still green. |
| **S3** | SHA-256 + PBKDF2 + AES-CBC W3C pad + SHA256-1K. Same rebuild. | `lo-legacy-aes-cbc.odt` same close-when as S2 (all five members, same unchanged-metadata comparison). |
| **S4** | Argon2id v13 + AES-GCM (IV prepended, 16-byte tag; ignore any checksum). Wholesome: decrypt **and inflate** the `encrypted-package` row; return that inner zip. | `lo-wholesome-gcm-argon2.odt` → inner package re-`classify`s `Plain` with 0 rows and a `content.xml`; inflated length == `manifest:size` 6977. `"wrong"` → `WrongPassword`. |
| **S5** | Constructed negatives: **ciphertext truncated *past* the 1 KiB digest window** (the checksum still matches — only the two §2 post-conditions catch it; a truncation *inside* the window is caught by the checksum for free and proves nothing), bad padding last-byte, checksum bytes flipped, GCM tag flipped, GCM member shorter than IV+tag (`ciphercontext.cxx:296`), GCM IV prefix mangled (`:277`), CBC ciphertext not a block multiple (`:311`). | Table-driven; `WrongPassword`, `BadParameters`, `Inflate`, or `Zip` as LO would fail closed — do not succeed. |

S3 and S4 block on S1, not on each other. S2 blocks on S1. S5 blocks on S2–S4.

## 8. Borrow / do not copy

**Borrow from odfdecrypt** as notes: GCM IV prepended; raw DEFLATE after decrypt.

**Do not copy its Blowfish mode.** `libre_office_odf_decryptor.py:154` passes `segment_size=8` (true CFB-8). The origin detector (`odf_origin_detector.py:142`) routes Blowfish+PBKDF2 to the **AOO** decryptor (64-bit CFB), which is why the tool works on LO files at all. That is the source of this plan’s first-draft CFB-8 error. LO sal is 64-bit-segment CFB; implement that.

**Do not copy:** `ODFOriginDetector`, try-LO-then-AOO, PKCS#7 unpadding, AES-256-only, substring `is_encrypted`, decrypting rows `classify` rejected, `cfb8` over Blowfish.

## 9. Open questions

Close in this file when evidence lands. Do not guess.

1. **StarOffice / MS-1252 SHA-1 retries, and the SHA-256 force.** **Closed 2026-09-02** by `lo-odf11-nonascii-password.odt`. LO’s read ladder (`ZipPackageStream.cxx` 1014–1070) applies, per the comment at `:1021`, to “ODF 1.1/OOoXML files written by any version” — exactly our Blowfish goldens’ shape, so the ladder could not be dismissed on version grounds.

   The probe password was built so that **all four SHA-1 start-key candidates are distinct**: one non-ASCII char (U+00E4) separates UTF-8 from MS-1252, and 52 chars puts both encodings (53 and 52 bytes) inside the `len % 64 ∈ {52,53,54,55}` window where `rtl_digest_SHA1` emits a spurious block — tdf#114939, `sal/rtl/digest.cxx:1053`, whose own comment says the test should be `>` not `>=`. Deriving each candidate and checking SHA1-1K against the file LO wrote:

   | Start key | Ladder rung | Decrypts |
   |---|---|---|
   | correct SHA-1(UTF-8) | `Bugs::None` | **yes** |
   | StarOffice SHA-1(UTF-8) | `Bugs::WrongSHA1` | no |
   | SHA-256(UTF-8) | rhbz#1013844 force-SHA256 | no |
   | StarOffice SHA-1(MS-1252) | `Bugs::WinEncodingWrongSHA1` | no |

   Re-derive this rather than trusting it: `python tests/goldens/sha1_star.py` self-tests the StarOffice digest against `hashlib`, then walks every rung against the golden. Current LO writes the **correct UTF-8 SHA-1** start key even on the ODF 1.1 path that keeps the ladder alive on read. **This arc ships correct UTF-8 only, now measured rather than assumed.** The ladder stays what it always was: read-compat for files from OOo 1.x / StarOffice / LO < 3.5, which this arc does not implement — those decrypt as `WrongPassword`. Reopen only if such a file lands in-tree.

2. **`EncryptedDataHeader` on a zip member.** Wrapped-raw prepends `MM\002\005`. Ordinary save does not. Close if a golden or corpus file starts with `0x4d4d0205`; otherwise leave unimplemented.

3. **Embedded-object two-latch golden.** Detection OQ2: `Object N/content.xml` alongside root can make `common` the nested row. Decrypt walks every `encrypted_entries` path and selects wholesome by `path == "encrypted-package"`, so `common` does not matter. A fifth golden would still pin `common` for detection; not a decrypt blocker.

Settled 2026-09-02: correct UTF-8 SHA-1 is what current LO writes (OQ1, measured); password is UTF-8 `&str`; empty is an error; output is a plaintext ODF zip; PGP is a later arc; `decrypt` feature default-on; **one Blowfish wire (64-bit-segment CFB)**; start key and derived key are zeroized after use; no PBKDF2/Argon2 cap (match LO); inflate ceiling 1 GiB; `--no-default-features` is a standing check.

## 10. Why this shape

Detection already answers which rows are complete and with which tuple. Decrypting from XML again would re-lose F1/F2. The zip-shape split (inflate the inner blob vs rebuild the outer) is LO’s wholesome vs per-entry storage, not a format guess.

Wrong password is a checksum or GCM tag, never “inflate looked like XML.” Malformed parameters on a complete row are `BadParameters`, not a wrong password.
