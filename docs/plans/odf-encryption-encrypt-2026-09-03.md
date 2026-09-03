Status: **Shipped (2026-09-03)** — modern-only password encryption; per-entry write (Blowfish/AES-CBC) is a later arc · Landed in [#24](https://github.com/Slurp9187/odf-crypto/pull/24) (`7bd6a89` implementation, `9686ff5` + `%%FIXSHA%%` review fixes), closing arc [#18](https://github.com/Slurp9187/odf-crypto/issues/18) and slices [#19](https://github.com/Slurp9187/odf-crypto/issues/19)–[#23](https://github.com/Slurp9187/odf-crypto/issues/23) · Authored 2026-09-03 against `07047a02f94d` · Review round 2026-09-03: every LO citation re-grepped against source (several line ranges in round 1 had drifted, two by more than 20 lines), emit table added, S5 gating fixed, mimetype question settled

Consumes [docs/plans/odf-encryption-detection-2026-09-01.md](odf-encryption-detection-2026-09-01.md) (Shipped) and [docs/plans/odf-encryption-decrypt-2026-09-02.md](odf-encryption-decrypt-2026-09-02.md) (Shipped, arc [#10](https://github.com/Slurp9187/odf-crypto/issues/10)). Do not re-derive `classify`'s accept predicates, and do not reimplement `decrypt`'s cipher/KDF primitives — `encrypt` shares them.

# Plan — ODF package password encryption (wholesome only)

> **Goal.** `encrypt(&[u8], &str) -> Result<Vec<u8>, EncryptError>` that turns a plaintext ODF package (`classify` reports `Mode::Plain`) into the package current LibreOffice writes for that same input under that password — one `encrypted-package` member, Argon2id-derived AES-256-GCM, no checksum. Round-trips against the arc already shipped: `decrypt(encrypt(p, pw)?, pw)? == p` byte-for-byte, and `classify(encrypt(p, pw)?)?` reports the tuple in §2's emit table.

> **Modern only.** LibreOffice's *default* save-with-password path today is wholesome Argon2id + AES-256-GCM (`UseODFWholesomeEncryption` true at `ODFSVER_LATEST_EXTENDED`, the current default — its concrete value is `ODFSVER_014_EXTENDED`, but the predicate itself, and this plan, name the alias). Per-entry write (Blowfish CFB for ODF 1.1, AES-CBC for ODF 1.2/1.3) is what `SetupStorage` falls back to at an *older configured* ODF version — real, but a deliberately deferred later arc, linked not attached (§9). PGP wrap stays a later arc too, same as decrypt.

> **The acceptance contract, stated once.** `classify`'s `password_complete` predicate (`src/classify.rs`) is the sole judge of "did we write a complete row." For an `AesGcmW3c` row that predicate needs exactly: `salt`, `iv`, `size`, `enc_alg`, and `kdf` with `Argon2id` args — checksum is optional and `encrypt` must omit it, matching LO. `encrypt` is defined as *whatever byte sequence makes that predicate true with the LO-current tuple*, not as a from-scratch reimplementation of LO's storage-commit machinery. If `classify(encrypt(...))` ever disagrees with the intended tuple, the bug is in `encrypt`'s emit — never bend `classify` to fit it.

This is **not** a generic ODF-writer. It does not build a package from XML fragments; it takes bytes `classify` already calls `Mode::Plain` and wraps them.

## Authority

Same pin as detection and decrypt. Do not re-download LibreOffice. Every range below was confirmed with `grep -n` against the pinned tree while writing this plan, not estimated from a scrolled read — re-verify the same way before trusting a citation across a pin bump.

| Tree | Path | Pin |
|---|---|---|
| LibreOffice core | `O:\projects-github-clones\LibreOffice\core` | `07047a02f94d`. Re-check the files below before changing this plan. |

Primary LO files (write path; the decrypt plan's citations cover the shared read/write primitives and are not repeated here):

- `sfx2/source/doc/objstor.cxx`:
  - `:190-193` `UseODFWholesomeEncryption` — wholesome iff `nODFVersion == ODFSVER_LATEST_EXTENDED`.
  - `:349-399` `SetupStorage` — the **complete algorithm-defaults table** (§1 below), from `nDefVersion`'s declaration through the `xEncr->setEncryptionAlgorithms(...)` call that applies it.
  - `:1881-1883` — the `encrypted-package` stream's `MediaType` is read off the **already-built inner storage's own `MediaType` property** (i.e. the plaintext input's own media type, not derived independently).
  - `:1995-2021` — the wholesome mechanism itself: build the inner package as an ordinary (unencrypted) storage, obtain its raw bytes as a stream, `SetupStorage` a **brand-new outer storage**, open a stream literally named `"encrypted-package"`, and `CopyInputToOutput` the inner bytes into it. The comment reads *"encryption: just copy into package stream"* — encryption is transparent at the `XOutputStream` layer, triggered by `SID_ENCRYPTIONDATA` already being set on the medium before `GetOutputStorage()`.
- `package/source/zippackage/ZipPackage.cxx`:
  - `:1751-1778` `ZipPackage::GetEncryptionKey()` — the **write-side start-key selector**. Deterministic, no retry ladder: `SHA256` → `PACKAGE_ENCRYPTIONDATA_SHA256UTF8`, `SHA1` → `PACKAGE_ENCRYPTIONDATA_SHA1CORRECT`. The StarOffice-buggy and MS-1252 candidates decrypt already refuses to write are **never selected on write either** — confirms decrypt's OQ1 finding from the other direction.
  - `:1400-1410` — PBKDF2 iteration count (`600000` wholesome / `100000` per-entry, `:1400`) and Argon2id args (`3, 1<<16, 4`, `:1405`) are each chosen **once per save**, then threaded through `saveContents` (`:1410`) into every stream — not re-randomized per member. (Moot for this arc: wholesome has exactly one row.)
- `package/source/zippackage/ZipPackageStream.cxx:587-607` — salt is always **16** random bytes, IV is `GetIVSize()` random bytes, both via `rtl_random_getBytes` (`:590`, `:594`), immediately assigned with `setInitialisationVector`/`setSalt` (`:604-605`). Comment: *"for GCM it's particularly important that IV is unique."*
- `package/source/zipapi/ZipOutputEntry.cxx` (`ZipOutputEntryBase`, `:44-169`) — the write-side pipeline in one class: raw-deflate the plaintext, feed the **first `n_ConstDigestLength` (1024) bytes of the deflated output** to a running digest (skipped entirely when `m_oCheckAlg` is unset, which `SetupStorage` guarantees for GCM — the digest-context construction at `:68` is itself guarded so it never runs for `AES_GCM_W3C`), *then* encrypt each deflated chunk, writing ciphertext as it's produced. The zip CRC32 (`m_aCRC.update(aEncryptionBuffer)`, `:147` and `:167`) runs over the **ciphertext**, not the plaintext — the exact mirror of the decrypt-audit finding that LO CRCs the ciphertext on read.
- `package/source/zipapi/ZipOutputStream.cxx:56-97` — `setEntry` (`:56`) sets the data-descriptor flag (`nFlag |= 8`) whenever size/CRC aren't known before the header is written (true of every streamed LO write, encrypted or not — this is *not* an encryption-specific bit). `rawCloseEntry(bEncrypt)` (`:88`, forcing `nMethod = STORED` at `:96`) is what forces STORED for an encrypted entry. **We do not need to reproduce the data descriptor**: `classify`'s `check_stored_data_descriptors` (`src/classify.rs`) only rejects a STORED+DD entry that is *not* encrypted; a STORED entry *without* a data descriptor is never inspected by that check. Since `encrypt` builds the whole ciphertext in memory before writing (unlike LO's streaming writer), it can write ordinary STORED headers with sizes/CRC known upfront. Simpler than LO's own mechanism, and `classify`-legal.
- `package/source/manifest/ManifestExport.cxx` (full file is 540 lines; this arc's write path touches most of it):
  - `:145-153` — inside the OASIS-media-type branch, `if (aDocVersion.compareTo(ODFVER_012_TEXT) >= 0)`: `bStoreStartKeyGeneration = true`, `manifest:version` is written, and the `xmlns:loext` namespace is added to the root element. All three happen together, gated on the same ODF-version check.
  - `:297` — the root `/` file-entry is **omitted outright** when `isWholesomeEncryption` (`continue` before the per-entry write loop runs for that sequence).
  - `:355` — `assert(fullPath == "encrypted-package" || fullPath.startsWith("META-INF/"))`: a wholesome manifest **only ever** describes those two things.
  - `:401-424` — the algorithm-name `if`/`else if` chain: AES-256-CBC and AES-256-GCM (`:401`, `:409`) both **throw** if `nDerivedKeySize != 32`; Blowfish (`:419`) has no such check; anything else throws (`:424`). LO's own writer can never emit AES-128/192; decrypt's dispatch on key length exists only for third-party/hand-crafted files, not for anything this `encrypt` will ever produce.
  - `:437-475` — `if (bStoreStartKeyGeneration)`: SHA-256 picks **`SHA256_URL`** (`http://www.w3.org/2001/04/xmlenc#sha256`, W3C) when the cipher is GCM, or **`SHA256_URL_ODF12`** (`http://www.w3.org/2000/09/xmldsig#sha256`, the "bad ODF URL" kept for ODF ≤ 1.4 interop) for CBC — comment: *"new encryption is incompatible anyway, use W3C URL"* vs *"to interop with ODF <= 1.4 consumers use bad ODF URL."* **Same `StartKeyAlg::Sha256`, two different written URIs, selected by cipher.** `key-size` is written as a decimal string (`32` for SHA-256, `20` for SHA-1).
  - `:477-498` — key-derivation, Argon2id branch: `ATTRIBUTE_KEY_DERIVATION_NAME` = `ARGON2ID_URL_LO`, then `loext:argon2-iterations`/`-memory`/`-lanes` (`:496-498`) from the `(t, m, p)` tuple. The PBKDF2 branch (not used by this arc) writes `manifest:iteration-count` instead. Salt is written in both branches, just below this block.
  - `:517-522` — `key-derivation`'s own `manifest:key-size` attribute (comment: *"ODF 1.3 specifies the default as 16 so have to write it for PGP"*) is written **only when `bStoreStartKeyGeneration`** is true — always true for wholesome, since wholesome only exists at ODF ≥ 1.2.
- `package/source/manifest/ManifestDefines.hxx:76-103` — the literal URI/name constants (`AESGCM256_URL`, `SHA256_URL`, `SHA256_URL_ODF12`, `ARGON2ID_URL_LO`, `ATTRIBUTE_ARGON2_{T,M,P}_LO`) `uris.rs` must already accept, since these are the exact strings the goldens were produced with.
- `xmlsecurity/source/xmlsec/nss/ciphercontext.cxx` — the encrypt-direction half of the same function decrypt already cites for read. GCM (`OCipherContext::finalizeCipherContextAndDispose`, encrypt branch): NSS does not prepend the IV, so LO does — `memcpy` the 12-byte IV first, then `PK11_Encrypt` writes ciphertext‖tag after it. AAD is empty.
- `xmlsecurity/source/xmlsec/nss/nssinitializer.cxx:583-596` — `ONSSInitializer::getCipherContext` maps `CipherID::AES_GCM_W3C` → the raw PKCS#11 mechanism `CKM_AES_GCM` (`:594-595`). Corroborates the algorithm choice from a second code path, independent of `ciphercontext.cxx`.
- `xmlsecurity/qa/unit/signing/signing2.cxx` — QA-level corroboration only (secondary to the production citations above): its wholesome fixtures carry no checksum attributes, its per-entry ODF 1.2/1.3/1.4 fixtures do. Do not walk the rest of `xmlsecurity/` looking for more — signatures, certificates, PDF signing, and GPG UI live there and none of it is this arc's write path.
- `package/source/zipapi/blowfishcontext.cxx` + `sal/rtl/cipher.cxx` — same class, same 64-bit-segment CFB, `bEncrypt` flag flips direction. **Out of scope for this arc** (per-entry only); cited here only so the later per-entry-write arc does not have to re-derive it — decrypt's Rust already has the correct primitive (`cfb_mode::BufDecryptor`; the encryptor is the same crate's `BufEncryptor`).

## Out of scope

- Per-entry write (Blowfish CFB for ODF 1.1, AES-CBC + SHA256-1K for ODF 1.2/1.3). Real LO behavior (`SetupStorage`'s non-wholesome branch), but a deliberately separate later arc (§9) — the wholesome case alone already exercises every shared primitive (start key, Argon2id, AES-GCM framing, manifest emit machinery) except the checksum-writing branch and the multi-row rebuild, both of which decrypt already implements the *read* half of.
- PGP wrap (`Kdf::PgpRsaOaepMgf1p`). Later arc, same status as in decrypt.
- `EncryptedDataHeader` / wrapped-raw output. Decrypt doesn't read it; encrypt won't write it.
- Building an ODF package "from scratch" (arbitrary XML in, package out). Input must already be a `Mode::Plain` package.
- `LO_ARGON2_DISABLE`. §1's table mentions it because `SetupStorage` does; this arc never reads that env var and never falls back to PBKDF2 for the wholesome case. It implements the one default row.
- Matching LO's *exact* compressed bytes. Raw DEFLATE is not byte-reproducible across encoders/levels for the same input in general, and it doesn't need to be: `inflate(deflate(x)) == x` regardless of encoder, which is the only property `decrypt` on the far end relies on. `encrypt`'s ciphertext will differ from a real LO save of the same input (different salt, IV, and probably different deflate bytes) — that is expected and does not affect correctness.
- Re-implementing `classify` or `decrypt`'s cipher primitives. `encrypt` calls into shared internal helpers factored out of `src/decrypt.rs` (§4); it does not carry its own copy of key derivation or the AES-GCM wrapper.
- Choosing an ODF version for the caller. Wholesome always writes `manifest:version="1.4"` (§2) — not derived from the input's own version, because LO's outer storage is brand-new and never inherits it (`SetupStorage` sets it from the current save-time default config, not from the document being wrapped).

## 1. The algorithm-defaults table (`SetupStorage`, `objstor.cxx:349-399`)

The full table, so the later per-entry arc has it in one place even though this arc only implements the last row:

| `nDefVersion` | Start key | Cipher | Checksum | KDF |
|---|---|---|---|---|
| `< ODFSVER_012` (ODF ≤ 1.1) | SHA-1 | Blowfish CFB | SHA1-1K | PBKDF2 |
| `>= ODFSVER_012`, not wholesome (ODF 1.2/1.3) | SHA-256 | AES-256-CBC-W3C | SHA256-1K | PBKDF2 |
| `ODFSVER_LATEST_EXTENDED` (wholesome) | SHA-256 | AES-256-GCM | **none** (`Value.clear()`) | Argon2id, unless `LO_ARGON2_DISABLE` is set (out of scope, see above) |

This arc implements only the last row. `manifest:version` is written (`"1.4"` for the wholesome row, per `getODFVersionAny`) for every row except the first, which writes no `Version` property at all — matching the ODF 1.1 goldens' omitted `manifest:version`.

## 2. Pipeline and exact emit values

Reverse of decrypt's, sharing every primitive except direction:

```
plaintext ODF zip (the whole input buffer, opaque)
  -> raw DEFLATE                              (miniz_oxide compress_to_vec -- raw, no zlib wrapper)
  -> start key: SHA-256(UTF-8(password))      (shared with decrypt)
  -> Argon2id v13, t=3, m=65536 KiB, p=4       (shared with decrypt; password to Argon2 is the start key)
  -> AES-256-GCM, random 12-byte IV, empty AAD (new encrypt-direction helper; §4)
  -> member bytes = IV || ciphertext || tag
  -> wrap: outer zip { mimetype, encrypted-package, META-INF/manifest.xml }
```

Salt is 16 random bytes; IV is 12 random bytes for GCM. Both come from a CSPRNG (§4) — this arc's one genuinely new primitive, since decrypt never had to generate randomness.

**No checksum is computed or written.** GCM's tag is the only integrity check, matching `SetupStorage`'s `Value.clear()` for the digest algorithm.

**Exact emit values** (this is the tuple every close-when in §7 checks against; derived from §Authority and cross-checked against `tests/goldens/URIS.md`'s recorded `lo-wholesome-gcm-argon2.odt` emit):

| Field | Written value |
|---|---|
| root `manifest:manifest/@manifest:version` | `1.4` |
| root `xmlns:loext` | present |
| `file-entry/@manifest:full-path` | `encrypted-package` |
| `file-entry/@manifest:media-type` | copied from the input's `mimetype` member (§3) |
| `file-entry/@manifest:size` | the plaintext input's length in bytes |
| `encryption-data` checksum attributes | absent |
| `algorithm/@manifest:algorithm-name` | `http://www.w3.org/2009/xmlenc11#aes256-gcm` |
| `algorithm/@manifest:initialisation-vector` | base64, 12 random bytes |
| `start-key-generation/@manifest:start-key-generation-name` | `http://www.w3.org/2001/04/xmlenc#sha256` (the W3C URL, **not** the CBC `xmldsig` one) |
| `start-key-generation/@manifest:key-size` | `32` |
| `key-derivation/@manifest:key-derivation-name` | `urn:org:documentfoundation:names:experimental:office:manifest:argon2id` |
| `key-derivation/@loext:argon2-iterations` | `3` |
| `key-derivation/@loext:argon2-memory` | `65536` |
| `key-derivation/@loext:argon2-lanes` | `4` |
| `key-derivation/@manifest:salt` | base64, 16 random bytes |
| `key-derivation/@manifest:key-size` | `32` |
| child order inside `encryption-data` | `algorithm`, `start-key-generation`, `key-derivation` |
| root `/` file-entry | absent |

## 3. Zip shape out

Exactly the inverse of decrypt's wholesome case, and just as simple: `objstor.cxx:1995-2021` shows LO treats the *entire* inner package as an opaque blob it never parses. `encrypt` does the same — it never touches the input's own manifest structure or member list beyond the two things below.

**Media type and the `mimetype` member.** Copy the input zip's own `mimetype` member **bytes verbatim** (read it directly from the input archive) rather than re-deriving them from `classify`'s recovered `media_type` string — the two can diverge on a trailing newline or an encoding nuance, and the input already has the exact bytes LO itself would reuse. If the input has no `mimetype` member at all (a constructed `Mode::Plain` zip that classify still accepts via the manifest-only path), fall back to writing `classify`'s `media_type` as raw UTF-8 with no trailing newline; if that is also `None`, write no `manifest:media-type` attribute on the `encrypted-package` file-entry at all — matching `ManifestExport.cxx`'s own behavior of only emitting the attribute when a `MediaType` value is actually present.

Steps:

1. `classify(bytes)?` — used only to reject non-`Plain` input (§6) and, when present, to source the `mimetype` fallback above. Nothing else about the `Classification` matters here.
2. Raw-deflate `bytes` (the whole input, unparsed) → encrypt → that is the `encrypted-package` member's payload.
3. Emit an outer zip with exactly three members, in this order: `mimetype` (STORED, contents per the paragraph above), `encrypted-package` (STORED, no data descriptor needed — §Authority), `META-INF/manifest.xml` (DEFLATED; the `zip` crate's existing `deflate` feature already writes this shape, proven by `decrypt::rebuild_zip`).
4. The manifest has **one** `file-entry` and the root attributes from §2's emit table — no `/` file-entry.

## 4. Types

Extends the same crate. `decrypt`'s internal cipher/KDF helpers move to an internal module both `decrypt.rs` and a new `encrypt.rs` call — **do not let `encrypt.rs` reimplement key derivation or the AES-GCM wrapper**; that is exactly the kind of duplication that let decrypt's AES-256-only bug ship once already (decrypt arc audit, `3c3bc33`). Concretely, during S1:

- `start_key` and `derive_key`'s Argon2id branch move as-is — key derivation does not depend on direction, so this is a verbatim relocation, not new code.
- The AES-GCM **decrypt** call already exists in `decrypt.rs` (dispatching `Aes128Gcm`/`Aes192Gcm`/`Aes256Gcm` by key length). `encrypt` needs a **new** sibling `aes_gcm_seal`-shaped helper calling `.encrypt(nonce, plaintext)` on the same key-length-dispatched cipher type — this is new code, not a relocation, and it is the one place a copy-paste of the Argon2 parameter order `(m, t, p)` (RustCrypto's `Params::new`, already gotten right once in decrypt) could quietly diverge if reimplemented independently instead of calling the shared function.
- A new `raw_deflate` helper (mirroring `raw_inflate`'s existing shape) is also new code — nothing to relocate, since decrypt only ever inflates.

A new **`encrypt` feature**, default-on, that *enables* `decrypt` (shared primitives). It needs a CSPRNG for salt/IV generation, and **as shipped that costs no new dependency** — §9's OQ2, settled during S1: `aes-gcm`'s own default `getrandom` feature already supplies `aes_gcm::aead::OsRng`. Name that reliance explicitly the same way the decrypt-arc audit insisted `flate2` be named or removed. As shipped:

```toml
[features]
default = ["encrypt"]
decrypt = [ ...unchanged... ]
encrypt = ["decrypt"]

[dependencies]
aes-gcm = { version = "0.10", optional = true, features = ["getrandom", "zeroize"] }
```

`default = ["encrypt"]` alone is sufficient (it pulls in `decrypt` transitively) — do not also list `"decrypt"` in `default`, that would just be redundant. `--no-default-features` still builds detection-only with neither feature enabled.

Note the consequence OQ2's original wording did not anticipate: because `aes-gcm` is a **`decrypt`**-feature dependency, its CSPRNG is in the `decrypt`-only graph too, not "only under `encrypt`". Nothing in `decrypt` uses it; the guarantee that holds — and that the standing check enforces — is the `--no-default-features` one, where no crypto crate appears at all.

```rust
fn encrypt(bytes: &[u8], password: &str) -> Result<Vec<u8>, EncryptError>;

#[non_exhaustive]
enum EncryptError {
    Classify(DetectError),   // classify() itself rejected the input (not a zip, no manifest, ...)
    AlreadyEncrypted,        // classify(bytes)?.mode != Mode::Plain -- covers PerEntry, Wholesome, and PGP rows alike
    EmptyPassword,           // mirrors decrypt::EmptyPassword / CreatePackageEncryptionData's empty sequence
    Random(String),          // CSPRNG failure -- vanishingly rare, but a library must not panic for it
    Deflate(String),         // raw-deflate of the input buffer failed
    Zip(String),             // building the outer zip container failed
}
```

`#[non_exhaustive]` for the same reason as `DecryptError`: a later per-entry-write arc adds variants without a semver break. No `BadParameters` analogue — unlike decrypt, `encrypt` never validates untrusted manifest fields; every parameter it emits is one it chose itself.

`EncryptProfile`-style parameterization (which cipher/KDF/ODF-version to target) is deliberately **not** part of this arc's API. There is exactly one thing to write. A later per-entry arc is the place to decide whether that becomes a second function or a parameter — do not pre-build the generality now.

**Deflate ceiling.** Name a `DEFLATE_CEILING` constant alongside `EncryptError`, matching decrypt's `INFLATE_CEILING` (1 GiB) in shape. It plays a different role here: decrypt's ceiling defends against an attacker-controlled `manifest:size`; `encrypt`'s caller supplies the plaintext directly, so this is hygiene (no unbounded allocation on a pathological input) rather than a security boundary. Say so in the doc comment so nobody "fixes" it into a security claim it isn't.

## 5. Validation strategy

Two layers, mirroring how decrypt was closed (self-consistency first, then real LibreOffice evidence for the parts self-consistency cannot catch):

**Round-trip, self-consistent.** `decrypt(encrypt(p, pw)?, pw)? == p` byte-for-byte is achievable and is the centerpiece close condition — not approximate, not "content-equivalent." Wholesome's opaque-blob shape (§3) makes this exact: `encrypt` deflates `p` once, `decrypt` inflates the same bytes back once, and `inflate(deflate(x)) == x` always holds for valid DEFLATE regardless of encoder or level. If this ever fails, the bug is in the framing (IV/tag placement, salt/IV lengths), not in compression.

**Self-consistency alone is not sufficient**, and this arc does not stop there. If `encrypt` and `decrypt` shared the same misunderstanding of the wire format, round-tripping against each other would never catch it — classify's own pre-audit history is exactly this failure mode (internally consistent, still wrong). The check that catches it is real LibreOffice opening our output:

- `make_goldens.py` already has full UNO bootstrap/connect scaffolding. Add a small counterpart that `loadComponentFromURL`s a file **produced by this crate's `encrypt`** with a `Password` property, and asserts the load succeeds and the recovered text matches what was written before encrypting. This is `tests/goldens/`'s existing LO-as-ground-truth pattern, run in the opposite direction from `make_goldens.py`'s own document creation.
- This is S5 (§7). It needs LibreOffice installed to *produce* its evidence, but it does not stay gated on that forever — see S5's close-when for how the evidence becomes a checked-in, environment-independent artifact, the same way detection's goldens are.

## 6. `encrypt` — steps

1. If `password` is empty, fail (`EmptyPassword`).
2. `classify(bytes)?`. Map `DetectError` to `Classify`. If `mode != Mode::Plain`, fail (`AlreadyEncrypted`).
3. Raw-deflate `bytes` in full, under `DEFLATE_CEILING` (`Deflate` on failure — should not happen for any input `classify` accepted, but library code does not `unwrap`).
4. Start key: `Sha256(UTF-8(password))`, zeroized after use.
5. Generate salt (16 random bytes) and IV (12 random bytes) via the CSPRNG (`Random` on failure).
6. Argon2id `(t=3, m=65536, p=4)` over the start key with that salt → 32-byte derived key, zeroized after use.
7. AES-256-GCM-encrypt the deflated buffer with that key/IV, empty AAD. Member payload = `IV || ciphertext || tag`.
8. Build the manifest XML per §2's emit table.
9. Assemble the three-member outer zip per §3.
10. Stop. No fallback cipher, no version negotiation, no attempt to also produce a per-entry package.

## 7. Slices

| Slice | Work | Done when |
|---|---|---|
| **S1** | `encrypt` feature (default on per §4's Cargo shape, enables `decrypt`; the CSPRNG needs no new dependency — OQ2). Factor `start_key` and `derive_key`'s Argon2id branch into shared `pub(crate)` helpers reused as-is by both modules (§4). `EncryptError` (`#[non_exhaustive]`). `encrypt` calls `classify`; refuses `Mode::Plain`-violating input and empty passwords. No cipher output yet. | `encrypt` on `lo-wholesome-gcm-argon2.odt` (already `Mode::Wholesome`) → `AlreadyEncrypted`. Empty password → `EmptyPassword`. `cargo test --offline --no-default-features` still green. |
| **S2** | Raw deflate, salt/IV generation, Argon2id, the new AES-256-GCM encrypt-direction helper (IV‖ct‖tag), manifest emit (§2's exact emit table), three-member outer zip, `mimetype` handling per §3. | `encrypt(lo-unencrypted.odt, "password")` produces a zip whose manifest matches §2's emit table exactly, and `classify` on it reports `Mode::Wholesome`, one row, `Cipher::AesGcmW3c`, `Kdf::Argon2id { t: 3, m: 65536, p: 4, .. }`, `StartKeyAlg::Sha256`, `Checksum::None`, `derived_key_len == 32`. |
| **S3** | Wire S2's output into the round-trip. | `decrypt(encrypt(lo-unencrypted.odt bytes, "password")?, "password")?` is **byte-identical** to the original bytes. Repeat for at least one non-trivial plaintext constructed in-test (embedded content, non-ASCII text) — and assert that constructed fixture itself `classify`s as `Mode::Plain` before encrypting it, so the test is exercising this arc and not accidentally validating a fixture `classify` would have rejected. |
| **S4** | Constructed negatives. | `"wrong"` against S3's output → `DecryptError::WrongPassword` from the GCM tag, before any inflate (same evidence shape decrypt's own S4/S5 already established). `encrypt` against **every** existing encrypted golden, discovered by iterating the goldens directory at run time rather than hardcoding a count that will drift again — as it did: the arc's own S5 evidence file (`lo-opens-our-encrypt-output.odt`) became a fifth before the arc even landed → `AlreadyEncrypted`. `cargo test --offline --no-default-features` still green (standing check, every slice). |
| **S5** | Real LibreOffice opens our output (§5): a UNO-driven script that loads `encrypt`'s output with the password and checks the recovered text. | The script exists in the repo **and** its output from a successful local run is checked in as evidence — the encrypted file it validated (or a recorded transcript of the load succeeding), the same way detection's real goldens are the checked-in evidence for its S6. Do not close this slice on "it happened to work when I ran it" with nothing committed; do not gate it on CI having LibreOffice installed, since it never will. If S2-S4 are green and this fails, the bug is a framing detail self-consistency cannot see (e.g. an IV/tag byte order LO's NSS binding is stricter about than our own decrypt is). |

S2 blocks on S1. S3 and S4 block on S2. S5 blocks on S3 (needs real output to feed LO).

## 8. Borrow / do not copy

**Borrow:** decrypt's already-audited `Zeroizing` key handling, its GCM framing constants (12-byte IV, 16-byte tag, IV-prepended), and its ceiling-on-a-buffer discipline (§4's `DEFLATE_CEILING`).

**Do not copy:** a per-stream salt/IV reuse (§Authority: LO generates fresh randomness per stream — moot here since wholesome has one row, but do not let a future per-entry arc reuse one salt/IV pair across members). Do not derive `manifest:version` from the input's own version (§Out of scope) — it is always `"1.4"` for this arc's one profile. Do not reimplement key derivation inside `encrypt.rs` (§4). Do not re-derive the `mimetype` member's bytes from `media_type` when the input already has a `mimetype` member to copy verbatim (§3).

## 9. Open questions

1. **Per-entry write (Blowfish CFB / AES-CBC).** Real LO behavior, fully characterized in §1's table and already cited in §Authority so the arc that implements it does not have to re-derive the primitives. Not started. Close when there is a concrete reason to target an older ODF version on write (there is none today — wholesome is LO's current default).
2. **`getrandom` vs. an already-vendored CSPRNG.** Settled during S1 (2026-09-03): no new dependency. `aes-gcm` 0.10.3's own `Cargo.toml` declares `default = ["aes", "alloc", "getrandom"]`, and its `getrandom` feature is `["aead/getrandom", "rand_core"]` — `aead` 0.5.2's `getrandom` feature in turn gates `pub use crypto_common::rand_core::OsRng;` and re-exports `rand_core` (hence `RngCore`). Confirmed against this repo's actual graph with `cargo tree -e features -p aes-gcm` (`getrandom`/`rand_core` both resolve in) and a throwaway compile check against `aes_gcm::aead::{OsRng, rand_core::RngCore}`. Since the crate's `aes-gcm` dependency had no `default-features = false`, this was already active with zero `Cargo.toml` changes; `Cargo.toml` now names it explicitly (`aes-gcm = { version = "0.10", optional = true, features = ["getrandom"] }`) to pin the reliance against aes-gcm ever changing its own defaults — the same naming discipline the decrypt-arc audit wanted for `flate2`. `encrypt`'s salt/IV generation uses `aes_gcm::aead::OsRng` with `aes_gcm::aead::rand_core::RngCore::try_fill_bytes` (the fallible variant, not `fill_bytes`, which panics). No `getrandom` crate appears in `[dependencies]`, and `encrypt`'s feature is simply `encrypt = ["decrypt"]` — §4's Cargo snippet (`dep:getrandom`) was this open question's original guess, superseded by this finding.

Settled 2026-09-03: modern-only (wholesome Argon2id + AES-256-GCM) is the full initial scope; per-entry write is a linked, unattached later arc. `manifest:version` is a fixed `"1.4"` for this arc, never derived from the input. `encrypt`/`decrypt` share cipher and KDF primitives through an internal module; neither carries its own copy. Self-consistent round-trip is necessary but not sufficient — a real-LibreOffice-opens-it slice is part of this arc, closed on checked-in evidence rather than on a re-runnable-if-you-happen-to-have-LO script. The `mimetype` member is copied verbatim from the input when one exists, not re-derived from `media_type` — settled during review round 2 once the two were shown able to diverge.

## 10. Why this shape

Decrypt answered "given a complete row, what does the plaintext look like." Encrypt answers the question decrypt never had to: which row to write in the first place. The two questions have almost the same answer — `SetupStorage`'s table (§1) is nothing but decrypt's cipher/KDF/checksum knowledge indexed by ODF version instead of read from a manifest — which is exactly why encrypt should not duplicate decrypt's crypto code: the two directions of the same cipher call are the only genuinely new logic this arc contains. Everything else — which URI, which order, whether a checksum exists — is a lookup decrypt already knows how to read and this arc only has to know how to write.

The strongest evidence this shape is right is not that our own `encrypt` and `decrypt` agree with each other (that only proves *we* are self-consistent), but that real LibreOffice — which was never shown a single line of this crate — accepts what `encrypt` writes. That is the same standard detection and decrypt were held to with real `.odt` goldens, applied to the direction that produces files instead of reading them.
