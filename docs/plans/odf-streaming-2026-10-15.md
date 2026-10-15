Status: **Built (2026-10-15)**, unreleased: S1–S9 in #97–#100 and the S8/S9 PR; rc.10 publishing is the owner's call · approved by the owner 2026-10-15 · Authored 2026-10-15 against `8e1e1b6` (rc.9) · LibreOffice citations against the local clone at `07047a02f94d`, the same pin as the earlier arcs · Consumer: EFV master issue #1193 (A5)

Consumes [odf-encryption-decrypt-2026-09-02.md](odf-encryption-decrypt-2026-09-02.md) and [odf-encryption-encrypt-2026-09-03.md](odf-encryption-encrypt-2026-09-03.md), both Shipped. Do not re-derive `classify`'s accept predicates. The streaming entry points run the **same** `ManifestImport` / `parseManifest` machines, made generic over `Read + Seek`.

# Plan: streaming `decrypt_to` / `encrypt_to` / `reencrypt_to` (rc.10)

> **Goal.** Decrypt, encrypt and re-key ODF packages from `R: Read + Seek` to a writer, with peak heap flat as the payload grows. That holds *within* a member: a wholesome package is one member, and a member can be a 4 GB video. The whole-buffer API keeps its signatures and behavior, and is reimplemented over the same core so there is one cipher implementation.

> **Out of scope.** Per-entry *write* (#59). PGP. Any format change: output is what rc.9 writes, and LibreOffice 24.8+ opens it.

## 1. What upstream does

- **CBC and Blowfish members.** `ZipFile::checkValidPassword` / `StaticHasValidPassword` (`package/source/zipapi/ZipFile.cxx:482-585`):
  - They decrypt at most `n_ConstDigestDecrypt` = 1056 bytes and digest the first 1024 bytes of deflated plaintext (`package/inc/PackageConstants.hxx:30-31`).
  - With no digest, any password is accepted (`ZipFile.cxx:522`).
  - Only then does `XUnbufferedStream` stream the **rest unauthenticated**, in chunks of at least 8 KiB (`XUnbufferedStream.cxx:253-285`). The CRC over ciphertext is compared at EOF, after release (`:300-301`).
- **GCM members.**
  - The NSS context buffers the whole member and releases nothing until `PK11_Decrypt` verifies the tag (`xmlsecurity/source/xmlsec/nss/ciphercontext.cxx:158-167, 277-293`).
  - `XBufferedStream` holds the inflated member (`ZipFile.cxx:606-635`).
- **Wholesome packages.** The inner package is copied whole into a `UNOMemoryStream`, "need a seekable stream => copy" (`sfx2/source/doc/docfile.cxx:1775-1779`).
- **Writing.**
  - The manifest goes last (`ZipPackage.cxx:1349 → 1410 → 1416`).
  - Deflate-then-encrypt runs chunk by chunk (`ZipOutputEntry.cxx:122-169`).
  - `manifest:size` is the uncompressed plaintext size (`ZipPackageStream.cxx:538-545`).
- **Zip64 and data descriptors.**
  - LibreOffice reads and writes Zip64 since 7.6 (`abda72eeac19`, tdf#82984).
  - It reads data descriptors (bit 3) (`ZipFile.cxx:1047, 1634, 1763`).

**Consequence.** Streaming goes *further* than LibreOffice on memory, because LibreOffice buffers GCM members and wholesome packages whole. It must make **the same accept/refuse decision**, and verify-before-release (§2) is that decision taken earlier.

## 2. Verdict per operation

| operation | streams with flat heap? | verify-before-release |
|---|---|---|
| decrypt, wholesome GCM | yes | **Two passes over `R`.**<br>• Pass 1 GHASHes the ciphertext and checks the tag in constant time; no plaintext exists yet.<br>• Pass 2 runs CTR → inflate → `W`, re-GHASHing; if the tag differs (input mutated between passes), it is an error. |
| decrypt, per-entry CBC / Blowfish | yes | **Hold back the 1K window.** Decrypt until 1024 bytes of deflated plaintext are final (CBC also holds back its last block for padding), check the digest, then release. This is exactly LibreOffice's guarantee; the rest is unauthenticated upstream too, and the docs say so. A member shorter than 1 KiB + 1 block is held whole. |
| decrypt, per-entry GCM | yes | The same two passes, per member. |
| SHA-1 ladder (`kdf::SHA1_LADDER`) | yes | 1K rows try each rung on the 1056-byte window. A GCM row costs one GHASH pass per rung (H differs per key), so at most 4. |
| encrypt (wholesome AES-256-GCM + Argon2id) | yes, one pass | read → deflate → CTR + incremental GHASH → Stored `encrypted-package`. The tag goes at the end; the manifest goes last, with `manifest:size` counted on the way. |
| re-encrypt, wholesome → wholesome | yes | Pass 1 checks the old tag. Pass 2 re-keys the **deflated stream as is**, so the deflate bytes and `manifest:size` carry over. An inflate-to-sink validates `manifest:size`. Plaintext never reaches disk. |
| re-encrypt, per-entry → wholesome | yes | 1K gate per member → inner zip in **streaming mode with data descriptors** (it lives inside a cipher stream and cannot be seeked) → deflate → GCM → `W`. Refusals are in §4. |

## 3. API (additive; whole-buffer signatures unchanged)

```rust
pub fn classify_reader<R: Read + Seek>(r: R) -> Result<Classification, DetectError>;
pub fn decrypt_to<R: Read + Seek, W: Write>(r: R, w: W, password: &str) -> Result<DecryptOutcome, DecryptError>;
pub fn decrypt_with_limits_to<R: Read + Seek, W: Write>(r: R, w: W, password: &str, limits: DecryptLimits) -> Result<DecryptOutcome, DecryptError>;
pub fn encrypt_to<R: Read + Seek, W: Write + Seek>(r: R, w: W, password: &str) -> Result<(), EncryptError>;
pub fn encrypt_with_params_to<R: Read + Seek, W: Write + Seek>(r: R, w: W, password: &str, params: Argon2Params) -> Result<(), EncryptError>;
pub fn reencrypt_to<R: Read + Seek, W: Write + Seek>(r: R, w: W, old: &str, new: &str, limits: DecryptLimits, params: Argon2Params) -> Result<DecryptOutcome, ReencryptError>;

#[non_exhaustive] pub struct DecryptOutcome { pub integrity: IntegrityOutcome }
#[non_exhaustive] pub enum IntegrityOutcome {
    Verified,          // an AEAD (GCM) tag covered every encrypted member
    PasswordCheckOnly, // some member was checked only by its 1K SHA-1/SHA-256 digest
}
```

**Signatures**

- `IntegrityOutcome` reports the **weakest** level across the members.
- **Bounds.**
  - `R` must seek: it holds the central directory and is read in two passes.
  - Decrypt's `W` is `Write` only, so a hashing sink works.
  - Encrypt and re-encrypt need `W: Seek`, to patch the Stored `encrypted-package` header.
- **Aligned with msoffice-crypto** (`decrypt_ooxml_to` / `encrypt_ooxml_to`). The owner wants the sibling APIs alike.
  - **Shared:** argument order (`r, w, password`, extras last); `encrypt` returns `()`; decrypt returns a `DecryptOutcome { integrity: IntegrityOutcome }`; on any `Err` the caller discards `W` (the docs say it in those words); two-pass verify with the tag recomputed on pass 2; a cancelling reader's error surfaces as an `Io` variant; the KDF is uninterruptible.
  - **Different, and forced by the format:**
    - There is no `IntegrityPolicy` parameter. ODF offers the reader no choice, and refusing a 1K-only file would refuse files LibreOffice opens.
    - Variant sets differ. msoffice-crypto has `Verified` / `NotDeclared` / `NotApplicable` / `Skipped`; only `Verified` means the same thing in both.
    - `max_output_bytes` / `OutputLimit` has no msoffice-crypto counterpart. There, plaintext is at most the `EncryptedPackage` stream and there is no inflate, so output cannot exceed input. ODF members inflate, so a bomb is possible here.

**Errors and limits**

- New `#[non_exhaustive]` variants:
  - `DecryptError::Io`, `EncryptError::Io`, `ReencryptError::Io`
  - `DecryptError::OutputLimit { limit: u64 }`
  - `ReencryptError::{PartiallyEncrypted, UnexpectedStreams}`, from §4
- Each new variant gets an entry in the CLI exit map and in the no-`_`-arm completeness tests. `OutputLimit` and both refusals map to exit 5.
- **`DecryptLimits::max_output_bytes: u64`**, default **16 GiB**, set with `with_max_output_bytes`.
  - It is checked against a running count on every chunk, across members, and in re-encrypt's validation inflate.
  - The docs call it **our policy, not a format rule**.
  - The whole-buffer path also keeps its 1 GiB memory ceilings.
  - Inflating past `manifest:size` still stops at `size + 1`.
- **Cancellation.** All work is driven by `R::read`. Key derivation runs between reads and stays bounded by `DecryptLimits`.

## 4. Re-encrypt refusals (owner decision Q4, narrowed)

- **A wholesome source skips the inner-package checks.** The GCM tag authenticated every byte, so this is a re-key, not an encrypt.
- **A per-entry source is refused** before any derivation, and before any write to `W`, when the outer `Classification` it already computes has any of:
  - **(a)** `has_non_encrypted_entries` → `PartiallyEncrypted`
  - **(b)** `has_unexpected_streams` at **any** ODF version → `UnexpectedStreams`. Below 1.2 these members are not fatal, and the rebuild would carry them through.
  - **(c)** the unlatched shape, `!package_encrypted` with encrypted entries → `PartiallyEncrypted`
- **Why.** Without these refusals, a plain member slipped into a legacy file would be laundered into a GCM-authenticated container. EFV's round-trip digest proves the rewrite was faithful, not that the source was intact.
- **This is our policy, not fidelity.** `decrypt` and `decrypt_to` still open every shape LibreOffice opens (`decrypt_tests.rs:1667`). LibreOffice's own re-key is open-then-save, after `ERRCODE_SFX_INCOMPLETE_ENCRYPTION` (`sfx2/source/doc/objmisc.cxx:1028-1063`).
- A per-entry source that passes returns `PasswordCheckOnly`. Tampering past a member's first 1 KB is undetectable, upstream included.

## 5. Design

- **GCM is composed from crates already in `Cargo.lock`:** `aes` 0.8, `ctr` 0.9 (`Ctr32BE`) and `ghash` 0.5. aes-gcm 0.10 has no streaming API.
  - The crate count must not change. Measure it with the `cargo tree` command in CLAUDE.md before and after.
  - The construction: J0 = IV‖0³¹‖1, CTR starts at J0+1, tag = GHASH(H, ∅, C) ⊕ E(K, J0). The tag is compared with `digest_eq`.
  - Proved against `aes-gcm` (randomized lengths, both directions) and NIST vectors.
- **CBC / Blowfish.** Incremental `cbc::Decryptor` and `cfb_mode::BufDecryptor`, the ciphers rc.9's `decrypt_aes_cbc` and `decrypt_blowfish_cfb64` ran whole-buffer, with rc.9's `verify_checksum` comparison on the held-back window. *(Those rc.9 functions were removed in S8; `stream::ChecksumGate` is the comparison now.)*
- **Inflate.** `miniz_oxide::inflate::core::decompress` into a caller-owned 32 KiB wrapping buffer, so the dictionary window is ours to wipe.
- **Deflate.** `miniz_oxide::deflate::core` at level 6, matching `raw_deflate` (`encrypt.rs:787`).
- **Zip** (`zip` 2.4.2):
  - Reads go through `ZipArchive<R>` with `by_index_raw`.
  - Encrypt writes through `ZipWriter<W: Write + Seek>`, Stored, chunk by chunk.
  - `large_file(true)` is set when the input is at least 4 GiB − 64 KiB. The exact bound on deflate expansion is written in the code.
  - Plain members are copied with `raw_copy_file`.
  - The per-entry decrypt rebuild **and** re-encrypt's inner zip use a **crate-private streaming zip writer** with data descriptors. *Amended after S1; see §7.*
  - The whole-buffer `decrypt` keeps a seekable rebuild over `Cursor<Vec<u8>>`, so its output stays byte-identical to rc.9. Only the zip-writer constructor differs; the crypto is shared.
- **Secrets** (secure-gate `=0.9.0-rc.12`, `odf-crypto-secure-gate` skill).
  - 64 KiB chunk buffers that hold plaintext, the inflate window and the 1K hold-back buffer are allocated once at their final size, fallibly, never grown, and wiped on drop.
    - Chunk-sized buffers are `Dynamic<[u8]>`: a boxed slice, heap-allocated, with no `push` or `extend`, so growing one does not compile. 16-byte secrets (the GCM tag mask, the held CBC block) are `Fixed<[u8; 16]>`. The streaming zip writer follows the same rule.
    - *Amended in S2, twice.* The draft said `Fixed` for all of them, but a 64 KiB array moved by value is the wrong shape. The first replacement, `Dynamic<Vec<u8>>` allocated once, was rejected in review: "never grown" held only until an edit grew it. The coordinator chose the boxed slice so the rule holds by construction.
  - No key or password appears in an error, a `Debug` output or a static. KDFs and `derive_key` are unchanged.
- **Named residual.** These hold plaintext dictionary state that cannot be wiped under `unsafe_code = "forbid"`. It is the #39 class, recorded in the code; the consumer's mitigation is a zero-on-dealloc allocator.
  - miniz's `CompressorOxide`
  - the zip crate's internal deflater in the per-entry rebuild
- **Residual closed.** #51's `read_member_at` infallible `read_to_end`: nothing reads a member whole any more. `ZipArchive::new`'s count-driven preallocation stays open, as documented.

## 6. Slices

| # | what | done when |
|---|---|---|
| S1 | `classify` generic over `Read + Seek` internally; `classify(&[u8])` becomes a `Cursor` call. `classify_reader`. `Io` variants and `OutputLimit`, with exit-map and completeness entries. `max_output_bytes`. Confirm the `zip` streaming APIs. | The full suite is green in all 3 configurations; `classify_reader == classify` on every golden, ladder and artifact file. |
| S2 | Crate-private streaming primitives: GCM (ctr + ghash), CBC / Blowfish with the 1K gate, inflate / deflate with wiped buffers. | KATs against `aes-gcm` and NIST; byte-equality with the whole-buffer primitives on every golden member; each gate falsified (break it, watch the test fail, record it in the commit). |
| S3 | `decrypt_to`, wholesome: two-pass GCM, ladder, per-chunk limit, pass-2 recheck. `IntegrityOutcome`. | Output **byte-identical** to `decrypt` on every wholesome golden and artifact; a mutated-between-passes test errors; `OutputLimit` fires. |
| S4 | `decrypt_to`, per-entry: 1K gate, streaming rebuild with data descriptors, raw copy, `PasswordCheckOnly`. | Every member's bytes and the stripped manifest equal `decrypt`'s on every per-entry golden and ladder file; LibreOffice opens the data-descriptor output. |
| S5 | `encrypt_to` and `encrypt_with_params_to`. | Round trip through `decrypt` and `decrypt_to`; `classify` shape equals `encrypt`'s; LibreOffice opens it. |
| S6 | `reencrypt_to`, plus the §4 refusals. New golden: per-entry with an embedded image, from `make_goldens.py`. | Round trip under the new password with the old one refused; LibreOffice opens both shapes. Five refusal tests, each falsified by deleting its condition:<br>• `unlatched_package()` is refused<br>• an extra plain listed row is refused<br>• an ODF 1.1 package with an unlisted member is refused<br>• a wholesome source with a plain META-INF member still re-keys<br>• `decrypt_to` still succeeds on each refused fixture<br>The image golden has `has_non_encrypted_entries == false` and re-keys. |
| S7 | `tests/streaming_memory.rs`: counting `#[global_allocator]`, `peak_rise`, a pattern reader and an incompressible reader, 256 MiB payloads. Modeled on EFV's `sevenz_streaming_memory_tests.rs`. | Every phase stays under a fixed bound well below the payload, and its rise at 16 MiB vs 256 MiB is within 1 MiB. Phases: wholesome decrypt, per-entry decrypt, encrypt, re-encrypt ×2. Each guard is falsified (buffer a member, collect the output, drop the hold-back cap) and recorded. |
| S8 | Whole-buffer `decrypt` / `encrypt` reimplemented over the core (owner decision Q2). The CLI streams `File` → `write_atomically`. | Existing tests unchanged and green; `decrypt` output byte-identical to rc.9 on the corpus; the CLI contracts are still pinned. |
| S9 | README (spine skill), troubleshooting, CHANGELOG under Unreleased, crate counts re-measured. | `docs` and `docsrs` green; every count is measured. |

Order: S1 → S2 → {S3, S4, S5} → S6 → S8 → S9. *S3 and S4 ship as one PR, one commit each (owner, 2026-10-15): on its own, S3 would land a public `decrypt_to` that refuses per-entry packages.*
- S7's harness lands with S3, and each later operation slice adds its phase.
- PRs follow slice boundaries.

## 7. Owner decisions (2026-10-15)

- **Q1.** Default `max_output_bytes` is 16 GiB, raisable by the caller and documented as policy.
  - Context from EFV STREAMING: the 7z arc chose no ceiling because its output stays compressed. ODF decrypt writes the inflated package, so disk is not bounded without one.
- **Q2.** Merge the whole-buffer API onto the streaming core **in this arc** (S8). Two cipher paths would be a standing fidelity hazard.
- **Q3.** No unverified-release path. Two passes cost one extra read of the ciphertext.
- **Q4.** Re-encrypt skips the inner-package checks for a wholesome source only. It was narrowed to the §4 refusals after EFV STREAMING raised laundering through legacy per-entry sources.
- **Q5.** Publishing rc.10 stays the owner's call, asked when S9 is done.
- **`Unverified`: added, then removed during S4 (owner, 2026-10-15).**
  - It was added as a third integrity level for "a CBC or Blowfish member with no checksum, which LibreOffice accepts for any password (`ZipFile.cxx:522`)".
  - That line is real, but nothing reaches it. `parseManifest` treats a password row as complete only when the cipher is GCM or the row has both `Digest` and `DigestAlgorithm` (`ZipPackage.cxx:365-367`), and `classify` mirrors that rule (`checksum_present_or_unneeded`). So no such member is ever decrypted, by LibreOffice or by this crate.
  - A variant that cannot be produced would have had EFV design a notice for a case that cannot occur.
  - The claim reached an owner decision without being checked against the upstream condition that guards it. That is why it is recorded here rather than quietly deleted.
- **Decrypt `W` bound: reversed during planning.**
  - The first draft had `W: Write + Seek` on decrypt, reasoning that the per-entry rebuild patches local headers and so stays byte-identical to rc.9.
  - That reasoning put byte-identity on the streaming path, where nobody needs it. EFV's round trip hashes into a Write-only sink, and msoffice-crypto's decrypt is Write-only.
  - The owner asked for the sibling APIs to match. Byte-identity to rc.9 is kept where it is a contract, in the whole-buffer `decrypt` (S8).

- **Streaming zip writer: reversed after S1 (#87).**
  - The plan assumed `zip` 2.4.2 had `ZipWriter::new_stream`. It does not: its writer is only `impl<W: Write + Seek>` (`zip-2.4.2/src/write.rs:789`). `new_stream` first appears in 4.x (checked: 4.6.1, 6.0.0, 8.6.0); current is 9.0.3.
  - The arc coordinator decided (option A) on a **crate-private streaming zip writer** for the two outputs that cannot seek: the per-entry `decrypt_to` rebuild and re-encrypt's inner zip. Reading stays on `zip` 2.4.2.
  - Bumping `zip` to 9 would replace the reader under `classify`. Its LibreOffice fidelity depends on raw names, data-descriptor metadata and the central-directory consistency check that caps #51. That is its own arc if anyone wants it.
  - Conditions set with the decision, all owned by S4:
    1. `mimetype` is written first, Stored, with no extra field, and with sizes and CRC in the local header and **no** bit 3. A `mimetype` written with bit 3 is caught by a test.
    2. Every output is read back through `zip` 2.4.2 **and** `classify`. It is byte-compared against `zip` 2.4.2's seekable writer for the same entries wherever that writer can produce them, so every differing byte is explained.
    3. Zip64 is tested at both 4 GiB boundaries (an entry, then the central-directory offset) without writing 4 GiB in CI, by a counting writer. One real large run, measured, is an `#[ignore]`d test.
    4. Its plaintext buffers are wrapped and wiped like the others.
    5. The LibreOffice gate runs on the per-entry `decrypt_to` output and the `reencrypt_to` result.

- **`ReencryptError`'s shape (S6).** Five variants:
  - `Decrypt(DecryptError)` for anything the source fails on;
  - `Encrypt(EncryptError)` for the new password and cost;
  - the two §4 refusals;
  - `Io`, which absorbs both sides' `Io`, so one match arm sees a cancel.
- **The CLI ships in rc.10 with `rekey` (owner, 2026-10-15).**
  - The plan gave the §4 refusals "CLI exit 5", but the CLI had no re-encrypt command, so there was nothing to map.
  - The owner asked for the CLI in this release, with streaming decrypt and encrypt. S8 therefore adds:
    - a `rekey` subcommand over `reencrypt_to`, with a `reencrypt_exit` map (both refusals exit 5);
    - a no-`_`-arm completeness test for `ReencryptError`;
    - streaming file I/O for `decrypt` and `encrypt`.
- **Image golden.** `lo-legacy-aes-cbc-image.odt` was written by LibreOffice 26.8.0.3, the corpus's first from that version. Every row it lists, `Pictures/` included, carries complete `encryption-data`. Proved by `a_per_entry_golden_with_a_picture_rekeys` and the corpus-wide `no_encrypted_libreoffice_golden_has_non_encrypted_entries`.

- **S8: the whole-buffer API's bytes, pinned before its code was replaced.** SHA-256 of rc.9's own `decrypt` output for all 15 fixture/password pairs was recorded from rc.9's code, then that code was removed; `whole_buffer_decrypt_returns_rc9_bytes` holds the new path to it. The first run caught a real difference: `zip`'s writer seeks to `End` for its central directory, and over a `Cursor` on a preallocated slice that is the slice's capacity, not the bytes written. `SliceWriter` answers `End` with the high-water mark.
- **S8: the CLI's temporary output (coordinator, owner).** Created beside the target with its permissions, deleted on every `Err`; Ctrl-C cancels through the library's reader-driven cancel (`ctrlc =3.5.2`, `cli` only, approved by the coordinator) and exits 130. **A hard kill can leave the temp: owner decision, no `unsafe` in the CLI** -- `forbid(unsafe_code)` stays the crate's identity, and the limit is stated in the README and CHANGELOG. (For a later change: `rustix` offers a safe `O_TMPFILE` + `linkat` on Linux; only Windows needs `unsafe`.)
- **S9: the rc.10 line opened** in the S8/S9 PR rather than direct to `main`, so the bump carries a review record; `CHANGELOG.md` has `## [0.1.0-rc.10] - Unreleased`. Publishing stays the owner's.

## 8. Verification

- `cargo test --locked -j 2 -- --test-threads=2`, in the foreground, under no features, `--features crypto-ops` and `--features cli`.
  - Test functions are counted with `--list`, not read off the summary line.
- Clippy, `docs` and `docsrs`, run as CI runs them.
- `cargo tree` crate counts before and after S2, unchanged.
- `cargo test --features crypto-ops --test streaming_memory -- --test-threads=1`, run alone.
- **LibreOffice gate.**
  - `validate_encrypt.py` and `lo_accepts.py`-style opening of the `encrypt_to`, `reencrypt_to` and per-entry `decrypt_to` outputs, run in both orders.
  - EFV NATIVE's 26.8 reader gate on the merge SHA before any release.
