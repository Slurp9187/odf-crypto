//! Password encryption for ODF packages.
//!
//! [`encrypt`] turns a plaintext ODF package (`classify` reports [`Mode::Plain`])
//! into what current LibreOffice writes for that same input under that password:
//! one `encrypted-package` member, Argon2id-derived AES-256-GCM, no checksum,
//! `manifest:version="1.4"`. Modern (wholesome) only -- per-entry write and PGP
//! wrap are later, out-of-scope arcs. See
//! `docs/plans/odf-encryption-encrypt-2026-09-03.md`.

use std::io::{Cursor, Read, Write};

use aes::Aes192;
use aes_gcm::{
    aead::{consts::U12, rand_core::RngCore as _, Aead, KeyInit, OsRng},
    Aes128Gcm, Aes256Gcm, AesGcm, Nonce,
};
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use zeroize::Zeroizing;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::classify::{classify, member_matches_path};
use crate::types::{Mode, StartKeyAlg};
use crate::uris;
use crate::DetectError;

/// Ceiling on the plaintext buffer [`encrypt`] will deflate, matching decrypt's
/// `INFLATE_CEILING` (1 GiB) in shape but not in purpose: decrypt's ceiling
/// defends against an attacker-controlled `manifest:size`, whereas `encrypt`'s
/// caller supplies the plaintext directly -- there is no attacker on the other
/// end. This is hygiene against an unbounded allocation on a pathological
/// input, not a security boundary.
const DEFLATE_CEILING: usize = 1 << 30;

const MANIFEST_PATH: &str = "META-INF/manifest.xml";

/// Failures from [`encrypt`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EncryptError {
    /// `classify()` itself rejected the input (not a zip, no manifest, ...).
    #[error("classification failed: {0}")]
    Classify(#[from] DetectError),
    /// `classify(bytes)?.mode != Mode::Plain` -- covers `PerEntry`, `Wholesome`,
    /// and PGP rows alike.
    #[error("package is already encrypted")]
    AlreadyEncrypted,
    /// Mirrors `decrypt::DecryptError::EmptyPassword` /
    /// `CreatePackageEncryptionData`'s empty sequence.
    #[error("password is empty")]
    EmptyPassword,
    /// CSPRNG failure -- vanishingly rare, but a library must not panic for it.
    #[error("random number generation failed: {0}")]
    Random(String),
    /// Raw-deflate of the input buffer failed.
    #[error("deflate failed: {0}")]
    Deflate(String),
    /// Building the outer zip container failed.
    #[error("zip error: {0}")]
    Zip(String),
}

/// Encrypt a plaintext ODF package with `password`, producing what current
/// LibreOffice writes for that input under that password (plan §6): wholesome
/// Argon2id-derived AES-256-GCM, one `encrypted-package` member, no checksum.
///
/// Refuses before any crypto runs: an empty password is rejected first
/// (mirroring [`crate::decrypt`]'s own ordering), then anything `classify`
/// does not report as [`Mode::Plain`] (already encrypted, in any of the three
/// `Mode`s classify can report).
pub fn encrypt(bytes: &[u8], password: &str) -> Result<Vec<u8>, EncryptError> {
    if password.is_empty() {
        return Err(EncryptError::EmptyPassword);
    }
    let class = classify(bytes)?;
    if class.mode != Mode::Plain {
        return Err(EncryptError::AlreadyEncrypted);
    }

    // Plan §6 step 3: raw-deflate the whole input buffer, unparsed.
    let compressed = raw_deflate(bytes)?;

    // Plan §6 step 5 / Authority `ZipPackageStream.cxx:587-607`: fresh salt
    // and IV per save (moot here -- wholesome writes exactly one row).
    let salt = random_bytes(16)?;
    let iv = random_bytes(12)?;

    // Plan §6 step 4/6: start key, then Argon2id over it with `salt`.
    // Zeroized immediately, mirroring decrypt::derive_key's own wrapping of
    // `crate::kdf::start_key`'s plain `Vec<u8>` return.
    let start_key = Zeroizing::new(crate::kdf::start_key(password, StartKeyAlg::Sha256));
    // `encrypt` only ever passes its own fixed constants (t=3, m=65536, p=4,
    // len=32) through Argon2id -- m >= 8*p holds trivially (65536 >= 32), so
    // this can never fail for any input `classify` would have accepted.
    // See plan's "deliberate gap in EncryptError" note: no BadParameters
    // analogue exists here, unlike decrypt's manifest-derived tuple.
    let derived_key = crate::kdf::derive_argon2id(&start_key, &salt, 3, 65536, 4, 32)
        .expect("encrypt's own fixed Argon2id params (t=3, m=65536, p=4, len=32) are always valid");

    // Plan §6 step 7: member payload = IV || ciphertext || tag.
    let ciphertext = encrypt_aes_gcm(&derived_key, &iv, &compressed);
    let mut member_payload = Vec::with_capacity(iv.len() + ciphertext.len());
    member_payload.extend_from_slice(&iv);
    member_payload.extend_from_slice(&ciphertext);

    // Plan §3: the mimetype fallback chain, shared by the zip member's raw
    // bytes and the manifest's `media-type` attribute (same source, not
    // re-derived from each other).
    let mimetype_source = resolve_mimetype_source(bytes, class.media_type.as_deref())?;
    let media_type_attr = mimetype_source
        .as_deref()
        .map(|b| String::from_utf8_lossy(b).into_owned());

    // Plan §2/§6 step 8: manifest.xml exactly per the emit table.
    let manifest_xml = build_manifest(
        bytes.len() as i64,
        &iv,
        &salt,
        media_type_attr.as_deref(),
    );

    // Plan §3/§6 step 9: the three-member outer zip.
    assemble_zip(
        mimetype_source.as_deref().unwrap_or(&[]),
        &member_payload,
        &manifest_xml,
    )
}

/// Raw DEFLATE of the whole input buffer (mirrors `decrypt::raw_inflate`'s
/// shape in the opposite direction). No zlib wrapper -- LO's own
/// `ZipOutputEntryBase` deflates raw too (Authority: `ZipOutputEntry.cxx`).
fn raw_deflate(bytes: &[u8]) -> Result<Vec<u8>, EncryptError> {
    if bytes.len() > DEFLATE_CEILING {
        return Err(EncryptError::Deflate(format!(
            "input {} bytes exceeds ceiling {DEFLATE_CEILING}",
            bytes.len()
        )));
    }
    Ok(miniz_oxide::deflate::compress_to_vec(bytes, 6))
}

/// `len` random bytes via a CSPRNG (Authority: `ZipPackageStream.cxx:590,594`
/// -- LO's `rtl_random_getBytes`, here `aes_gcm::aead::OsRng`). Uses the
/// fallible `try_fill_bytes`, not `fill_bytes`, which panics -- a library
/// must not panic for an ordinary CSPRNG failure (plan §4).
fn random_bytes(len: usize) -> Result<Vec<u8>, EncryptError> {
    let mut buf = vec![0u8; len];
    OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| EncryptError::Random(e.to_string()))?;
    Ok(buf)
}

/// AES-*-GCM encrypt, dispatching on key length the same shape as
/// `decrypt::decrypt_aes_gcm` but in the write direction: `.encrypt(nonce,
/// plaintext)` on the matching cipher type, empty AAD (Authority:
/// `ciphercontext.cxx`'s encrypt branch -- NSS doesn't prepend the IV, so LO
/// does, and so do we, at the call site in [`encrypt`]). Returns
/// ciphertext‖tag; RustCrypto's own `.encrypt()` already appends the 16-byte
/// tag, so nothing here appends it again.
///
/// `encrypt`'s own KDF always emits a 32-byte key (`derive_argon2id(..., 32)`
/// above) -- the 16/24-byte arms exist only for shape-symmetry with
/// `decrypt_aes_gcm`, which really does see attacker-controlled key lengths.
/// Both `new_from_slice` and `.encrypt()` are `.expect()`-ed rather than
/// threaded through a new `EncryptError` variant: the key length always
/// matches the arm that dispatched here, and the plaintext is bounded by
/// `DEFLATE_CEILING`, far under AES-GCM's per-key plaintext limit (see plan's
/// "deliberate gap in EncryptError" note).
fn encrypt_aes_gcm(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
    type Aes192Gcm = AesGcm<Aes192, U12>;
    let nonce = Nonce::from_slice(iv);
    match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .expect("key length matches the arm that dispatched here")
            .encrypt(nonce, plaintext)
            .expect("plaintext bounded by DEFLATE_CEILING, far under AES-GCM's per-key limit"),
        24 => Aes192Gcm::new_from_slice(key)
            .expect("key length matches the arm that dispatched here")
            .encrypt(nonce, plaintext)
            .expect("plaintext bounded by DEFLATE_CEILING, far under AES-GCM's per-key limit"),
        32 => Aes256Gcm::new_from_slice(key)
            .expect("key length matches the arm that dispatched here")
            .encrypt(nonce, plaintext)
            .expect("plaintext bounded by DEFLATE_CEILING, far under AES-GCM's per-key limit"),
        n => unreachable!("encrypt's own KDF only ever emits 16/24/32-byte keys, got {n}"),
    }
}

/// Plan §3's mimetype fallback chain, shared by the `mimetype` zip member's
/// bytes and the manifest `media-type` attribute: the input's own `mimetype`
/// member, read verbatim (never re-derived from `classify`'s recovered
/// string, since the two can diverge on a trailing newline or encoding
/// nuance); else `classify`'s `media_type` as raw UTF-8 with no trailing
/// newline; else `None`.
fn resolve_mimetype_source(
    bytes: &[u8],
    classify_media_type: Option<&str>,
) -> Result<Option<Vec<u8>>, EncryptError> {
    if let Some(raw) = read_input_mimetype_member(bytes)? {
        return Ok(Some(raw));
    }
    Ok(classify_media_type.map(|s| s.as_bytes().to_vec()))
}

/// Read the input zip's own `mimetype` member, verbatim, straight off the
/// archive -- not through `Classification` (plan §6 step 7). Mirrors
/// `decrypt.rs`'s `member_for_archive` / `read_member_at` scan style.
fn read_input_mimetype_member(bytes: &[u8]) -> Result<Option<Vec<u8>>, EncryptError> {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|e| EncryptError::Zip(e.to_string()))?;
    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| EncryptError::Zip(e.to_string()))?;
        let name = file.name().to_string();
        if !member_matches_path(&name, "mimetype") {
            continue;
        }
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .map_err(|e| EncryptError::Zip(e.to_string()))?;
        return Ok(Some(buf));
    }
    Ok(None)
}

/// Build `META-INF/manifest.xml` exactly per plan §2's emit table: one
/// `file-entry` for `encrypted-package`, no checksum attributes at all
/// (Authority: `SetupStorage`'s `Value.clear()` for GCM), `manifest:version`
/// fixed at `"1.4"`, and no root `/` file-entry (Authority:
/// `ManifestExport.cxx:297` -- wholesome `continue`s past the per-entry write
/// loop for that sequence). Child order inside `encryption-data`: algorithm,
/// start-key-generation, key-derivation (Authority: `ManifestExport.cxx`
/// write order).
///
/// Writing to an in-memory `Vec<u8>` cannot fail, so every `write_event` here
/// is `.expect()`-ed rather than threaded through a new `EncryptError`
/// variant -- there is no I/O on the other end of this writer.
fn build_manifest(size: i64, iv: &[u8], salt: &[u8], media_type: Option<&str>) -> Vec<u8> {
    const INFALLIBLE: &str = "writing to an in-memory Vec<u8> cannot fail";
    let mut writer = Writer::new(Vec::new());

    writer
        .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))
        .expect(INFALLIBLE);

    // `ManifestExport.cxx:145-153`: `xmlns:loext` and `manifest:version` are
    // both written together, gated on the same ODF->=1.2 check -- always true
    // for wholesome, which only exists at ODF ODFSVER_LATEST_EXTENDED ("1.4").
    let mut root = BytesStart::new(uris::ELEMENT_MANIFEST);
    root.push_attribute(("xmlns:manifest", uris::MANIFEST_NS_OASIS));
    root.push_attribute(("xmlns:loext", uris::MANIFEST_NS_LOEXT));
    root.push_attribute((uris::ATTR_VERSION, "1.4"));
    writer.write_event(Event::Start(root)).expect(INFALLIBLE);

    let size_str = size.to_string();
    let mut file_entry = BytesStart::new(uris::ELEMENT_FILE_ENTRY);
    file_entry.push_attribute((uris::ATTR_FULL_PATH, "encrypted-package"));
    file_entry.push_attribute((uris::ATTR_SIZE, size_str.as_str()));
    if let Some(mt) = media_type {
        file_entry.push_attribute((uris::ATTR_MEDIA_TYPE, mt));
    }
    writer
        .write_event(Event::Start(file_entry))
        .expect(INFALLIBLE);

    writer
        .write_event(Event::Start(BytesStart::new(uris::ELEMENT_ENCRYPTION_DATA)))
        .expect(INFALLIBLE);

    let iv_b64 = crate::manifest::encode_b64(iv);
    let mut algorithm = BytesStart::new(uris::ELEMENT_ALGORITHM);
    algorithm.push_attribute((uris::ATTR_ALGORITHM_NAME, uris::AESGCM256_URL));
    algorithm.push_attribute((uris::ATTR_IV, iv_b64.as_str()));
    writer
        .write_event(Event::Empty(algorithm))
        .expect(INFALLIBLE);

    // Authority `ManifestExport.cxx:437-475`: GCM picks the W3C SHA-256 URL
    // (`SHA256_URL`), not the "bad ODF URL" (`SHA256_URL_ODF12`) CBC keeps
    // for ODF<=1.4 interop -- comment there reads "new encryption is
    // incompatible anyway, use W3C URL".
    let mut start_key_gen = BytesStart::new(uris::ELEMENT_START_KEY_GENERATION);
    start_key_gen.push_attribute((uris::ATTR_START_KEY_NAME, uris::SHA256_URL));
    start_key_gen.push_attribute((uris::ATTR_KEY_SIZE, "32"));
    writer
        .write_event(Event::Empty(start_key_gen))
        .expect(INFALLIBLE);

    let salt_b64 = crate::manifest::encode_b64(salt);
    let mut key_derivation = BytesStart::new(uris::ELEMENT_KEY_DERIVATION);
    key_derivation.push_attribute((uris::ATTR_KEY_DERIVATION_NAME, uris::ARGON2ID_URL_LO));
    key_derivation.push_attribute((uris::ATTR_ARGON2_T_LO, "3"));
    key_derivation.push_attribute((uris::ATTR_ARGON2_M_LO, "65536"));
    key_derivation.push_attribute((uris::ATTR_ARGON2_P_LO, "4"));
    key_derivation.push_attribute((uris::ATTR_SALT, salt_b64.as_str()));
    // `ManifestExport.cxx:517-522`: key-derivation's own `key-size` is
    // written only when `bStoreStartKeyGeneration` -- always true here.
    key_derivation.push_attribute((uris::ATTR_KEY_SIZE, "32"));
    writer
        .write_event(Event::Empty(key_derivation))
        .expect(INFALLIBLE);

    writer
        .write_event(Event::End(BytesEnd::new(uris::ELEMENT_ENCRYPTION_DATA)))
        .expect(INFALLIBLE);
    writer
        .write_event(Event::End(BytesEnd::new(uris::ELEMENT_FILE_ENTRY)))
        .expect(INFALLIBLE);
    writer
        .write_event(Event::End(BytesEnd::new(uris::ELEMENT_MANIFEST)))
        .expect(INFALLIBLE);

    writer.into_inner()
}

/// Assemble the outer zip: exactly three members, in order -- `mimetype`
/// (STORED), `encrypted-package` (STORED, no data descriptor -- the whole
/// ciphertext is already in memory, so `ZipWriter` over a `Cursor<Vec<u8>>`
/// can write ordinary STORED headers with size/CRC known upfront, the same
/// reasoning `decrypt::rebuild_zip` already relies on), `META-INF/manifest.xml`
/// (DEFLATED, via the `zip` crate's existing `deflate` feature).
fn assemble_zip(
    mimetype_bytes: &[u8],
    member_payload: &[u8],
    manifest_xml: &[u8],
) -> Result<Vec<u8>, EncryptError> {
    let mut out = ZipWriter::new(Cursor::new(Vec::new()));
    let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let deflated = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    out.start_file("mimetype", stored)
        .map_err(|e| EncryptError::Zip(e.to_string()))?;
    out.write_all(mimetype_bytes)
        .map_err(|e| EncryptError::Zip(e.to_string()))?;

    out.start_file("encrypted-package", stored)
        .map_err(|e| EncryptError::Zip(e.to_string()))?;
    out.write_all(member_payload)
        .map_err(|e| EncryptError::Zip(e.to_string()))?;

    out.start_file(MANIFEST_PATH, deflated)
        .map_err(|e| EncryptError::Zip(e.to_string()))?;
    out.write_all(manifest_xml)
        .map_err(|e| EncryptError::Zip(e.to_string()))?;

    let buf = out
        .finish()
        .map_err(|e| EncryptError::Zip(e.to_string()))?
        .into_inner();
    Ok(buf)
}

#[cfg(test)]
#[path = "encrypt_tests.rs"]
mod tests;
