//! Password decryption for LO-encrypted ODF packages.

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::{
    aead::{consts::U12, Aead, KeyInit},
    Aes128Gcm, Aes256Gcm, AesGcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use blowfish::Blowfish;
use cbc::cipher::{BlockDecryptMut, KeyIvInit as CbcKeyIvInit};
use cbc::Decryptor;
use cfb_mode::BufDecryptor;
use miniz_oxide::inflate::decompress_to_vec_with_limit;
use pbkdf2::pbkdf2_hmac;
use secure_gate::{RevealSecret, RevealSecretMut};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, Writer};

fn is_manifest_size_attr(key: &[u8]) -> bool {
    key.ends_with(b":size") || key == b"size"
}

use crate::classify::{classify, member_matches_path};
use crate::sensitive::{DerivedKey, PasswordDigest};
use crate::types::{Checksum, Cipher, EntryEncryption, Kdf, Mode, StartKeyAlg};
use crate::DetectError;

const INFLATE_CEILING: usize = 1 << 30;
const MANIFEST_PATH: &str = "META-INF/manifest.xml";

/// Failures from [`decrypt`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecryptError {
    #[error("classification failed: {0}")]
    Classify(#[from] DetectError),
    #[error("package is not encrypted")]
    NotEncrypted,
    #[error("password is empty")]
    EmptyPassword,
    #[error("PGP-encrypted packages are not supported")]
    UnsupportedPgp,
    #[error("wrong password")]
    WrongPassword,
    #[error("invalid encryption parameters: {0}")]
    BadParameters(String),
    #[error("inflate failed: {0}")]
    Inflate(String),
    #[error("zip error: {0}")]
    Zip(String),
}

/// Decrypt an LO-encrypted ODF package to a plaintext ODF zip.
pub fn decrypt(bytes: &[u8], password: &str) -> Result<Vec<u8>, DecryptError> {
    if password.is_empty() {
        return Err(DecryptError::EmptyPassword);
    }
    let class = classify(bytes)?;
    if class.mode == Mode::Plain {
        return Err(DecryptError::NotEncrypted);
    }
    if class
        .encrypted_entries
        .iter()
        .any(|e| matches!(e.kdf, Kdf::PgpRsaOaepMgf1p))
    {
        return Err(DecryptError::UnsupportedPgp);
    }

    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|e| DecryptError::Zip(e.to_string()))?;
    let manifest = read_member_by_path(&mut archive, MANIFEST_PATH)?;

    if class.mode == Mode::Wholesome {
        let row = class
            .encrypted_entries
            .iter()
            .find(|e| e.path == "encrypted-package")
            .ok_or_else(|| {
                DecryptError::BadParameters("wholesome package missing encrypted-package row".into())
            })?;
        let (index, _) = member_for_archive(&mut archive, &row.path)?;
        let ciphertext = read_member_at(&mut archive, index)?;
        let compressed = decrypt_member(row, password, &ciphertext)?;
        return raw_inflate(&compressed, row.size);
    }

    let mut plain: HashMap<String, Vec<u8>> = HashMap::new();
    for row in &class.encrypted_entries {
        let (index, member) = member_for_archive(&mut archive, &row.path)?;
        let ciphertext = read_member_at(&mut archive, index)?;
        let compressed = decrypt_member(row, password, &ciphertext)?;
        let inflated = raw_inflate(&compressed, row.size)?;
        plain.insert(member, inflated);
    }

    rebuild_zip(bytes, &manifest, &plain)
}

fn read_member_by_path(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    want: &str,
) -> Result<Vec<u8>, DecryptError> {
    for i in 0..archive.len() {
        let name = archive
            .by_index(i)
            .map_err(|e| DecryptError::Zip(e.to_string()))?
            .name()
            .to_string();
        if member_matches_path(&name, want) {
            return read_member_at(archive, i);
        }
    }
    Err(DecryptError::BadParameters(format!(
        "zip member {want:?} not found"
    )))
}

fn read_member_at(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    index: usize,
) -> Result<Vec<u8>, DecryptError> {
    let mut file = archive
        .by_index(index)
        .map_err(|e| DecryptError::Zip(e.to_string()))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|e| DecryptError::Zip(e.to_string()))?;
    Ok(buf)
}

/// First member whose raw or slash-collapsed name matches - the rule `classify`
/// itself uses, because a row path is a folder-tree path, not a namelist key.
fn member_for_archive(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    path: &str,
) -> Result<(usize, String), DecryptError> {
    for i in 0..archive.len() {
        let name = archive
            .by_index(i)
            .map_err(|e| DecryptError::Zip(e.to_string()))?
            .name()
            .to_string();
        if member_matches_path(&name, path) {
            return Ok((i, name));
        }
    }
    Err(DecryptError::BadParameters(format!(
        "row path {path:?} has no zip member"
    )))
}

fn start_key(password: &str, alg: StartKeyAlg) -> PasswordDigest {
    match alg {
        StartKeyAlg::Sha1 => {
            let mut h = Sha1::new();
            h.update(password.as_bytes());
            PasswordDigest::new(h.finalize().to_vec())
        }
        StartKeyAlg::Sha256 => {
            let mut h = Sha256::new();
            h.update(password.as_bytes());
            PasswordDigest::new(h.finalize().to_vec())
        }
    }
}

fn derive_key(row: &EntryEncryption, password: &str) -> Result<DerivedKey, DecryptError> {
    let sk = start_key(password, row.start_key);
    let n = row.derived_key_len;
    if n <= 0 {
        return Err(DecryptError::BadParameters(format!(
            "derived_key_len {n}"
        )));
    }
    let n = n as usize;
    let mut derived = DerivedKey::new(vec![0u8; n]);
    sk.with_secret(|sk_bytes| {
        derived.with_secret_mut(|derived_bytes| -> Result<(), DecryptError> {
            match &row.kdf {
                Kdf::Pbkdf2 { iterations, salt } => {
                    if *iterations <= 0 {
                        return Err(DecryptError::BadParameters(format!(
                            "iterations {iterations}"
                        )));
                    }
                    pbkdf2_hmac::<Sha1>(sk_bytes, salt, *iterations as u32, derived_bytes);
                    Ok(())
                }
                Kdf::Argon2id { t, m, p, salt } => {
                    let params = Params::new(*m as u32, *t as u32, *p as u32, Some(n))
                        .map_err(|e| DecryptError::BadParameters(format!("argon2 params: {e}")))?;
                    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
                    argon2
                        .hash_password_into(sk_bytes, salt, derived_bytes)
                        .map_err(|e| DecryptError::BadParameters(format!("argon2: {e}")))?;
                    Ok(())
                }
                Kdf::PgpRsaOaepMgf1p => unreachable!("PGP refused earlier"),
            }
        })
    })?;
    Ok(derived)
}

fn decrypt_member(
    row: &EntryEncryption,
    password: &str,
    blob: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    let key = derive_key(row, password)?;
    key.with_secret(|k| match row.cipher {
        Cipher::AesGcmW3c => decrypt_aes_gcm(k, row, blob),
        Cipher::AesCbcW3c => decrypt_aes_cbc(k, row, blob),
        Cipher::BlowfishCfb8 => decrypt_blowfish_cfb64(k, row, blob),
    })
}

fn decrypt_aes_gcm(key: &[u8], row: &EntryEncryption, blob: &[u8]) -> Result<Vec<u8>, DecryptError> {
    if row.iv.len() != 12 {
        return Err(DecryptError::BadParameters("GCM IV length".into()));
    }
    if blob.len() <= 12 + 16 {
        return Err(DecryptError::BadParameters("shorter than IV+tag".into()));
    }
    if blob[..12] != row.iv[..] {
        return Err(DecryptError::BadParameters("inconsistent IV".into()));
    }
    // NSS selects AES-128/192/256 from the derived key length, so the row's
    // `derived_key_len` decides the variant. `#aes128-gcm` and `#aes192-gcm` are
    // both in the accepted URI table, and an absent `manifest:key-size` derives 16.
    type Aes192Gcm = AesGcm<Aes192, U12>;
    let nonce = Nonce::from_slice(&row.iv);
    let ct = &blob[12..];
    let out = match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .map_err(|_| DecryptError::BadParameters("AES-GCM key".into()))?
            .decrypt(nonce, ct),
        24 => Aes192Gcm::new_from_slice(key)
            .map_err(|_| DecryptError::BadParameters("AES-GCM key".into()))?
            .decrypt(nonce, ct),
        32 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| DecryptError::BadParameters("AES-GCM key".into()))?
            .decrypt(nonce, ct),
        n => {
            return Err(DecryptError::BadParameters(format!(
                "AES key length {n}"
            )))
        }
    };
    out.map_err(|_| DecryptError::WrongPassword)
}

fn decrypt_aes_cbc(key: &[u8], row: &EntryEncryption, blob: &[u8]) -> Result<Vec<u8>, DecryptError> {
    if row.iv.len() != 16 {
        return Err(DecryptError::BadParameters("CBC IV length".into()));
    }
    if blob.is_empty() || blob.len() % 16 != 0 {
        return Err(DecryptError::BadParameters("not a block multiple".into()));
    }
    let mut buf = blob.to_vec();
    // As in GCM: the variant follows the derived key length, not the URI's name.
    macro_rules! cbc_decrypt_with {
        ($aes:ty) => {{
            let mut cipher = Decryptor::<$aes>::new_from_slices(key, &row.iv)
                .map_err(|_| DecryptError::BadParameters("AES-CBC key/IV".into()))?;
            for chunk in buf.chunks_mut(16) {
                cipher.decrypt_block_mut(cbc::cipher::Block::<$aes>::from_mut_slice(chunk));
            }
        }};
    }
    match key.len() {
        16 => cbc_decrypt_with!(Aes128),
        24 => cbc_decrypt_with!(Aes192),
        32 => cbc_decrypt_with!(Aes256),
        n => {
            return Err(DecryptError::BadParameters(format!(
                "AES key length {n}"
            )))
        }
    }
    let Some(&pad) = buf.last() else {
        return Err(DecryptError::WrongPassword);
    };
    let pad = pad as usize;
    if !(1..=16).contains(&pad) || buf.len() < pad {
        return Err(DecryptError::WrongPassword);
    }
    buf.truncate(buf.len() - pad);
    verify_checksum(row, &buf)?;
    Ok(buf)
}

fn decrypt_blowfish_cfb64(
    key: &[u8],
    row: &EntryEncryption,
    blob: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    if row.iv.len() != 8 {
        return Err(DecryptError::BadParameters("Blowfish IV length".into()));
    }
    type BfCfb64 = BufDecryptor<Blowfish>;
    let mut cipher = BfCfb64::new_from_slices(key, &row.iv)
        .map_err(|_| DecryptError::BadParameters("Blowfish key/IV".into()))?;
    let mut pt = blob.to_vec();
    cipher.decrypt(&mut pt);
    verify_checksum(row, &pt)?;
    Ok(pt)
}

fn verify_checksum(row: &EntryEncryption, compressed_plain: &[u8]) -> Result<(), DecryptError> {
    let window = &compressed_plain[..compressed_plain.len().min(1024)];
    match &row.checksum {
        Checksum::Sha1_1K(want) => {
            let mut h = Sha1::new();
            h.update(window);
            if h.finalize().as_slice() != want.as_slice() {
                return Err(DecryptError::WrongPassword);
            }
        }
        Checksum::Sha256_1K(want) => {
            let mut h = Sha256::new();
            h.update(window);
            if h.finalize().as_slice() != want.as_slice() {
                return Err(DecryptError::WrongPassword);
            }
        }
        Checksum::None => {}
    }
    Ok(())
}

/// Raw DEFLATE, then plan section 2's two post-conditions. Both run only after the
/// checksum or GCM tag has already passed, so neither is a password oracle.
/// `decompress_to_vec_with_limit` fails an unterminated stream rather than
/// returning the partial output it managed; the length check then pins the rest.
fn raw_inflate(compressed: &[u8], expected_size: i64) -> Result<Vec<u8>, DecryptError> {
    let out = decompress_to_vec_with_limit(compressed, INFLATE_CEILING)
        .map_err(|e| DecryptError::Inflate(e.to_string()))?;
    if out.len() as i64 != expected_size {
        return Err(DecryptError::Inflate(format!(
            "inflated {} != manifest:size {}",
            out.len(),
            expected_size
        )));
    }
    Ok(out)
}

/// Rebuild a start tag without `manifest:size`, which an LO plaintext save never writes.
fn without_size(e: &BytesStart<'_>) -> BytesStart<'static> {
    let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
    let mut out = BytesStart::new(name);
    let strip_size = e.local_name().as_ref() == b"file-entry";
    for attr in e.attributes().flatten() {
        if strip_size && is_manifest_size_attr(attr.key.as_ref()) {
            continue;
        }
        out.push_attribute((attr.key.as_ref(), attr.value.as_ref()));
    }
    out.into_owned()
}

fn strip_manifest(xml: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Vec::new());
    let mut buf = Vec::new();
    let mut skip_depth = 0u32;

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                if skip_depth > 0 {
                    skip_depth += 1;
                    continue;
                }
                if e.local_name().as_ref() == b"encryption-data" {
                    skip_depth = 1;
                    continue;
                }
                writer
                    .write_event(Event::Start(without_size(&e)))
                    .map_err(|e| DecryptError::Zip(e.to_string()))?;
            }
            Ok(Event::End(e)) => {
                if skip_depth > 0 {
                    skip_depth -= 1;
                    continue;
                }
                writer
                    .write_event(Event::End(e.into_owned()))
                    .map_err(|e| DecryptError::Zip(e.to_string()))?;
            }
            Ok(Event::Empty(e)) => {
                if skip_depth > 0 {
                    continue;
                }
                if e.local_name().as_ref() == b"encryption-data" {
                    continue;
                }
                // A file-entry with no children is an Empty event, and it can still
                // carry manifest:size. Filtering only Start would leave those behind.
                writer
                    .write_event(Event::Empty(without_size(&e)))
                    .map_err(|e| DecryptError::Zip(e.to_string()))?;
            }
            Ok(other) => {
                if skip_depth > 0 {
                    continue;
                }
                writer
                    .write_event(other)
                    .map_err(|e| DecryptError::Zip(e.to_string()))?;
            }
            Err(e) => return Err(DecryptError::Zip(e.to_string())),
        }
    }
    Ok(writer.into_inner())
}

fn rebuild_zip(
    input: &[u8],
    manifest_xml: &[u8],
    plain_members: &HashMap<String, Vec<u8>>,
) -> Result<Vec<u8>, DecryptError> {
    let stripped = strip_manifest(manifest_xml)?;
    let mut src =
        ZipArchive::new(Cursor::new(input)).map_err(|e| DecryptError::Zip(e.to_string()))?;
    let mut out = ZipWriter::new(Cursor::new(Vec::new()));

    for i in 0..src.len() {
        let mut file = src
            .by_index(i)
            .map_err(|e| DecryptError::Zip(e.to_string()))?;
        let name = file.name().to_string();
        let method = file.compression();
        let mut body = Vec::new();
        file.read_to_end(&mut body)
            .map_err(|e| DecryptError::Zip(e.to_string()))?;

        let (method, body) = if member_matches_path(&name, MANIFEST_PATH) {
            (CompressionMethod::Deflated, stripped.clone())
        } else if let Some(pt) = plain_members.get(&name) {
            (CompressionMethod::Deflated, pt.clone())
        } else {
            (method, body)
        };

        let options = SimpleFileOptions::default().compression_method(method);
        out.start_file(&name, options)
            .map_err(|e| DecryptError::Zip(e.to_string()))?;
        out.write_all(&body)
            .map_err(|e| DecryptError::Zip(e.to_string()))?;
    }

    let out_buf = out
        .finish()
        .map_err(|e| DecryptError::Zip(e.to_string()))?
        .into_inner();
    Ok(out_buf)
}

/// Compare metadata that must survive per-entry decrypt (for tests).
#[cfg(test)]
pub(crate) fn classification_metadata_unchanged(
    before: &crate::Classification,
    after: &crate::Classification,
) -> bool {
    before.odf_version == after.odf_version
        && before.media_type == after.media_type
        && before.zip_has_encrypted_package == after.zip_has_encrypted_package
}

#[cfg(test)]
#[path = "decrypt_tests.rs"]
mod tests;
