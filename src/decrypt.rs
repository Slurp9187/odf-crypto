//! Password decryption for LO-encrypted ODF packages.

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

use aes::Aes256;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use blowfish::Blowfish;
use cbc::cipher::{BlockDecryptMut, KeyIvInit as CbcKeyIvInit};
use cbc::Decryptor;
use cfb_mode::cipher::KeyIvInit as CfbKeyIvInit;
use cfb_mode::BufDecryptor;
use miniz_oxide::inflate::decompress_to_vec_with_limit;
use pbkdf2::pbkdf2_hmac;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use zeroize::Zeroize;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, Writer};

fn is_manifest_size_attr(key: &[u8]) -> bool {
    key.ends_with(b":size") || key == b"size"
}

use crate::classify::{classify, member_matches_path};
use crate::types::{Checksum, Cipher, EntryEncryption, Kdf, Mode, StartKeyAlg};
use crate::{Classification, DetectError};

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
        let member = member_for_archive(&mut archive, &row.path)?;
        let ciphertext = read_member_by_path(&mut archive, &member)?;
        let compressed = decrypt_member(row, password, &ciphertext)?;
        return raw_inflate(&compressed, row.size);
    }

    let mut plain: HashMap<String, Vec<u8>> = HashMap::new();
    for row in &class.encrypted_entries {
        let member = member_for_archive(&mut archive, &row.path)?;
        let ciphertext = read_member_by_path(&mut archive, &member)?;
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

fn member_for_archive(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    path: &str,
) -> Result<String, DecryptError> {
    for i in 0..archive.len() {
        let name = archive
            .by_index(i)
            .map_err(|e| DecryptError::Zip(e.to_string()))?
            .name()
            .to_string();
        if member_matches_path(&name, path) {
            return Ok(name);
        }
    }
    Err(DecryptError::BadParameters(format!(
        "row path {path:?} has no zip member"
    )))
}

fn start_key(password: &str, alg: StartKeyAlg) -> Vec<u8> {
    match alg {
        StartKeyAlg::Sha1 => {
            let mut h = Sha1::new();
            h.update(password.as_bytes());
            h.finalize().to_vec()
        }
        StartKeyAlg::Sha256 => {
            let mut h = Sha256::new();
            h.update(password.as_bytes());
            h.finalize().to_vec()
        }
    }
}

fn derive_key(row: &EntryEncryption, password: &str) -> Result<Vec<u8>, DecryptError> {
    let mut sk = start_key(password, row.start_key);
    let n = row.derived_key_len;
    if n <= 0 {
        sk.zeroize();
        return Err(DecryptError::BadParameters(format!(
            "derived_key_len {n}"
        )));
    }
    let n = n as usize;
    let mut derived = vec![0u8; n];
    let result = match &row.kdf {
        Kdf::Pbkdf2 { iterations, salt } => {
            if *iterations <= 0 {
                Err(DecryptError::BadParameters(format!(
                    "iterations {iterations}"
                )))
            } else {
                pbkdf2_hmac::<Sha1>(&sk, salt, *iterations as u32, &mut derived);
                Ok(())
            }
        }
        Kdf::Argon2id { t, m, p, salt } => {
            let params = Params::new(*m as u32, *t as u32, *p as u32, Some(n)).map_err(|e| {
                DecryptError::BadParameters(format!("argon2 params: {e}"))
            })?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            argon2
                .hash_password_into(&sk, salt, &mut derived)
                .map_err(|e| DecryptError::BadParameters(format!("argon2: {e}")))?;
            Ok(())
        }
        Kdf::PgpRsaOaepMgf1p => unreachable!("PGP refused earlier"),
    };
    sk.zeroize();
    result?;
    Ok(derived)
}

fn decrypt_member(
    row: &EntryEncryption,
    password: &str,
    blob: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    let mut key = derive_key(row, password)?;
    let pt = match row.cipher {
        Cipher::AesGcmW3c => {
            let out = decrypt_aes_gcm(&key, row, blob)?;
            key.zeroize();
            out
        }
        Cipher::AesCbcW3c => {
            let out = decrypt_aes_cbc(&key, row, blob)?;
            key.zeroize();
            out
        }
        Cipher::BlowfishCfb8 => {
            let out = decrypt_blowfish_cfb64(&key, row, blob)?;
            key.zeroize();
            out
        }
    };
    Ok(pt)
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
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| DecryptError::BadParameters("AES-GCM key".into()))?;
    let nonce = Nonce::from_slice(&row.iv);
    cipher
        .decrypt(nonce, &blob[12..])
        .map_err(|_| DecryptError::WrongPassword)
}

fn decrypt_aes_cbc(key: &[u8], row: &EntryEncryption, blob: &[u8]) -> Result<Vec<u8>, DecryptError> {
    if row.iv.len() != 16 {
        return Err(DecryptError::BadParameters("CBC IV length".into()));
    }
    if blob.is_empty() || blob.len() % 16 != 0 {
        return Err(DecryptError::BadParameters("not a block multiple".into()));
    }
    type Aes256CbcDec = Decryptor<Aes256>;
    let mut buf = blob.to_vec();
    let mut cipher = Aes256CbcDec::new_from_slices(key, &row.iv)
        .map_err(|_| DecryptError::BadParameters("AES-CBC key/IV".into()))?;
    for chunk in buf.chunks_mut(16) {
        cipher.decrypt_block_mut(cbc::cipher::Block::<Aes256>::from_mut_slice(chunk));
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
                let tag = e.name().as_ref().to_vec();
                let name = String::from_utf8_lossy(&tag).into_owned();
                let mut start = BytesStart::new(&name);
                let strip_size = e.local_name().as_ref() == b"file-entry";
                for attr in e.attributes().flatten() {
                    if strip_size && is_manifest_size_attr(attr.key.as_ref()) {
                        continue;
                    }
                    start.push_attribute((attr.key.as_ref(), attr.value.as_ref()));
                }
                writer
                    .write_event(Event::Start(start))
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
                writer
                    .write_event(Event::Empty(e.into_owned()))
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

        let (method, body) = if name == MANIFEST_PATH || member_matches_path(&name, MANIFEST_PATH)
        {
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
    before: &Classification,
    after: &Classification,
) -> bool {
    before.odf_version == after.odf_version
        && before.media_type == after.media_type
        && before.zip_has_encrypted_package == after.zip_has_encrypted_package
}

#[cfg(test)]
#[path = "decrypt_tests.rs"]
mod tests;
