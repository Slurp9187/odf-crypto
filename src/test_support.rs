//! Fixtures and helpers shared by `classify_tests`, `decrypt_tests` and
//! `encrypt_tests`.
//!
//! These lived in three copies that had already drifted -- only one of the
//! three `load_golden`s named the file that was missing or how to regenerate
//! it. One copy means a fix to the golden path, the member lookup or the zip
//! builder lands everywhere at once.
//!
//! Module-wide `dead_code` allow rather than per-item: most of what lives here
//! is consumed by `decrypt_tests`/`encrypt_tests`, which compile out entirely
//! under `--no-default-features`, leaving `classify_tests` as the only caller.
//! A shared fixture menu having entries some feature configuration does not
//! order is the normal state for this module, not a smell worth annotating one
//! item at a time.
#![allow(dead_code)]

use std::io::{Cursor, Read, Write};
use std::path::PathBuf;

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

pub(crate) const PASSWORD: &str = "password";
/// 52 chars, one non-ASCII: separates all four SHA-1 start-key candidates
/// (decrypt plan OQ1). Matches `make_goldens.py`'s `NONASCII_PASSWORD`.
pub(crate) const NONASCII_PASSWORD: &str = "äbcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP";
pub(crate) const B64: &str = "AQIDBA==";
pub(crate) const MIME_TEXT: &str = "application/vnd.oasis.opendocument.text";

pub(crate) fn goldens_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("goldens")
}

pub(crate) fn golden_path(name: &str) -> PathBuf {
    goldens_dir().join(name)
}

pub(crate) fn load_golden(name: &str) -> Vec<u8> {
    let path = golden_path(name);
    std::fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "golden missing at {}: {err}. Generate with tests/goldens/make_goldens.py",
            path.display()
        )
    })
}

pub(crate) fn zip_namelist(bytes: &[u8]) -> Vec<String> {
    let mut z = ZipArchive::new(Cursor::new(bytes)).unwrap();
    (0..z.len())
        .map(|i| z.by_index(i).unwrap().name().to_string())
        .collect()
}

pub(crate) fn zip_method(bytes: &[u8], name: &str) -> CompressionMethod {
    let mut z = ZipArchive::new(Cursor::new(bytes)).unwrap();
    let method = z.by_name(name).unwrap().compression();
    method
}

pub(crate) fn read_member(zip_bytes: &[u8], path: &str) -> Vec<u8> {
    let mut z = ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
    for i in 0..z.len() {
        let mut f = z.by_index(i).unwrap();
        if f.name() == path {
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            return buf;
        }
    }
    panic!("member {path} not in zip");
}

/// Build a zip, DEFLATED except `mimetype` (STORED, as every real producer
/// writes it).
pub(crate) fn zip_with(files: &[(&str, &[u8])]) -> Vec<u8> {
    let with_methods: Vec<_> = files
        .iter()
        .map(|(name, data)| {
            let method = if *name == "mimetype" {
                CompressionMethod::Stored
            } else {
                CompressionMethod::Deflated
            };
            (*name, *data, method)
        })
        .collect();
    zip_with_methods(&with_methods)
}

/// Build a zip with an explicit compression method per member, for fixtures
/// where the method itself is what is under test.
pub(crate) fn zip_with_methods(files: &[(&str, &[u8], CompressionMethod)]) -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data, method) in files {
        zip.start_file(
            *name,
            SimpleFileOptions::default().compression_method(*method),
        )
        .unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

/// A two-row PGP-encrypted package: `content.xml` carries the `KeyInfo`, and
/// both rows name `PGP` as their key derivation. `classify` reports
/// `Mode::PerEntry` with `Kdf::PgpRsaOaepMgf1p` rows, which `decrypt` refuses
/// as `UnsupportedPgp` and `encrypt` refuses as `AlreadyEncrypted`.
pub(crate) fn pgp_two_row_zip() -> Vec<u8> {
    let manifest = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" xmlns:loext="urn:org:documentfoundation:names:experimental:office:xmlns:loext:1.0" manifest:version="1.3">
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml" manifest:size="100">
  <loext:encrypted-key>
   <loext:encryption-method loext:PGPAlgorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
   <loext:KeyInfo>
    <loext:PGPData>
     <loext:PGPKeyID>{B64}</loext:PGPKeyID>
     <loext:PGPKeyPacket>{B64}</loext:PGPKeyPacket>
    </loext:PGPData>
   </loext:KeyInfo>
   <loext:CipherData>
    <loext:CipherValue>{B64}</loext:CipherValue>
   </loext:CipherData>
  </loext:encrypted-key>
  <manifest:encryption-data>
   <manifest:algorithm manifest:algorithm-name="http://www.w3.org/2009/xmlenc11#aes256-gcm" manifest:initialisation-vector="{B64}"/>
   <manifest:key-derivation manifest:key-derivation-name="PGP"/>
  </manifest:encryption-data>
 </manifest:file-entry>
 <manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml" manifest:size="50">
  <manifest:encryption-data>
   <manifest:algorithm manifest:algorithm-name="http://www.w3.org/2009/xmlenc11#aes256-gcm" manifest:initialisation-vector="{B64}"/>
   <manifest:key-derivation manifest:key-derivation-name="PGP"/>
  </manifest:encryption-data>
 </manifest:file-entry>
</manifest:manifest>
"#
    );
    zip_with(&[
        ("mimetype", MIME_TEXT.as_bytes()),
        ("META-INF/manifest.xml", manifest.as_bytes()),
        ("content.xml", b"encrypted-content"),
        ("styles.xml", b"encrypted-styles"),
    ])
}

/// Strict RFC 4648 base64 decode: rejects anything `manifest::decode_b64`
/// would leniently skip (whitespace, a URL-safe alphabet, missing padding).
/// Emitted attributes are checked with this rather than with the lenient
/// reader, so a malformed encoder cannot pass by being forgiven twice.
pub(crate) fn strict_b64_decode(s: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() % 4 != 0 {
        return Err(format!(
            "{s:?}: length {} is not a multiple of 4",
            bytes.len()
        ));
    }
    let pad = bytes.iter().rev().take_while(|&&b| b == b'=').count();
    if pad > 2 {
        return Err(format!("{s:?}: {pad} padding bytes"));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut acc = 0u32;
    for (i, &b) in bytes[..bytes.len() - pad].iter().enumerate() {
        let Some(v) = ALPHABET.iter().position(|&a| a == b) else {
            return Err(format!(
                "{s:?}: byte {b:#04x} is outside the base64 alphabet"
            ));
        };
        acc = (acc << 6) | v as u32;
        if i % 4 == 3 {
            out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]);
            acc = 0;
        }
    }
    match pad {
        1 => {
            acc <<= 6;
            out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8]);
        }
        2 => {
            acc <<= 12;
            out.push((acc >> 16) as u8);
        }
        _ => {}
    }
    Ok(out)
}
