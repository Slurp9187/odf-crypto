//! Decrypt arc tests (issues #11–#15).

use std::io::{Cursor, Read, Write};
use std::path::PathBuf;

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::classify::classify;
use crate::decrypt::{classification_metadata_unchanged, decrypt, DecryptError};
use crate::{Kdf, Mode};

const PASSWORD: &str = "password";
const NONASCII_PASSWORD: &str = "äbcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP";
const B64: &str = "AQIDBA==";
const MIME_TEXT: &str = "application/vnd.oasis.opendocument.text";

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("goldens")
        .join(name)
}

fn load_golden(name: &str) -> Vec<u8> {
    std::fs::read(golden_path(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn zip_namelist(bytes: &[u8]) -> Vec<String> {
    let mut z = ZipArchive::new(Cursor::new(bytes)).unwrap();
    (0..z.len())
        .map(|i| z.by_index(i).unwrap().name().to_string())
        .collect()
}

fn pgp_two_row_zip() -> Vec<u8> {
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
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in [
        ("mimetype", MIME_TEXT.as_bytes()),
        ("META-INF/manifest.xml", manifest.as_bytes()),
        ("content.xml", b"encrypted-content" as &[u8]),
        ("styles.xml", b"encrypted-styles"),
    ] {
        let method = if name == "mimetype" {
            CompressionMethod::Stored
        } else {
            CompressionMethod::Deflated
        };
        zip.start_file(name, SimpleFileOptions::default().compression_method(method))
            .unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

// --- S1 ---

#[test]
fn s1_unencrypted_is_not_encrypted() {
    let err = decrypt(&load_golden("lo-unencrypted.odt"), PASSWORD).unwrap_err();
    assert!(matches!(err, DecryptError::NotEncrypted));
}

#[test]
fn s1_empty_password() {
    let err = decrypt(&load_golden("lo-unencrypted.odt"), "").unwrap_err();
    assert!(matches!(err, DecryptError::EmptyPassword));
}

#[test]
fn s1_pgp_zip_unsupported() {
    let zip = pgp_two_row_zip();
    let class = classify(&zip).expect("pgp zip classifies");
    assert!(!class.pgp_keys.is_empty(), "pgp_keys from first entry KeyInfo");
    let err = decrypt(&zip, PASSWORD).unwrap_err();
    assert!(matches!(err, DecryptError::UnsupportedPgp));
}

#[test]
fn s1_goldens_have_empty_pgp_keys() {
    for name in [
        "lo-unencrypted.odt",
        "aoo-blowfish-pbkdf2.odt",
        "lo-odf11-nonascii-password.odt",
        "lo-legacy-aes-cbc.odt",
        "lo-wholesome-gcm-argon2.odt",
    ] {
        let class = classify(&load_golden(name)).expect(name);
        assert!(class.pgp_keys.is_empty(), "{name}");
    }
}

// --- S2 / S3 / S4 goldens ---

fn read_member(zip_bytes: &[u8], path: &str) -> Vec<u8> {
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

fn assert_well_formed_xml(body: &[u8]) {
    let mut reader = quick_xml::Reader::from_reader(body);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Eof) => break,
            Ok(_) => {}
            Err(e) => panic!("malformed XML: {e}"),
        }
    }
}

fn assert_decrypts_to_plain(golden: &str, password: &str) {
    let input = load_golden(golden);
    let before = classify(&input).expect("input classifies");
    let out = decrypt(&input, password).expect("decrypt");
    let after = classify(&out).expect("output classifies");
    assert_eq!(after.mode, Mode::Plain);
    assert!(after.encrypted_entries.is_empty());
    assert!(classification_metadata_unchanged(&before, &after));

    let manifest_bytes = read_member(&out, "META-INF/manifest.xml");
    let mf = String::from_utf8_lossy(&manifest_bytes);
    assert!(!mf.contains("encryption-data"), "{golden}");
    assert!(!mf.contains("manifest:size"), "{golden}");
    assert_eq!(zip_namelist(&input), zip_namelist(&out), "{golden} members");

    for row in &before.encrypted_entries {
        if row.path == "encrypted-package" {
            continue;
        }
        let body = read_member(&out, &row.path);
        assert_eq!(body.len() as i64, row.size, "{} {}", golden, row.path);
        if row.path.ends_with(".xml") || row.path.ends_with(".rdf") {
            assert_well_formed_xml(&body);
        }
    }
}

#[test]
fn s2_blowfish_golden() {
    assert_decrypts_to_plain("aoo-blowfish-pbkdf2.odt", PASSWORD);
    let err = decrypt(&load_golden("aoo-blowfish-pbkdf2.odt"), "wrong").unwrap_err();
    assert!(matches!(err, DecryptError::WrongPassword));
}

#[test]
fn s2_nonascii_password_golden() {
    assert_decrypts_to_plain("lo-odf11-nonascii-password.odt", NONASCII_PASSWORD);
    let err = decrypt(
        &load_golden("lo-odf11-nonascii-password.odt"),
        "wrong",
    )
    .unwrap_err();
    assert!(matches!(err, DecryptError::WrongPassword));
}

#[test]
fn s3_aes_cbc_golden() {
    assert_decrypts_to_plain("lo-legacy-aes-cbc.odt", PASSWORD);
    let err = decrypt(&load_golden("lo-legacy-aes-cbc.odt"), "wrong").unwrap_err();
    assert!(matches!(err, DecryptError::WrongPassword));
}

#[test]
fn s4_wholesome_gcm_golden() {
    let input = load_golden("lo-wholesome-gcm-argon2.odt");
    let before = classify(&input).unwrap();
    let out = decrypt(&input, PASSWORD).expect("wholesome decrypt");
    let after = classify(&out).unwrap();
    assert_eq!(after.mode, Mode::Plain);
    assert!(after.encrypted_entries.is_empty());
    assert!(zip_namelist(&out).iter().any(|n| n == "content.xml"));
    let row = before
        .encrypted_entries
        .iter()
        .find(|e| e.path == "encrypted-package")
        .unwrap();
    assert_eq!(out.len() as i64, row.size);
    let err = decrypt(&input, "wrong").unwrap_err();
    assert!(matches!(err, DecryptError::WrongPassword));
}

// --- S5 constructed negatives ---
//
// `BadParameters` rows are a deliberate divergence in error granularity from LO
// (plan §4 / issue #15): both fail closed; we expose more detail.

/// A fixture transform: takes a member or manifest body, returns the mutated one.
type Rewrite = fn(&[u8]) -> Vec<u8>;

fn mutate_zip(
    golden: &str,
    member: Option<&str>,
    member_mut: Option<Rewrite>,
    manifest_fn: Option<Rewrite>,
) -> Vec<u8> {
    let input = load_golden(golden);
    let mut src = ZipArchive::new(Cursor::new(&input)).unwrap();
    let mut buf = Vec::new();
    let mut out = ZipWriter::new(Cursor::new(&mut buf));
    for i in 0..src.len() {
        let mut file = src.by_index(i).unwrap();
        let name = file.name().to_string();
        let method = file.compression();
        let mut body = Vec::new();
        file.read_to_end(&mut body).unwrap();
        if let (Some(want), Some(f)) = (member, member_mut) {
            if name == want {
                body = f(&body);
            }
        }
        if name == "META-INF/manifest.xml" {
            if let Some(f) = manifest_fn {
                body = f(&body);
            }
        }
        out.start_file(
            &name,
            SimpleFileOptions::default().compression_method(method),
        )
        .unwrap();
        out.write_all(&body).unwrap();
    }
    out.finish().unwrap();
    buf
}

fn flip_checksum_manifest(xml: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(xml);
    let marker = "checksum=\"";
    let Some(start) = s.find(marker) else {
        return xml.to_vec();
    };
    let b64_start = start + marker.len();
    let mut owned = s.into_owned().into_bytes();
    owned[b64_start] ^= 1;
    owned
}

#[test]
fn s5_constructed_negatives() {
    let blob = mutate_zip(
        "aoo-blowfish-pbkdf2.odt",
        Some("content.xml"),
        Some(|b| b[..b.len().saturating_sub(64)].to_vec()),
        None,
    );
    assert!(matches!(
        decrypt(&blob, PASSWORD).unwrap_err(),
        DecryptError::Inflate(_)
    ));

    let blob = mutate_zip(
        "aoo-blowfish-pbkdf2.odt",
        None,
        None,
        Some(flip_checksum_manifest),
    );
    assert!(matches!(
        decrypt(&blob, PASSWORD).unwrap_err(),
        DecryptError::WrongPassword
    ));

    let blob = mutate_zip(
        "aoo-blowfish-pbkdf2.odt",
        Some("content.xml"),
        Some(|b| {
            let mut v = b.to_vec();
            v[0] ^= 1;
            v
        }),
        None,
    );
    assert!(matches!(
        decrypt(&blob, PASSWORD).unwrap_err(),
        DecryptError::WrongPassword
    ));

    let blob = mutate_zip(
        "lo-legacy-aes-cbc.odt",
        None,
        None,
        Some(flip_checksum_manifest),
    );
    assert!(matches!(
        decrypt(&blob, PASSWORD).unwrap_err(),
        DecryptError::WrongPassword
    ));

    let blob = mutate_zip(
        "lo-legacy-aes-cbc.odt",
        Some("content.xml"),
        Some(|b| b[..b.len() - 1].to_vec()),
        None,
    );
    assert!(matches!(
        decrypt(&blob, PASSWORD).unwrap_err(),
        DecryptError::BadParameters(_)
    ));

    let blob = mutate_zip(
        "lo-legacy-aes-cbc.odt",
        Some("content.xml"),
        Some(|b| {
            let mut v = b.to_vec();
            let last = v.len() - 1;
            v[last] ^= 0xff;
            v
        }),
        None,
    );
    assert!(matches!(
        decrypt(&blob, PASSWORD).unwrap_err(),
        DecryptError::WrongPassword
    ));

    let blob = mutate_zip(
        "lo-wholesome-gcm-argon2.odt",
        Some("encrypted-package"),
        Some(|b| {
            let mut v = b.to_vec();
            let last = v.len() - 1;
            v[last] ^= 1;
            v
        }),
        None,
    );
    assert!(matches!(
        decrypt(&blob, PASSWORD).unwrap_err(),
        DecryptError::WrongPassword
    ));

    let blob = mutate_zip(
        "lo-wholesome-gcm-argon2.odt",
        Some("encrypted-package"),
        Some(|b| b[..20].to_vec()),
        None,
    );
    assert!(matches!(
        decrypt(&blob, PASSWORD).unwrap_err(),
        DecryptError::BadParameters(_)
    ));

    let blob = mutate_zip(
        "lo-wholesome-gcm-argon2.odt",
        Some("encrypted-package"),
        Some(|b| {
            let mut v = b.to_vec();
            v[0] ^= 1;
            v
        }),
        None,
    );
    assert!(matches!(
        decrypt(&blob, PASSWORD).unwrap_err(),
        DecryptError::BadParameters(_)
    ));

    let blob = mutate_zip(
        "lo-wholesome-gcm-argon2.odt",
        Some("encrypted-package"),
        Some(|b| {
            let mut v = b.to_vec();
            v[40] ^= 1;
            v
        }),
        None,
    );
    assert!(matches!(
        decrypt(&blob, PASSWORD).unwrap_err(),
        DecryptError::WrongPassword
    ));
}

// --- regressions ---

/// Replace `manifest:key-size` on key-derivation only, leaving start-key-generation's.
fn rewrite_kdf_key_size(xml: &str, to: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(pos) = rest.find("<manifest:key-derivation") {
        let (head, tail) = rest.split_at(pos);
        out.push_str(head);
        let end = tail.find("/>").map(|e| e + 2).unwrap_or(tail.len());
        let (elem, after) = tail.split_at(end);
        out.push_str(&elem.replace(
            "manifest:key-size=\"32\"",
            &format!("manifest:key-size=\"{to}\""),
        ));
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Re-encrypt every row of the AES-256 golden under a 16-byte derived key and declare
/// it as `#aes128-cbc` with `manifest:key-size="16"`. NSS picks the AES variant from
/// the derived key length, so LibreOffice opens this file; `classify` accepts the URI
/// and reports `derived_key_len == 16`. Salt, iteration count, IV and checksum are
/// untouched - the checksum covers the compressed plaintext, which does not change.
fn reencrypt_cbc_as_aes128(golden: &str) -> Vec<u8> {
    use aes::{Aes128, Aes256};
    use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
    use pbkdf2::pbkdf2_hmac;
    use sha1::Sha1;
    use sha2::{Digest, Sha256};

    let input = load_golden(golden);
    let class = classify(&input).unwrap();
    let start = Sha256::digest(PASSWORD.as_bytes()).to_vec();
    let mut bodies: std::collections::HashMap<String, Vec<u8>> = Default::default();

    for row in &class.encrypted_entries {
        let (salt, iters) = match &row.kdf {
            Kdf::Pbkdf2 { iterations, salt } => (salt.clone(), *iterations as u32),
            other => panic!("expected PBKDF2, got {other:?}"),
        };
        let mut k32 = vec![0u8; 32];
        pbkdf2_hmac::<Sha1>(&start, &salt, iters, &mut k32);
        let mut buf = read_member(&input, &row.path);
        let mut dec = cbc::Decryptor::<Aes256>::new_from_slices(&k32, &row.iv).unwrap();
        for chunk in buf.chunks_mut(16) {
            dec.decrypt_block_mut(cbc::cipher::Block::<Aes256>::from_mut_slice(chunk));
        }
        let pad = *buf.last().unwrap() as usize;
        buf.truncate(buf.len() - pad);

        let mut k16 = vec![0u8; 16];
        pbkdf2_hmac::<Sha1>(&start, &salt, iters, &mut k16);
        let padlen = 16 - (buf.len() % 16);
        buf.resize(buf.len() + padlen - 1, 0);
        buf.push(padlen as u8);
        let mut enc = cbc::Encryptor::<Aes128>::new_from_slices(&k16, &row.iv).unwrap();
        for chunk in buf.chunks_mut(16) {
            enc.encrypt_block_mut(cbc::cipher::Block::<Aes128>::from_mut_slice(chunk));
        }
        bodies.insert(row.path.clone(), buf);
    }

    let manifest = String::from_utf8(read_member(&input, "META-INF/manifest.xml")).unwrap();
    let manifest = rewrite_kdf_key_size(&manifest.replace("#aes256-cbc", "#aes128-cbc"), "16");

    let mut src = ZipArchive::new(Cursor::new(&input)).unwrap();
    let mut buf = Vec::new();
    let mut out = ZipWriter::new(Cursor::new(&mut buf));
    for i in 0..src.len() {
        let mut file = src.by_index(i).unwrap();
        let name = file.name().to_string();
        let method = file.compression();
        let mut body = Vec::new();
        file.read_to_end(&mut body).unwrap();
        let body = if name == "META-INF/manifest.xml" {
            manifest.clone().into_bytes()
        } else {
            bodies.get(&name).cloned().unwrap_or(body)
        };
        out.start_file(
            &name,
            SimpleFileOptions::default().compression_method(method),
        )
        .unwrap();
        out.write_all(&body).unwrap();
    }
    out.finish().unwrap();
    buf
}

/// AES-128 and AES-192 are in the accepted URI table, and an absent `manifest:key-size`
/// derives 16 bytes even under an `aes256-cbc` URI. Hardcoding AES-256 refused those
/// files as `BadParameters` - claiming the package was malformed when it was not.
#[test]
fn s3_aes128_cbc_decrypts_rather_than_being_refused() {
    let bytes = reencrypt_cbc_as_aes128("lo-legacy-aes-cbc.odt");
    let before = classify(&bytes).unwrap();
    assert!(!before.encrypted_entries.is_empty());
    assert!(
        before.encrypted_entries.iter().all(|e| e.derived_key_len == 16),
        "fixture must derive 16-byte keys"
    );

    let out = decrypt(&bytes, PASSWORD).expect("AES-128 package must decrypt");
    let after = classify(&out).unwrap();
    assert_eq!(after.mode, Mode::Plain);
    assert!(after.encrypted_entries.is_empty());

    // byte-identical to what the AES-256 original yields
    let want = decrypt(&load_golden("lo-legacy-aes-cbc.odt"), PASSWORD).unwrap();
    for path in ["content.xml", "styles.xml", "meta.xml"] {
        assert_eq!(read_member(&out, path), read_member(&want, path), "{path}");
    }
    assert!(matches!(
        decrypt(&bytes, "wrong").unwrap_err(),
        DecryptError::WrongPassword
    ));
}

fn add_size_to_self_closing_entry(xml: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(xml)
        .replacen(
            "<manifest:file-entry manifest:full-path=\"Configurations2/\"",
            "<manifest:file-entry manifest:size=\"99\" manifest:full-path=\"Configurations2/\"",
            1,
        )
        .into_bytes()
}

/// A file-entry with no children is an `Event::Empty`, and it can still carry
/// `manifest:size`. Filtering only `Event::Start` left those behind - invisible to the
/// goldens, where every entry with a size also has an `encryption-data` child.
#[test]
fn s2_manifest_size_stripped_from_self_closing_entry() {
    let bytes = mutate_zip(
        "aoo-blowfish-pbkdf2.odt",
        None,
        None,
        Some(add_size_to_self_closing_entry),
    );
    let fixture = String::from_utf8(read_member(&bytes, "META-INF/manifest.xml")).unwrap();
    assert!(
        fixture.contains("manifest:size=\"99\""),
        "fixture must carry the attribute it is testing"
    );

    let out = decrypt(&bytes, PASSWORD).unwrap();
    let mf = String::from_utf8(read_member(&out, "META-INF/manifest.xml")).unwrap();
    assert!(
        !mf.contains("manifest:size"),
        "manifest:size must be dropped from self-closing entries too:\n{mf}"
    );
    assert_eq!(classify(&out).unwrap().mode, Mode::Plain);
}

/// Plan section 2 wants two post-conditions after inflate: the stream reaches its end
/// marker, and the length equals `manifest:size`. The length check is explicit in
/// `raw_inflate`; this pins the other one, which is a property of the inflater rather
/// than of our code, so a dependency swap cannot quietly remove it.
#[test]
fn truncated_deflate_stream_errors_rather_than_returning_partial_output() {
    let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let compressed = miniz_oxide::deflate::compress_to_vec(&data, 6);
    assert_eq!(
        miniz_oxide::inflate::decompress_to_vec_with_limit(&compressed, 1 << 20).unwrap(),
        data
    );
    for cut in [1usize, 4, 16] {
        let truncated = &compressed[..compressed.len() - cut];
        assert!(
            miniz_oxide::inflate::decompress_to_vec_with_limit(truncated, 1 << 20).is_err(),
            "a stream truncated by {cut} B must be an error, not partial output"
        );
    }
}
