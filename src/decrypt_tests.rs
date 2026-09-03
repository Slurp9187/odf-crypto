//! Decrypt arc tests (issues #11–#15).

use std::io::{Cursor, Read, Write};

use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

use crate::classify::classify;
use crate::decrypt::{classification_metadata_unchanged, decrypt, DecryptError};
use crate::test_support::{
    load_golden, pgp_two_row_zip, read_member, zip_namelist, NONASCII_PASSWORD, PASSWORD,
};
use crate::{Kdf, Mode};

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

// --- shared kdf.rs (encrypt arc review): hostile Argon2 tuples ---
//
// `t`/`m`/`p` come straight off an attacker-supplied manifest, and until the
// encrypt arc factored key derivation into `kdf.rs` the only guard was
// `> 0` in `manifest.rs`. Both cases below reach a public `decrypt()` call:
// neither may panic, abort, or hang -- `BadParameters` is the whole contract.

fn set_argon2_lanes_to_overflow(xml: &[u8]) -> Vec<u8> {
    // 2^29: `Params::new` computes `m_cost < p_cost * 8` *before* range-checking
    // `p_cost`, so this overflows u32 and panics in any overflow-checks build
    // (argon2 0.5.3 params.rs:119) unless `kdf.rs` rejects it first.
    String::from_utf8_lossy(xml)
        .replace("loext:argon2-lanes=\"4\"", "loext:argon2-lanes=\"536870912\"")
        .into_bytes()
}

fn set_argon2_memory_to_2gib(xml: &[u8]) -> Vec<u8> {
    // ~2 TiB of Argon2 blocks: `vec!` aborts the process rather than returning
    // an error, where LO's own libargon2 returns ARGON2_MEMORY_ALLOCATION_ERROR.
    String::from_utf8_lossy(xml)
        .replace("loext:argon2-memory=\"65536\"", "loext:argon2-memory=\"2147483647\"")
        .into_bytes()
}

fn set_argon2_memory_below_lanes(xml: &[u8]) -> Vec<u8> {
    // m < 8p: argon2's own `MemoryTooLittle`, surfaced rather than panicked on.
    String::from_utf8_lossy(xml)
        .replace("loext:argon2-memory=\"65536\"", "loext:argon2-memory=\"1\"")
        .into_bytes()
}

#[test]
fn argon2_hostile_parameters_are_bad_parameters_not_a_panic() {
    for (label, rewrite) in [
        ("lanes 2^29 (overflows Params::new's m < 8p test)", set_argon2_lanes_to_overflow as Rewrite),
        ("memory 2 GiB KiB (~2 TiB of blocks)", set_argon2_memory_to_2gib),
        ("memory 1 KiB (below 8 * lanes)", set_argon2_memory_below_lanes),
    ] {
        let blob = mutate_zip("lo-wholesome-gcm-argon2.odt", None, None, Some(rewrite));
        // The fixture must still be a complete row, or this proves nothing:
        // classify has to hand decrypt an Argon2id tuple to reject.
        let class = classify(&blob).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(class.mode, Mode::Wholesome, "{label}");
        assert!(
            matches!(class.encrypted_entries[0].kdf, Kdf::Argon2id { .. }),
            "{label}: fixture must still carry an Argon2id row"
        );

        let err = decrypt(&blob, PASSWORD).unwrap_err();
        assert!(
            matches!(err, DecryptError::BadParameters(_)),
            "{label}: expected BadParameters, got {err:?}"
        );
    }
}

/// A hostile `manifest:key-size` used to reach `vec![0u8; n]` before any cipher had
/// a chance to reject the length. `derived_key_len` is an `i32`, so the worst case
/// is a ~2 GiB allocation followed by a PBKDF2 over all of it - a hang no `Result`
/// can report. `derive_key` now bounds the length first and returns
/// `BadParameters` without allocating. `classify` is checked to pass the value
/// through unchanged, so the guard - not the parser - is what this exercises.
#[test]
fn hostile_derived_key_len_is_refused_before_allocating() {
    fn huge_key_size(xml: &[u8]) -> Vec<u8> {
        rewrite_kdf_key_size(std::str::from_utf8(xml).unwrap(), "2000000000").into_bytes()
    }
    let bytes = mutate_zip("lo-legacy-aes-cbc.odt", None, None, Some(huge_key_size));
    let class = classify(&bytes).expect("classify passes the manifest key-size through");
    assert!(
        class
            .encrypted_entries
            .iter()
            .all(|e| e.derived_key_len == 2_000_000_000),
        "fixture must carry the hostile key-size"
    );
    match decrypt(&bytes, PASSWORD) {
        Err(DecryptError::BadParameters(msg)) => {
            assert!(msg.contains("derived_key_len"), "unexpected message: {msg}")
        }
        other => panic!("expected BadParameters, got {other:?}"),
    }
}
