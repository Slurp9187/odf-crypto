//! Decrypt arc tests (issues #11–#15).

use std::io::{Cursor, Read, Write};

use zip::write::SimpleFileOptions;
use zip::{ZipArchive, ZipWriter};

use crate::classify::classify;
use crate::decrypt::{classification_metadata_unchanged, decrypt, AllocationSite, DecryptError};
use crate::test_support::{
    append_stored_member, load_golden, pgp_two_row_zip, read_member, zip_namelist,
    NONASCII_PASSWORD, PASSWORD,
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
    assert!(
        !class.pgp_keys.is_empty(),
        "pgp_keys from first entry KeyInfo"
    );
    let err = decrypt(&zip, PASSWORD).unwrap_err();
    assert!(matches!(err, DecryptError::UnsupportedPgp));
}

#[test]
fn odf12_fatal_encrypted_package_is_refused() {
    let blob = append_stored_member(&load_golden("lo-legacy-aes-cbc.odt"), "extra.bin", b"nope");
    let class = classify(&blob).expect("fixture classifies");
    assert!(
        class.odf12_fatal,
        "unlisted root stream on ODF 1.2 must be fatal"
    );
    assert_eq!(class.mode, Mode::PerEntry);
    assert!(matches!(
        decrypt(&blob, PASSWORD).unwrap_err(),
        DecryptError::Odf12Fatal
    ));
}

#[test]
fn pre_12_unexpected_stream_still_decrypts() {
    let blob = append_stored_member(
        &load_golden("aoo-blowfish-pbkdf2.odt"),
        "extra.bin",
        b"nope",
    );
    let class = classify(&blob).expect("fixture classifies");
    assert!(class.has_unexpected_streams);
    assert!(
        !class.odf12_fatal,
        "no ODF >= 1.2 root version, so not fatal"
    );
    decrypt(&blob, PASSWORD).expect("ODF 1.1 unexpected streams are not fatal");
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
    let err = decrypt(&load_golden("lo-odf11-nonascii-password.odt"), "wrong").unwrap_err();
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
        before
            .encrypted_entries
            .iter()
            .all(|e| e.derived_key_len == 16),
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
/// `inflate_into`; this pins the other one, which is a property of the inflater rather
/// than of our code, so a dependency swap cannot quietly remove it.
///
/// Pinned against `decompress_slice_iter_to_slice`, which is the function the decrypt
/// path actually calls. That matters more than it used to: the slice API is documented
/// to leave whatever it managed to write *in the caller's buffer* when it fails, so
/// this test also records why the per-entry caller builds through `try_new_with` --
/// the wrapper is live for the whole fill and zeroizes that partial document on `Err`.
#[test]
fn truncated_deflate_stream_errors_rather_than_returning_partial_output() {
    use miniz_oxide::inflate::decompress_slice_iter_to_slice;

    let data: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let compressed = miniz_oxide::deflate::compress_to_vec(&data, 6);

    let mut slot = vec![0u8; data.len()];
    assert_eq!(
        decompress_slice_iter_to_slice(&mut slot, std::iter::once(&compressed[..]), false, true)
            .unwrap(),
        data.len()
    );
    assert_eq!(slot, data);

    for cut in [1usize, 4, 16] {
        let truncated = &compressed[..compressed.len() - cut];
        let mut slot = vec![0u8; data.len()];
        assert!(
            decompress_slice_iter_to_slice(&mut slot, std::iter::once(truncated), false, true)
                .is_err(),
            "a stream truncated by {cut} B must be an error, not a short success"
        );
    }
}

fn rewrite_manifest_size(xml: &[u8], from: &str, to: &str) -> Vec<u8> {
    let before = format!("manifest:size=\"{from}\"");
    let after = format!("manifest:size=\"{to}\"");
    let s = String::from_utf8_lossy(xml);
    assert!(s.contains(&before), "fixture must carry {before}");
    s.replace(&before, &after).into_bytes()
}

/// `manifest:size` became an allocation length when the inflate moved into a sized
/// slot, so it needs the same treatment `manifest:key-size` already had. It is an
/// `i64` the manifest controls, and `vec![0u8; 9_000_000_000]` is a 9 GB allocation
/// -- or on a 32-bit target a capacity-overflow panic -- reached before any cipher
/// could object. Under the old grown-`Vec` inflate this was the decompressor's
/// ceiling to enforce; now it is ours, and it is enforced before key derivation so a
/// hostile row costs a comparison rather than a 64 MiB Argon2id.
#[test]
fn hostile_manifest_size_is_refused_before_allocating() {
    let bytes = mutate_zip(
        "lo-wholesome-gcm-argon2.odt",
        None,
        None,
        Some(|xml| rewrite_manifest_size(xml, "6977", "9000000000")),
    );
    let class = classify(&bytes).expect("classify passes manifest:size through");
    assert!(
        class
            .encrypted_entries
            .iter()
            .any(|e| e.size == 9_000_000_000),
        "fixture must carry the hostile size"
    );
    match decrypt(&bytes, PASSWORD) {
        Err(DecryptError::BadParameters(msg)) => {
            assert!(msg.contains("manifest:size"), "unexpected message: {msg}")
        }
        other => panic!("expected BadParameters, got {other:?}"),
    }
}

/// The hazard the sized slot introduces, and the reason the length check is
/// load-bearing rather than belt-and-braces. A slot is zero-filled before the
/// closure runs, so a manifest that OVERSTATES `size` inflates fewer bytes than the
/// slot holds and the decoder still reports success -- the difference is a tail of
/// zeros. Without comparing the written count to the slot length, a truncated
/// document would be accepted as a whole one and handed to the caller padded.
#[test]
fn overstated_manifest_size_is_rejected_rather_than_zero_padded() {
    let bytes = mutate_zip(
        "lo-wholesome-gcm-argon2.odt",
        None,
        None,
        Some(|xml| rewrite_manifest_size(xml, "6977", "7000")),
    );
    match decrypt(&bytes, PASSWORD) {
        Err(DecryptError::Inflate(msg)) => assert!(
            msg.contains("6977") && msg.contains("7000"),
            "message should name both lengths: {msg}"
        ),
        other => panic!("expected Inflate, got {other:?}"),
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
        .replace(
            "loext:argon2-lanes=\"4\"",
            "loext:argon2-lanes=\"536870912\"",
        )
        .into_bytes()
}

fn set_argon2_memory_to_2gib(xml: &[u8]) -> Vec<u8> {
    // ~2 TiB of Argon2 blocks: `vec!` aborts the process rather than returning
    // an error, where LO's own libargon2 returns ARGON2_MEMORY_ALLOCATION_ERROR.
    String::from_utf8_lossy(xml)
        .replace(
            "loext:argon2-memory=\"65536\"",
            "loext:argon2-memory=\"2147483647\"",
        )
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
        (
            "lanes 2^29 (overflows Params::new's m < 8p test)",
            set_argon2_lanes_to_overflow as Rewrite,
        ),
        (
            "memory 2 GiB KiB (~2 TiB of blocks)",
            set_argon2_memory_to_2gib,
        ),
        (
            "memory 1 KiB (below 8 * lanes)",
            set_argon2_memory_below_lanes,
        ),
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

fn set_pbkdf2_iterations(xml: &[u8], value: &str) -> Vec<u8> {
    String::from_utf8_lossy(xml)
        .replace(
            "manifest:iteration-count=\"100000\"",
            &format!("manifest:iteration-count=\"{value}\""),
        )
        .into_bytes()
}

#[test]
fn hostile_pbkdf2_iterations_are_bad_parameters_not_a_hang() {
    let blob = mutate_zip(
        "lo-legacy-aes-cbc.odt",
        None,
        None,
        Some(|xml| set_pbkdf2_iterations(xml, "2147483647")),
    );
    let class = classify(&blob).expect("classify passes iteration-count through");
    assert!(
        class.encrypted_entries.iter().any(|e| matches!(
            e.kdf,
            Kdf::Pbkdf2 {
                iterations: 2_147_483_647,
                ..
            }
        )),
        "fixture must carry hostile iteration count"
    );
    assert!(matches!(
        decrypt(&blob, PASSWORD).unwrap_err(),
        DecryptError::BadParameters(_)
    ));
}

#[test]
fn pbkdf2_zero_iterations_is_bad_parameters() {
    let blob = mutate_zip(
        "lo-legacy-aes-cbc.odt",
        None,
        None,
        Some(|xml| set_pbkdf2_iterations(xml, "0")),
    );
    let class = classify(&blob).expect("classify still accepts a complete row with 0 iterations");
    assert!(
        class
            .encrypted_entries
            .iter()
            .any(|e| matches!(e.kdf, Kdf::Pbkdf2 { iterations: 0, .. })),
        "fixture must carry iteration-count 0"
    );
    assert!(matches!(
        decrypt(&blob, PASSWORD).unwrap_err(),
        DecryptError::BadParameters(_)
    ));
}

#[test]
fn encrypted_entry_count_ceiling_refuses_without_running_kdf() {
    assert!(super::ensure_encrypted_entry_count(1, 1).is_ok());
    let err = super::ensure_encrypted_entry_count(2, 1).unwrap_err();
    match err {
        DecryptError::BadParameters(msg) => {
            assert!(msg.contains("encrypted entry count"), "message: {msg}");
        }
        other => panic!("expected BadParameters, got {other:?}"),
    }
}

#[test]
fn gcm_iv_tag_only_frame_is_not_rejected_as_too_short() {
    fn iv_tag_only_member(_body: &[u8]) -> Vec<u8> {
        let input = load_golden("lo-wholesome-gcm-argon2.odt");
        let iv = classify(&input)
            .unwrap()
            .encrypted_entries
            .into_iter()
            .find(|e| e.path == "encrypted-package")
            .unwrap()
            .iv;
        let mut frame = vec![0u8; crate::limits::AES_GCM_IV_LEN + crate::limits::AES_GCM_TAG_LEN];
        frame[..crate::limits::AES_GCM_IV_LEN].copy_from_slice(&iv);
        frame
    }
    let blob = mutate_zip(
        "lo-wholesome-gcm-argon2.odt",
        Some("encrypted-package"),
        Some(iv_tag_only_member),
        None,
    );
    let err = decrypt(&blob, PASSWORD).unwrap_err();
    assert!(
        !matches!(err, DecryptError::BadParameters(ref m) if m.contains("shorter than IV+tag")),
        "IV||tag-only member must reach the cipher, not BadParameters: {err:?}"
    );
}

// --- the sized-slot inflate at its boundary ---
//
// `manifest:size = 0` is legal: an empty member is a normal thing for an ODF
// package to carry. It is also the one input shape the sized-slot inflate had
// never seen, because none of the goldens has an empty encrypted member. The
// old grown-`Vec` inflate could not get this wrong -- it allocated nothing and
// compared lengths afterwards. A slot is allocated first, so zero is now a real
// case with real behaviour, and these pin it rather than assuming it.

/// A zero-length slot is what `try_new_with(0, ..)` hands the closure.
/// miniz_oxide's own source special-cases it -- without that, any write against
/// a zero-length output buffer reports `HasMoreOutput` -- so this records that
/// the decrypt path depends on that behaviour rather than merely expecting it.
#[test]
fn an_empty_member_inflates_into_a_zero_length_slot() {
    let compressed = miniz_oxide::deflate::compress_to_vec(&[], 6);
    let mut slot: [u8; 0] = [];
    crate::decrypt::inflate_into(&compressed, &mut slot)
        .expect("an empty member must inflate into an empty slot, not error");
}

/// The other half, and the one that would actually lose data: a member whose
/// manifest claims 0 but whose ciphertext holds content must not decrypt to
/// nothing.
///
/// Note which guard fires, because it is NOT the one that catches every other
/// short inflate. At zero length our own `written != slot.len()` comparison is
/// `0 != 0` and passes -- it cannot see this. What rejects it is the decoder
/// itself, reporting `HasMoreOutput` because it has bytes to write and nowhere
/// to put them. The assertion pins that distinction: an error message carrying
/// `!=` would mean our comparison caught it, and at this length it cannot, so
/// if that ever becomes the failing path something has changed underneath.
#[test]
fn a_zero_length_slot_refuses_a_stream_that_has_content() {
    let compressed = miniz_oxide::deflate::compress_to_vec(b"not empty", 6);
    let mut slot: [u8; 0] = [];
    let err = crate::decrypt::inflate_into(&compressed, &mut slot)
        .expect_err("a non-empty stream must not pass through a zero-length slot");
    let DecryptError::Inflate(msg) = &err else {
        panic!("expected Inflate, got {err:?}");
    };
    assert!(
        !msg.contains("!="),
        "at zero length the decoder must be what refuses this, not our length          comparison, which is 0 != 0 and passes: {msg}"
    );
}

/// The bound exists to stop a hostile `manifest:size` becoming a huge
/// allocation, so it must not also reject the legal small end. Zero is in
/// range; negative is not, because `size as usize` on a negative `i64` is an
/// enormous length rather than an error.
#[test]
fn zero_is_a_legal_manifest_size_and_negative_is_not() {
    assert_eq!(
        crate::decrypt::inflated_len(0).expect("0 must be in range"),
        0
    );
    assert!(matches!(
        crate::decrypt::inflated_len(-1),
        Err(DecryptError::BadParameters(_))
    ));
}

// --- kdf.rs's block buffer: fallible, not an abort ---
//
// `derive_argon2id` reserves its Argon2 working buffer with
// `Vec::try_reserve_exact` rather than `vec![]` specifically so a host that
// cannot supply the memory gets a `KdfError::HostCannotAllocate` back instead
// of `handle_alloc_error` aborting the process with `PasswordDigest`/
// `DerivedKey` still live and unwiped (see the doc comment on
// `kdf::derive_argon2id`). A fallible path nobody has ever seen fail is
// decoration, not evidence, so this drives the call with `m` at the crate's
// own ceiling (`ARGON2_MAX_M_COST_KIB`, 1 GiB of blocks -- the scope this
// crate accepts, not a value beyond it) and asserts the specific error.
//
// This is a genuine allocation attempt sized by how much memory the host
// actually has free right now, so it can only witness `HostCannotAllocate`
// on a host that is this tight on memory at the moment the test runs; it is
// deliberately not manufactured with a value beyond `ARGON2_MAX_M_COST_KIB`,
// which would only prove the earlier range check, not this one. On a
// generously-provisioned host the request may simply succeed.
//
// `#[ignore]`, recording a real result rather than a hoped-for one: run in
// isolation on the machine this was written on (16 GiB RAM, `Get-CimInstance
// Win32_OperatingSystem` reporting `FreeVirtualMemory` fluctuating around
// 1.8-2.3 GiB), this 1 GiB request `Ok`'d -- the crate's own legal ceiling
// was not, on that occasion, above what the host could satisfy. Getting a
// deterministic `Err` from here would mean either raising the request past
// `ARGON2_MAX_M_COST_KIB` (out of scope -- see this arc's scope fence) or
// deliberately exhausting the host's memory first, which was not done
// because this suite may run on a live, shared machine where that is not a
// safe thing for a test to do. Run explicitly with `cargo test -- --ignored
// argon2_block_buffer_reports_host_capacity_not_an_abort` on a host you know
// is this tight on memory (or under a container/`ulimit`/cgroup memory cap
// below 1 GiB) to see the assertion actually pass.
#[test]
#[ignore = "host-capacity-dependent: passes only when the host has under ~1 GiB free at call time; not reliably true on a well-provisioned machine or CI runner"]
fn argon2_block_buffer_reports_host_capacity_not_an_abort() {
    let salt = [0u8; 16];
    let mut out = [0u8; 32];
    let result = crate::kdf::derive_argon2id(
        b"start-key-bytes-are-arbitrary-for-this-probe",
        &salt,
        1,                                           // t: minimum iterations
        crate::limits::ARGON2_MAX_M_COST_KIB as i32, // 1 GiB: the crate's own ceiling
        1,                                           // p: minimum lanes
        &mut out,
    );
    let requested_bytes = match result {
        Err(crate::kdf::KdfError::HostCannotAllocate { requested_bytes }) => requested_bytes,
        other => panic!(
            "expected KdfError::HostCannotAllocate on this host; got {other:?} instead \
             -- this machine had enough free memory to satisfy a 1 GiB Argon2 request, \
             so the failure path was not exercised here"
        ),
    };
    assert_eq!(requested_bytes, 1 << 30, "1 GiB of Argon2 blocks");
    // Reaching this line at all is the point: `try_reserve_exact` returned
    // `Err` and unwound normally rather than the allocator aborting the
    // process, which is the one thing a `vec![]`-based version could never
    // let this test observe.
}

#[test]
fn a_host_capacity_failure_is_not_a_bad_parameter() {
    // A refusal the ALLOCATOR makes still cannot be tested deterministically:
    // that needs a #[global_allocator] shim, and `unsafe_code = "forbid"` in
    // Cargo.toml makes one impossible -- `forbid` cannot be lifted by `allow`.
    // The ignored test above drives a real 1 GiB request and is the only thing
    // that exercises the allocator itself saying no, on a host small enough.
    //
    // A refusal `try_reserve_exact` makes on its own IS deterministic, and
    // `try_reserve_exact_refuses_an_impossible_request` below covers it on
    // every host. Two different failures reaching one variant; neither test
    // stands in for the other.
    //
    // Everything downstream of that refusal IS deterministic, and it is where
    // the damage would be done: a host failure reported as `BadParameters`
    // tells the user their manifest is wrong when it may be perfectly legal
    // and decrypt fine on a bigger machine.
    let mapped = crate::decrypt::kdf_error(crate::kdf::KdfError::HostCannotAllocate {
        requested_bytes: 1 << 30,
    });
    assert!(
        matches!(
            mapped,
            DecryptError::HostCannotAllocate {
                site: AllocationSite::KeyDerivation,
                requested_bytes: 1_073_741_824
            }
        ),
        "host capacity must not collapse into BadParameters, got {mapped:?}"
    );

    // And the other arm still lands where it did, so the split is real rather
    // than everything becoming HostCannotAllocate.
    let params = crate::decrypt::kdf_error(crate::kdf::KdfError::Params("argon2 t 0".into()));
    assert!(matches!(params, DecryptError::BadParameters(_)));
}

#[test]
fn try_reserve_exact_refuses_an_impossible_request() {
    // Deterministic on every host, and it is the guard firing rather than a
    // proxy for it: `try_reserve_exact` rejects a request whose byte count
    // overflows before it asks the allocator for anything, so no machine is
    // large enough to make this pass by accident. The `#[ignore]`d 1 GiB test
    // covers the other half -- the allocator itself refusing -- and cannot run
    // on a well-provisioned box.
    //
    // What it proves is the property the change is for: an allocation sized
    // from the package RETURNS instead of aborting. A `vec![0u8; n]` here would
    // end the test process, not fail the test.
    for site in [
        AllocationSite::MemberPlaintext,
        AllocationSite::PackagePlaintext,
        AllocationSite::DerivedKey,
        AllocationSite::CipherBuffer,
    ] {
        let got = crate::decrypt::try_zeroed(usize::MAX, site);
        assert!(
            matches!(
                got,
                Err(DecryptError::HostCannotAllocate { site: s, requested_bytes })
                    if s == site && requested_bytes == usize::MAX
            ),
            "{site:?} must return, and must carry its own site, got {got:?}"
        );
    }
}

#[test]
fn a_fallible_allocation_that_succeeds_is_exact_and_filled() {
    // The success path of both helpers, because a guard that only ever returns
    // Err would pass the test above and break every decrypt.
    let zeroed = crate::decrypt::try_zeroed(64, AllocationSite::DerivedKey)
        .expect("64 bytes is not a host-capacity failure");
    assert_eq!(zeroed.len(), 64);
    assert!(zeroed.iter().all(|b| *b == 0));
    // Exact capacity is the half that matters for residue: a buffer with spare
    // capacity would still be correct, but `try_reserve_exact` asking for more
    // than it needs is worth catching here rather than in a heap dump.
    assert_eq!(zeroed.capacity(), 64);

    let copied = crate::decrypt::try_copy_of(b"abc", AllocationSite::CipherBuffer)
        .expect("3 bytes is not a host-capacity failure");
    assert_eq!(copied, b"abc");
    assert_eq!(
        copied.capacity(),
        3,
        "extend_from_slice must not have grown it"
    );
}

#[test]
fn every_allocation_site_renders_distinctly() {
    // The site exists because the message was wrong without it -- the variant's
    // Display said "for key derivation" unconditionally. Two sites sharing a
    // string would put that back for one of them.
    let sites = [
        AllocationSite::KeyDerivation,
        AllocationSite::DerivedKey,
        AllocationSite::MemberPlaintext,
        AllocationSite::PackagePlaintext,
        AllocationSite::CipherBuffer,
    ];
    let mut seen: Vec<String> = sites.iter().map(|s| s.to_string()).collect();
    seen.sort();
    let before = seen.len();
    seen.dedup();
    assert_eq!(seen.len(), before, "two sites render the same: {seen:?}");

    // And the rendered message names the site rather than the KDF.
    let e = DecryptError::HostCannotAllocate {
        site: AllocationSite::MemberPlaintext,
        requested_bytes: 4096,
    };
    assert_eq!(
        e.to_string(),
        "host could not allocate 4096 bytes for a decrypted package member"
    );
}

// --- #48: the rewrite's read error is unreachable, and this keeps it so -----

/// A complete per-entry manifest: one latch row on `content.xml` with a full
/// `encryption-data`, so `parse_manifest` yields a row and `classify` reports
/// [`Mode::PerEntry`].
fn complete_per_entry_manifest() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">
 <manifest:file-entry manifest:full-path="/" manifest:version="1.2" manifest:media-type="{mime}"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml" manifest:size="64">
  <manifest:encryption-data manifest:checksum-type="{sha1_1k}" manifest:checksum="{b64}">
   <manifest:algorithm manifest:algorithm-name="{aes}" manifest:initialisation-vector="{b64}"/>
   <manifest:start-key-generation manifest:start-key-generation-name="{sha1}"/>
   <manifest:key-derivation manifest:key-derivation-name="{pbkdf2}" manifest:salt="{b64}" manifest:iteration-count="1024" manifest:key-size="32"/>
  </manifest:encryption-data>
 </manifest:file-entry>
</manifest:manifest>
"#,
        mime = crate::test_support::MIME_TEXT,
        sha1_1k = crate::uris::SHA1_1K_NAME,
        aes = crate::uris::AES256_URL,
        sha1 = crate::uris::SHA1_NAME,
        pbkdf2 = crate::uris::PBKDF2_NAME,
        b64 = crate::test_support::B64,
    )
}

/// **The guard behind [`DecryptError::Zip`]'s "why it is not elided" section.**
///
/// That variant can carry a `quick-xml` error whose payload is an element name
/// taken from the document, unbounded — the same shape `DetectError::Inconsistent`
/// was elided for. It is *not* elided here, on the argument that the path cannot
/// be reached: `parse_manifest` maps any read error to an empty row list,
/// `classify` then reports `Mode::Plain`, and `decrypt` refuses that with
/// `NotEncrypted` before the rewrite runs.
///
/// That argument rests on quick-xml 0.38.4 internals — specifically that
/// `expand_empty_elements`, the only configuration difference between the two
/// readers, cannot change *which* inputs are ill-formed. A dependency bump could
/// falsify it with no diff in this crate at all, which is exactly the kind of
/// claim that should not live only in prose.
///
/// So: mutate a complete manifest every way that is cheap, and assert the
/// implication directly. **Any failure here means the elision is now required.**
#[test]
fn classify_accepting_a_manifest_implies_the_rewrite_accepts_it() {
    let base = complete_per_entry_manifest();

    // The premise. If this stops holding the corpus below is vacuous — every
    // mutation would trivially satisfy an implication whose antecedent is never
    // true — so it is asserted rather than assumed.
    assert!(
        !crate::manifest::parse_manifest(base.as_bytes()).is_empty(),
        "baseline manifest must yield rows, or this test proves nothing"
    );
    assert!(crate::decrypt::strip_manifest(base.as_bytes()).is_ok());

    let injections = [
        "<x/>",
        "</x>",
        "<x>",
        "<a/></a>",
        "<a></a>",
        "<a/><a/>",
        "<!--c-->",
        "<?pi?>",
        "<a/></b>",
        "</a>",
        "<a></b>",
        "&",
        "<![CDATA[]]>",
        "<a/>t",
        "</manifest:manifest>",
        "<manifest:file-entry/>",
        "]]>",
        "<!DOCTYPE m>",
    ];

    let mut candidates: Vec<String> = Vec::new();
    // Truncation at every char boundary: catches unterminated everything.
    for i in 0..base.len() {
        if base.is_char_boundary(i) {
            candidates.push(base[..i].to_string());
        }
    }
    // Injection at every inter-tag boundary, which is where a manifest's
    // structure can actually be perturbed.
    for (i, _) in base.match_indices('>') {
        for inj in injections {
            let mut m = String::with_capacity(base.len() + inj.len());
            m.push_str(&base[..=i]);
            m.push_str(inj);
            m.push_str(&base[i + 1..]);
            candidates.push(m);
        }
    }

    let mut antecedent_true = 0usize;
    let mut strip_refused = 0usize;
    for m in &candidates {
        let rows_exist = !crate::manifest::parse_manifest(m.as_bytes()).is_empty();
        let strip_ok = crate::decrypt::strip_manifest(m.as_bytes()).is_ok();
        if !strip_ok {
            strip_refused += 1;
        }
        if rows_exist {
            antecedent_true += 1;
            assert!(
                strip_ok,
                "REACHABLE: classify accepts this manifest and the rewrite refuses it, \
                 so DecryptError::Zip can carry unbounded document text and must now be \
                 elided (see its rustdoc). Manifest:\n{m}"
            );
        }
    }

    // Coverage, not just a pass: a corpus that never exercised either side of
    // the implication would pass silently and mean nothing.
    assert!(
        antecedent_true > 100,
        "too few mutations kept classify happy ({antecedent_true}); corpus is not exercising the implication"
    );
    assert!(
        strip_refused > 100,
        "too few mutations made the rewrite refuse ({strip_refused}); corpus is not hostile enough"
    );
}

// --- CLI exit-code tripwire (#40) ----------------------------------------

/// Every [`DecryptError`] variant has an exit code assigned in `src/bin/odf-crypto.rs`
/// -- approximated by "every variant is named in the match below", because the
/// real property is not observable from where the mapping lives.
///
/// The binary is a separate crate from this one, and [`DecryptError`] is
/// `#[non_exhaustive]`, so rustc *requires* `decrypt_exit` to carry a `_` arm.
/// A variant added tomorrow compiles, falls through that arm, and silently
/// becomes EX_MALFORMED -- which is the whole of #40. A canary written beside
/// the mapping inherits the same `_` arm and cannot catch it either; measured,
/// not assumed (E0004: "`odf_crypto::DecryptError` is marked as non-exhaustive, so a
/// wildcard `_` is necessary to match exhaustively").
///
/// Inside the defining crate the attribute does not apply, so this match needs
/// no `_` arm and does not have one. That is the entire mechanism.
///
/// **If this stopped compiling, you added a variant.** Give it an exit code in
/// `decrypt_exit`, add it to `the_decrypt_exit_map_is_the_documented_one` in `src/bin/odf-crypto_tests.rs`, then name
/// it here.
///
/// It maps to `()` deliberately. A number here would be a second copy of the
/// mapping, free to drift from the one the binary actually runs: this half
/// checks that every variant is *considered*, the binary's half checks that
/// each one is *right*.
#[test]
fn every_decrypt_error_variant_is_accounted_for_in_the_cli_exit_map() {
    fn accounted_for(e: &DecryptError) {
        match e {
            DecryptError::Classify(_) => (),
            DecryptError::NotEncrypted => (),
            DecryptError::EmptyPassword => (),
            DecryptError::UnsupportedPgp => (),
            DecryptError::Odf12Fatal => (),
            DecryptError::WrongPassword => (),
            DecryptError::BadParameters(_) => (),
            DecryptError::Internal(_) => (),
            DecryptError::HostCannotAllocate { .. } => (),
            DecryptError::Inflate(_) => (),
            DecryptError::Zip(_) => (),
        }
    }
    accounted_for(&DecryptError::NotEncrypted);
}
