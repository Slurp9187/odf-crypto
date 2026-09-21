//! Encrypt arc tests (issues #19-#23).

use zip::CompressionMethod;

use crate::classify::classify;
use crate::decrypt::{decrypt, DecryptError};
use crate::encrypt::{
    encrypt, encrypt_with_params, Argon2Axis, Argon2Params, EncryptError, ParamsReason,
};
use crate::test_support::{
    append_stored_member, goldens_dir, load_golden, read_member, strict_b64_decode, zip_method,
    zip_namelist, zip_with, zip_with_methods, MIME_TEXT, NONASCII_PASSWORD, PASSWORD,
};
use crate::{Checksum, Cipher, Kdf, Mode, StartKeyAlg};

// --- S1 ---

#[test]
fn s1_already_encrypted_wholesome() {
    let err = encrypt(&load_golden("lo-wholesome-gcm-argon2.odt"), PASSWORD).unwrap_err();
    assert!(matches!(err, EncryptError::AlreadyEncrypted));
}

#[test]
fn s1_empty_password() {
    let err = encrypt(&load_golden("lo-unencrypted.odt"), "").unwrap_err();
    assert!(matches!(err, EncryptError::EmptyPassword));
}

#[test]
fn odf12_fatal_plain_package_is_refused() {
    let blob = append_stored_member(&load_golden("lo-unencrypted.odt"), "extra.bin", b"nope");
    let class = classify(&blob).expect("fixture classifies");
    assert_eq!(class.mode, Mode::Plain);
    assert!(
        class.odf12_fatal,
        "unlisted root stream on ODF 1.4 must be fatal"
    );
    assert!(matches!(
        encrypt(&blob, PASSWORD).unwrap_err(),
        EncryptError::Odf12Fatal
    ));
}

/// The `Classify` variant exists for input `classify` itself rejects, before
/// any of encrypt's own predicates run. Nothing else covered it.
#[test]
fn s1_classify_failure_is_reported_as_classify() {
    let err = encrypt(b"not a zip at all", PASSWORD).unwrap_err();
    assert!(
        matches!(err, EncryptError::Classify(crate::DetectError::NotZip)),
        "expected Classify(NotZip), got {err:?}"
    );

    // A zip, but not an ODF package: no META-INF/manifest.xml.
    let bare = zip_with(&[("content.xml", b"<x/>")]);
    let err = encrypt(&bare, PASSWORD).unwrap_err();
    assert!(
        matches!(
            err,
            EncryptError::Classify(crate::DetectError::MissingManifest)
        ),
        "expected Classify(MissingManifest), got {err:?}"
    );
}

/// A PGP package is `Mode::PerEntry` **with the latch set**, so it is
/// `AlreadyEncrypted` rather than `PartiallyEncrypted` -- the same refusal,
/// reached without `encrypt` needing a PGP notion of its own. The latch is what
/// decides between the two now, so this test also pins which side of that split
/// a PGP package falls on, which the old single variant could not express.
#[test]
fn s1_pgp_package_is_already_encrypted() {
    let pgp = crate::test_support::pgp_two_row_zip();
    assert_ne!(
        classify(&pgp).expect("pgp zip classifies").mode,
        Mode::Plain
    );
    let err = encrypt(&pgp, PASSWORD).unwrap_err();
    assert!(
        matches!(err, EncryptError::AlreadyEncrypted),
        "expected AlreadyEncrypted, got {err:?}"
    );
}

/// The split #4 of the rc.5 plan's §4 produced, and the case that forced it.
///
/// A package whose only complete `encryption-data` row sits on a member that is
/// neither `content.xml` nor `encrypted-package` gets `Mode::PerEntry` --
/// `classify.rs`'s mode is `!encrypted_entries.is_empty()` -- while
/// `package_encrypted` stays false, because that latch is LibreOffice's
/// `HasEncryptedEntries` and only a row on one of those two members sets it
/// (`ZipPackage.cxx:435-446`).
///
/// **LibreOffice opens this without prompting.** So the old single
/// `AlreadyEncrypted`, whose message is "package is already encrypted", was
/// telling a caller something the specifying implementation contradicts. The
/// refusal itself was never in question and has not changed.
#[test]
fn s1_encrypted_rows_without_a_latch_are_partially_encrypted() {
    let manifest = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">
 <manifest:file-entry manifest:full-path="/" manifest:version="1.2" manifest:media-type="{MIME_TEXT}"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
 <manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml" manifest:size="64">
  <manifest:encryption-data manifest:checksum-type="{sha1_1k}" manifest:checksum="{b64}">
   <manifest:algorithm manifest:algorithm-name="{aes}" manifest:initialisation-vector="{b64}"/>
   <manifest:start-key-generation manifest:start-key-generation-name="{sha1}"/>
   <manifest:key-derivation manifest:key-derivation-name="{pbkdf2}" manifest:salt="{b64}" manifest:iteration-count="1024" manifest:key-size="32"/>
  </manifest:encryption-data>
 </manifest:file-entry>
</manifest:manifest>
"#,
        sha1_1k = crate::uris::SHA1_1K_NAME,
        aes = crate::uris::AES256_URL,
        sha1 = crate::uris::SHA1_NAME,
        pbkdf2 = crate::uris::PBKDF2_NAME,
        b64 = crate::test_support::B64,
    );
    let pkg = zip_with(&[
        ("mimetype", MIME_TEXT.as_bytes()),
        ("META-INF/manifest.xml", manifest.as_bytes()),
        ("content.xml", b"x"),
        ("styles.xml", b"y"),
    ]);

    // The premise, asserted rather than assumed -- if classify ever stopped
    // producing this shape the test below would pass for the wrong reason.
    let class = classify(&pkg).expect("constructed package classifies");
    assert_eq!(class.mode, Mode::PerEntry, "rows exist, so PerEntry");
    assert!(
        !class.package_encrypted,
        "no row on content.xml or encrypted-package, so no latch"
    );
    assert!(!class.encrypted_entries.is_empty());

    let err = encrypt(&pkg, PASSWORD).unwrap_err();
    assert!(
        matches!(err, EncryptError::PartiallyEncrypted),
        "expected PartiallyEncrypted, got {err:?}"
    );
    // The distinction is in the message, which is the whole point of the split.
    assert!(
        err.to_string().contains("without prompting"),
        "message must not claim the package is encrypted: {err}"
    );
}

/// The other side of the split: with a latch row, the claim is true and the
/// variant stays `AlreadyEncrypted`. Both still refuse; only the claim differs.
#[test]
fn s1_a_latched_package_is_still_already_encrypted() {
    let sealed = encrypt(&load_golden("lo-unencrypted.odt"), PASSWORD).expect("seals");
    assert!(classify(&sealed).expect("classifies").package_encrypted);
    assert!(matches!(
        encrypt(&sealed, PASSWORD).unwrap_err(),
        EncryptError::AlreadyEncrypted
    ));
}

// --- S2: exact emit table (plan §2) ---

/// Every attribute [`build_manifest`] can write, collected from a real parse
/// of the produced `manifest.xml` -- not substring checks, so attribute
/// *order* and *absence* (the checksum attributes, a second `file-entry`) are
/// both verifiable, not just presence.
#[derive(Default, Debug)]
struct ManifestCheck {
    root_version: Option<String>,
    root_has_loext_ns: bool,
    file_entry_count: usize,
    full_path: Option<String>,
    size: Option<String>,
    media_type: Option<String>,
    checksum_type: Option<String>,
    checksum: Option<String>,
    /// Local names of `encryption-data`'s children, in document order.
    child_order: Vec<String>,
    algorithm_name: Option<String>,
    iv: Option<String>,
    start_key_name: Option<String>,
    start_key_size: Option<String>,
    kdf_name: Option<String>,
    argon2_t: Option<String>,
    argon2_m: Option<String>,
    argon2_p: Option<String>,
    salt: Option<String>,
    kdf_key_size: Option<String>,
}

fn check_manifest(xml: &[u8]) -> ManifestCheck {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    fn attr(e: &quick_xml::events::BytesStart<'_>, key: &str) -> Option<String> {
        e.attributes()
            .flatten()
            .find(|a| a.key.as_ref() == key.as_bytes())
            .map(|a| String::from_utf8_lossy(a.value.as_ref()).into_owned())
    }

    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut out = ManifestCheck::default();
    let mut in_encryption_data = false;

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                match name.as_str() {
                    "manifest:manifest" => {
                        out.root_version = attr(&e, "manifest:version");
                        out.root_has_loext_ns = e.attributes().flatten().any(|a| {
                            a.key.as_ref() == b"xmlns:loext"
                                && a.value.as_ref() == crate::uris::MANIFEST_NS_LOEXT.as_bytes()
                        });
                    }
                    "manifest:file-entry" => {
                        out.file_entry_count += 1;
                        out.full_path = attr(&e, "manifest:full-path");
                        out.size = attr(&e, "manifest:size");
                        out.media_type = attr(&e, "manifest:media-type");
                    }
                    "manifest:encryption-data" => {
                        in_encryption_data = true;
                        out.checksum_type = attr(&e, "manifest:checksum-type");
                        out.checksum = attr(&e, "manifest:checksum");
                    }
                    "manifest:algorithm" if in_encryption_data => {
                        out.child_order.push("algorithm".into());
                        out.algorithm_name = attr(&e, "manifest:algorithm-name");
                        out.iv = attr(&e, "manifest:initialisation-vector");
                    }
                    "manifest:start-key-generation" if in_encryption_data => {
                        out.child_order.push("start-key-generation".into());
                        out.start_key_name = attr(&e, "manifest:start-key-generation-name");
                        out.start_key_size = attr(&e, "manifest:key-size");
                    }
                    "manifest:key-derivation" if in_encryption_data => {
                        out.child_order.push("key-derivation".into());
                        out.kdf_name = attr(&e, "manifest:key-derivation-name");
                        out.argon2_t = attr(&e, "loext:argon2-iterations");
                        out.argon2_m = attr(&e, "loext:argon2-memory");
                        out.argon2_p = attr(&e, "loext:argon2-lanes");
                        out.salt = attr(&e, "manifest:salt");
                        out.kdf_key_size = attr(&e, "manifest:key-size");
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                if e.name().as_ref() == b"manifest:encryption-data" {
                    in_encryption_data = false;
                }
            }
            Ok(_) => {}
            Err(e) => panic!("manifest.xml parse error: {e}"),
        }
    }
    out
}

#[test]
fn s2_wholesome_emit_matches_table() {
    let input = load_golden("lo-unencrypted.odt");
    let input_mimetype = read_member(&input, "mimetype");
    let out = encrypt(&input, PASSWORD).expect("encrypt");

    // --- zip shape (plan §3): exactly three members, in order ---
    assert_eq!(
        zip_namelist(&out),
        vec!["mimetype", "encrypted-package", "META-INF/manifest.xml"]
    );
    assert_eq!(zip_method(&out, "mimetype"), CompressionMethod::Stored);
    assert_eq!(
        zip_method(&out, "encrypted-package"),
        CompressionMethod::Stored
    );
    assert_eq!(
        zip_method(&out, "META-INF/manifest.xml"),
        CompressionMethod::Deflated
    );
    // Copied verbatim from the input's own `mimetype` member (plan §3), not
    // re-derived from `classify`'s recovered `media_type` string.
    assert_eq!(read_member(&out, "mimetype"), input_mimetype);

    // --- manifest.xml, every field in plan §2's emit table ---
    let mf_bytes = read_member(&out, "META-INF/manifest.xml");
    let mf = check_manifest(&mf_bytes);

    assert_eq!(mf.root_version.as_deref(), Some("1.4"));
    assert!(mf.root_has_loext_ns, "xmlns:loext must be present: {mf:?}");
    assert_eq!(
        mf.file_entry_count, 1,
        "wholesome writes exactly one file-entry, no root \"/\" row: {mf:?}"
    );
    assert_eq!(mf.full_path.as_deref(), Some("encrypted-package"));
    assert_eq!(mf.size.as_deref(), Some(input.len().to_string().as_str()));
    assert_eq!(
        mf.media_type.as_deref(),
        Some(String::from_utf8_lossy(&input_mimetype).as_ref())
    );
    assert!(
        mf.checksum_type.is_none() && mf.checksum.is_none(),
        "GCM writes no checksum attributes at all: {mf:?}"
    );

    assert_eq!(
        mf.child_order,
        vec!["algorithm", "start-key-generation", "key-derivation"]
    );

    assert_eq!(
        mf.algorithm_name.as_deref(),
        Some("http://www.w3.org/2009/xmlenc11#aes256-gcm")
    );
    // Decoded strictly, not with LO's deliberately lenient reader: a
    // whitespace-wrapping or URL-safe-alphabet regression in `encode_b64`
    // would be forgiven twice if the test used the same lenient decoder the
    // manifest parser does.
    let iv = strict_b64_decode(mf.iv.as_deref().expect("iv present")).expect("IV is strict base64");
    assert_eq!(iv.len(), 12, "IV must be 12 random bytes");

    assert_eq!(
        mf.start_key_name.as_deref(),
        Some("http://www.w3.org/2001/04/xmlenc#sha256"),
        "must be the W3C SHA-256 URL, not the ODF12 xmldsig one"
    );
    assert_eq!(mf.start_key_size.as_deref(), Some("32"));

    assert_eq!(
        mf.kdf_name.as_deref(),
        Some("urn:org:documentfoundation:names:experimental:office:manifest:argon2id")
    );
    assert_eq!(mf.argon2_t.as_deref(), Some("3"));
    assert_eq!(mf.argon2_m.as_deref(), Some("65536"));
    assert_eq!(mf.argon2_p.as_deref(), Some("4"));
    let salt = strict_b64_decode(mf.salt.as_deref().expect("salt present"))
        .expect("salt is strict base64");
    assert_eq!(salt.len(), 16, "salt must be 16 random bytes");
    assert_eq!(mf.kdf_key_size.as_deref(), Some("32"));

    // --- classify's own parse must agree with the textual emit above ---
    let after = classify(&out).expect("output classifies");
    assert_eq!(after.mode, Mode::Wholesome);
    assert_eq!(after.encrypted_entries.len(), 1);
    let row = &after.encrypted_entries[0];
    assert_eq!(row.path, "encrypted-package");
    assert_eq!(row.cipher, Cipher::AesGcmW3c);
    match &row.kdf {
        Kdf::Argon2id { t, m, p, salt } => {
            assert_eq!(*t, 3);
            assert_eq!(*m, 65536);
            assert_eq!(*p, 4);
            assert_eq!(salt.len(), 16);
        }
        other => panic!("expected Kdf::Argon2id, got {other:?}"),
    }
    assert_eq!(row.start_key, StartKeyAlg::Sha256);
    assert_eq!(row.checksum, Checksum::None);
    assert_eq!(row.derived_key_len, 32);
    assert_eq!(row.size, input.len() as i64);

    // N3: the same two properties the LO wholesome golden is pinned on, so a
    // regression in either shows up against our own output too, not only
    // against LibreOffice's.
    assert_eq!(
        after.odf_version.as_deref(),
        Some("1.4"),
        "wholesome writes manifest:version=\"1.4\""
    );
    assert!(
        !after.has_unexpected_streams,
        "a three-member wholesome package has no unexpected ODF 1.2 streams"
    );
}

#[test]
fn s2_salt_and_iv_are_fresh_per_call() {
    let input = load_golden("lo-unencrypted.odt");
    let a = encrypt(&input, PASSWORD).expect("encrypt a");
    let b = encrypt(&input, PASSWORD).expect("encrypt b");
    let mf_a = check_manifest(&read_member(&a, "META-INF/manifest.xml"));
    let mf_b = check_manifest(&read_member(&b, "META-INF/manifest.xml"));
    assert_ne!(mf_a.iv, mf_b.iv, "IV must be fresh per encrypt() call");
    assert_ne!(
        mf_a.salt, mf_b.salt,
        "salt must be fresh per encrypt() call"
    );
}

#[test]
fn s2_no_mimetype_member_falls_back_to_classify_media_type() {
    // A constructed Mode::Plain zip with no raw "mimetype" member at all --
    // classify still accepts it via the manifest-only path (plan §3's second
    // fallback tier: classify's media_type as raw UTF-8, no trailing newline).
    let media_type = MIME_TEXT;
    let manifest = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.4">
 <manifest:file-entry manifest:full-path="/" manifest:media-type="{media_type}"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>
"#
    );
    let input = zip_with(&[
        ("META-INF/manifest.xml", manifest.as_bytes()),
        ("content.xml", b"<office:document-content/>"),
    ]);

    let before = classify(&input).expect("constructed fixture classifies");
    assert_eq!(before.mode, Mode::Plain, "fixture must be Mode::Plain");
    assert_eq!(before.media_type.as_deref(), Some(media_type));
    assert!(
        !zip_namelist(&input).iter().any(|n| n == "mimetype"),
        "fixture must have no raw mimetype member"
    );

    let out = encrypt(&input, PASSWORD).expect("encrypt");
    let mf = check_manifest(&read_member(&out, "META-INF/manifest.xml"));
    assert_eq!(mf.media_type.as_deref(), Some(media_type));
    assert_eq!(
        read_member(&out, "mimetype"),
        media_type.as_bytes(),
        "mimetype member falls back to classify's media_type, raw UTF-8, no trailing newline"
    );
}

// --- S4: constructed negatives (issue #22) ---
//
// Table-driven: 1) `encrypt`'s own output, decrypted under the wrong password,
// must fail the same way decrypt's own S4/S5 already established for its
// other ciphers (`decrypt_tests.rs`'s `s2_*`/`s3_*`/`s4_wholesome_gcm_golden`
// each end on a `WrongPassword` check for the golden's real cipher -- this is
// the same evidence shape, for `encrypt`'s AES-GCM output specifically).
// 2) every already-encrypted golden refuses `encrypt`, discovered by sweeping
// `tests/goldens/*.odt` at runtime rather than a hardcoded list or count --
// the plan (`docs/plans/odf-encryption-encrypt-2026-09-03.md` §7, S4 row)
// warns this arc's own review already had to fix a stale "three goldens"
// claim once after a fifth golden landed mid-arc.

#[test]
fn s4_wrong_password_after_encrypt() {
    let original = load_golden("lo-unencrypted.odt");
    let encrypted = encrypt(&original, PASSWORD).expect("encrypt");
    let err = decrypt(&encrypted, "wrong").unwrap_err();
    assert!(
        matches!(err, DecryptError::WrongPassword),
        "expected DecryptError::WrongPassword, got {err:?}"
    );
}

#[test]
fn s4_encrypt_refuses_every_already_encrypted_golden() {
    let dir = goldens_dir();
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "odt").unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !names.is_empty(),
        "sweep found no *.odt files under {dir:?} -- the directory itself is broken"
    );

    let mut already_encrypted_count = 0usize;
    for name in &names {
        let bytes = load_golden(name);
        let class = classify(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        if class.mode == Mode::Plain {
            continue;
        }
        already_encrypted_count += 1;
        let err = encrypt(&bytes, PASSWORD).unwrap_err();
        assert!(
            matches!(err, EncryptError::AlreadyEncrypted),
            "{name}: expected AlreadyEncrypted, got {err:?}"
        );
    }
    // A floor, not an exact count: stays true no matter how many more
    // already-encrypted goldens land later, so it cannot go stale the way a
    // hardcoded count already has once in this arc.
    assert!(
        already_encrypted_count > 0,
        "swept {} goldens ({names:?}) but none classified as already-encrypted -- \
         the sweep itself is broken, not exercising this test's negative",
        names.len()
    );
    eprintln!(
        "s4_encrypt_refuses_every_already_encrypted_golden: {already_encrypted_count} of {} \
         goldens under {dir:?} classified as already-encrypted and were refused by encrypt()",
        names.len()
    );
}

// --- S3: wire into the round-trip (issue #21) ---
//
// `decrypt(encrypt(p, pw)?, pw)? == p` byte-for-byte. Wholesome's opaque-blob
// shape (plan §3) makes this exact, not approximate: `encrypt` deflates `p`
// once, `decrypt` inflates the same bytes back once, and `inflate(deflate(x))
// == x` always holds for valid DEFLATE regardless of encoder or level (plan
// §5). A mismatch here is a framing bug (IV/tag placement, salt/IV lengths),
// never a compression quirk.

#[test]
fn s3_round_trip_byte_identical_lo_unencrypted() {
    let original = load_golden("lo-unencrypted.odt");
    let encrypted = encrypt(&original, PASSWORD).expect("encrypt");
    let round_tripped = decrypt(&encrypted, PASSWORD).expect("decrypt");
    assert_eq!(
        round_tripped, original,
        "decrypt(encrypt(p, pw), pw) must be byte-identical to p"
    );
}

/// A hand-built `Mode::Plain` ODF package that is deliberately more elaborate
/// than the golden: a real `mimetype` member, several XML parts, non-ASCII
/// UTF-8 text (accented Latin, CJK, and an emoji outside the BMP) inside
/// `content.xml`, and an embedded binary member (`Pictures/image.png`) whose
/// bytes are not valid UTF-8 at all. Mirrors `decrypt_tests.rs`'s
/// `pgp_two_row_zip()` pattern of hand-building a zip with `ZipWriter`.
fn nontrivial_plain_fixture() -> Vec<u8> {
    let media_type = "application/vnd.oasis.opendocument.text";
    let manifest = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">
 <manifest:file-entry manifest:full-path="/" manifest:version="1.3" manifest:media-type="{media_type}"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
 <manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml"/>
 <manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/>
 <manifest:file-entry manifest:full-path="Pictures/image.png" manifest:media-type="image/png"/>
</manifest:manifest>
"#
    );

    let content_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
 <office:body>
  <office:text>
   <text:p>Café résumé 日本語 🎉</text:p>
  </office:text>
 </office:body>
</office:document-content>
"#;
    let styles_xml = r#"<?xml version="1.0" encoding="UTF-8"?><office:document-styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"/>"#;
    let meta_xml = r#"<?xml version="1.0" encoding="UTF-8"?><office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"/>"#;

    // Not a real PNG decoder target -- just non-UTF-8 binary content standing
    // in for an embedded picture, past the actual PNG signature bytes.
    let mut image_png: Vec<u8> = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    image_png.extend((0u32..512).map(|i| (i % 256) as u8));

    let manifest = manifest.into_bytes();
    zip_with_methods(&[
        ("mimetype", media_type.as_bytes(), CompressionMethod::Stored),
        (
            "META-INF/manifest.xml",
            &manifest,
            CompressionMethod::Deflated,
        ),
        (
            "content.xml",
            content_xml.as_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "styles.xml",
            styles_xml.as_bytes(),
            CompressionMethod::Deflated,
        ),
        ("meta.xml", meta_xml.as_bytes(), CompressionMethod::Deflated),
        (
            "Pictures/image.png",
            &image_png,
            CompressionMethod::Deflated,
        ),
    ])
}

/// The checked-in S5 evidence -- the file real LibreOffice opened -- must
/// also decrypt back to the exact golden it was made from. Without this the
/// artifact is inert between LibreOffice runs: a framing change that
/// `encrypt` and `decrypt` mirror would keep every round-trip test green and
/// still ship output LO rejects, and nothing in CI would notice, because CI
/// has no LibreOffice.
#[test]
fn s5_checked_in_evidence_still_decrypts_to_its_source_golden() {
    let evidence = load_golden("lo-opens-our-encrypt-output.odt");
    let source = load_golden("lo-unencrypted.odt");
    assert_eq!(
        classify(&evidence).expect("evidence classifies").mode,
        Mode::Wholesome
    );
    assert_eq!(
        decrypt(&evidence, PASSWORD).expect("evidence decrypts"),
        source,
        "tests/goldens/lo-opens-our-encrypt-output.odt must decrypt to \
         lo-unencrypted.odt byte-for-byte -- regenerate it with \
         tests/goldens/validate_encrypt.py if encrypt's framing changed"
    );
}

// --- mimetype guards (review finding: an unbounded, unvalidated copy) ---

/// `classify` admits a package after reading only the first 1024 bytes of its
/// `mimetype` member, so copying an unbounded member verbatim would be a side
/// door around `DEFLATE_CEILING` -- and a member over 8 MiB would push the
/// emitted manifest past `classify`'s own `MANIFEST_READ_CAP`, making output
/// this crate's own `decrypt` refuses.
#[test]
fn mimetype_over_ceiling_is_refused() {
    let mut mimetype = MIME_TEXT.as_bytes().to_vec();
    mimetype.resize(2048, b'x');
    let manifest = r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.4">
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>
"#;
    let input = zip_with_methods(&[
        ("mimetype", &mimetype, CompressionMethod::Deflated),
        (
            "META-INF/manifest.xml",
            manifest.as_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "content.xml",
            b"<office:document-content/>",
            CompressionMethod::Deflated,
        ),
    ]);

    // The fixture must be one classify itself accepts, or this proves nothing.
    assert_eq!(
        classify(&input).expect("fixture classifies").mode,
        Mode::Plain
    );
    let err = encrypt(&input, PASSWORD).unwrap_err();
    assert!(
        matches!(err, EncryptError::Mimetype(_)),
        "expected Mimetype, got {err:?}"
    );
}

/// A NUL in the media type is not an XML 1.0 `Char`. quick-xml escapes the
/// five markup characters and emits this one as-is, so copying it verbatim
/// would produce a manifest expat -- LibreOffice's own reader -- rejects,
/// discarding every row: a package that classifies here and will not open
/// there. Fail closed instead.
#[test]
fn mimetype_with_non_xml_char_is_refused() {
    let mut mimetype = MIME_TEXT.as_bytes().to_vec();
    mimetype.push(0);
    let manifest = r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.4">
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>
"#;
    let input = zip_with_methods(&[
        ("mimetype", &mimetype, CompressionMethod::Stored),
        (
            "META-INF/manifest.xml",
            manifest.as_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "content.xml",
            b"<office:document-content/>",
            CompressionMethod::Deflated,
        ),
    ]);

    assert_eq!(
        classify(&input).expect("fixture classifies").mode,
        Mode::Plain,
        "classify tolerates the NUL -- its check is starts_with(\"application/vnd.\")"
    );
    let err = encrypt(&input, PASSWORD).unwrap_err();
    assert!(
        matches!(err, EncryptError::Mimetype(_)),
        "expected Mimetype, got {err:?}"
    );
}

/// A trailing newline is a legal XML `Char`, so the check above lets it
/// through -- but XML 1.0 §3.3.3 attribute-value normalization turns it into a
/// space on the way back in, so the verbatim `mimetype` member and the parsed
/// `manifest:media-type` would disagree. Two things this crate writes that are
/// meant to say the same thing must not be able to diverge.
///
/// Measured before being refused, in both directions: `classify` only admits
/// such an input when its manifest declares no root media type (with one, the
/// mimetype-vs-manifest conflict check already rejects it), and real
/// LibreOffice cannot open a document of that shape *before* encryption
/// either. So no loadable file is affected -- but the divergence was real, and
/// the previous version of this test asserted it was correct.
#[test]
fn whitespace_unstable_mimetype_is_refused() {
    for (label, suffix) in [("newline", "\n"), ("tab", "\t"), ("carriage return", "\r")] {
        let mimetype = format!("{MIME_TEXT}{suffix}").into_bytes();
        let manifest = r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.4">
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>
"#;
        let input = zip_with_methods(&[
            ("mimetype", &mimetype, CompressionMethod::Stored),
            (
                "META-INF/manifest.xml",
                manifest.as_bytes(),
                CompressionMethod::Deflated,
            ),
            (
                "content.xml",
                b"<office:document-content/>",
                CompressionMethod::Deflated,
            ),
        ]);
        assert_eq!(
            classify(&input).expect("fixture classifies").mode,
            Mode::Plain,
            "{label}: classify tolerates it -- that is why encrypt has to not"
        );
        let err = encrypt(&input, PASSWORD).unwrap_err();
        assert!(
            matches!(err, EncryptError::Mimetype(_)),
            "{label}: expected Mimetype, got {err:?}"
        );
    }
}

/// The far side of the same guard: a `mimetype` that is unusual but attribute
/// stable is still copied verbatim, per plan §3 -- the guard must not have
/// narrowed the rule for real files.
#[test]
fn unusual_but_legal_mimetype_is_still_copied_verbatim() {
    // Not a media type any producer writes, but every byte survives an XML
    // attribute round trip unchanged, which is the only thing being asked.
    let mimetype = b"application/vnd.oasis.opendocument.text;version=1.4+odd".to_vec();
    let manifest = r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.4">
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>
"#;
    let input = zip_with_methods(&[
        ("mimetype", &mimetype, CompressionMethod::Stored),
        (
            "META-INF/manifest.xml",
            manifest.as_bytes(),
            CompressionMethod::Deflated,
        ),
        (
            "content.xml",
            b"<office:document-content/>",
            CompressionMethod::Deflated,
        ),
    ]);
    assert_eq!(
        classify(&input).expect("fixture classifies").mode,
        Mode::Plain
    );

    let out = encrypt(&input, PASSWORD).expect("encrypt");
    assert_eq!(
        read_member(&out, "mimetype"),
        mimetype,
        "an attribute-stable mimetype is the input's own bytes, copied, not re-derived"
    );
    // And the attribute agrees with the member, which is the property the
    // whitespace refusal above exists to preserve.
    let mf = check_manifest(&read_member(&out, "META-INF/manifest.xml"));
    assert_eq!(
        mf.media_type.as_deref(),
        Some(std::str::from_utf8(&mimetype).unwrap()),
        "the parsed attribute must equal the verbatim member bytes"
    );
    assert_eq!(decrypt(&out, PASSWORD).expect("decrypt"), input);
}

/// N1: this arc's start key is SHA-256 over UTF-8, and nothing exercised it
/// with a non-ASCII password -- `NONASCII_PASSWORD` existed only for decrypt's
/// SHA-1 story (OQ1). A byte-identical round trip pins that the write side
/// hashes the same UTF-8 bytes the read side does.
#[test]
fn round_trip_under_a_non_ascii_password() {
    let original = load_golden("lo-unencrypted.odt");
    let encrypted = encrypt(&original, NONASCII_PASSWORD).expect("encrypt");
    assert_eq!(
        decrypt(&encrypted, NONASCII_PASSWORD).expect("decrypt"),
        original
    );
    // And the ASCII password must not open it, which would mean the non-ASCII
    // bytes never reached the digest.
    assert!(matches!(
        decrypt(&encrypted, PASSWORD).unwrap_err(),
        DecryptError::WrongPassword
    ));
}

/// N2: `DEFLATE_CEILING` had no test -- reaching the real 1 GiB bound would
/// mean allocating a gigabyte, so the ceiling is a parameter of the inner
/// helper and this exercises the rejection at a size that costs nothing.
#[test]
fn deflate_ceiling_refuses_an_oversized_buffer() {
    let buf = vec![0u8; 4096];
    assert!(
        crate::encrypt::raw_deflate_with_ceiling(&buf, 8192).is_ok(),
        "under the ceiling must compress"
    );
    let err = crate::encrypt::raw_deflate_with_ceiling(&buf, 1024).unwrap_err();
    match err {
        EncryptError::Deflate(msg) => {
            assert!(
                msg.contains("4096") && msg.contains("1024"),
                "message: {msg}"
            )
        }
        other => panic!("expected Deflate, got {other:?}"),
    }
}

#[test]
fn s3_round_trip_byte_identical_nontrivial_fixture() {
    let original = nontrivial_plain_fixture();

    // Pin that this fixture actually exercises the arc: a package `classify`
    // would already reject on its own would make the round-trip below
    // vacuously pass for the wrong reason.
    let before = classify(&original).expect("fixture classifies");
    assert_eq!(before.mode, Mode::Plain, "fixture must be Mode::Plain");
    assert!(before.encrypted_entries.is_empty());

    let encrypted = encrypt(&original, PASSWORD).expect("encrypt");
    let round_tripped = decrypt(&encrypted, PASSWORD).expect("decrypt");
    assert_eq!(
        round_tripped, original,
        "decrypt(encrypt(p, pw), pw) must be byte-identical to p"
    );
}

// --- Caller-chosen Argon2 cost ---

#[test]
fn default_params_match_what_encrypt_writes_on_its_own() {
    // `encrypt` delegates to `encrypt_with_params` with LIBREOFFICE_DEFAULT.
    // If those two ever disagree, every other test here keeps passing while
    // the plain `encrypt` silently changes profile -- so pin the tuple against
    // the manifest of a package `encrypt` actually produced.
    let sealed = encrypt(&load_golden("lo-unencrypted.odt"), PASSWORD).expect("encrypt");
    let row = classify(&sealed)
        .expect("classify")
        .common
        .expect("latch row");
    let d = Argon2Params::LIBREOFFICE_DEFAULT;
    assert_eq!((d.t(), d.m_kib(), d.p()), (3, 65536, 4));
    assert!(
        matches!(row.kdf, Kdf::Argon2id { t, m, p, .. } if (t, m, p) == (d.t(), d.m_kib(), d.p())),
        "encrypt() must write LIBREOFFICE_DEFAULT, got {:?}",
        row.kdf
    );
}

#[test]
fn caller_params_reach_both_the_manifest_and_the_derivation() {
    // The manifest could agree with the caller while the key was derived from
    // something else -- a file that decrypts here and nowhere else. The round
    // trip alone would not catch it, because decrypt reads the manifest's
    // copy. So assert the manifest says what was asked for AND that the
    // package still round-trips, which together pin both halves.
    let plain = load_golden("lo-unencrypted.odt");
    let params = Argon2Params::new(2, 8192, 2).expect("valid tuple");
    let sealed = encrypt_with_params(&plain, PASSWORD, params).expect("encrypt");

    let row = classify(&sealed)
        .expect("classify")
        .common
        .expect("latch row");
    assert!(
        matches!(
            row.kdf,
            Kdf::Argon2id {
                t: 2,
                m: 8192,
                p: 2,
                ..
            }
        ),
        "manifest must record the caller's tuple, got {:?}",
        row.kdf
    );
    assert_eq!(
        decrypt(&sealed, PASSWORD).expect("decrypt"),
        plain,
        "a package derived at a caller-chosen cost must still round-trip"
    );
}

#[test]
fn weak_but_runnable_params_are_accepted() {
    // The project rule: warn, never block. A tuple argon2 can run is written,
    // however weak -- this is the lowest the crate's own bounds allow.
    let params = Argon2Params::new(1, 8, 1).expect("m = 8 * p exactly, argon2's floor");
    assert!(params.is_weaker_than_libreoffice());
    let plain = load_golden("lo-unencrypted.odt");
    let sealed = encrypt_with_params(&plain, PASSWORD, params).expect("weak must not be refused");
    assert_eq!(decrypt(&sealed, PASSWORD).expect("decrypt"), plain);
}

#[test]
fn the_refusal_reason_names_whose_rule_it_was() {
    // The point of the typed reason, and the thing a String could not carry:
    // a consumer must be able to tell "the format forbids this" from "this
    // crate declined". Reporting our own policy bound as a rule of argon2 or
    // of ODF would be a lie a consumer renders as authoritative.
    //
    // OURS: the ODF manifest schema types these as unbounded positiveInteger
    // and LibreOffice checks only `0 < t`, so nothing but this crate refuses
    // a large t.
    match Argon2Params::new(i32::MAX, 65536, 4) {
        Err(EncryptError::Params(ParamsReason::OutOfRange { axis, got, .. })) => {
            assert_eq!(axis, Argon2Axis::T);
            assert_eq!(got, i32::MAX);
        }
        other => panic!("expected OutOfRange on t, got {other:?}"),
    }

    // ARGON2'S: m >= 8p is the KDF's own requirement. Widening our range
    // would not make this tuple runnable, and saying "outside the range this
    // crate acts on" would point the caller at the wrong fix.
    match Argon2Params::new(3, 8, 4) {
        Err(EncryptError::Params(ParamsReason::CipherRejects { axis, got, min, .. })) => {
            assert_eq!(axis, Argon2Axis::MKib);
            assert_eq!(got, 8);
            assert_eq!(min, 32, "8 * p");
        }
        other => panic!("expected CipherRejects on m, got {other:?}"),
    }

    // The Display text carries the attribution too, since that is what a
    // consumer without a match arm will render.
    let ours = Argon2Params::new(0, 65536, 4).unwrap_err().to_string();
    assert!(ours.contains("this crate acts on"), "{ours}");
    let theirs = Argon2Params::new(3, 8, 4).unwrap_err().to_string();
    assert!(theirs.contains("argon2 itself requires"), "{theirs}");
}

#[test]
fn params_are_refused_only_when_argon2_cannot_run_them() {
    // m < 8p is argon2's own requirement, not a policy of ours.
    assert!(matches!(
        Argon2Params::new(3, 8, 4),
        Err(EncryptError::Params(_))
    ));
    // Zero and negative are outside the supported range in both directions.
    assert!(matches!(
        Argon2Params::new(0, 65536, 4),
        Err(EncryptError::Params(_))
    ));
    assert!(matches!(
        Argon2Params::new(3, -1, 4),
        Err(EncryptError::Params(_))
    ));
    // ... but m = 8p exactly is the boundary and must be allowed, or the
    // check is off by one in the direction that blocks a legal tuple.
    assert!(Argon2Params::new(1, 32, 4).is_ok());
}

#[test]
fn is_weaker_is_any_axis_below_not_a_strength_ordering() {
    // Raised by the encrypted-file-vault integration, whose worked example was
    // `(4, 65536, 4)` -- claimed to report weaker. It does not; the assertion
    // below is what that case actually does. But the concern underneath it is
    // real and the second case is where it bites: one fewer pass against twice
    // the memory reports weaker, and is not obviously weaker at all.
    //
    // That is deliberate -- it is below the reference on an axis and a caller
    // deserves to be told before it is frozen into a document -- so this test
    // pins the semantics rather than the intuition, because the two differ.
    let stronger_t = Argon2Params::new(4, 65536, 4).unwrap();
    assert!(
        !stronger_t.is_weaker_than_libreoffice(),
        "stronger on t, identical elsewhere, must not report weaker"
    );

    let fewer_passes_double_memory = Argon2Params::new(2, 131_072, 4).unwrap();
    assert!(
        fewer_passes_double_memory.is_weaker_than_libreoffice(),
        "any axis below the reference reports weaker, even when another is well above"
    );
}

#[test]
fn is_weaker_than_libreoffice_reports_but_does_not_gate() {
    assert!(!Argon2Params::LIBREOFFICE_DEFAULT.is_weaker_than_libreoffice());
    // Weaker on any single axis counts.
    assert!(Argon2Params::new(2, 65536, 4)
        .unwrap()
        .is_weaker_than_libreoffice());
    assert!(Argon2Params::new(3, 8192, 4)
        .unwrap()
        .is_weaker_than_libreoffice());
    assert!(Argon2Params::new(3, 65536, 2)
        .unwrap()
        .is_weaker_than_libreoffice());
    // Stronger is not "weaker".
    assert!(!Argon2Params::new(4, 131_072, 4)
        .unwrap()
        .is_weaker_than_libreoffice());
}

// --- #67: the Argon2 memory policy cap is gone ------------------------------

/// **The tuple the old `1 << 20` cap refused**, and the reason it went.
///
/// RFC 9106 §4 names `t=1, p=4, m=2^21` (2 GiB) as its **first recommended**
/// option. 2 GiB is twice the old ceiling, so a caller following the RFC to the
/// letter got [`ParamsReason::OutOfRange`] — this crate's own policy refusing a
/// tuple the specification recommends and LibreOffice would write and read.
///
/// Constructing the parameters allocates nothing; only `encrypt_with_params`
/// would, and this deliberately does not call it.
#[test]
fn rfc9106_first_recommended_tuple_is_accepted() {
    let p = Argon2Params::new(1, 2_097_152, 4).expect("RFC 9106 §4 first recommended option");
    assert_eq!(p.t(), 1);
    assert_eq!(p.m_kib(), 2_097_152);
    assert_eq!(p.p(), 4);
}

/// The RFC's larger examples too, since "raise the cap to 2 GiB" was the
/// obvious fix and would have refused these.
#[test]
fn the_rfcs_larger_examples_are_accepted_as_well() {
    // 4 GiB and 6 GiB -- the RFC's own further examples. An earlier draft of
    // this test used 1 << 23 (8 GiB), which is not a figure the RFC gives; the
    // citation in `limits.rs` said 4 and 6 while the test said 4 and 8.
    for m_kib in [1 << 22, 6 * 1024 * 1024] {
        assert!(
            Argon2Params::new(1, m_kib, 4).is_ok(),
            "m = {m_kib} KiB must not be refused by a bound of ours"
        );
    }
}

/// The ceiling that remains is the manifest field's own width, not a number of
/// ours — so nothing expressible in a package is refused for being too large.
#[test]
fn the_remaining_memory_ceiling_is_the_field_width() {
    assert_eq!(
        crate::limits::ARGON2_MAX_M_COST_KIB_WRITE,
        i32::MAX as u32,
        "the write ceiling must BE the field width, not merely be at least it --          `limits.rs` justifies keeping the check by the range an error reports"
    );
    assert!(
        Argon2Params::new(1, i32::MAX, 4).is_ok(),
        "and nothing of ours may sit below it"
    );
}

/// What still refuses, and **whose rule it is** — the distinction
/// [`ParamsReason`] exists for. Neither of these is a policy cap.
#[test]
fn what_refuses_a_memory_value_now_is_the_cipher_or_the_format() {
    // The cipher: argon2 needs 8 KiB per lane, so `m >= 8p`.
    let err = Argon2Params::new(1, 8, 4).expect_err("m = 8 with p = 4 is below argon2's own floor");
    assert!(
        matches!(
            err,
            EncryptError::Params(ParamsReason::CipherRejects {
                axis: Argon2Axis::MKib,
                ..
            })
        ),
        "argon2's own requirement must not be reported as ours, got {err:?}"
    );

    // The format: `positiveInteger`, and LibreOffice checks `0 < m`.
    let err = Argon2Params::new(1, 0, 1).expect_err("zero is not a positive integer");
    assert!(
        matches!(
            err,
            EncryptError::Params(ParamsReason::OutOfRange {
                axis: Argon2Axis::MKib,
                ..
            })
        ),
        "got {err:?}"
    );
    let err = Argon2Params::new(1, -1, 1).expect_err("negative is not a positive integer");
    assert!(matches!(
        err,
        EncryptError::Params(ParamsReason::OutOfRange { .. })
    ));
}

// --- #69: the `t` ceiling stays, and now does more work ---------------------

/// `ARGON2_MAX_T_COST` is kept deliberately, and #67 is why it matters more
/// than it did: argon2's cost is roughly `t × m`, and `m` is now bounded only
/// by the host. Uncapping both is the hang.
///
/// Nothing legitimate reaches it — RFC 9106 recommends `t` of 1 or 3, OWASP
/// 1–5, LibreOffice writes 3 — which is the argument for leaving it where it
/// is rather than minting a tighter number nobody measured.
#[test]
fn the_t_ceiling_still_refuses_the_expensive_direction() {
    assert!(
        Argon2Params::new(3, 65536, 4).is_ok(),
        "LibreOffice's own tuple must pass"
    );
    // Literals, not `ARGON2_MAX_T_COST`. Reading the constant to build both the
    // accept and the reject case makes the test self-referential: it would pass
    // at 32, at 4, at anything. #69's decision was specifically NOT to lower it,
    // so the test has to pin the value, which means naming it.
    assert_eq!(crate::limits::ARGON2_MAX_T_COST, 65_536);
    assert!(
        Argon2Params::new(65_536, 65536, 4).is_ok(),
        "the ceiling itself is inclusive"
    );
    let err = Argon2Params::new(65_537, 65536, 4).expect_err("one past the ceiling is refused");
    assert!(
        matches!(
            err,
            EncryptError::Params(ParamsReason::OutOfRange {
                axis: Argon2Axis::T,
                ..
            })
        ),
        "and it is reported as OURS, because it is: {err:?}"
    );
}

// --- CLI exit-code tripwire (#40) ----------------------------------------

/// Every [`EncryptError`] variant has an exit code assigned in `src/bin/odf-crypto.rs`
/// -- approximated by "every variant is named in the match below", because the
/// real property is not observable from where the mapping lives.
///
/// The binary is a separate crate from this one, and [`EncryptError`] is
/// `#[non_exhaustive]`, so rustc *requires* `encrypt_exit` to carry a `_` arm.
/// A variant added tomorrow compiles, falls through that arm, and silently
/// becomes EX_MALFORMED -- which is the whole of #40. A canary written beside
/// the mapping inherits the same `_` arm and cannot catch it either; measured,
/// not assumed (E0004: "`odf_crypto::EncryptError` is marked as non-exhaustive, so a
/// wildcard `_` is necessary to match exhaustively").
///
/// Inside the defining crate the attribute does not apply, so this match needs
/// no `_` arm and does not have one. That is the entire mechanism.
///
/// **If this stopped compiling, you added a variant.** Give it an exit code in
/// `encrypt_exit`, add it to `the_encrypt_exit_map_is_the_documented_one` in `src/bin/odf-crypto_tests.rs`, then name
/// it here.
///
/// It maps to `()` deliberately. A number here would be a second copy of the
/// mapping, free to drift from the one the binary actually runs: this half
/// checks that every variant is *considered*, the binary's half checks that
/// each one is *right*.
#[test]
fn every_encrypt_error_variant_is_accounted_for_in_the_cli_exit_map() {
    fn accounted_for(e: &EncryptError) {
        match e {
            EncryptError::Classify(_) => (),
            EncryptError::AlreadyEncrypted => (),
            EncryptError::PartiallyEncrypted => (),
            EncryptError::Odf12Fatal => (),
            EncryptError::EmptyPassword => (),
            EncryptError::Random(_) => (),
            EncryptError::Params(_) => (),
            EncryptError::HostCannotAllocate { .. } => (),
            EncryptError::Deflate(_) => (),
            EncryptError::Mimetype(_) => (),
            EncryptError::Zip(_) => (),
            EncryptError::Internal(_) => (),
        }
    }
    accounted_for(&EncryptError::AlreadyEncrypted);
}
