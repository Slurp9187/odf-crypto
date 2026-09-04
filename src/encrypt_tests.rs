//! Encrypt arc tests (issues #19-#23).

use zip::CompressionMethod;

use crate::classify::classify;
use crate::decrypt::{decrypt, DecryptError};
use crate::encrypt::{encrypt, EncryptError};
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

/// A PGP package is `Mode::PerEntry`, so `AlreadyEncrypted` covers it -- the
/// same refusal, reached without `encrypt` needing a PGP notion of its own
/// (plan §4: `AlreadyEncrypted` "covers PerEntry, Wholesome, and PGP rows
/// alike"). Nothing pinned that claim.
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
