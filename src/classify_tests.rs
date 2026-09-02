//! Constructed zip+manifest fixtures for S1–S5, plus real-file goldens (S6).

use super::*;
use crate::manifest::parse_manifest_for_test;
use crate::uris;
use std::io::{Cursor, Write};
use std::path::PathBuf;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const B64: &str = "AQIDBA==";
const MIME_TEXT: &str = "application/vnd.oasis.opendocument.text";
const MIME_WRONG: &str = "text/plain";

fn zip_with(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in files {
        let method = if *name == "mimetype" {
            CompressionMethod::Stored
        } else {
            CompressionMethod::Deflated
        };
        zip.start_file(
            *name,
            SimpleFileOptions::default().compression_method(method),
        )
        .unwrap();
        zip.write_all(data).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn manifest_wrap(package_version: Option<&str>, body: &str) -> String {
    let ver = match package_version {
        Some(v) => format!(" manifest:version=\"{v}\""),
        None => String::new(),
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" xmlns:loext="urn:org:documentfoundation:names:experimental:office:xmlns:loext:1.0"{ver}>
{body}
</manifest:manifest>
"#
    )
}

struct PwOpts<'a> {
    path: &'a str,
    media_type: &'a str,
    size: Option<i64>,
    cipher: &'a str,
    checksum: bool,
    start_key: Option<&'a str>,
    kdf: &'a str,
    iteration_count: Option<i32>,
    key_size: Option<i32>,
    argon2: Option<(i32, i32, i32)>,
    kdf_before_algorithm: bool,
}

impl Default for PwOpts<'_> {
    fn default() -> Self {
        Self {
            path: "content.xml",
            media_type: "text/xml",
            size: Some(100),
            cipher: uris::AES256_URL,
            checksum: true,
            start_key: Some(uris::SHA1_NAME),
            kdf: uris::PBKDF2_NAME,
            iteration_count: Some(1024),
            key_size: Some(32),
            argon2: None,
            kdf_before_algorithm: false,
        }
    }
}

fn file_entry(opts: PwOpts<'_>) -> String {
    let size = match opts.size {
        Some(n) => format!(" manifest:size=\"{n}\""),
        None => String::new(),
    };
    let checksum = if opts.checksum {
        format!(
            " manifest:checksum-type=\"{}\" manifest:checksum=\"{B64}\"",
            uris::SHA1_1K_NAME
        )
    } else {
        String::new()
    };
    let algorithm = format!(
        r#"  <manifest:algorithm manifest:algorithm-name="{}" manifest:initialisation-vector="{B64}"/>"#,
        opts.cipher
    );
    let start_key = match opts.start_key {
        Some(name) => format!(
            r#"  <manifest:start-key-generation manifest:start-key-generation-name="{name}"/>"#
        ),
        None => String::new(),
    };
    let key_size = match opts.key_size {
        Some(n) => format!(" manifest:key-size=\"{n}\""),
        None => String::new(),
    };
    let kdf = if let Some((t, m, p)) = opts.argon2 {
        format!(
            r#"  <manifest:key-derivation manifest:key-derivation-name="{kdf}" manifest:salt="{B64}" manifest:argon2-iterations="{t}" manifest:argon2-memory="{m}" manifest:argon2-lanes="{p}"{key_size}/>"#,
            kdf = opts.kdf,
        )
    } else {
        let count = match opts.iteration_count {
            Some(n) => format!(" manifest:iteration-count=\"{n}\""),
            None => String::new(),
        };
        format!(
            r#"  <manifest:key-derivation manifest:key-derivation-name="{kdf}" manifest:salt="{B64}"{count}{key_size}/>"#,
            kdf = opts.kdf,
        )
    };
    let children = if opts.kdf_before_algorithm {
        format!("{kdf}\n{start_key}\n{algorithm}")
    } else {
        format!("{algorithm}\n{start_key}\n{kdf}")
    };
    format!(
        r#" <manifest:file-entry manifest:full-path="{path}" manifest:media-type="{mt}"{size}>
  <manifest:encryption-data{checksum}>
{children}
  </manifest:encryption-data>
 </manifest:file-entry>
"#,
        path = opts.path,
        mt = opts.media_type,
    )
}

fn root_row(version: &str, media_type: &str) -> String {
    format!(
        r#" <manifest:file-entry manifest:full-path="/" manifest:version="{version}" manifest:media-type="{media_type}"/>
"#
    )
}

fn plain_row(path: &str, media_type: &str) -> String {
    format!(
        r#" <manifest:file-entry manifest:full-path="{path}" manifest:media-type="{media_type}"/>
"#
    )
}

fn classify_pkg(manifest: &str, files: &[(&str, &[u8])]) -> Classification {
    let mut all = vec![("META-INF/manifest.xml", manifest.as_bytes())];
    all.extend_from_slice(files);
    classify(&zip_with(&all)).expect("constructed package should classify")
}

const UNENCRYPTED_MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">
 <manifest:file-entry manifest:full-path="/" manifest:version="1.3" manifest:media-type="application/vnd.oasis.opendocument.text"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
 <manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml"/>
 <manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/>
 <manifest:file-entry manifest:full-path="settings.xml" manifest:media-type="text/xml"/>
</manifest:manifest>
"#;

const CONTENT_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" office:version="1.3">
 <office:body>
  <office:text>
   <text:p>Hello</text:p>
  </office:text>
 </office:body>
</office:document-content>
"#;

const STYLES_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-styles xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" office:version="1.3"/>
"#;

const META_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" office:version="1.3"/>
"#;

const SETTINGS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-settings xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" office:version="1.3"/>
"#;

fn unencrypted_odt() -> Vec<u8> {
    zip_with(&[
        ("mimetype", MIME_TEXT.as_bytes()),
        ("META-INF/manifest.xml", UNENCRYPTED_MANIFEST.as_bytes()),
        ("content.xml", CONTENT_XML.as_bytes()),
        ("styles.xml", STYLES_XML.as_bytes()),
        ("meta.xml", META_XML.as_bytes()),
        ("settings.xml", SETTINGS_XML.as_bytes()),
    ])
}

/// First file-entry gets KeyInfo; `styles.xml` has no encrypted-key of its own.
fn pgp_two_row_manifest() -> String {
    format!(
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
    )
}

fn pgp_two_row_zip() -> Vec<u8> {
    let manifest = pgp_two_row_manifest();
    zip_with(&[
        ("mimetype", MIME_TEXT.as_bytes()),
        ("META-INF/manifest.xml", manifest.as_bytes()),
        ("content.xml", b"encrypted-content"),
        ("styles.xml", b"encrypted-styles"),
    ])
}

/// Issue #2 close-when 1 / plan §7 S1. A real LibreOffice `.odt`: `mimetype`
/// stored first, an explicit `Configurations2/` directory entry, an implicit
/// `Thumbnails/` folder with no directory entry of its own, and every stream
/// listed in the manifest. This is the only fixture that runs the non-wholesome
/// unexpected-stream scan over a member set a producer actually writes.
#[test]
fn classify_real_unencrypted_odt_is_plain() {
    let class = classify(&load_golden("lo-unencrypted.odt")).expect("real unencrypted");
    assert_eq!(class.mode, Mode::Plain);
    assert!(!class.package_encrypted);
    assert!(class.common.is_none());
    assert!(class.encrypted_entries.is_empty());
    assert!(!class.zip_has_encrypted_package);
    // Root row carries both; no mimetype fallback is needed.
    assert_eq!(class.odf_version.as_deref(), Some("1.4"));
    assert_eq!(class.media_type.as_deref(), Some(MIME_TEXT));
    // Every stream is in the manifest, so the scan stays quiet even though the
    // root version is >= 1.2 and would make an unlisted stream fatal.
    assert!(!class.has_unexpected_streams);
    assert!(!class.odf12_fatal);
}

#[test]
fn classify_unencrypted_odt_is_plain() {
    let bytes = unencrypted_odt();
    let class = classify(&bytes).expect("unencrypted ODT should classify");
    assert_eq!(class.mode, Mode::Plain);
    assert!(!class.package_encrypted);
    assert!(class.encrypted_entries.is_empty());
    assert!(class.common.is_none());
    assert!(!class.zip_has_encrypted_package);
    assert!(!class.has_unexpected_streams);
    assert!(!class.odf12_fatal);
}

#[test]
fn pgp_two_row_key_info_leaks_to_styles() {
    let xml = pgp_two_row_manifest();
    let bags = parse_manifest_for_test(&xml);
    assert_eq!(bags.len(), 2, "two file-entry bags");
    assert!(bags[0].key_info.is_some(), "first entry carries KeyInfo");
    assert!(
        bags[1].key_info.is_none(),
        "second entry has no KeyInfo of its own"
    );
    assert_eq!(bags[0].full_path, "content.xml");
    assert_eq!(bags[1].full_path, "styles.xml");
    assert_eq!(bags[0].kdf, Some(KdfId::PgpRsaOaepMgf1p));
    assert_eq!(bags[1].kdf, Some(KdfId::PgpRsaOaepMgf1p));

    let class = classify(&pgp_two_row_zip()).expect("constructed PGP zip should classify");
    assert_eq!(class.encrypted_entries.len(), 2);
    assert!(
        class
            .encrypted_entries
            .iter()
            .any(|e| e.path == "styles.xml" && matches!(e.kdf, Kdf::PgpRsaOaepMgf1p)),
        "styles.xml satisfies the PGP predicate because of sticky key_info"
    );
    assert!(class
        .encrypted_entries
        .iter()
        .any(|e| e.path == "content.xml" && matches!(e.kdf, Kdf::PgpRsaOaepMgf1p)));
    assert_eq!(class.mode, Mode::PerEntry);
    assert!(class.package_encrypted);
    assert_eq!(
        class.common.as_ref().map(|e| e.path.as_str()),
        Some("content.xml")
    );
}

// --- S2: accept predicates, first-wins latch, constructed fixtures ---

enum S2Expect {
    Plain,
    PerEntryLatch { check: fn(&EntryEncryption) },
}

fn s2_min_zip() -> [(&'static str, &'static [u8]); 2] {
    [("mimetype", MIME_TEXT.as_bytes()), ("content.xml", b"x")]
}

#[test]
fn s2_accept_predicate_fixtures() {
    struct Row {
        name: &'static str,
        body: String,
        expect: S2Expect,
        pre: Option<fn(&str)>,
    }

    let rows = [
        Row {
            name: "missing manifest:size",
            body: format!(
                "{}{}",
                root_row("1.2", MIME_TEXT),
                file_entry(PwOpts {
                    size: None,
                    ..PwOpts::default()
                })
            ),
            expect: S2Expect::Plain,
            pre: None,
        },
        Row {
            name: "GCM without checksum",
            body: format!(
                "{}{}",
                root_row("1.2", MIME_TEXT),
                file_entry(PwOpts {
                    cipher: uris::AESGCM256_URL,
                    checksum: false,
                    ..PwOpts::default()
                })
            ),
            expect: S2Expect::PerEntryLatch {
                check: |e| {
                    assert_eq!(e.cipher, Cipher::AesGcmW3c);
                    assert_eq!(e.checksum, Checksum::None);
                },
            },
            pre: None,
        },
        Row {
            name: "CBC without checksum",
            body: format!(
                "{}{}",
                root_row("1.2", MIME_TEXT),
                file_entry(PwOpts {
                    checksum: false,
                    ..PwOpts::default()
                })
            ),
            expect: S2Expect::Plain,
            pre: None,
        },
        Row {
            name: "Argon2 t=0",
            body: format!(
                "{}{}",
                root_row("1.2", MIME_TEXT),
                file_entry(PwOpts {
                    cipher: uris::AESGCM256_URL,
                    checksum: false,
                    kdf: uris::ARGON2ID_URL,
                    argon2: Some((0, 65536, 4)),
                    iteration_count: None,
                    ..PwOpts::default()
                })
            ),
            expect: S2Expect::Plain,
            pre: Some(|xml| {
                let bags = parse_manifest_for_test(xml);
                let content = bags
                    .iter()
                    .find(|b| b.full_path == "content.xml")
                    .expect("content row");
                assert_eq!(content.kdf, Some(KdfId::Argon2id));
                assert!(content.argon2_args.is_none());
            }),
        },
        Row {
            name: "missing start-key",
            body: format!(
                "{}{}",
                root_row("1.2", MIME_TEXT),
                file_entry(PwOpts {
                    start_key: None,
                    ..PwOpts::default()
                })
            ),
            expect: S2Expect::PerEntryLatch {
                check: |e| assert_eq!(e.start_key, StartKeyAlg::Sha1),
            },
            pre: None,
        },
        Row {
            name: "unknown cipher URI",
            body: format!(
                "{}{}",
                root_row("1.2", MIME_TEXT),
                file_entry(PwOpts {
                    cipher: "not-a-cipher",
                    ..PwOpts::default()
                })
            ),
            expect: S2Expect::Plain,
            pre: None,
        },
        Row {
            name: "KDF before algorithm, aes256-cbc, no key-size",
            body: format!(
                "{}{}",
                root_row("1.2", MIME_TEXT),
                file_entry(PwOpts {
                    cipher: uris::AES256_URL,
                    key_size: None,
                    kdf_before_algorithm: true,
                    ..PwOpts::default()
                })
            ),
            expect: S2Expect::PerEntryLatch {
                check: |e| {
                    assert_eq!(e.cipher, Cipher::AesCbcW3c);
                    assert_eq!(e.derived_key_len, 16);
                    assert_eq!(e.size, 100);
                    assert_eq!(e.iv, vec![1, 2, 3, 4]);
                },
            },
            pre: None,
        },
        Row {
            name: "algorithm before KDF, aes256-cbc, no key-size",
            body: format!(
                "{}{}",
                root_row("1.2", MIME_TEXT),
                file_entry(PwOpts {
                    cipher: uris::AES256_URL,
                    key_size: None,
                    ..PwOpts::default()
                })
            ),
            expect: S2Expect::PerEntryLatch {
                check: |e| assert_eq!(e.derived_key_len, 32),
            },
            pre: None,
        },
        Row {
            name: "algorithm before KDF, aes192-gcm, no key-size",
            body: format!(
                "{}{}",
                root_row("1.2", MIME_TEXT),
                file_entry(PwOpts {
                    cipher: uris::AESGCM192_URL,
                    checksum: false,
                    key_size: None,
                    ..PwOpts::default()
                })
            ),
            expect: S2Expect::PerEntryLatch {
                check: |e| {
                    assert_eq!(e.cipher, Cipher::AesGcmW3c);
                    assert_eq!(e.derived_key_len, 24);
                },
            },
            pre: None,
        },
        Row {
            name: "key-size 256 is sal_Int32 not u8",
            body: format!(
                "{}{}",
                root_row("1.2", MIME_TEXT),
                file_entry(PwOpts {
                    key_size: Some(256),
                    ..PwOpts::default()
                })
            ),
            expect: S2Expect::PerEntryLatch {
                check: |e| assert_eq!(e.derived_key_len, 256),
            },
            pre: None,
        },
        Row {
            name: "argon2 iterations +3",
            body: format!(
                "{}{}",
                root_row("1.2", MIME_TEXT),
                file_entry(PwOpts {
                    cipher: uris::AESGCM256_URL,
                    checksum: false,
                    kdf: uris::ARGON2ID_URL,
                    argon2: Some((3, 65536, 4)),
                    iteration_count: None,
                    ..PwOpts::default()
                })
                .replace(
                    "manifest:argon2-iterations=\"3\"",
                    "manifest:argon2-iterations=\"+3\""
                )
            ),
            expect: S2Expect::PerEntryLatch {
                check: |e| match &e.kdf {
                    Kdf::Argon2id { t, m, p, .. } => {
                        assert_eq!((*t, *m, *p), (3, 65536, 4));
                    }
                    other => panic!("{other:?}"),
                },
            },
            pre: None,
        },
        Row {
            name: "missing iteration-count, PBKDF2",
            body: format!(
                "{}{}",
                root_row("1.2", MIME_TEXT),
                file_entry(PwOpts {
                    iteration_count: None,
                    ..PwOpts::default()
                })
            ),
            expect: S2Expect::PerEntryLatch {
                check: |e| match &e.kdf {
                    Kdf::Pbkdf2 { iterations, .. } => assert_eq!(*iterations, 0),
                    other => panic!("expected PBKDF2 with 0 iterations, got {other:?}"),
                },
            },
            pre: None,
        },
        Row {
            name: "slash file-entry applies root version and media-type",
            body: format!(
                "{}{}",
                root_row("1.2", MIME_TEXT),
                file_entry(PwOpts::default())
            ),
            expect: S2Expect::PerEntryLatch { check: |_| {} },
            pre: None,
        },
    ];

    for row in rows {
        let manifest = manifest_wrap(Some("1.2"), &row.body);
        if let Some(pre) = row.pre {
            pre(&manifest);
        }
        let class = classify_pkg(&manifest, &s2_min_zip());
        match row.expect {
            S2Expect::Plain => {
                assert_eq!(class.mode, Mode::Plain, "{}", row.name);
                assert!(!class.package_encrypted, "{}", row.name);
                assert!(class.encrypted_entries.is_empty(), "{}", row.name);
            }
            S2Expect::PerEntryLatch { check } => {
                assert_eq!(class.mode, Mode::PerEntry, "{}", row.name);
                assert!(class.package_encrypted, "{}", row.name);
                let entry = class.common.as_ref().expect(row.name);
                check(entry);
                if row.name == "slash file-entry applies root version and media-type" {
                    assert_eq!(class.odf_version.as_deref(), Some("1.2"));
                    assert_eq!(class.media_type.as_deref(), Some(MIME_TEXT));
                }
            }
        }
    }
}

/// Issue #3 row 10 / plan F11. The resolution itself is pinned directly by
/// `zip_tree::tests::implicit_folder_from_member_path` (a `Pictures/` lookup
/// returns `Folder` with no directory entry in the zip) and, at this layer, by
/// `pictures_folder_row_poisons_nested_content_xml_onto_root`, where the row has
/// to resolve for the A10 cache write to happen at all. What this fixture adds
/// is the surrounding package: a folder synthesized purely from a member path
/// does not disturb the scan, and the unlisted `Pictures/photo.png` under it is
/// still reported.
#[test]
fn s2_pictures_folder_resolves_without_zip_dir_entry() {
    let body = format!(
        "{}{}{}",
        root_row("1.2", MIME_TEXT),
        plain_row("Pictures/", "application/vnd.oasis.opendocument.text"),
        file_entry(PwOpts::default())
    );
    let bytes = zip_with(&[
        ("mimetype", MIME_TEXT.as_bytes()),
        (
            "META-INF/manifest.xml",
            manifest_wrap(Some("1.2"), &body).as_bytes(),
        ),
        ("content.xml", b"x"),
        ("Pictures/photo.png", b"png"),
    ]);
    let names: Vec<String> = {
        let mut archive = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
        (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect()
    };
    assert!(
        !names.iter().any(|n| n == "Pictures/" || n == "Pictures"),
        "fixture must not include an explicit Pictures/ zip directory entry"
    );
    let class = classify(&bytes).expect("Pictures/ row must resolve");
    assert_eq!(class.mode, Mode::PerEntry);
    assert_eq!(class.odf_version.as_deref(), Some("1.2"));
    assert!(
        class.has_unexpected_streams,
        "Pictures/photo.png is in the zip but not the manifest"
    );
}

#[test]
fn s2_first_wins_latch_encrypted_package_before_content() {
    let body = format!(
        "{}{}{}",
        file_entry(PwOpts {
            path: "encrypted-package",
            media_type: MIME_TEXT,
            ..PwOpts::default()
        }),
        file_entry(PwOpts::default()),
        root_row("1.2", MIME_TEXT)
    );
    let class = classify_pkg(
        &manifest_wrap(Some("1.2"), &body),
        &[
            ("mimetype", MIME_TEXT.as_bytes()),
            ("encrypted-package", b"inner"),
            ("content.xml", b"x"),
        ],
    );
    assert_eq!(class.mode, Mode::Wholesome);
    assert_eq!(
        class.common.as_ref().map(|e| e.path.as_str()),
        Some("encrypted-package")
    );
}

#[test]
fn s2_first_wins_latch_content_before_encrypted_package() {
    let body = format!(
        "{}{}",
        file_entry(PwOpts::default()),
        file_entry(PwOpts {
            path: "encrypted-package",
            media_type: MIME_TEXT,
            ..PwOpts::default()
        })
    );
    let class = classify_pkg(
        &manifest_wrap(Some("1.2"), &body),
        &[
            ("mimetype", MIME_TEXT.as_bytes()),
            ("encrypted-package", b"inner"),
            ("content.xml", b"x"),
        ],
    );
    assert_eq!(class.mode, Mode::Wholesome);
    assert_eq!(
        class.common.as_ref().map(|e| e.path.as_str()),
        Some("content.xml")
    );
}

// --- S3: wholesome zip member vs XML-only; mimetype fallback ---

fn wholesome_body(include_slash: bool) -> String {
    let mut body = String::new();
    if include_slash {
        body.push_str(&root_row("1.3", MIME_TEXT));
    }
    body.push_str(&file_entry(PwOpts {
        path: "encrypted-package",
        media_type: MIME_TEXT,
        cipher: uris::AESGCM256_URL,
        checksum: false,
        kdf: uris::ARGON2ID_URL,
        argon2: Some((3, 65536, 4)),
        iteration_count: None,
        start_key: Some(uris::SHA256_URL),
        ..PwOpts::default()
    }));
    body
}

#[test]
fn s3_zip_member_and_complete_bag_is_wholesome() {
    let class = classify_pkg(
        &manifest_wrap(Some("1.3"), &wholesome_body(false)),
        &[
            ("mimetype", MIME_TEXT.as_bytes()),
            ("encrypted-package", b"inner"),
        ],
    );
    assert_eq!(class.mode, Mode::Wholesome);
    assert!(class.package_encrypted);
    assert!(class.zip_has_encrypted_package);
    assert_eq!(
        class.common.as_ref().map(|e| e.path.as_str()),
        Some("encrypted-package")
    );
}

#[test]
fn s3_xml_only_encrypted_package_is_not_wholesome() {
    let class = classify_pkg(
        &manifest_wrap(Some("1.3"), &wholesome_body(false)),
        &[("mimetype", MIME_TEXT.as_bytes())],
    );
    assert_ne!(class.mode, Mode::Wholesome);
    assert!(!class.zip_has_encrypted_package);
    assert!(!class.package_encrypted);
    assert!(class.encrypted_entries.is_empty());
}

#[test]
fn s3_package_version_copied_onto_first_entry_when_slash_omitted() {
    let xml = manifest_wrap(Some("1.3"), &wholesome_body(false));
    let bags = parse_manifest_for_test(&xml);
    assert_eq!(bags[0].full_path, "encrypted-package");
    assert_eq!(bags[0].version.as_deref(), Some("1.3"));

    let class = classify_pkg(
        &xml,
        &[
            ("mimetype", MIME_TEXT.as_bytes()),
            ("encrypted-package", b"inner"),
        ],
    );
    assert_eq!(class.odf_version.as_deref(), Some("1.3"));
}

#[test]
fn s3_mimetype_fallback_only_with_vnd_prefix() {
    let xml = manifest_wrap(Some("1.3"), &wholesome_body(false));
    let present = classify_pkg(
        &xml,
        &[
            ("mimetype", MIME_TEXT.as_bytes()),
            ("encrypted-package", b"inner"),
        ],
    );
    assert_eq!(present.odf_version.as_deref(), Some("1.3"));
    assert_eq!(present.media_type.as_deref(), Some(MIME_TEXT));

    let missing = classify_pkg(&xml, &[("encrypted-package", b"inner")]);
    assert!(missing.odf_version.is_none());
    assert!(missing.media_type.is_none());

    let wrong = classify_pkg(
        &xml,
        &[
            ("mimetype", MIME_WRONG.as_bytes()),
            ("encrypted-package", b"inner"),
        ],
    );
    assert!(wrong.odf_version.is_none());
    assert!(wrong.media_type.is_none());
}

// --- S4: unexpected-stream scan; zip check not mode ---

#[test]
fn s4_extra_root_stream_version_12_is_fatal() {
    let body = format!(
        "{}{}{}",
        root_row("1.2", MIME_TEXT),
        file_entry(PwOpts::default()),
        plain_row("content.xml", "text/xml")
    );
    let class = classify_pkg(
        &manifest_wrap(Some("1.2"), &body),
        &[
            ("mimetype", MIME_TEXT.as_bytes()),
            ("content.xml", b"x"),
            ("extra.bin", b"nope"),
        ],
    );
    assert!(class.has_unexpected_streams);
    assert!(class.odf12_fatal);
}

#[test]
fn s4_extra_root_stream_pre_12_is_not_fatal() {
    let body = format!(
        "{}{}",
        root_row("1.1", MIME_TEXT),
        file_entry(PwOpts::default())
    );
    let class = classify_pkg(
        &manifest_wrap(Some("1.1"), &body),
        &[
            ("mimetype", MIME_TEXT.as_bytes()),
            ("content.xml", b"x"),
            ("extra.bin", b"nope"),
        ],
    );
    assert!(class.has_unexpected_streams);
    assert!(!class.odf12_fatal);
}

#[test]
fn s4_incomplete_encrypted_package_member_still_uses_wholesome_allow_list() {
    let body = file_entry(PwOpts {
        path: "encrypted-package",
        media_type: MIME_TEXT,
        size: None,
        cipher: uris::AESGCM256_URL,
        checksum: false,
        kdf: uris::ARGON2ID_URL,
        argon2: Some((3, 65536, 4)),
        iteration_count: None,
        ..PwOpts::default()
    });
    let extra_listed = format!(
        "{}{}",
        body,
        plain_row("extra.bin", "application/octet-stream")
    );
    let class = classify_pkg(
        &manifest_wrap(Some("1.3"), &extra_listed),
        &[
            ("mimetype", MIME_TEXT.as_bytes()),
            ("encrypted-package", b"inner"),
            ("extra.bin", b"listed"),
        ],
    );
    assert_ne!(class.mode, Mode::Wholesome);
    assert!(class.zip_has_encrypted_package);
    assert!(
        class.has_unexpected_streams,
        "wholesome allow-list flags extra.bin even when listed"
    );
}

#[test]
fn s4_xml_only_encrypted_package_uses_non_wholesome_scan() {
    let body = format!(
        "{}{}",
        file_entry(PwOpts {
            path: "encrypted-package",
            media_type: MIME_TEXT,
            cipher: uris::AESGCM256_URL,
            checksum: false,
            kdf: uris::ARGON2ID_URL,
            argon2: Some((3, 65536, 4)),
            iteration_count: None,
            ..PwOpts::default()
        }),
        plain_row("extra.bin", "application/octet-stream")
    );
    let class = classify_pkg(
        &manifest_wrap(Some("1.3"), &body),
        &[("mimetype", MIME_TEXT.as_bytes()), ("extra.bin", b"listed")],
    );
    assert!(!class.zip_has_encrypted_package);
    assert_ne!(class.mode, Mode::Wholesome);
    assert!(
        !class.has_unexpected_streams,
        "non-wholesome scan accepts a listed extra.bin"
    );
}

#[test]
fn s4_nested_mimetype_is_not_exempt() {
    let body = format!(
        "{}{}",
        root_row("1.2", MIME_TEXT),
        file_entry(PwOpts::default())
    );
    let class = classify_pkg(
        &manifest_wrap(Some("1.2"), &body),
        &[
            ("mimetype", MIME_TEXT.as_bytes()),
            ("content.xml", b"x"),
            ("foo/mimetype", b"nested"),
        ],
    );
    assert!(class.has_unexpected_streams);
    assert!(class.odf12_fatal);
}

// --- S5: PGP bag typed; loext and manifest trees ---

fn loext_encrypted_key(wrap_uri: &str) -> String {
    format!(
        r#"  <loext:encrypted-key>
   <loext:encryption-method loext:PGPAlgorithm="{wrap_uri}"/>
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
"#
    )
}

fn manifest_encrypted_key(wrap_uri: &str) -> String {
    format!(
        r#" <manifest:encrypted-key>
  <manifest:encryption-method manifest:PGPAlgorithm="{wrap_uri}"/>
  <manifest:keyinfo>
   <manifest:PGPData>
    <manifest:PGPKeyID>{B64}</manifest:PGPKeyID>
    <manifest:PGPKeyPacket>{B64}</manifest:PGPKeyPacket>
   </manifest:PGPData>
  </manifest:keyinfo>
  <manifest:CipherData>
   <manifest:CipherValue>{B64}</manifest:CipherValue>
  </manifest:CipherData>
 </manifest:encrypted-key>
"#
    )
}

fn pgp_row(path: &str, size: i64, key_size: Option<i32>, cipher: &str) -> String {
    let key_size = match key_size {
        Some(n) => format!(" manifest:key-size=\"{n}\""),
        None => String::new(),
    };
    format!(
        r#" <manifest:file-entry manifest:full-path="{path}" manifest:media-type="text/xml" manifest:size="{size}">
  <manifest:encryption-data>
   <manifest:algorithm manifest:algorithm-name="{cipher}" manifest:initialisation-vector="{B64}"/>
   <manifest:key-derivation manifest:key-derivation-name="PGP"{key_size}/>
  </manifest:encryption-data>
 </manifest:file-entry>
"#
    )
}

#[test]
fn s5_loext_tree_classifies_as_pgp() {
    let xml = manifest_wrap(
        Some("1.3"),
        &format!(
            r#" <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml" manifest:size="100">
{}
  <manifest:encryption-data>
   <manifest:algorithm manifest:algorithm-name="{}" manifest:initialisation-vector="{B64}"/>
   <manifest:key-derivation manifest:key-derivation-name="PGP"/>
  </manifest:encryption-data>
 </manifest:file-entry>
"#,
            loext_encrypted_key(uris::PGP_WRAP_URI),
            uris::AESGCM256_URL
        ),
    );
    let class = classify_pkg(
        &xml,
        &[("mimetype", MIME_TEXT.as_bytes()), ("content.xml", b"x")],
    );
    assert_eq!(class.mode, Mode::PerEntry);
    assert!(matches!(
        class.common.as_ref().map(|e| &e.kdf),
        Some(Kdf::PgpRsaOaepMgf1p)
    ));
}

#[test]
fn s5_manifest_tree_classifies_as_pgp_without_version_gate() {
    let xml = manifest_wrap(
        Some("1.2"),
        &format!(
            "{}{}",
            manifest_encrypted_key(uris::PGP_WRAP_URI),
            pgp_row("content.xml", 100, None, uris::AESGCM256_URL)
        ),
    );
    let class = classify_pkg(
        &xml,
        &[("mimetype", MIME_TEXT.as_bytes()), ("content.xml", b"x")],
    );
    assert_eq!(class.mode, Mode::PerEntry);
    assert!(matches!(
        class.common.as_ref().map(|e| &e.kdf),
        Some(Kdf::PgpRsaOaepMgf1p)
    ));
}

#[test]
fn s5_wrong_wrap_uri_discards_key_and_suppresses_keyinfo() {
    let xml = manifest_wrap(
        Some("1.3"),
        &format!(
            r#" <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml" manifest:size="100">
{}
  <manifest:encryption-data>
   <manifest:algorithm manifest:algorithm-name="{}" manifest:initialisation-vector="{B64}"/>
   <manifest:key-derivation manifest:key-derivation-name="PGP"/>
  </manifest:encryption-data>
 </manifest:file-entry>
"#,
            loext_encrypted_key("http://www.w3.org/2001/04/xmlenc#rsa-1_5"),
            uris::AESGCM256_URL
        ),
    );
    let bags = parse_manifest_for_test(&xml);
    assert!(
        bags[0].key_info.is_none(),
        "malformed wrap suppresses package KeyInfo"
    );
    assert_ne!(bags[0].kdf, Some(KdfId::PgpRsaOaepMgf1p));

    let class = classify_pkg(
        &xml,
        &[("mimetype", MIME_TEXT.as_bytes()), ("content.xml", b"x")],
    );
    assert!(class.encrypted_entries.is_empty());
    assert!(!class.package_encrypted);
}

#[test]
fn s5_pgp_derived_key_len_ignores_lying_key_size() {
    let xml = manifest_wrap(
        Some("1.3"),
        &format!(
            "{}{}",
            manifest_encrypted_key(uris::PGP_WRAP_URI),
            pgp_row("content.xml", 100, Some(16), uris::AESGCM256_URL)
        ),
    );
    let gcm = classify_pkg(
        &xml,
        &[("mimetype", MIME_TEXT.as_bytes()), ("content.xml", b"x")],
    );
    assert_eq!(gcm.common.as_ref().unwrap().derived_key_len, 32);
    assert_eq!(gcm.common.as_ref().unwrap().cipher, Cipher::AesGcmW3c);

    let cbc_row = format!(
        r#" <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml" manifest:size="100">
  <manifest:encryption-data manifest:checksum-type="{}" manifest:checksum="{B64}">
   <manifest:algorithm manifest:algorithm-name="{}" manifest:initialisation-vector="{B64}"/>
   <manifest:key-derivation manifest:key-derivation-name="PGP" manifest:key-size="16"/>
  </manifest:encryption-data>
 </manifest:file-entry>
"#,
        uris::SHA1_1K_NAME,
        uris::AES256_URL
    );
    let xml = manifest_wrap(
        Some("1.3"),
        &format!("{}{}", manifest_encrypted_key(uris::PGP_WRAP_URI), cbc_row),
    );
    let cbc = classify_pkg(
        &xml,
        &[("mimetype", MIME_TEXT.as_bytes()), ("content.xml", b"x")],
    );
    assert_eq!(cbc.common.as_ref().unwrap().derived_key_len, 32);
    assert_eq!(cbc.common.as_ref().unwrap().cipher, Cipher::AesCbcW3c);
}

// --- S6: real LO/AOO goldens ---

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("goldens")
        .join(name)
}

fn load_golden(name: &str) -> Vec<u8> {
    let path = golden_path(name);
    std::fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "S6 golden missing at {}: {err}. Generate with tests/goldens/make_goldens.py",
            path.display()
        )
    })
}

#[test]
fn s6_wholesome_gcm_argon2() {
    let class = classify(&load_golden("lo-wholesome-gcm-argon2.odt")).expect("golden");
    assert_eq!(class.mode, Mode::Wholesome);
    assert!(class.package_encrypted);
    assert!(class.zip_has_encrypted_package);
    let common = class.common.as_ref().expect("latch");
    assert_eq!(common.path, "encrypted-package");
    assert_eq!(common.cipher, Cipher::AesGcmW3c);
    assert!(matches!(
        common.kdf,
        Kdf::Argon2id {
            t: 3,
            m: 65536,
            p: 4,
            ..
        }
    ));
    assert_eq!(common.start_key, StartKeyAlg::Sha256);
    assert_eq!(common.checksum, Checksum::None);
    assert_eq!(common.derived_key_len, 32);
    assert_eq!(class.odf_version.as_deref(), Some("1.4"));
    assert!(!class.has_unexpected_streams);
    assert!(!class.odf12_fatal);
    assert_eq!(class.encrypted_entries.len(), 1);
    assert_eq!(common.size, 6977);
    assert!(!common.iv.is_empty());
}

#[test]
fn s6_legacy_aes_cbc() {
    let class = classify(&load_golden("lo-legacy-aes-cbc.odt")).expect("golden");
    assert_eq!(class.mode, Mode::PerEntry);
    assert!(class.package_encrypted);
    assert!(!class.zip_has_encrypted_package);
    let common = class.common.as_ref().expect("latch");
    assert_eq!(common.path, "content.xml");
    assert_eq!(common.cipher, Cipher::AesCbcW3c);
    assert!(matches!(
        common.kdf,
        Kdf::Pbkdf2 {
            iterations: 100000,
            ..
        }
    ));
    assert_eq!(common.start_key, StartKeyAlg::Sha256);
    assert!(matches!(common.checksum, Checksum::Sha256_1K(_)));
    assert_eq!(common.derived_key_len, 32);
    assert_eq!(class.odf_version.as_deref(), Some("1.2"));
    assert!(!class.has_unexpected_streams);
    assert!(!class.odf12_fatal);
    assert!(class.encrypted_entries.len() >= 2);
    assert_eq!(common.size, 4251);
    assert!(!common.iv.is_empty());
}

#[test]
fn s6_blowfish_pbkdf2() {
    let class = classify(&load_golden("aoo-blowfish-pbkdf2.odt")).expect("golden");
    assert_eq!(class.mode, Mode::PerEntry);
    assert!(class.package_encrypted);
    assert!(!class.zip_has_encrypted_package);
    let common = class.common.as_ref().expect("latch");
    assert_eq!(common.path, "content.xml");
    assert_eq!(common.cipher, Cipher::BlowfishCfb8);
    assert!(matches!(
        common.kdf,
        Kdf::Pbkdf2 {
            iterations: 100000,
            ..
        }
    ));
    assert_eq!(common.start_key, StartKeyAlg::Sha1);
    assert!(matches!(common.checksum, Checksum::Sha1_1K(_)));
    assert_eq!(common.derived_key_len, 16);
    assert!(!class.has_unexpected_streams);
    assert!(!class.odf12_fatal);
    assert!(class.odf_version.is_none() || class.odf_version.as_deref() == Some(""));
    assert!(class.encrypted_entries.len() >= 2);
    assert!(!common.iv.is_empty());
    assert!(common.size > 0);
}

fn classify_err(bytes: &[u8]) -> DetectError {
    classify(bytes).expect_err("expected classify to refuse")
}

#[test]
fn not_zip_is_detect_error() {
    assert!(matches!(classify_err(b"not a zip"), DetectError::NotZip));
}

#[test]
fn missing_manifest_is_detect_error() {
    let bytes = zip_with(&[("mimetype", MIME_TEXT.as_bytes())]);
    assert!(matches!(classify_err(&bytes), DetectError::MissingManifest));
}

#[test]
fn invalid_zip_entry_name_is_refused() {
    let bytes = zip_with(&[
        ("mimetype", MIME_TEXT.as_bytes()),
        ("META-INF/manifest.xml", UNENCRYPTED_MANIFEST.as_bytes()),
        ("a/../content.xml", b"x"),
    ]);
    assert!(matches!(classify_err(&bytes), DetectError::Zip(_)));
}

#[test]
fn s3_slash_first_and_versionless_gets_package_version() {
    let slash = format!(
        r#" <manifest:file-entry manifest:full-path="/" manifest:media-type="{MIME_TEXT}"/>
"#
    );
    let body = format!(
        "{}{}{}",
        slash,
        file_entry(PwOpts::default()),
        plain_row("content.xml", "text/xml")
    );
    let class = classify_pkg(
        &manifest_wrap(Some("1.2"), &body),
        &[
            ("mimetype", MIME_TEXT.as_bytes()),
            ("content.xml", b"x"),
            ("extra.bin", b"nope"),
        ],
    );
    assert_eq!(class.odf_version.as_deref(), Some("1.2"));
    assert!(class.has_unexpected_streams);
    assert!(class.odf12_fatal);
}

#[test]
fn s4_extra_root_stream_empty_root_version_is_not_fatal() {
    let xml = manifest_wrap(Some("1.3"), &wholesome_body(false));
    let class = classify_pkg(
        &xml,
        &[("encrypted-package", b"inner"), ("extra.bin", b"nope")],
    );
    assert!(class.odf_version.is_none());
    assert!(class.has_unexpected_streams);
    assert!(!class.odf12_fatal);
}

#[test]
fn s5_malformed_key_poisons_only_first_entry() {
    let poisoned = format!(
        r#" <manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml" manifest:size="100">
{}
  <manifest:encryption-data>
   <manifest:algorithm manifest:algorithm-name="{}" manifest:initialisation-vector="{B64}"/>
   <manifest:key-derivation manifest:key-derivation-name="PGP"/>
  </manifest:encryption-data>
 </manifest:file-entry>
"#,
        loext_encrypted_key("http://www.w3.org/2001/04/xmlenc#rsa-1_5"),
        uris::AESGCM256_URL
    );
    let body = format!("{}{}", poisoned, file_entry(PwOpts::default()));
    let class = classify_pkg(
        &manifest_wrap(Some("1.3"), &body),
        &[
            ("mimetype", MIME_TEXT.as_bytes()),
            ("styles.xml", b"s"),
            ("content.xml", b"x"),
        ],
    );
    assert!(class.package_encrypted);
    assert_eq!(
        class.common.as_ref().map(|e| e.path.as_str()),
        Some("content.xml")
    );
}

#[test]
fn s5_pgp_start_key_clamps_to_sha256() {
    let xml = manifest_wrap(
        Some("1.3"),
        &format!(
            r#" <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml" manifest:size="100">
{}
  <manifest:encryption-data>
   <manifest:algorithm manifest:algorithm-name="{}" manifest:initialisation-vector="{B64}"/>
   <manifest:start-key-generation manifest:start-key-generation-name="{}"/>
   <manifest:key-derivation manifest:key-derivation-name="PGP"/>
  </manifest:encryption-data>
 </manifest:file-entry>
"#,
            loext_encrypted_key(uris::PGP_WRAP_URI),
            uris::AESGCM256_URL,
            uris::SHA1_NAME
        ),
    );
    let class = classify_pkg(
        &xml,
        &[("mimetype", MIME_TEXT.as_bytes()), ("content.xml", b"x")],
    );
    assert_eq!(
        class.common.as_ref().map(|e| e.start_key),
        Some(StartKeyAlg::Sha256)
    );
}

#[test]
fn derived_key_size_resets_per_encryption_data() {
    let first = file_entry(PwOpts {
        key_size: Some(32),
        ..PwOpts::default()
    });
    let second = file_entry(PwOpts {
        path: "styles.xml",
        key_size: None,
        kdf_before_algorithm: true,
        ..PwOpts::default()
    });
    let class = classify_pkg(
        &manifest_wrap(Some("1.2"), &format!("{}{}", first, second)),
        &[
            ("mimetype", MIME_TEXT.as_bytes()),
            ("content.xml", b"x"),
            ("styles.xml", b"s"),
        ],
    );
    let styles = class
        .encrypted_entries
        .iter()
        .find(|e| e.path == "styles.xml")
        .expect("styles");
    assert_eq!(styles.derived_key_len, 16);
}

#[test]
fn typo_root_element_still_imports_file_entries() {
    let body = file_entry(PwOpts::default());
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest-typo xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
{body}
</manifest:manifest-typo>
"#
    );
    let class = classify_pkg(
        &xml,
        &[("mimetype", MIME_TEXT.as_bytes()), ("content.xml", b"x")],
    );
    assert_eq!(class.mode, Mode::PerEntry);
    assert!(class.package_encrypted);
}

#[test]
fn truncated_manifest_is_plain_not_partial() {
    let body = file_entry(PwOpts::default());
    let xml = manifest_wrap(Some("1.3"), &body);
    let truncated = &xml[..xml.len().saturating_sub(20)];
    let class = classify_pkg(
        truncated,
        &[("mimetype", MIME_TEXT.as_bytes()), ("content.xml", b"x")],
    );
    assert_eq!(class.mode, Mode::Plain);
    assert!(!class.package_encrypted);
}

#[test]
fn nested_encrypted_package_row_is_not_wholesome() {
    let body = format!(
        "{}{}",
        file_entry(PwOpts {
            path: "encrypted-package",
            media_type: "text/plain",
            size: None,
            cipher: uris::AESGCM256_URL,
            checksum: false,
            kdf: uris::ARGON2ID_URL,
            argon2: Some((3, 65536, 4)),
            iteration_count: None,
            ..PwOpts::default()
        }),
        file_entry(PwOpts {
            path: "Object 1/encrypted-package",
            media_type: MIME_TEXT,
            cipher: uris::AESGCM256_URL,
            checksum: false,
            kdf: uris::ARGON2ID_URL,
            argon2: Some((3, 65536, 4)),
            iteration_count: None,
            ..PwOpts::default()
        })
    );
    let class = classify_pkg(
        &manifest_wrap(Some("1.3"), &body),
        &[
            ("mimetype", MIME_TEXT.as_bytes()),
            ("encrypted-package", b"inner"),
            ("Object 1/encrypted-package", b"nested"),
        ],
    );
    assert_ne!(class.mode, Mode::Wholesome);
    assert!(class.zip_has_encrypted_package);
}

#[test]
fn later_bare_slash_row_clears_root_version() {
    let body = format!(
        "{}{}{}",
        root_row("1.2", MIME_TEXT),
        r#" <manifest:file-entry manifest:full-path="/"/>
"#,
        file_entry(PwOpts::default())
    );
    // No mimetype: fallback cannot restore `o_first_version`. A sticky first
    // `/` version would make this fatal; clearing it does not.
    let class = classify_pkg(
        &manifest_wrap(Some("1.2"), &body),
        &[("content.xml", b"x"), ("stray.txt", b"x")],
    );
    assert!(class.has_unexpected_streams);
    assert!(!class.odf12_fatal);
    assert!(class.odf_version.is_none() || class.odf_version.as_deref() == Some(""));
}

#[test]
fn double_slash_member_resolves_and_latches() {
    let body = file_entry(PwOpts {
        path: "a//content.xml",
        ..PwOpts::default()
    });
    let class = classify_pkg(
        &manifest_wrap(Some("1.2"), &body),
        &[("mimetype", MIME_TEXT.as_bytes()), ("a//content.xml", b"x")],
    );
    assert!(class.package_encrypted);
    assert_eq!(class.mode, Mode::PerEntry);
}

#[test]
fn second_encryption_data_rereads_checksum() {
    let xml = manifest_wrap(
        Some("1.2"),
        &format!(
            r#" <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml" manifest:size="100">
  <manifest:encryption-data manifest:checksum-type="{}" manifest:checksum="{B64}">
   <manifest:algorithm manifest:algorithm-name="{}" manifest:initialisation-vector="{B64}"/>
   <manifest:key-derivation manifest:key-derivation-name="PBKDF2" manifest:salt="{B64}" manifest:iteration-count="1" manifest:key-size="32"/>
  </manifest:encryption-data>
  <manifest:encryption-data manifest:checksum-type="bogus" manifest:checksum="QUJDRA==">
  </manifest:encryption-data>
 </manifest:file-entry>
"#,
            uris::SHA1_1K_NAME,
            uris::AES256_URL
        ),
    );
    let class = classify_pkg(
        &xml,
        &[("mimetype", MIME_TEXT.as_bytes()), ("content.xml", b"x")],
    );
    match class.common.as_ref().map(|e| &e.checksum) {
        Some(Checksum::Sha1_1K(d)) => assert_eq!(d, b"ABCD"),
        other => panic!("{other:?}"),
    }
}

/// A deep subtree must not swallow the rest of the manifest. LO invalidates
/// everything past level 6 but keeps parsing; a depth cap that unbalanced the
/// element stack made the whole document read as malformed (zero rows → Plain).
#[test]
fn deep_subtree_does_not_drop_later_entries() {
    let mut deep = String::from(
        " <manifest:file-entry manifest:full-path=\"junk\" manifest:media-type=\"text/xml\" \
         xmlns:m2=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\">\n",
    );
    for _ in 0..40 {
        deep.push_str("<m2:foo>");
    }
    for _ in 0..40 {
        deep.push_str("</m2:foo>");
    }
    deep.push_str(" </manifest:file-entry>\n");

    let body = format!(
        "{}{}{}",
        root_row("1.2", MIME_TEXT),
        deep,
        file_entry(PwOpts::default())
    );
    let class = classify_pkg(
        &manifest_wrap(Some("1.2"), &body),
        &[
            ("mimetype", MIME_TEXT.as_bytes()),
            ("content.xml", b"x"),
            ("junk", b"x"),
        ],
    );
    assert_eq!(class.mode, Mode::PerEntry);
    assert!(class.package_encrypted);
    assert_eq!(class.encrypted_entries.len(), 1);
    assert_eq!(class.odf_version.as_deref(), Some("1.2"));
}

/// `hasByHierarchicalName("/content.xml")` is false in LO: the walk breaks on
/// the empty first segment and then looks up the whole remainder, leading slash
/// included, as a single child name. The row must not latch.
#[test]
fn leading_slash_stream_row_is_not_applied() {
    let body = format!(
        "{}{}",
        root_row("1.2", MIME_TEXT),
        file_entry(PwOpts {
            path: "/content.xml",
            ..PwOpts::default()
        })
    );
    let class = classify_pkg(
        &manifest_wrap(Some("1.2"), &body),
        &[("mimetype", MIME_TEXT.as_bytes()), ("content.xml", b"x")],
    );
    assert_eq!(class.mode, Mode::Plain);
    assert!(!class.package_encrypted);
    assert!(class.encrypted_entries.is_empty());
}

/// A10: nested `Pictures/album/photo.png` seeds `m_aRecent["Pictures/album"]`
/// only. A `Pictures/` folder row then caches `pPrevious` (root). The following
/// `Pictures/content.xml` complete row resolves as **root** `content.xml` and
/// latches. Folder meta from `Pictures/` still lands on the Pictures folder
/// (`pCurrent`), not the poisoned cache parent.
#[test]
fn pictures_folder_row_poisons_nested_content_xml_onto_root() {
    let body = format!(
        r#" <manifest:file-entry manifest:full-path="Pictures/" manifest:version="1.2" manifest:media-type="image/"/>
{}"#,
        file_entry(PwOpts {
            path: "Pictures/content.xml",
            ..PwOpts::default()
        })
    );
    let class = classify_pkg(
        &manifest_wrap(None, &body),
        &[
            ("content.xml", b"plain-root"),
            ("Pictures/album/photo.png", b"png"),
        ],
    );
    assert_eq!(class.mode, Mode::PerEntry);
    assert!(class.package_encrypted);
    assert_eq!(
        class.common.as_ref().map(|e| e.path.as_str()),
        Some("content.xml")
    );
    assert_eq!(class.encrypted_entries.len(), 1);
    assert_eq!(class.encrypted_entries[0].path, "content.xml");
    // Pictures/ version and media-type must not have landed on the root.
    assert!(class.odf_version.is_none());
    assert!(class.media_type.is_none());
}

/// A10 control: the same zip as the poison case, minus the `Pictures/` folder
/// row. Seeding `m_aRecent["Pictures/album"]` at insert is not itself enough —
/// the folder row is what writes the shallow entry — so the nested row does not
/// resolve and nothing latches.
#[test]
fn nested_row_without_a_folder_row_does_not_latch() {
    let class = classify_pkg(
        &manifest_wrap(
            None,
            &file_entry(PwOpts {
                path: "Pictures/content.xml",
                ..PwOpts::default()
            }),
        ),
        &[
            ("content.xml", b"plain-root"),
            ("Pictures/album/photo.png", b"png"),
        ],
    );
    assert_eq!(class.mode, Mode::Plain);
    assert!(!class.package_encrypted);
    assert!(class.common.is_none());
    assert!(class.encrypted_entries.is_empty());
}

/// A10 negative: `Pictures/photo.png` insert already cached `"Pictures"`
/// correctly, so a later `Pictures/` is a hit and does not poison.
#[test]
fn pictures_photo_insert_then_folder_row_does_not_poison() {
    let body = format!(
        r#" <manifest:file-entry manifest:full-path="Pictures/" manifest:version="1.2" manifest:media-type="image/"/>
{}"#,
        file_entry(PwOpts {
            path: "Pictures/content.xml",
            ..PwOpts::default()
        })
    );
    let class = classify_pkg(
        &manifest_wrap(None, &body),
        &[
            ("content.xml", b"plain-root"),
            ("Pictures/photo.png", b"png"),
        ],
    );
    assert_eq!(class.mode, Mode::Plain);
    assert!(!class.package_encrypted);
    assert!(class.common.is_none());
    assert!(class.encrypted_entries.is_empty());
    assert!(class.odf_version.is_none());
    assert!(class.media_type.is_none());
}
