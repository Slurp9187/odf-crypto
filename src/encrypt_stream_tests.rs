//! S5 (#91): `encrypt_to` against the whole-buffer `encrypt`.

use super::*;

use std::io::Cursor;

use crate::classify::classify;
use crate::decrypt::decrypt;
use crate::decrypt_stream::decrypt_to;
use crate::test_support::{load_golden, zip_with, MIME_TEXT, PASSWORD};
use crate::Mode;

/// The cheapest legal Argon2id, so a test that encrypts many times stays fast.
fn cheap() -> Argon2Params {
    Argon2Params::new(1, 8, 1).unwrap()
}

fn seal(plain: &[u8], params: Argon2Params) -> Result<Vec<u8>, EncryptError> {
    let mut out = Cursor::new(Vec::new());
    encrypt_with_params_to(Cursor::new(plain), &mut out, PASSWORD, params)?;
    Ok(out.into_inner())
}

/// Plain packages of several shapes: the LibreOffice golden, one with a
/// large compressible member, and one whose `mimetype` member is absent so the
/// manifest's media type is the fallback.
fn plains() -> Vec<(&'static str, Vec<u8>)> {
    let manifest = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">
 <manifest:file-entry manifest:full-path="/" manifest:version="1.3" manifest:media-type="{MIME_TEXT}"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>"#
    );
    let big = b"<text:p>streaming</text:p>".repeat(20_000);
    vec![
        ("lo-unencrypted.odt", load_golden("lo-unencrypted.odt")),
        (
            "large member",
            zip_with(&[
                ("mimetype", MIME_TEXT.as_bytes()),
                ("META-INF/manifest.xml", manifest.as_bytes()),
                ("content.xml", &big),
            ]),
        ),
        (
            "no mimetype member",
            zip_with(&[
                ("META-INF/manifest.xml", manifest.as_bytes()),
                ("content.xml", b"<x/>"),
            ]),
        ),
    ]
}

/// Round trip through both decrypt paths, back to the exact input bytes.
#[test]
fn encrypt_to_round_trips_through_both_decrypt_paths() {
    for (name, plain) in plains() {
        let sealed = seal(&plain, cheap()).unwrap();
        assert_eq!(classify(&sealed).unwrap().mode, Mode::Wholesome, "{name}");
        assert!(
            decrypt(&sealed, PASSWORD).unwrap() == plain,
            "{name}: decrypt"
        );
        let mut out = Vec::new();
        decrypt_to(Cursor::new(&sealed), &mut out, PASSWORD).unwrap();
        assert!(out == plain, "{name}: decrypt_to");
    }
}

/// The member names, methods and lengths of a zip, in order.
fn shape(zip: &[u8]) -> Vec<(String, zip::CompressionMethod, u64)> {
    let mut z = ZipArchive::new(Cursor::new(zip)).unwrap();
    (0..z.len())
        .map(|i| {
            let f = z.by_index(i).unwrap();
            (f.name().to_string(), f.compression(), f.size())
        })
        .collect()
}

/// The manifest with the two values that are fresh per call -- the IV and the
/// salt -- blanked, so two encryptions of one input can be compared.
fn manifest_without_randomness(zip: &[u8]) -> String {
    let xml = String::from_utf8(crate::test_support::read_member(zip, MANIFEST_PATH)).unwrap();
    let blank = |xml: String, attr: &str| {
        let start = xml.find(attr).unwrap() + attr.len();
        let end = start + xml[start..].find('"').unwrap();
        format!("{}{}", &xml[..start], &xml[end..])
    };
    blank(
        blank(xml, r#"manifest:initialisation-vector=""#),
        r#"manifest:salt=""#,
    )
}

/// The same package as `encrypt` writes, but for the salt and IV: the same
/// members in the same order with the same methods and the **same lengths**
/// -- the DEFLATE stream is identical, so the ciphertext is the same size --
/// and the same manifest. Never compared byte for byte: the salt and IV are
/// fresh per call (CLAUDE.md, "never assert on encrypt's output bytes").
#[test]
fn encrypt_to_writes_what_encrypt_writes() {
    for (name, plain) in plains() {
        let streamed = seal(&plain, cheap()).unwrap();
        let whole = crate::encrypt::encrypt_with_params(&plain, PASSWORD, cheap()).unwrap();
        assert_eq!(shape(&streamed), shape(&whole), "{name}");
        assert_eq!(
            manifest_without_randomness(&streamed),
            manifest_without_randomness(&whole),
            "{name}"
        );
        assert_eq!(
            crate::test_support::read_member(&streamed, "mimetype"),
            crate::test_support::read_member(&whole, "mimetype"),
            "{name}"
        );
    }
}

/// Every fixture `encrypt` refuses, `encrypt_to` refuses with the same
/// variant -- encrypted packages above all -- before deriving anything.
#[test]
fn encrypt_to_refuses_what_encrypt_refuses() {
    let goldens = crate::test_support::goldens_dir();
    let mut refused = 0;
    for dir in ["goldens", "ladder", "artifacts"] {
        for entry in std::fs::read_dir(goldens.with_file_name(dir)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|x| x != "odt") {
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            let whole = crate::encrypt::encrypt_with_params(&bytes, PASSWORD, cheap());
            let streamed = seal(&bytes, cheap());
            match (whole, streamed) {
                (Ok(_), Ok(_)) => {}
                (Err(a), Err(b)) => {
                    refused += 1;
                    assert_eq!(
                        std::mem::discriminant(&a),
                        std::mem::discriminant(&b),
                        "{path:?}: encrypt {a:?}, encrypt_to {b:?}"
                    );
                }
                (a, b) => panic!("{path:?}: encrypt {a:?}, encrypt_to {b:?}"),
            }
        }
    }
    assert!(refused >= 10, "only {refused} refusals compared");
    let err = encrypt_to(Cursor::new(b"not a zip"), Cursor::new(Vec::new()), PASSWORD).unwrap_err();
    assert!(matches!(err, EncryptError::Classify(_)), "{err:?}");
    let err = encrypt_to(Cursor::new(b"x"), Cursor::new(Vec::new()), "").unwrap_err();
    assert!(matches!(err, EncryptError::EmptyPassword), "{err:?}");
}

#[derive(Debug)]
struct Cancelled;
impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cancelled")
    }
}
impl std::error::Error for Cancelled {}

struct CancelsAt {
    inner: Cursor<Vec<u8>>,
    calls: usize,
    at: usize,
}
impl CancelsAt {
    fn tick(&mut self) -> io::Result<()> {
        self.calls += 1;
        if self.calls >= self.at {
            return Err(io::Error::other(Cancelled));
        }
        Ok(())
    }
}
impl Read for CancelsAt {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tick()?;
        self.inner.read(buf)
    }
}
impl Seek for CancelsAt {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.tick()?;
        self.inner.seek(pos)
    }
}

/// A reader that cancels at its N-th call yields `Io` carrying the caller's
/// own error, for every N until the call completes.
#[test]
fn a_cancelling_reader_is_io_at_every_call() {
    let plain = load_golden("lo-unencrypted.odt");
    let mut at = 1;
    loop {
        let reader = CancelsAt {
            inner: Cursor::new(plain.clone()),
            calls: 0,
            at,
        };
        match encrypt_with_params_to(reader, Cursor::new(Vec::new()), PASSWORD, cheap()) {
            Err(EncryptError::Io(e)) => {
                let inner = e.get_ref().expect("the caller's error");
                assert!(inner.is::<Cancelled>(), "call {at}: {e}");
            }
            Ok(()) => {
                assert!(at > 1);
                break;
            }
            Err(other) => panic!("call {at}: expected Io, got {other:?}"),
        }
        at += 1;
    }
}

/// A writer that fails is the caller's failure: `Io`.
#[test]
fn a_failing_writer_is_io() {
    struct Full;
    impl Write for Full {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::StorageFull, "disk full"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Seek for Full {
        fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
            Ok(0)
        }
    }
    let err = encrypt_with_params_to(
        Cursor::new(load_golden("lo-unencrypted.odt")),
        Full,
        PASSWORD,
        cheap(),
    )
    .unwrap_err();
    assert!(
        matches!(&err, EncryptError::Io(e) if e.kind() == io::ErrorKind::StorageFull),
        "{err:?}"
    );
}

/// Writes `encrypt_to`'s output for the LibreOffice gate into the directory
/// named by `ODF_CRYPTO_LO_GATE_DIR`. Not a check by itself.
#[test]
#[ignore = "writes a file for the LibreOffice gate"]
fn write_lo_gate_output() {
    let dir = std::path::PathBuf::from(std::env::var("ODF_CRYPTO_LO_GATE_DIR").unwrap());
    std::fs::create_dir_all(&dir).unwrap();
    let mut out = Cursor::new(Vec::new());
    encrypt_to(
        Cursor::new(load_golden("lo-unencrypted.odt")),
        &mut out,
        PASSWORD,
    )
    .unwrap();
    std::fs::write(dir.join("encrypt-to.odt"), out.into_inner()).unwrap();
}
