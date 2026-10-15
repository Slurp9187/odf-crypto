//! S6 (#92): `reencrypt_to`, and the plan's §4 refusals.

use super::*;

use std::io::Cursor;

use crate::classify::classify;
use crate::decrypt::decrypt;
use crate::decrypt_stream::decrypt_to;
use crate::test_support::{
    append_stored_member, load_golden, load_ladder_fixture, unlatched_package, NONASCII_PASSWORD,
    PASSWORD,
};

const NEW: &str = "a new password";

fn cheap() -> Argon2Params {
    Argon2Params::new(1, 8, 1).unwrap()
}

fn rekey(src: &[u8], old: &str) -> (Result<DecryptOutcome, ReencryptError>, Vec<u8>) {
    let mut out = Cursor::new(Vec::new());
    let r = reencrypt_to(
        Cursor::new(src),
        &mut out,
        old,
        NEW,
        DecryptLimits::default(),
        cheap(),
    );
    (r, out.into_inner())
}

fn artifact(name: &str) -> Vec<u8> {
    std::fs::read(
        crate::test_support::goldens_dir()
            .with_file_name("artifacts")
            .join(name),
    )
    .unwrap()
}

/// A wholesome source is re-keyed without recompressing: the new package
/// decrypts under the new password to **exactly** the inner package the old
/// one held, and no longer opens under the old password.
#[test]
fn a_wholesome_source_rekeys_byte_for_byte() {
    for (name, src, old) in [
        (
            "lo-wholesome-gcm-argon2",
            load_golden("lo-wholesome-gcm-argon2.odt"),
            PASSWORD,
        ),
        (
            "wholesome-nonascii-password",
            artifact("wholesome-nonascii-password.odt"),
            NONASCII_PASSWORD,
        ),
        (
            "argon2-floor-1-8-1",
            artifact("argon2-floor-1-8-1.odt"),
            PASSWORD,
        ),
    ] {
        let (r, out) = rekey(&src, old);
        assert_eq!(r.unwrap().integrity, IntegrityOutcome::Verified, "{name}");
        assert_eq!(classify(&out).unwrap().mode, Mode::Wholesome, "{name}");
        assert!(
            decrypt(&out, NEW).unwrap() == decrypt(&src, old).unwrap(),
            "{name}"
        );
        assert!(
            matches!(decrypt(&out, old), Err(DecryptError::WrongPassword)),
            "{name}"
        );
    }
}

/// A per-entry source becomes a wholesome package whose inner package is
/// **exactly** what `decrypt_to` writes for it -- the same rebuild, now
/// encrypted -- and the outcome reports what the source was checked with.
#[test]
fn a_per_entry_source_becomes_wholesome() {
    for (name, src, old) in [
        (
            "lo-legacy-aes-cbc",
            load_golden("lo-legacy-aes-cbc.odt"),
            PASSWORD,
        ),
        (
            "aoo-blowfish-pbkdf2",
            load_golden("aoo-blowfish-pbkdf2.odt"),
            PASSWORD,
        ),
        (
            "ladder-staroffice-utf8",
            load_ladder_fixture("ladder-staroffice-utf8.odt"),
            NONASCII_PASSWORD,
        ),
    ] {
        let (r, out) = rekey(&src, old);
        assert_eq!(
            r.unwrap().integrity,
            IntegrityOutcome::PasswordCheckOnly,
            "{name}"
        );
        assert_eq!(classify(&out).unwrap().mode, Mode::Wholesome, "{name}");
        let mut streamed = Vec::new();
        decrypt_to(Cursor::new(&src), &mut streamed, old).unwrap();
        assert!(decrypt(&out, NEW).unwrap() == streamed, "{name}");
        let mut again = Vec::new();
        decrypt_to(Cursor::new(&out), &mut again, NEW).unwrap();
        assert!(again == streamed, "{name}: through decrypt_to");
    }
}

#[test]
fn passwords_are_checked_before_anything_else() {
    let src = load_golden("lo-wholesome-gcm-argon2.odt");
    let (r, out) = rekey(&src, "wrong");
    assert!(
        matches!(r, Err(ReencryptError::Decrypt(DecryptError::WrongPassword))),
        "{r:?}"
    );
    assert!(
        out.is_empty(),
        "a wrong old password wrote {} bytes",
        out.len()
    );

    let mut out = Cursor::new(Vec::new());
    let r = reencrypt_to(
        Cursor::new(&src),
        &mut out,
        "",
        NEW,
        DecryptLimits::default(),
        cheap(),
    );
    assert!(
        matches!(r, Err(ReencryptError::Decrypt(DecryptError::EmptyPassword))),
        "{r:?}"
    );
    let r = reencrypt_to(
        Cursor::new(&src),
        &mut out,
        PASSWORD,
        "",
        DecryptLimits::default(),
        cheap(),
    );
    assert!(
        matches!(r, Err(ReencryptError::Encrypt(EncryptError::EmptyPassword))),
        "{r:?}"
    );
}

/// `lo-legacy-aes-cbc.odt` plus a member the manifest lists with no
/// `encryption-data`: plaintext slipped into an old encrypted file.
fn with_plain_listed_row() -> Vec<u8> {
    let golden = load_golden("lo-legacy-aes-cbc.odt");
    let mut src = ZipArchive::new(Cursor::new(&golden)).unwrap();
    let mut out = ZipWriter::new(Cursor::new(Vec::new()));
    for i in 0..src.len() {
        let name = src.by_index(i).unwrap().name().to_string();
        if name == MANIFEST_PATH {
            let mut xml = String::new();
            src.by_index(i).unwrap().read_to_string(&mut xml).unwrap();
            let xml = xml.replace(
                "</manifest:manifest>",
                r#" <manifest:file-entry manifest:full-path="extra.xml" manifest:media-type="text/xml"/>
</manifest:manifest>"#,
            );
            let opt = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            out.start_file(MANIFEST_PATH, opt).unwrap();
            out.write_all(xml.as_bytes()).unwrap();
        } else {
            out.raw_copy_file(src.by_index_raw(i).unwrap()).unwrap();
        }
    }
    let opt = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    out.start_file("extra.xml", opt).unwrap();
    out.write_all(b"<slipped-in/>").unwrap();
    out.finish().unwrap().into_inner()
}

/// An ODF 1.1 per-entry package with a member its manifest does not list. Not
/// fatal to LibreOffice below 1.2, which is why the refusal is ours.
fn with_unlisted_member() -> Vec<u8> {
    append_stored_member(
        &load_golden("aoo-blowfish-pbkdf2.odt"),
        "unlisted.xml",
        b"<x/>",
    )
}

/// Refusal (a): a plain listed row.
#[test]
fn a_plain_listed_row_is_refused() {
    let pkg = with_plain_listed_row();
    assert!(classify(&pkg).unwrap().has_non_encrypted_entries);
    let (r, out) = rekey(&pkg, PASSWORD);
    assert!(
        matches!(r, Err(ReencryptError::PartiallyEncrypted)),
        "{r:?}"
    );
    assert!(out.is_empty(), "refused before writing");
}

/// Refusal (b): an unlisted member, at an ODF version where LibreOffice does
/// not refuse it.
#[test]
fn an_unlisted_member_is_refused_below_odf_12() {
    let pkg = with_unlisted_member();
    let class = classify(&pkg).unwrap();
    assert!(
        class.has_unexpected_streams && !class.odf12_fatal,
        "{class:?}"
    );
    let (r, out) = rekey(&pkg, PASSWORD);
    assert!(matches!(r, Err(ReencryptError::UnexpectedStreams)), "{r:?}");
    assert!(out.is_empty());
}

/// `lo-legacy-aes-cbc.odt` with `content.xml` and its manifest row both
/// removed: encrypted rows remain, none of them latches the package, and
/// there is no plain row and no unlisted member -- so refusal (c) alone
/// catches it. `unlatched_package()` also carries a plain row, which (a)
/// would catch first.
fn without_content() -> Vec<u8> {
    let golden = load_golden("lo-legacy-aes-cbc.odt");
    let mut src = ZipArchive::new(Cursor::new(&golden)).unwrap();
    let mut out = ZipWriter::new(Cursor::new(Vec::new()));
    for i in 0..src.len() {
        let name = src.by_index(i).unwrap().name().to_string();
        if name == "content.xml" {
            continue;
        }
        if name == MANIFEST_PATH {
            let mut xml = String::new();
            src.by_index(i).unwrap().read_to_string(&mut xml).unwrap();
            let start = xml
                .find(r#"<manifest:file-entry manifest:full-path="content.xml""#)
                .unwrap();
            let end = start
                + xml[start..].find("</manifest:file-entry>").unwrap()
                + "</manifest:file-entry>".len();
            let xml = format!("{}{}", &xml[..start], &xml[end..]);
            let opt = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            out.start_file(MANIFEST_PATH, opt).unwrap();
            out.write_all(xml.as_bytes()).unwrap();
        } else {
            out.raw_copy_file(src.by_index_raw(i).unwrap()).unwrap();
        }
    }
    out.finish().unwrap().into_inner()
}

/// Refusal (c): the unlatched shape -- encrypted rows, but none on
/// `content.xml`, so LibreOffice opens it without asking. Both fixtures: the
/// one only (c) can catch, and the one built for rc.9's decision.
#[test]
fn the_unlatched_shape_is_refused() {
    let only_c = without_content();
    let class = classify(&only_c).unwrap();
    assert!(
        !class.package_encrypted && !class.encrypted_entries.is_empty(),
        "{class:?}"
    );
    assert!(
        !class.has_non_encrypted_entries && !class.has_unexpected_streams,
        "{class:?}"
    );
    for pkg in [only_c, unlatched_package()] {
        let (r, _) = rekey(&pkg, PASSWORD);
        assert!(
            matches!(r, Err(ReencryptError::PartiallyEncrypted)),
            "{r:?}"
        );
    }
}

/// The refusals are `reencrypt_to`'s policy, not fidelity: every refused
/// package still decrypts, as LibreOffice still opens it.
#[test]
fn every_refused_package_still_decrypts() {
    for (name, pkg) in [
        ("plain listed row", with_plain_listed_row()),
        ("unlisted member", with_unlisted_member()),
        ("unlatched", unlatched_package()),
        ("no content.xml", without_content()),
    ] {
        let mut out = Vec::new();
        decrypt_to(Cursor::new(&pkg), &mut out, PASSWORD)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
}

/// A wholesome source is not screened that way: its tag covered every byte
/// it holds. An extra unlisted member under `META-INF/` -- where LibreOffice
/// keeps signatures -- does not stop the re-key, and is not carried over.
#[test]
fn a_wholesome_source_with_an_extra_meta_inf_member_still_rekeys() {
    let src = append_stored_member(
        &load_golden("lo-wholesome-gcm-argon2.odt"),
        "META-INF/documentsignatures.xml",
        b"<x/>",
    );
    assert_eq!(classify(&src).unwrap().mode, Mode::Wholesome);
    let (r, out) = rekey(&src, PASSWORD);
    r.unwrap();
    let names = crate::test_support::zip_namelist(&out);
    assert_eq!(names, ["mimetype", "encrypted-package", MANIFEST_PATH]);
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

/// A cancelling reader is `Io`, carrying the caller's error, at every call --
/// for both source shapes.
#[test]
fn a_cancelling_reader_is_io_at_every_call() {
    for src in [
        artifact("argon2-floor-1-8-1.odt"),
        load_golden("lo-legacy-aes-cbc.odt"),
    ] {
        let mut at = 1;
        loop {
            let reader = CancelsAt {
                inner: Cursor::new(src.clone()),
                calls: 0,
                at,
            };
            let r = reencrypt_to(
                reader,
                Cursor::new(Vec::new()),
                PASSWORD,
                NEW,
                DecryptLimits::default(),
                cheap(),
            );
            match r {
                Err(ReencryptError::Io(e)) => {
                    let inner = e.get_ref().expect("the caller's error");
                    assert!(inner.is::<Cancelled>(), "call {at}: {e}");
                }
                Ok(_) => break,
                Err(other) => panic!("call {at}: expected Io, got {other:?}"),
            }
            at += 1;
        }
    }
}

/// A failing writer is `Io` too, from either shape -- including the per-entry
/// one, where the failure surfaces deep inside the rebuild.
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
    for name in ["lo-wholesome-gcm-argon2.odt", "lo-legacy-aes-cbc.odt"] {
        let r = reencrypt_to(
            Cursor::new(load_golden(name)),
            Full,
            PASSWORD,
            NEW,
            DecryptLimits::default(),
            cheap(),
        );
        assert!(
            matches!(&r, Err(ReencryptError::Io(e)) if e.kind() == io::ErrorKind::StorageFull),
            "{name}: {r:?}"
        );
    }
}

/// Writes `reencrypt_to` outputs for the LibreOffice gate into the directory
/// named by `ODF_CRYPTO_LO_GATE_DIR`; they open there with `NEW`.
#[test]
#[ignore = "writes files for the LibreOffice gate"]
fn write_lo_gate_outputs() {
    let dir = std::path::PathBuf::from(std::env::var("ODF_CRYPTO_LO_GATE_DIR").unwrap());
    std::fs::create_dir_all(&dir).unwrap();
    for name in [
        "lo-wholesome-gcm-argon2.odt",
        "lo-legacy-aes-cbc.odt",
        "aoo-blowfish-pbkdf2.odt",
    ] {
        let mut out = Cursor::new(Vec::new());
        reencrypt_to(
            Cursor::new(load_golden(name)),
            &mut out,
            PASSWORD,
            NEW,
            DecryptLimits::default(),
            Argon2Params::LIBREOFFICE_DEFAULT,
        )
        .unwrap();
        std::fs::write(dir.join(format!("rekeyed-{name}")), out.into_inner()).unwrap();
    }
}
