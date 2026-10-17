//! S3 and S4 (#89, #90): `decrypt_to` against the whole-buffer `decrypt`, on
//! every fixture the crate ships, and the behaviours only streaming has.

use super::*;

use std::io::Cursor;

use crate::classify::classify;
use crate::decrypt::decrypt;
use crate::test_support::{load_golden, NONASCII_PASSWORD, PASSWORD};

fn every_fixture() -> Vec<std::path::PathBuf> {
    let goldens = crate::test_support::goldens_dir();
    let mut out = Vec::new();
    for dir in ["goldens", "ladder", "artifacts"] {
        let dir = goldens.with_file_name(dir);
        let before = out.len();
        for entry in std::fs::read_dir(&dir).expect("fixture dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().is_some_and(|x| x == "odt") {
                out.push(path);
            }
        }
        assert!(out.len() > before, "no .odt under {dir:?}");
    }
    out
}

fn stream(bytes: &[u8], password: &str) -> (Result<DecryptOutcome, DecryptError>, Vec<u8>) {
    let mut out = Vec::new();
    let r = decrypt_to(Cursor::new(bytes), &mut out, password);
    (r, out)
}

/// Every member in order, with its contents, via the reader `decrypt`'s
/// callers use.
fn members(zip: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut z = ZipArchive::new(Cursor::new(zip)).unwrap();
    (0..z.len())
        .map(|i| {
            let mut f = z.by_index(i).unwrap();
            let mut body = Vec::new();
            f.read_to_end(&mut body).unwrap();
            (f.name().unwrap().to_string(), body)
        })
        .collect()
}

/// The equivalence the plan's S3 and S4 rows ask for, on the whole corpus:
///
/// - wholesome: the output is `decrypt`'s, **byte for byte**;
/// - per-entry: the same members, in the same order, with the same contents,
///   and `classify` says the same about both. Not byte for byte: the
///   streaming zip carries data descriptors.
/// - a package `decrypt` refuses, `decrypt_to` refuses with the same variant.
#[test]
fn decrypt_to_agrees_with_decrypt_on_every_fixture() {
    let mut decrypted = 0;
    for path in every_fixture() {
        let bytes = std::fs::read(&path).unwrap();
        let mode = classify(&bytes).map(|c| c.mode);
        for pw in [PASSWORD, NONASCII_PASSWORD] {
            let whole = decrypt(&bytes, pw);
            let (streamed, out) = stream(&bytes, pw);
            match (whole, streamed) {
                (Ok(whole), Ok(outcome)) => {
                    decrypted += 1;
                    if matches!(mode, Ok(Mode::Wholesome)) {
                        assert!(out == whole, "{path:?}: wholesome output differs");
                        assert_eq!(outcome.integrity, IntegrityOutcome::Verified);
                    } else {
                        assert_eq!(members(&out), members(&whole), "{path:?}");
                        assert_eq!(classify(&out).unwrap(), classify(&whole).unwrap());
                    }
                }
                (Err(a), Err(b)) => assert_eq!(
                    std::mem::discriminant(&a),
                    std::mem::discriminant(&b),
                    "{path:?} with {pw:?}: decrypt {a:?}, decrypt_to {b:?}"
                ),
                (a, b) => panic!("{path:?} with {pw:?}: decrypt {a:?}, decrypt_to {b:?}"),
            }
        }
    }
    assert!(
        decrypted >= 10,
        "only {decrypted} fixture/password pairs decrypted"
    );
}

#[test]
fn integrity_reports_what_was_checked() {
    for (name, want) in [
        ("lo-wholesome-gcm-argon2.odt", IntegrityOutcome::Verified),
        ("lo-legacy-aes-cbc.odt", IntegrityOutcome::PasswordCheckOnly),
        (
            "aoo-blowfish-pbkdf2.odt",
            IntegrityOutcome::PasswordCheckOnly,
        ),
    ] {
        let (r, _) = stream(&load_golden(name), PASSWORD);
        assert_eq!(r.unwrap().integrity, want, "{name}");
    }
}

/// Verify before release: under a wrong password a wholesome package writes
/// nothing at all, because the tag is checked in a pass that decrypts
/// nothing.
#[test]
fn a_wrong_password_writes_nothing_for_a_wholesome_package() {
    let (r, out) = stream(&load_golden("lo-wholesome-gcm-argon2.odt"), "wrong");
    assert!(matches!(r, Err(DecryptError::WrongPassword)), "{r:?}");
    assert!(out.is_empty(), "{} bytes written", out.len());
}

/// Flips one byte of the wholesome member the **second** time it is read,
/// as if the file changed between the verify and release passes.
struct ChangesOnSecondPass {
    inner: Cursor<Vec<u8>>,
    at: u64,
    reads_over_it: usize,
}

impl Read for ChangesOnSecondPass {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let start = self.inner.position();
        let n = self.inner.read(buf)?;
        if (start..start + n as u64).contains(&self.at) {
            self.reads_over_it += 1;
            if self.reads_over_it >= 2 {
                buf[(self.at - start) as usize] ^= 0x01;
            }
        }
        Ok(n)
    }
}

impl Seek for ChangesOnSecondPass {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// The call fails, so the caller discards what was written. Which layer
/// notices first depends on what changed: the zip layer's CRC over the member
/// usually does (`Zip`), and the recomputed GCM tag is the backstop beneath it
/// (`Io` of kind `InvalidData`) -- exercised directly by
/// `stream::tests::gcm_release_pass_reports_input_changed_between_passes`.
#[test]
fn input_changed_between_passes_fails_the_call() {
    let bytes = load_golden("lo-wholesome-gcm-argon2.odt");
    let at = {
        let mut z = ZipArchive::new(Cursor::new(&bytes)).unwrap();
        let f = z.by_name("encrypted-package").unwrap();
        f.data_start().unwrap() + 100
    };
    let reader = ChangesOnSecondPass {
        inner: Cursor::new(bytes),
        at,
        reads_over_it: 0,
    };
    let err = decrypt_to(reader, io::sink(), PASSWORD).unwrap_err();
    match err {
        DecryptError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}"),
        DecryptError::Zip(_) => {}
        other => panic!("expected Zip or Io(InvalidData), got {other:?}"),
    }
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
/// own error, for every N until the call completes -- in both modes. The
/// Argon2 floor artifact keeps the wholesome derivations cheap.
#[test]
fn a_cancelling_reader_is_io_at_every_call() {
    for (bytes, pw) in [
        (
            std::fs::read(
                crate::test_support::goldens_dir()
                    .with_file_name("artifacts")
                    .join("argon2-floor-1-8-1.odt"),
            )
            .unwrap(),
            PASSWORD,
        ),
        (load_golden("lo-legacy-aes-cbc.odt"), PASSWORD),
    ] {
        let mut at = 1;
        loop {
            let reader = CancelsAt {
                inner: Cursor::new(bytes.clone()),
                calls: 0,
                at,
            };
            match decrypt_to(reader, io::sink(), pw) {
                Err(DecryptError::Io(e)) => {
                    let inner = e.get_ref().expect("the caller's error");
                    assert!(inner.is::<Cancelled>(), "call {at}: {e}");
                }
                Ok(_) => {
                    assert!(at > 1);
                    break;
                }
                Err(other) => panic!("call {at}: expected Io, got {other:?}"),
            }
            at += 1;
        }
    }
}

/// A writer failure is the caller's too, and comes back as `Io`.
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
    for name in ["lo-wholesome-gcm-argon2.odt", "lo-legacy-aes-cbc.odt"] {
        let err = decrypt_to(Cursor::new(load_golden(name)), Full, PASSWORD).unwrap_err();
        assert!(
            matches!(&err, DecryptError::Io(e) if e.kind() == io::ErrorKind::StorageFull),
            "{name}: {err:?}"
        );
    }
}

/// `max_output_bytes` holds for the streaming path too, before derivation.
#[test]
fn the_output_limit_holds_in_both_modes() {
    for name in ["lo-wholesome-gcm-argon2.odt", "lo-legacy-aes-cbc.odt"] {
        let limits = DecryptLimits::default().with_max_output_bytes(10);
        let err =
            decrypt_with_limits_to(Cursor::new(load_golden(name)), io::sink(), "wrong", limits)
                .unwrap_err();
        assert!(
            matches!(err, DecryptError::OutputLimit { limit: 10 }),
            "{name}: {err:?}"
        );
    }
}

/// Writes each fixture's `decrypt_to` output beside `decrypt`'s, for the
/// LibreOffice gate (`tests/goldens/validate_decrypt_to.py`), into the
/// directory named by `ODF_CRYPTO_LO_GATE_DIR`. Not a check by itself.
#[test]
#[ignore = "writes files for the LibreOffice gate; see validate_decrypt_to.py"]
fn write_lo_gate_outputs() {
    let dir = std::path::PathBuf::from(
        std::env::var("ODF_CRYPTO_LO_GATE_DIR").expect("ODF_CRYPTO_LO_GATE_DIR"),
    );
    std::fs::create_dir_all(&dir).unwrap();
    for path in every_fixture() {
        let bytes = std::fs::read(&path).unwrap();
        let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
        for pw in [PASSWORD, NONASCII_PASSWORD] {
            if let Ok(whole) = decrypt(&bytes, pw) {
                let (r, out) = stream(&bytes, pw);
                r.unwrap();
                std::fs::write(dir.join(format!("{stem}.whole.odt")), whole).unwrap();
                std::fs::write(dir.join(format!("{stem}.streamed.odt")), out).unwrap();
            }
        }
    }
}

/// Damage at the very end of an encrypted member -- past the checked 1K, in
/// the block that carries the CBC padding -- fails `decrypt_to` as it fails
/// `decrypt`. The streaming path must read each member to its end after the
/// inflater stops, or this damage would go unseen.
#[test]
fn damage_at_a_member_end_fails_both_paths_alike() {
    let golden = load_golden("lo-legacy-aes-cbc.odt");
    let class = classify(&golden).unwrap();
    let mut z = ZipArchive::new(Cursor::new(&golden)).unwrap();
    let mut checked = 0;
    for row in &class.encrypted_entries {
        let end = {
            let f = z.by_name(&row.path).unwrap();
            f.data_start().unwrap() + f.compressed_size() - 1
        };
        let mut bad = golden.clone();
        bad[end as usize] ^= 0x5a;
        let whole = decrypt(&bad, PASSWORD).unwrap_err();
        let (streamed, _) = stream(&bad, PASSWORD);
        let streamed = streamed.unwrap_err();
        assert_eq!(
            std::mem::discriminant(&whole),
            std::mem::discriminant(&streamed),
            "{}: decrypt {whole:?}, decrypt_to {streamed:?}",
            row.path
        );
        checked += 1;
    }
    assert!(checked > 0);
}

/// The drain after inflating a CBC or Blowfish member is what reads the
/// member to its end, where the zip layer checks its CRC. CBC reaches the end
/// regardless, because it holds its last block back until then; Blowfish
/// holds nothing back. So: a Blowfish member with more than a chunk of bytes
/// after its DEFLATE end marker, and a zip CRC that no longer matches. The
/// whole-buffer path reads every byte and refuses it; so must this one.
#[test]
fn a_bad_crc_past_the_deflate_end_is_caught_on_blowfish() {
    use blowfish::Blowfish;
    use cbc::cipher::KeyIvInit as _;
    use cfb_mode::{BufDecryptor, BufEncryptor};
    use secure_gate::RevealSecret as _;

    let golden = load_golden("aoo-blowfish-pbkdf2.odt");
    let class = classify(&golden).unwrap();
    let row = class
        .encrypted_entries
        .iter()
        .find(|r| r.path == "content.xml")
        .unwrap();
    let mut z = ZipArchive::new(Cursor::new(&golden)).unwrap();
    let index = z.index_for_name("content.xml").unwrap();
    let key = crate::decrypt_entries::checksum_key(
        &mut z,
        index,
        row,
        PASSWORD,
        &DecryptLimits::default(),
    )
    .unwrap();
    let mut body = Vec::new();
    z.by_index(index).unwrap().read_to_end(&mut body).unwrap();

    // Decrypt, add more than one chunk after the DEFLATE end, re-encrypt.
    key.with_secret(|k| {
        let mut dec = BufDecryptor::<Blowfish>::new_from_slices(k, &row.iv).unwrap();
        dec.decrypt(&mut body);
        body.extend(std::iter::repeat_n(0xA5u8, crate::stream::CHUNK + 4096));
        BufEncryptor::<Blowfish>::new_from_slices(k, &row.iv)
            .unwrap()
            .encrypt(&mut body);
    });

    // Rebuild the package with that member, then make its CRC wrong.
    let mut out = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for i in 0..z.len() {
        let f = z.by_index_raw(i).unwrap();
        if f.name().unwrap() == "content.xml" {
            let opt = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            drop(f);
            out.start_file("content.xml", opt).unwrap();
            out.write_all(&body).unwrap();
        } else {
            out.raw_copy_file(f).unwrap();
        }
    }
    let mut pkg = out.finish().unwrap().into_inner();
    let local = {
        let mut z = ZipArchive::new(Cursor::new(&pkg)).unwrap();
        let f = z.by_name("content.xml").unwrap();
        f.header_start() as usize
    };
    pkg[local + 14] ^= 0xFF;
    let name = b"content.xml";
    let cen = (0..pkg.len() - 4)
        .find(|&i| pkg[i..i + 4] == [0x50, 0x4b, 0x01, 0x02] && pkg[i + 46..].starts_with(name))
        .unwrap();
    pkg[cen + 16] ^= 0xFF;

    assert!(matches!(decrypt(&pkg, PASSWORD), Err(DecryptError::Zip(_))));
    let (streamed, _) = stream(&pkg, PASSWORD);
    assert!(
        matches!(streamed, Err(DecryptError::Zip(_))),
        "{streamed:?}"
    );
}
