//! `decrypt_to` holds a bounded amount of memory whatever the package
//! decrypts to (#93, S7 of `docs/plans/odf-streaming-2026-10-15.md`).
//!
//! A test binary of its own, because it installs a counting global allocator:
//! the peak it records is this process's, and nothing else may run beside it.
//! Every round-trip test elsewhere would still pass against a version that
//! held a whole member; only a memory bound tells streaming from buffering.
//!
//! Its tests hold one lock, so they never measure each other. Optimized is
//! quicker -- the payloads are large:
//!
//!     cargo test --release --features crypto-ops --test streaming_memory
//!
//! Modeled on EFV's `crates/efv-core/tests/sevenz_streaming_memory_tests.rs`.
//! `peak_alloc` stands in for that file's hand-written allocator because this
//! crate's `unsafe_code = "forbid"` covers test targets too.
#![cfg(feature = "crypto-ops")]

use std::io::{self, Cursor, Read, Write};

use aes::cipher::{BlockEncryptMut, KeyIvInit};
use odf_crypto::{
    classify, decrypt_to, encrypt_with_params, encrypt_with_params_to, reencrypt_to, Argon2Params,
    DecryptLimits, IntegrityOutcome, Mode,
};
use peak_alloc::PeakAlloc;
use sha2::{Digest, Sha256};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

#[global_allocator]
static PEAK: PeakAlloc = PeakAlloc;

const PASSWORD: &str = "password";
const MIB: u64 = 1024 * 1024;

/// What a phase may add to the heap. `decrypt_to`'s working set is a few
/// 64 KiB chunks, a 32 KiB inflate window, miniz's compressor and
/// decompressor state, and the zip central directory -- fixed, whatever the
/// member -- measured at 171 KiB wholesome, 444 KiB per-entry (rc.15; 180 and
/// 625 before the per-entry rebuild stopped recompressing). Holding a 256 MiB
/// member would need 64 times this.
const BOUND: usize = 4 * MIB as usize;

/// How far a phase's peak may move when its payload grows sixteenfold. A
/// streaming implementation's peak does not depend on the payload at all; the
/// slack absorbs the central directory and allocator noise.
const FLAT: usize = MIB as usize;

/// One phase at a time across the whole binary: the counters are global, and
/// `cargo test` runs tests in parallel by default. Every test here holds this
/// for its whole body.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run `f` and return how far the heap rose above its level at the start.
fn peak_rise(f: impl FnOnce()) -> usize {
    let start = PEAK.current_usage();
    PEAK.reset_peak_usage();
    f();
    PEAK.peak_usage().saturating_sub(start)
}

/// `n` bytes of a short repeating pattern: compresses to almost nothing, so the
/// package is small while its member inflates large. Allocates nothing.
struct Pattern(u64);
impl Read for Pattern {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (buf.len() as u64).min(self.0) as usize;
        for (i, b) in buf[..n].iter_mut().enumerate() {
            *b = b"odf-crypto streaming "[i % 21];
        }
        self.0 -= n as u64;
        Ok(n)
    }
}

/// `n` bytes of xorshift noise: does not compress, so the package is as large
/// as its plaintext and every cipher block is real work. Allocates nothing.
struct Noise(u64, u64);
impl Read for Noise {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (buf.len() as u64).min(self.0) as usize;
        for b in &mut buf[..n] {
            self.1 ^= self.1 << 13;
            self.1 ^= self.1 >> 7;
            self.1 ^= self.1 << 17;
            *b = self.1 as u8;
        }
        self.0 -= n as u64;
        Ok(n)
    }
}

const MIME: &[u8] = b"application/vnd.oasis.opendocument.text";

/// A plain ODF package whose `content.xml` is `body`, **stored**: so the
/// package itself is as large as the payload, and a wholesome package made
/// from it inflates to that size inside `decrypt_to`.
fn plain_package(body: &mut dyn Read) -> Vec<u8> {
    let manifest = br#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">
 <manifest:file-entry manifest:full-path="/" manifest:version="1.3" manifest:media-type="application/vnd.oasis.opendocument.text"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>"#;
    let mut w = ZipWriter::new(Cursor::new(Vec::new()));
    let opt = |m| {
        SimpleFileOptions::default()
            .compression_method(m)
            .large_file(true)
    };
    w.start_file("mimetype", opt(CompressionMethod::Stored))
        .unwrap();
    w.write_all(MIME).unwrap();
    w.start_file("META-INF/manifest.xml", opt(CompressionMethod::Deflated))
        .unwrap();
    w.write_all(manifest).unwrap();
    w.start_file("content.xml", opt(CompressionMethod::Stored))
        .unwrap();
    io::copy(body, &mut w).unwrap();
    w.finish().unwrap().into_inner()
}

/// The package current LibreOffice writes: wholesome AES-256-GCM, with the
/// cheapest Argon2id tuple so setup stays quick.
fn wholesome(body: &mut dyn Read) -> Vec<u8> {
    let params = Argon2Params::new(1, 8, 1).unwrap();
    encrypt_with_params(&plain_package(body), PASSWORD, params).unwrap()
}

fn b64(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A legacy per-entry package, built the way LibreOffice's ODF 1.2 writer
/// does: `content.xml` deflated, then AES-256-CBC under a PBKDF2 key from a
/// SHA-256 start key, with the SHA-256 digest of its first 1024 deflated bytes
/// in the manifest. Its shape matches `tests/goldens/lo-legacy-aes-cbc.odt`.
fn per_entry(body: &mut dyn Read, size: u64) -> Vec<u8> {
    let mut plain = Vec::new();
    body.read_to_end(&mut plain).unwrap();
    let mut deflated = miniz_oxide::deflate::compress_to_vec(&plain, 6);
    drop(plain);
    let checksum = Sha256::digest(&deflated[..deflated.len().min(1024)]);

    let (salt, iv) = ([7u8; 16], [9u8; 16]);
    let start_key = Sha256::digest(PASSWORD.as_bytes());
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(&start_key, &salt, 1, &mut key);
    let pad = 16 - deflated.len() % 16;
    deflated.extend(std::iter::repeat_n(pad as u8, pad));
    let mut enc = cbc::Encryptor::<aes::Aes256>::new_from_slices(&key, &iv).unwrap();
    for block in deflated.as_chunks_mut::<16>().0 {
        enc.encrypt_block_mut(cbc::cipher::Block::<aes::Aes256>::from_mut_slice(block));
    }

    let manifest = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">
 <manifest:file-entry manifest:full-path="/" manifest:version="1.2" manifest:media-type="application/vnd.oasis.opendocument.text"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml" manifest:size="{size}">
  <manifest:encryption-data manifest:checksum-type="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k" manifest:checksum="{}">
   <manifest:algorithm manifest:algorithm-name="http://www.w3.org/2001/04/xmlenc#aes256-cbc" manifest:initialisation-vector="{}"/>
   <manifest:start-key-generation manifest:start-key-generation-name="http://www.w3.org/2000/09/xmldsig#sha256" manifest:key-size="32"/>
   <manifest:key-derivation manifest:key-derivation-name="PBKDF2" manifest:iteration-count="1" manifest:salt="{}" manifest:key-size="32"/>
  </manifest:encryption-data>
 </manifest:file-entry>
</manifest:manifest>"#,
        b64(&checksum),
        b64(&iv),
        b64(&salt)
    );
    let mut w = ZipWriter::new(Cursor::new(Vec::new()));
    let opt = |m| {
        SimpleFileOptions::default()
            .compression_method(m)
            .large_file(true)
    };
    w.start_file("mimetype", opt(CompressionMethod::Stored))
        .unwrap();
    w.write_all(MIME).unwrap();
    w.start_file("META-INF/manifest.xml", opt(CompressionMethod::Deflated))
        .unwrap();
    w.write_all(manifest.as_bytes()).unwrap();
    w.start_file("content.xml", opt(CompressionMethod::Stored))
        .unwrap();
    w.write_all(&deflated).unwrap();
    w.finish().unwrap().into_inner()
}

/// Counts what it is given and keeps none of it: the output side must not be
/// what holds the payload either.
#[derive(Default)]
struct Count(u64);
impl Write for Count {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Decrypt `pkg` under a peak measurement. Success is itself the proof that
/// the payload went through: `decrypt_to` fails unless each member inflates
/// to exactly its `manifest:size`, and every `manifest:size` here is at least
/// the payload.
fn measured(pkg: &[u8], want_mode: Mode, want: IntegrityOutcome) -> usize {
    assert_eq!(classify(pkg).unwrap().mode, want_mode);
    let mut out = Count::default();
    let rise = peak_rise(|| {
        let outcome = decrypt_to(Cursor::new(pkg), &mut out, PASSWORD).unwrap();
        assert_eq!(outcome.integrity, want);
    });
    assert!(out.0 > 0);
    rise
}

/// Each phase stays under [`BOUND`], and its peak does not move when the
/// payload grows from 16 MiB to 256 MiB (pattern) or 8 MiB to 64 MiB (noise,
/// smaller only to keep setup quick).
///
/// Falsified, each recorded in the commit that added this file:
/// - `decrypt_stream::copy_out` collecting the inflated member into a `Vec`
///   before writing it: the wholesome phases pass `BOUND`.
/// - `zip_stream::ZipStreamWriter::deflated` doing the same: the per-entry
///   phases pass `BOUND`.
#[test]
fn decrypt_to_peak_heap_is_flat_in_the_payload() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    type Build = fn(&mut dyn Read, u64) -> Vec<u8>;
    let phases: [(&str, Build, Mode, IntegrityOutcome, bool); 4] = [
        (
            "wholesome, pattern",
            |r, _| wholesome(r),
            Mode::Wholesome,
            IntegrityOutcome::Verified,
            false,
        ),
        (
            "wholesome, noise",
            |r, _| wholesome(r),
            Mode::Wholesome,
            IntegrityOutcome::Verified,
            true,
        ),
        (
            "per-entry, pattern",
            per_entry,
            Mode::PerEntry,
            IntegrityOutcome::PasswordCheckOnly,
            false,
        ),
        (
            "per-entry, noise",
            per_entry,
            Mode::PerEntry,
            IntegrityOutcome::PasswordCheckOnly,
            true,
        ),
    ];
    for (name, build, mode, integrity, noise) in phases {
        let (small, large) = if noise {
            (8 * MIB, 64 * MIB)
        } else {
            (16 * MIB, 256 * MIB)
        };
        let mut rises = Vec::new();
        for n in [small, large] {
            let mut body: Box<dyn Read> = if noise {
                Box::new(Noise(n, 0x9E37_79B9_7F4A_7C15))
            } else {
                Box::new(Pattern(n))
            };
            let pkg = build(&mut body, n);
            let rise = measured(&pkg, mode, integrity);
            eprintln!(
                "{name}: {} MiB payload, peak rise {} KiB",
                n / MIB,
                rise / 1024
            );
            assert!(
                rise < BOUND,
                "{name}, {n} bytes: rose {rise}, bound {BOUND}"
            );
            rises.push(rise);
        }
        let drift = rises[1].abs_diff(rises[0]);
        assert!(
            drift < FLAT,
            "{name}: peak moved {drift} bytes with the payload"
        );
    }
}

/// A seekable sink that keeps nothing: it tracks the position and length the
/// zip writer needs to patch headers, and drops every byte.
#[derive(Default)]
struct CountSeek {
    pos: u64,
    len: u64,
}

impl Write for CountSeek {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pos += buf.len() as u64;
        self.len = self.len.max(self.pos);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Seek for CountSeek {
    fn seek(&mut self, to: io::SeekFrom) -> io::Result<u64> {
        self.pos = match to {
            io::SeekFrom::Start(n) => n,
            io::SeekFrom::End(d) => self.len.checked_add_signed(d).unwrap(),
            io::SeekFrom::Current(d) => self.pos.checked_add_signed(d).unwrap(),
        };
        Ok(self.pos)
    }
}

/// `encrypt_to` and `reencrypt_to` from both source shapes, under the same
/// bound and the same flatness as decrypt. The output goes to a sink that
/// keeps nothing, so whatever the heap holds is the implementation's.
///
/// Falsified, each recorded in the commit that added these phases:
/// - `encrypt_stream::pump` collecting the input before deflating it: the
///   encrypt phase passes `BOUND`.
/// - `reencrypt`'s tee collecting what it forwards: the wholesome re-key
///   phase passes `BOUND`.
#[test]
fn encrypt_and_reencrypt_peak_heap_is_flat_in_the_payload() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let cheap = Argon2Params::new(1, 8, 1).unwrap();
    for noise in [false, true] {
        let (small, large) = if noise {
            (8 * MIB, 64 * MIB)
        } else {
            (16 * MIB, 256 * MIB)
        };
        let body = |n: u64| -> Box<dyn Read> {
            if noise {
                Box::new(Noise(n, 0x2545_F491_4F6C_DD1D))
            } else {
                Box::new(Pattern(n))
            }
        };
        let kind = if noise { "noise" } else { "pattern" };
        let mut rises: [Vec<usize>; 3] = Default::default();
        for n in [small, large] {
            let plain = plain_package(&mut body(n));
            let rise = peak_rise(|| {
                encrypt_with_params_to(Cursor::new(&plain), CountSeek::default(), PASSWORD, cheap)
                    .unwrap();
            });
            drop(plain);
            rises[0].push(rise);

            for (slot, src) in [
                (1, wholesome(&mut body(n))),
                (2, per_entry(&mut body(n), n)),
            ] {
                let rise = peak_rise(|| {
                    reencrypt_to(
                        Cursor::new(&src),
                        CountSeek::default(),
                        PASSWORD,
                        "new",
                        DecryptLimits::default(),
                        cheap,
                    )
                    .unwrap();
                });
                rises[slot].push(rise);
            }
        }
        for (name, r) in [
            "encrypt_to",
            "reencrypt_to wholesome",
            "reencrypt_to per-entry",
        ]
        .iter()
        .zip(&rises)
        {
            eprintln!(
                "{name}, {kind}: peak rise {} KiB, then {} KiB",
                r[0] / 1024,
                r[1] / 1024
            );
            for &rise in r {
                assert!(rise < BOUND, "{name}, {kind}: rose {rise}, bound {BOUND}");
            }
            let drift = r[1].abs_diff(r[0]);
            assert!(
                drift < FLAT,
                "{name}, {kind}: peak moved {drift} bytes with the payload"
            );
        }
    }
}
