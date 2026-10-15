//! The streaming zip writer against `zip` 2.4.2's own writer, against
//! `classify`, and at the Zip64 boundaries. Conditions (1)-(3) of the zip
//! writer decision, `docs/plans/odf-streaming-2026-10-15.md` §7.

use super::*;

use std::io::Cursor;

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::classify::classify;
use crate::DetectError;

const MIME: &[u8] = b"application/vnd.oasis.opendocument.text";
const MANIFEST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">
 <manifest:file-entry manifest:full-path="/" manifest:version="1.3" manifest:media-type="application/vnd.oasis.opendocument.text"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
</manifest:manifest>"#;

fn content() -> Vec<u8> {
    b"<office:document-content>hello hello hello world</office:document-content>".repeat(40)
}

/// The same package from both writers: `mimetype` stored, the manifest and
/// `content.xml` deflated, and a stored member with a non-ASCII name.
fn both() -> (Vec<u8>, Vec<u8>) {
    let picture = b"\x89PNG not really".to_vec();
    let entries: Vec<(&str, bool, Vec<u8>)> = vec![
        ("mimetype", false, MIME.to_vec()),
        ("META-INF/manifest.xml", true, MANIFEST.to_vec()),
        ("content.xml", true, content()),
        ("Pictures/é.png", false, picture),
    ];

    let mut theirs = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, deflate, body) in &entries {
        let method = if *deflate {
            CompressionMethod::Deflated
        } else {
            CompressionMethod::Stored
        };
        theirs
            .start_file(
                *name,
                SimpleFileOptions::default().compression_method(method),
            )
            .unwrap();
        theirs.write_all(body).unwrap();
    }
    let theirs = theirs.finish().unwrap().into_inner();

    let mut ours = ZipStreamWriter::new(Vec::new());
    for (name, deflate, body) in &entries {
        if *deflate {
            ours.deflated(name, body.len() as u64, &mut body.as_slice())
                .unwrap();
        } else {
            let crc = crc32fast::hash(body);
            ours.stored(name, crc, body.len() as u64, &mut body.as_slice())
                .unwrap();
        }
    }
    (ours.finish().unwrap(), theirs)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Local {
    needed: u16,
    flags: u16,
    method: u16,
    time: u16,
    date: u16,
    crc: u32,
    csize: u32,
    usize: u32,
    name: Vec<u8>,
    extra: Vec<u8>,
    data: Vec<u8>,
    descriptor: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cen {
    made_by: u16,
    needed: u16,
    flags: u16,
    method: u16,
    time: u16,
    date: u16,
    crc: u32,
    csize: u32,
    usize: u32,
    name: Vec<u8>,
    extra: Vec<u8>,
    external: u32,
    offset: u32,
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}
fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}

/// A deliberately small parser: the comparison below must not trust either
/// writer's own reader.
fn parse(b: &[u8]) -> (Vec<Local>, Vec<Cen>) {
    let (mut locals, mut cens) = (Vec::new(), Vec::new());
    let mut i = 0;
    loop {
        match u32_at(b, i) {
            LOCAL => {
                let flags = u16_at(b, i + 6);
                let (n, x) = (u16_at(b, i + 26) as usize, u16_at(b, i + 28) as usize);
                let name = b[i + 30..i + 30 + n].to_vec();
                let extra = b[i + 30 + n..i + 30 + n + x].to_vec();
                let start = i + 30 + n + x;
                let csize = u32_at(b, i + 18);
                let (data, descriptor, next) = if flags & FLAG_DESCRIPTOR != 0 {
                    // Find the descriptor: the data runs up to its signature.
                    let rel = b[start..]
                        .windows(4)
                        .position(|w| w == DESCRIPTOR.to_le_bytes())
                        .unwrap();
                    let d = start + rel;
                    (b[start..d].to_vec(), Some(b[d..d + 16].to_vec()), d + 16)
                } else {
                    let end = start + csize as usize;
                    (b[start..end].to_vec(), None, end)
                };
                locals.push(Local {
                    needed: u16_at(b, i + 4),
                    flags,
                    method: u16_at(b, i + 8),
                    time: u16_at(b, i + 10),
                    date: u16_at(b, i + 12),
                    crc: u32_at(b, i + 14),
                    csize,
                    usize: u32_at(b, i + 22),
                    name,
                    extra,
                    data,
                    descriptor,
                });
                i = next;
            }
            CENTRAL => {
                let (n, x, c) = (
                    u16_at(b, i + 28) as usize,
                    u16_at(b, i + 30) as usize,
                    u16_at(b, i + 32) as usize,
                );
                cens.push(Cen {
                    made_by: u16_at(b, i + 4),
                    needed: u16_at(b, i + 6),
                    flags: u16_at(b, i + 8),
                    method: u16_at(b, i + 10),
                    time: u16_at(b, i + 12),
                    date: u16_at(b, i + 14),
                    crc: u32_at(b, i + 16),
                    csize: u32_at(b, i + 20),
                    usize: u32_at(b, i + 24),
                    name: b[i + 46..i + 46 + n].to_vec(),
                    extra: b[i + 46 + n..i + 46 + n + x].to_vec(),
                    external: u32_at(b, i + 38),
                    offset: u32_at(b, i + 42),
                });
                i += 46 + n + x + c;
            }
            END => return (locals, cens),
            other => panic!("unexpected signature {other:#x} at {i}"),
        }
    }
}

/// Condition (2): every byte that differs from `zip` 2.4.2's output is named.
/// The only differences allowed are the ones a writer that cannot seek must
/// make on a **deflated** member: bit 3 set, zero CRC and sizes in its local
/// header, a 16-byte data descriptor after it -- and the later offsets that
/// descriptor shifts. Everything else, the DEFLATE data included, is equal.
#[test]
fn every_difference_from_zip_242_is_a_data_descriptor() {
    let (ours, theirs) = both();
    let (ol, oc) = parse(&ours);
    let (tl, tc) = parse(&theirs);
    assert_eq!(ol.len(), tl.len());
    let mut shift = 0u32;
    for (i, (o, t)) in ol.iter().zip(&tl).enumerate() {
        let mut expect = t.clone();
        if t.method == DEFLATED {
            expect.flags |= FLAG_DESCRIPTOR;
            expect.crc = 0;
            expect.csize = 0;
            expect.usize = 0;
            let mut d = DESCRIPTOR.to_le_bytes().to_vec();
            d.extend_from_slice(&t.crc.to_le_bytes());
            d.extend_from_slice(&t.csize.to_le_bytes());
            d.extend_from_slice(&t.usize.to_le_bytes());
            expect.descriptor = Some(d);
        }
        assert_eq!(o, &expect, "local header {i}");

        let mut cen = tc[i].clone();
        cen.offset += shift;
        if t.method == DEFLATED {
            cen.flags |= FLAG_DESCRIPTOR;
            shift += 16;
        }
        assert_eq!(oc[i], cen, "central entry {i}");
    }
    // The end record differs only in where the directory starts.
    let (oe, te) = (&ours[ours.len() - 22..], &theirs[theirs.len() - 22..]);
    assert_eq!(oe[..16], te[..16]);
    assert_eq!(u32_at(oe, 16), u32_at(te, 16) + shift);
    assert_eq!(oe[20..], te[20..]);
}

/// Condition (2): the output reads back through `zip` 2.4.2 with every
/// member's CRC checked, and `classify` accepts it.
#[test]
fn the_output_reads_back_through_zip_and_classify() {
    let (ours, _) = both();
    let mut z = ZipArchive::new(Cursor::new(&ours)).unwrap();
    for (name, want) in [
        ("mimetype", MIME.to_vec()),
        ("content.xml", content()),
        ("META-INF/manifest.xml", MANIFEST.to_vec()),
    ] {
        let mut body = Vec::new();
        z.by_name(name).unwrap().read_to_end(&mut body).unwrap();
        assert_eq!(body, want, "{name}");
    }
    let class = classify(&ours).unwrap();
    assert_eq!(class.mode, crate::Mode::Plain);
}

/// Condition (1): `mimetype` is first, stored, with its CRC and sizes in the
/// local header, no data descriptor and no extra field.
#[test]
fn mimetype_is_written_as_odf_requires() {
    let (ours, _) = both();
    let (locals, _) = parse(&ours);
    let m = &locals[0];
    assert_eq!(m.name, b"mimetype");
    assert_eq!(m.method, STORED);
    assert_eq!(m.flags & FLAG_DESCRIPTOR, 0);
    assert!(m.extra.is_empty());
    assert_eq!(m.crc, crc32fast::hash(MIME));
    assert_eq!((m.csize, m.usize), (MIME.len() as u32, MIME.len() as u32));
    assert_eq!(&ours[30..30 + 8], b"mimetype");
}

/// Condition (1), the other half: were `mimetype` ever written with bit 3,
/// `classify` refuses the package, as LibreOffice refuses a stored member
/// with a data descriptor. The bit is set by hand in both headers.
#[test]
fn a_mimetype_with_a_data_descriptor_is_caught() {
    let (mut ours, _) = both();
    ours[6] |= FLAG_DESCRIPTOR as u8;
    let cen = ours
        .windows(4)
        .position(|w| w == CENTRAL.to_le_bytes())
        .unwrap();
    ours[cen + 8] |= FLAG_DESCRIPTOR as u8;
    let err = classify(&ours).unwrap_err();
    assert!(matches!(err, DetectError::Zip(_)), "{err:?}");
}

/// A stored member whose bytes do not match the CRC it was promised is an
/// error, not a silently wrong zip.
#[test]
fn a_stored_member_with_the_wrong_crc_is_refused() {
    let mut w = ZipStreamWriter::new(Vec::new());
    match w.stored("x", 0xdead_beef, 3, &mut &b"abc"[..]) {
        Err(ZipStreamError::Corrupt(m)) => assert!(m.contains("CRC"), "{m}"),
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

/// Discards bytes but counts them, keeping only what lies outside `skip`:
/// the headers of a multi-gigabyte zip, without the gigabytes.
struct Sparse {
    pos: u64,
    skip: std::ops::Range<u64>,
    kept: Vec<(u64, u8)>,
}

impl Write for Sparse {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for (i, &b) in buf.iter().enumerate() {
            let at = self.pos + i as u64;
            if !self.skip.contains(&at) {
                self.kept.push((at, b));
            }
        }
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Zeros, without allocating them.
struct Zeros(u64);
impl Read for Zeros {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (buf.len() as u64).min(self.0) as usize;
        buf[..n].fill(0);
        self.0 -= n as u64;
        Ok(n)
    }
}

/// CRC-32 of `n` zero bytes, without hashing them: the combine operation.
fn crc_of_zeros(n: u64) -> u32 {
    let mut h = crc32fast::Hasher::new();
    let block = vec![0u8; 1 << 20];
    let mut left = n;
    while left > 0 {
        let k = left.min(block.len() as u64) as usize;
        h.update(&block[..k]);
        left -= k as u64;
    }
    h.finalize()
}

/// Condition (3), both 4 GiB boundaries, without writing 4 GiB: a stored
/// member past `u32::MAX` (its sizes go to Zip64), then a member whose offset
/// is past it, then a central directory that starts past it. Ignored by
/// default because hashing 4 GiB of zeros takes most of a minute unoptimised;
/// run with `cargo test --release -- --ignored zip64`.
#[test]
#[ignore = "hashes 4 GiB; run with --release -- --ignored zip64"]
fn zip64_at_both_boundaries() {
    let big = U32_LIMIT + 10;
    let crc = crc_of_zeros(big);
    let header = 30 + 3 + 20; // "big", Zip64 extra
    let mut w = ZipStreamWriter::new(Sparse {
        pos: 0,
        skip: header..header + big,
        kept: Vec::new(),
    });
    w.stored("big", crc, big, &mut Zeros(big)).unwrap();
    let small = b"after the boundary".repeat(10);
    w.deflated("small", small.len() as u64, &mut small.as_slice())
        .unwrap();
    let sink = w.finish().unwrap();
    let kept: Vec<u8> = sink.kept.iter().map(|&(_, b)| b).collect();

    // The big member's local header: 0xFFFFFFFF sizes, Zip64 extra with both.
    assert_eq!(u32_at(&kept, 18), u32::MAX);
    assert_eq!(u32_at(&kept, 22), u32::MAX);
    assert_eq!(u16_at(&kept, 33), ZIP64_TAG);
    assert_eq!(u64::from_le_bytes(kept[37..45].try_into().unwrap()), big);

    // The end records: a Zip64 end record, its locator, then a classic end
    // record whose directory offset is 0xFFFFFFFF.
    let end = kept.len() - 22;
    assert_eq!(u32_at(&kept, end), END);
    assert_eq!(u32_at(&kept, end + 16), u32::MAX);
    let locator = end - 20;
    assert_eq!(u32_at(&kept, locator), LOCATOR64);
    let end64 = locator - 56;
    assert_eq!(u32_at(&kept, end64), END64);
    let cd_start = u64::from_le_bytes(kept[end64 + 48..end64 + 56].try_into().unwrap());
    assert!(cd_start > U32_LIMIT);

    // The second member's central entry carries only its offset in Zip64.
    let positions: Vec<u64> = sink.kept.iter().map(|&(p, _)| p).collect();
    let cd_at = positions.iter().position(|&p| p == cd_start).unwrap();
    let first = &kept[cd_at..];
    let second = 46 + 3 + u16_at(first, 30) as usize;
    let second = &first[second..];
    assert_eq!(&second[46..51], b"small");
    assert_eq!(u32_at(second, 42), u32::MAX, "offset moved to Zip64");
    assert_eq!(u16_at(second, 30), 12, "extra = tag + len + one u64");
    let offset = u64::from_le_bytes(second[51 + 4..51 + 12].try_into().unwrap());
    assert!(offset > U32_LIMIT);
}

/// The Zip64 decision for a deflated member is made from the size it is told,
/// before any data: past the bound, the local header carries the Zip64 extra
/// and the descriptor uses 8-byte sizes. Small, so it always runs.
#[test]
fn a_deflated_member_that_could_pass_4_gib_is_zip64_from_the_start() {
    let mut w = ZipStreamWriter::new(Vec::new());
    let body = b"tiny";
    w.deflated("claimed-big", U32_LIMIT, &mut &body[..])
        .unwrap();
    let out = w.finish().unwrap();
    assert_eq!(u16_at(&out, 4), 45, "version needed");
    assert_eq!(u16_at(&out, 28), 20, "Zip64 extra present");
    assert_eq!(u16_at(&out, 30 + 11), ZIP64_TAG);
    // And it still reads back.
    let mut z = ZipArchive::new(Cursor::new(&out)).unwrap();
    let mut got = Vec::new();
    z.by_index(0).unwrap().read_to_end(&mut got).unwrap();
    assert_eq!(got, body);
}

#[test]
fn deflate_bound_is_above_the_worst_case() {
    // Incompressible input is stored blocks; miniz's output must fit.
    let mut x = 0x2545_F491_4F6C_DD1Du64;
    let noise: Vec<u8> = (0..300_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    let out = miniz_oxide::deflate::compress_to_vec(&noise, 6);
    assert!((out.len() as u64) <= deflate_bound(noise.len() as u64));
}

/// Condition (3), the real run: a zip past 4 GiB on disk, read back through
/// `zip` 2.4.2 with both members' CRCs checked. Measured on the dev machine
/// (release): see the commit that added it. Ignored by default: it writes
/// and reads 4 GiB.
#[test]
#[ignore = "writes 4 GiB to the temp dir; run with --release -- --ignored real_zip64"]
fn real_zip64_file_reads_back_through_zip() {
    let path = std::env::temp_dir().join("odf-crypto-real-zip64.zip");
    let big = U32_LIMIT + 10;
    let crc = crc_of_zeros(big);
    let small = b"after the boundary".repeat(10);
    {
        let file = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        let mut w = ZipStreamWriter::new(file);
        w.stored("big", crc, big, &mut Zeros(big)).unwrap();
        w.deflated("small", small.len() as u64, &mut small.as_slice())
            .unwrap();
        w.finish().unwrap().flush().unwrap();
    }
    let result = (|| {
        let mut z = ZipArchive::new(std::fs::File::open(&path)?)?;
        let mut got = Vec::new();
        z.by_name("small")?.read_to_end(&mut got)?;
        assert_eq!(got, small);
        let n = io::copy(&mut z.by_name("big")?, &mut io::sink())?;
        assert_eq!(n, big);
        Ok::<_, Box<dyn std::error::Error>>(())
    })();
    let _ = std::fs::remove_file(&path);
    result.unwrap();
}

/// A failing source and a failing output stay distinguishable, carrying the
/// caller's own errors: `decrypt_to` maps the first to the member and the
/// second to `Io`.
#[test]
fn source_and_output_failures_are_kept_apart() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::ConnectionReset, "source"))
        }
    }
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::StorageFull, "output"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut w = ZipStreamWriter::new(Vec::new());
    match w.deflated("x", 10, &mut Broken) {
        Err(ZipStreamError::Read(e)) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
        other => panic!("expected Read, got {other:?}"),
    }
    let mut w = ZipStreamWriter::new(Broken);
    match w.stored("x", 0, 0, &mut io::empty()) {
        Err(ZipStreamError::Write(e)) => assert_eq!(e.kind(), io::ErrorKind::StorageFull),
        other => panic!("expected Write, got {other:?}"),
    }
}
