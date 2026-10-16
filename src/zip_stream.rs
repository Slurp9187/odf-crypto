//! A zip writer for an output that cannot seek.
//!
//! `zip` 2.4.2, which this crate used through rc.10, writes only to
//! `Write + Seek`: it seeks back to patch each local header once a member's
//! CRC and sizes are known. Two outputs here cannot seek -- `decrypt_to`'s
//! per-entry rebuild, whose writer is `Write` only, and `reencrypt_to`'s inner
//! package, which lives inside a cipher stream -- so this writes the other way
//! the format allows. Reading stays on `zip`, now 8.6.0, which does have
//! `ZipWriter::new_stream`; moving to it is a separate decision, not part of
//! the version port that brought it into reach.
//! See `docs/plans/odf-streaming-2026-10-15.md`, §7.
//!
//! # Two kinds of member
//!
//! - **Stored, sizes known**: CRC and sizes go in the local header and general
//!   purpose bit 3 is clear. Used for every stored member, `mimetype` above all:
//!   ODF wants it first, stored, with no extra field, and LibreOffice refuses a
//!   stored member that carries a data descriptor (`classify`'s
//!   `check_stored_data_descriptors`).
//! - **Deflated, sizes learned at the end**: bit 3 set, zeros in the local
//!   header, and a data descriptor after the data. LibreOffice reads these
//!   (`ZipFile.cxx:1047, 1634, 1763`).
//!
//! # Matching `zip`'s writer
//!
//! Every field this writer shares with `zip`'s own output takes the value
//! that crate writes, measured from 2.4.2's output and held under 8.6.0 by
//! [`file_options`] and the `flate2` backend `Cargo.toml` names: version
//! needed 10 (stored) or 20 (deflated), 45 with Zip64; made-by Unix (`3 << 8 | needed`); time 0, date
//! 1980-01-01; bit 11 (UTF-8) exactly when the name is not ASCII; external
//! attributes `0o100644 << 16`; no extra field unless Zip64 needs one. The
//! DEFLATE data is level 6 raw, the same as `zip`'s. `zip_stream_tests.rs`
//! compares the two writers byte by byte and names each difference.
//!
//! # Zip64
//!
//! A stored member whose size reaches `u32::MAX` gets a Zip64 extra field with
//! both sizes in its local header. A deflated member that *could* reach it is
//! decided up front, from its uncompressed size and a bound on DEFLATE's
//! expansion: its local header then carries a Zip64 extra field and its data
//! descriptor uses 8-byte sizes, as APPNOTE 4.3.9.2 requires. The central
//! directory and the end records switch to Zip64 per field, past `u32::MAX`
//! offsets and `u16::MAX` entries.

use std::io::{self, Read, Write};

use secure_gate::{RevealSecret, RevealSecretMut};

use crate::stream::{chunk_buffer, DeflateWriter, CHUNK};

const LOCAL: u32 = 0x0403_4b50;
const DESCRIPTOR: u32 = 0x0807_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const END: u32 = 0x0605_4b50;
const END64: u32 = 0x0606_4b50;
const LOCATOR64: u32 = 0x0706_4b50;

const STORED: u16 = 0;
const DEFLATED: u16 = 8;
const FLAG_DESCRIPTOR: u16 = 1 << 3;
const FLAG_UTF8: u16 = 1 << 11;
const MADE_BY_UNIX: u16 = 3 << 8;
const EXTERNAL_ATTRIBUTES: u32 = 0o100_644 << 16;
/// 1980-01-01 in MS-DOS date format, with time 0: `zip`'s default when
/// built without its `time` feature, as it is here.
/// Year 0 (1980) in bits 9-15, month 1 in bits 5-8, day 1 in bits 0-4.
const DOS_DATE: u16 = (1 << 5) | 1;
const ZIP64_TAG: u16 = 0x0001;

/// Past this, a 32-bit field holds `0xFFFF_FFFF` and the value moves to Zip64.
const U32_LIMIT: u64 = u32::MAX as u64;

/// Why a member could not be written.
#[derive(Debug)]
pub(crate) enum ZipStreamError {
    /// The member's source failed; the caller decides what that means.
    Read(io::Error),
    /// The output failed.
    Write(io::Error),
    /// The source did not match what its header promised.
    Corrupt(String),
}

struct Central {
    name: Vec<u8>,
    method: u16,
    flags: u16,
    crc: u32,
    compressed: u64,
    uncompressed: u64,
    offset: u64,
    /// The local header carried a Zip64 extra field.
    zip64_local: bool,
}

/// Writes counted bytes to `out`.
struct Counting<'a, W: Write> {
    out: &'a mut W,
    written: u64,
}

impl<W: Write> Write for Counting<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.out.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

pub(crate) struct ZipStreamWriter<W: Write> {
    out: W,
    pos: u64,
    entries: Vec<Central>,
}

/// An upper bound on raw DEFLATE's output for `n` input bytes. The worst case
/// is stored blocks: 5 bytes of header per 65,535 bytes, plus the final block.
/// Doubled per block and padded, so it errs high: a high guess costs a Zip64
/// extra field nobody needed; a low one would be a corrupt descriptor.
pub(crate) fn deflate_bound(n: u64) -> u64 {
    n.saturating_add((n / 65_535 + 1).saturating_mul(10))
        .saturating_add(64)
}

fn needed(method: u16, zip64: bool) -> u16 {
    if zip64 {
        45
    } else if method == DEFLATED {
        20
    } else {
        10
    }
}

fn name_flags(name: &[u8]) -> u16 {
    if name.is_ascii() {
        0
    } else {
        FLAG_UTF8
    }
}

impl<W: Write> ZipStreamWriter<W> {
    pub(crate) fn new(out: W) -> Self {
        Self {
            out,
            pos: 0,
            entries: Vec::new(),
        }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), ZipStreamError> {
        self.out.write_all(bytes).map_err(ZipStreamError::Write)?;
        self.pos += bytes.len() as u64;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn local_header(
        &mut self,
        name: &[u8],
        method: u16,
        flags: u16,
        crc: u32,
        compressed: u64,
        uncompressed: u64,
        zip64: bool,
    ) -> Result<(), ZipStreamError> {
        let mut h = Vec::with_capacity(30 + name.len() + 20);
        h.extend_from_slice(&LOCAL.to_le_bytes());
        h.extend_from_slice(&needed(method, zip64).to_le_bytes());
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&method.to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes()); // time
        h.extend_from_slice(&DOS_DATE.to_le_bytes());
        h.extend_from_slice(&crc.to_le_bytes());
        let (c32, u32_) = if zip64 {
            (u32::MAX, u32::MAX)
        } else {
            (compressed as u32, uncompressed as u32)
        };
        h.extend_from_slice(&c32.to_le_bytes());
        h.extend_from_slice(&u32_.to_le_bytes());
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&(if zip64 { 20u16 } else { 0 }).to_le_bytes());
        h.extend_from_slice(name);
        if zip64 {
            // APPNOTE 4.5.3: in a local header both sizes are present, the
            // uncompressed first; with bit 3 they are zero here.
            h.extend_from_slice(&ZIP64_TAG.to_le_bytes());
            h.extend_from_slice(&16u16.to_le_bytes());
            h.extend_from_slice(&uncompressed.to_le_bytes());
            h.extend_from_slice(&compressed.to_le_bytes());
        }
        self.put(&h)
    }

    /// A stored member whose CRC and size the caller knows -- from the source
    /// zip's central directory. Exactly `size` bytes are copied from `data`,
    /// which must then be at its end, and their CRC must equal `crc`.
    pub(crate) fn stored(
        &mut self,
        name: &str,
        crc: u32,
        size: u64,
        data: &mut dyn Read,
    ) -> Result<(), ZipStreamError> {
        let name = name.as_bytes();
        let offset = self.pos;
        let zip64 = size >= U32_LIMIT;
        let flags = name_flags(name);
        self.local_header(name, STORED, flags, crc, size, size, zip64)?;
        let mut hasher = crc32fast::Hasher::new();
        let mut buf = chunk_buffer(CHUNK).map_err(|f| ZipStreamError::Corrupt(f.to_string()))?;
        let mut left = size;
        while left > 0 {
            let want = left.min(CHUNK as u64) as usize;
            let n = buf
                .with_secret_mut(|b| data.read(&mut b[..want]))
                .map_err(ZipStreamError::Read)?;
            if n == 0 {
                return Err(ZipStreamError::Corrupt("stored member is short".into()));
            }
            buf.with_secret(|b| hasher.update(&b[..n]));
            buf.with_secret(|b| self.out.write_all(&b[..n]))
                .map_err(ZipStreamError::Write)?;
            self.pos += n as u64;
            left -= n as u64;
        }
        let extra = buf
            .with_secret_mut(|b| data.read(&mut b[..1]))
            .map_err(ZipStreamError::Read)?;
        if extra != 0 {
            return Err(ZipStreamError::Corrupt("stored member is long".into()));
        }
        if hasher.finalize() != crc {
            return Err(ZipStreamError::Corrupt("stored member CRC mismatch".into()));
        }
        self.entries.push(Central {
            name: name.to_vec(),
            method: STORED,
            flags,
            crc,
            compressed: size,
            uncompressed: size,
            offset,
            zip64_local: zip64,
        });
        Ok(())
    }

    /// A deflated member: everything `data` yields, compressed as it streams,
    /// with a data descriptor after it. `size_hint` is the uncompressed size the
    /// caller expects -- it decides Zip64 up front -- and the member fails if
    /// `data` yields more. Returns the bytes read from `data`.
    pub(crate) fn deflated(
        &mut self,
        name: &str,
        size_hint: u64,
        data: &mut dyn Read,
    ) -> Result<u64, ZipStreamError> {
        let name = name.as_bytes();
        let offset = self.pos;
        let zip64 = deflate_bound(size_hint) >= U32_LIMIT || size_hint >= U32_LIMIT;
        let flags = name_flags(name) | FLAG_DESCRIPTOR;
        self.local_header(name, DEFLATED, flags, 0, 0, 0, zip64)?;

        let mut hasher = crc32fast::Hasher::new();
        let mut buf = chunk_buffer(CHUNK).map_err(|f| ZipStreamError::Corrupt(f.to_string()))?;
        let mut sink = Counting {
            out: &mut self.out,
            written: 0,
        };
        let mut deflate =
            DeflateWriter::new(&mut sink).map_err(|f| ZipStreamError::Corrupt(f.to_string()))?;
        let mut uncompressed = 0u64;
        loop {
            let n = buf
                .with_secret_mut(|b| data.read(b))
                .map_err(ZipStreamError::Read)?;
            if n == 0 {
                break;
            }
            uncompressed += n as u64;
            if uncompressed > size_hint {
                return Err(ZipStreamError::Corrupt(format!(
                    "member is larger than the {size_hint} bytes expected"
                )));
            }
            buf.with_secret(|b| hasher.update(&b[..n]));
            buf.with_secret(|b| deflate.write_all(&b[..n]))
                .map_err(ZipStreamError::Write)?;
        }
        deflate.finish().map_err(ZipStreamError::Write)?;
        let compressed = sink.written;
        self.pos += compressed;
        let crc = hasher.finalize();

        let mut d = Vec::with_capacity(24);
        d.extend_from_slice(&DESCRIPTOR.to_le_bytes());
        d.extend_from_slice(&crc.to_le_bytes());
        if zip64 {
            d.extend_from_slice(&compressed.to_le_bytes());
            d.extend_from_slice(&uncompressed.to_le_bytes());
        } else {
            d.extend_from_slice(&(compressed as u32).to_le_bytes());
            d.extend_from_slice(&(uncompressed as u32).to_le_bytes());
        }
        self.put(&d)?;
        self.entries.push(Central {
            name: name.to_vec(),
            method: DEFLATED,
            flags,
            crc,
            compressed,
            uncompressed,
            offset,
            zip64_local: zip64,
        });
        Ok(uncompressed)
    }

    /// Write the central directory and the end records, and return the output.
    pub(crate) fn finish(mut self) -> Result<W, ZipStreamError> {
        let cd_start = self.pos;
        let entries = std::mem::take(&mut self.entries);
        for e in &entries {
            // APPNOTE 4.5.3: in the central directory, only the fields that
            // overflowed appear in the extra field, in this order.
            let mut extra = Vec::new();
            let big_u = e.uncompressed >= U32_LIMIT;
            let big_c = e.compressed >= U32_LIMIT;
            let big_o = e.offset >= U32_LIMIT;
            if big_u {
                extra.extend_from_slice(&e.uncompressed.to_le_bytes());
            }
            if big_c {
                extra.extend_from_slice(&e.compressed.to_le_bytes());
            }
            if big_o {
                extra.extend_from_slice(&e.offset.to_le_bytes());
            }
            let zip64 = !extra.is_empty() || e.zip64_local;
            let need = needed(e.method, zip64);
            let mut h = Vec::with_capacity(46 + e.name.len() + 28);
            h.extend_from_slice(&CENTRAL.to_le_bytes());
            h.extend_from_slice(&(MADE_BY_UNIX | need).to_le_bytes());
            h.extend_from_slice(&need.to_le_bytes());
            h.extend_from_slice(&e.flags.to_le_bytes());
            h.extend_from_slice(&e.method.to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes());
            h.extend_from_slice(&DOS_DATE.to_le_bytes());
            h.extend_from_slice(&e.crc.to_le_bytes());
            let clip = |v: u64, big: bool| if big { u32::MAX } else { v as u32 };
            h.extend_from_slice(&clip(e.compressed, big_c).to_le_bytes());
            h.extend_from_slice(&clip(e.uncompressed, big_u).to_le_bytes());
            h.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            let extra_len = if extra.is_empty() { 0 } else { 4 + extra.len() };
            h.extend_from_slice(&(extra_len as u16).to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes()); // comment
            h.extend_from_slice(&0u16.to_le_bytes()); // disk
            h.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
            h.extend_from_slice(&EXTERNAL_ATTRIBUTES.to_le_bytes());
            h.extend_from_slice(&clip(e.offset, big_o).to_le_bytes());
            h.extend_from_slice(&e.name);
            if !extra.is_empty() {
                h.extend_from_slice(&ZIP64_TAG.to_le_bytes());
                h.extend_from_slice(&(extra.len() as u16).to_le_bytes());
                h.extend_from_slice(&extra);
            }
            self.put(&h)?;
        }
        let cd_size = self.pos - cd_start;
        let count = entries.len() as u64;
        let zip64_end =
            count >= u64::from(u16::MAX) || cd_start >= U32_LIMIT || cd_size >= U32_LIMIT;
        if zip64_end {
            let end64_at = self.pos;
            let mut r = Vec::with_capacity(56 + 20);
            r.extend_from_slice(&END64.to_le_bytes());
            r.extend_from_slice(&44u64.to_le_bytes()); // size of the rest
            r.extend_from_slice(&(MADE_BY_UNIX | 45).to_le_bytes());
            r.extend_from_slice(&45u16.to_le_bytes());
            r.extend_from_slice(&0u32.to_le_bytes()); // this disk
            r.extend_from_slice(&0u32.to_le_bytes()); // disk with the directory
            r.extend_from_slice(&count.to_le_bytes());
            r.extend_from_slice(&count.to_le_bytes());
            r.extend_from_slice(&cd_size.to_le_bytes());
            r.extend_from_slice(&cd_start.to_le_bytes());
            r.extend_from_slice(&LOCATOR64.to_le_bytes());
            r.extend_from_slice(&0u32.to_le_bytes());
            r.extend_from_slice(&end64_at.to_le_bytes());
            r.extend_from_slice(&1u32.to_le_bytes()); // total disks
            self.put(&r)?;
        }
        let count16 = if zip64_end { u16::MAX } else { count as u16 };
        let clip = |v: u64| {
            if zip64_end && v >= U32_LIMIT {
                u32::MAX
            } else {
                v as u32
            }
        };
        let mut r = Vec::with_capacity(22);
        r.extend_from_slice(&END.to_le_bytes());
        r.extend_from_slice(&0u16.to_le_bytes());
        r.extend_from_slice(&0u16.to_le_bytes());
        r.extend_from_slice(&count16.to_le_bytes());
        r.extend_from_slice(&count16.to_le_bytes());
        r.extend_from_slice(&clip(cd_size).to_le_bytes());
        r.extend_from_slice(&clip(cd_start).to_le_bytes());
        r.extend_from_slice(&0u16.to_le_bytes()); // comment length
        self.put(&r)?;
        self.out.flush().map_err(ZipStreamError::Write)?;
        Ok(self.out)
    }
}

/// Where a rebuilt package's members go: the streaming writer above, or
/// `zip`'s own writer when the output can seek. `decrypt_entries`
/// writes through this, so the rebuild is one piece of code whichever frames
/// the zip.
pub(crate) trait ZipSink {
    /// A stored member with CRC and size known up front.
    fn stored(
        &mut self,
        name: &str,
        crc: u32,
        size: u64,
        data: &mut dyn Read,
    ) -> Result<(), ZipStreamError>;
    /// A deflated member; returns the bytes read from `data`.
    fn deflated(
        &mut self,
        name: &str,
        size_hint: u64,
        data: &mut dyn Read,
    ) -> Result<u64, ZipStreamError>;
}

impl<W: Write> ZipSink for ZipStreamWriter<W> {
    fn stored(
        &mut self,
        name: &str,
        crc: u32,
        size: u64,
        data: &mut dyn Read,
    ) -> Result<(), ZipStreamError> {
        ZipStreamWriter::stored(self, name, crc, size, data)
    }
    fn deflated(
        &mut self,
        name: &str,
        size_hint: u64,
        data: &mut dyn Read,
    ) -> Result<u64, ZipStreamError> {
        ZipStreamWriter::deflated(self, name, size_hint, data)
    }
}

/// `zip`'s writer behind [`ZipSink`], for an output that can seek: it
/// writes ordinary headers with no data descriptors, exactly as the
/// whole-buffer `decrypt` did through rc.9, so that path's output stays byte
/// for byte what it was. Members are copied through a wiped chunk buffer.
pub(crate) struct SeekableZipSink<W: Write + io::Seek> {
    zip: zip::ZipWriter<W>,
}

impl<W: Write + io::Seek> SeekableZipSink<W> {
    pub(crate) fn new(out: W) -> Self {
        Self {
            zip: zip::ZipWriter::new(out),
        }
    }

    pub(crate) fn finish(self) -> Result<W, ZipStreamError> {
        self.zip.finish().map_err(zip_error)
    }

    fn copy(&mut self, data: &mut dyn Read, limit: u64) -> Result<(u64, u32), ZipStreamError> {
        let mut hasher = crc32fast::Hasher::new();
        let mut buf = chunk_buffer(CHUNK).map_err(|f| ZipStreamError::Corrupt(f.to_string()))?;
        let mut total = 0u64;
        loop {
            let n = buf
                .with_secret_mut(|b| data.read(b))
                .map_err(ZipStreamError::Read)?;
            if n == 0 {
                return Ok((total, hasher.finalize()));
            }
            total += n as u64;
            if total > limit {
                return Err(ZipStreamError::Corrupt(format!(
                    "member is larger than the {limit} bytes expected"
                )));
            }
            buf.with_secret(|b| hasher.update(&b[..n]));
            let zip = &mut self.zip;
            buf.with_secret(|b| zip.write_all(&b[..n]))
                .map_err(ZipStreamError::Write)?;
        }
    }
}

/// `zip`'s write options for `method`, with the host system pinned to Unix.
///
/// `zip` 8 records `System::Dos` in "version made by" when built for Windows
/// and `System::Unix` elsewhere (`zip-8.6.0/src/types.rs:425-434`). `zip`
/// 2.4.2 wrote Unix on every host, and so does [`ZipStreamWriter`]. Pinning it
/// keeps every writer's output the same on every host and byte for byte what
/// rc.10 wrote. Every `ZipWriter` this crate drives takes its options here.
pub(crate) fn file_options(method: zip::CompressionMethod) -> zip::write::SimpleFileOptions {
    zip::write::SimpleFileOptions::default()
        .compression_method(method)
        .system(zip::System::Unix)
}

fn zip_error(e: zip::result::ZipError) -> ZipStreamError {
    match e {
        zip::result::ZipError::Io(e) => ZipStreamError::Write(e),
        other => ZipStreamError::Corrupt(crate::zip_err::message(&other)),
    }
}

impl<W: Write + io::Seek> ZipSink for SeekableZipSink<W> {
    fn stored(
        &mut self,
        name: &str,
        crc: u32,
        size: u64,
        data: &mut dyn Read,
    ) -> Result<(), ZipStreamError> {
        let options = file_options(zip::CompressionMethod::Stored);
        self.zip.start_file(name, options).map_err(zip_error)?;
        let (got, got_crc) = self.copy(data, size)?;
        if got != size {
            return Err(ZipStreamError::Corrupt("stored member is short".into()));
        }
        if got_crc != crc {
            return Err(ZipStreamError::Corrupt("stored member CRC mismatch".into()));
        }
        Ok(())
    }

    fn deflated(
        &mut self,
        name: &str,
        size_hint: u64,
        data: &mut dyn Read,
    ) -> Result<u64, ZipStreamError> {
        let options = file_options(zip::CompressionMethod::Deflated);
        self.zip.start_file(name, options).map_err(zip_error)?;
        Ok(self.copy(data, size_hint)?.0)
    }
}

#[cfg(test)]
#[path = "zip_stream_tests.rs"]
mod tests;
