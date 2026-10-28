//! `decrypt_to`: [`crate::decrypt`] from a reader to a writer, with peak memory
//! that does not grow with the package.
//!
//! The same refusals, in the same order, as the whole-buffer path: both call
//! [`screen_class`] and [`screen_shape`], derive through [`derive_key`], and walk
//! the same SHA-1 start-key ladder. What differs is that no member is ever
//! held whole. See `docs/plans/odf-streaming-2026-10-15.md`.

use std::io::{self, Read, Seek, SeekFrom, Write};

use secure_gate::{RevealSecret, RevealSecretMut};
use zip::ZipArchive;

use crate::classify::{classify_latched, open_archive};
use crate::decrypt::{
    derive_key, member_for_archive, no_member, screen_class, screen_shape, AllocationSite,
    DecryptError, DecryptLimits,
};
use crate::io_latch::{Latch, Latched};
use crate::limits::{AES_GCM_IV_LEN, AES_GCM_TAG_LEN};
use crate::sensitive::DerivedKey;
use crate::stream::{
    chunk_buffer, gcm_verify, ChunkBuffer, Fault, GcmDecryptReader, GcmStream, InflateReader, CHUNK,
};
use crate::types::{EntryEncryption, StartKeyAlg};
use crate::zip_err;
use crate::zip_stream::{deflate_bound, SeekableZipSink, ZipStreamWriter};
use crate::Mode;

/// What [`decrypt_to`] can say about the integrity of what it wrote.
///
/// Not an error and not a policy: every level here is a package LibreOffice
/// opens, and `decrypt_to` decrypts them all. It reports how much of the
/// output a check actually covered, so a caller can tell its user.
///
/// When members differ, the **weakest** level among them is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntegrityOutcome {
    /// An AES-GCM tag covered every encrypted member, and was verified before
    /// any of that member's plaintext was written.
    Verified,
    /// Some member was checked only by the SHA-1 or SHA-256 digest of its first
    /// 1024 deflated bytes -- the legacy AES-CBC and Blowfish formats. That
    /// confirms the password; the rest of the member is unauthenticated, in
    /// LibreOffice too (`ZipFile.cxx:482-585`).
    ///
    /// There is no weaker level. An AES-CBC or Blowfish row with no checksum
    /// is not a password row at all -- LibreOffice requires a digest unless the
    /// cipher is GCM (`ZipPackage.cxx:365-367`), and `classify` agrees -- so no
    /// member is ever decrypted unchecked.
    PasswordCheckOnly,
}

/// The result of a successful [`decrypt_to`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecryptOutcome {
    /// How much of the output a check covered.
    pub integrity: IntegrityOutcome,
}

/// [`crate::decrypt`], reading the package from `reader` and writing the
/// plaintext package to `writer`, in bounded memory.
///
/// `reader` must seek: the zip is read from its central directory, and each
/// AES-GCM member is read twice. The first pass checks the tag and decrypts
/// nothing; the second writes. So no byte of a member reaches `writer` before
/// LibreOffice would have accepted the member. If the input changes between
/// the passes the call fails: usually the member's zip CRC notices
/// ([`DecryptError::Zip`]), and beneath it the second pass recomputes the tag.
///
/// `writer` need not seek.
///
/// **On any `Err`, `writer`'s contents are unspecified and must be
/// discarded.** A failure late in a member -- damaged DEFLATE past the checked
/// window, a reader that is cancelled -- can follow plaintext already written.
///
/// # Errors
///
/// Those of [`crate::decrypt`], in the same order, plus:
///
/// - [`DecryptError::Io`] when `reader` or `writer` fails. A reader failure
///   takes precedence over whatever the zip layer made of it, so a cancel is
///   reported as a cancel. It is also `Io`, of kind `InvalidData`, when the
///   recomputed tag shows the input changed between the two passes over an
///   AES-GCM member and the zip CRC did not catch it first.
/// - [`DecryptError::OutputLimit`] past [`DecryptLimits::max_output_bytes`].
///   The whole-buffer path's 1 GiB memory ceilings do not apply here.
///
/// # Examples
///
/// ```
/// use std::fs::File;
/// use odf_crypto::{decrypt, decrypt_to, IntegrityOutcome};
///
/// let path = "tests/goldens/lo-wholesome-gcm-argon2.odt";
/// let mut plain = Vec::new();
/// let outcome = decrypt_to(File::open(path)?, &mut plain, "password")?;
///
/// assert_eq!(outcome.integrity, IntegrityOutcome::Verified);
/// assert_eq!(plain, decrypt(&std::fs::read(path)?, "password")?);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn decrypt_to<R: Read + Seek, W: Write>(
    reader: R,
    writer: W,
    password: &str,
) -> Result<DecryptOutcome, DecryptError> {
    decrypt_with_limits_to(reader, writer, password, DecryptLimits::default())
}

/// [`decrypt_to`], with the ceilings on what a package may ask for under the
/// caller's control. See [`DecryptLimits`].
///
/// # Errors
///
/// As [`decrypt_to`].
pub fn decrypt_with_limits_to<R: Read + Seek, W: Write>(
    reader: R,
    mut writer: W,
    password: &str,
    limits: DecryptLimits,
) -> Result<DecryptOutcome, DecryptError> {
    if password.is_empty() {
        return Err(DecryptError::EmptyPassword);
    }
    let latch = Latch::default();
    let mut src = Latched::new(reader, &latch);
    let result = run(&mut src, &mut writer, password, &limits);
    match latch.take() {
        Some(err) => Err(DecryptError::Io(err)),
        None => result,
    }
}

fn run<R: Read + Seek, W: Write>(
    src: &mut R,
    writer: &mut W,
    password: &str,
    limits: &DecryptLimits,
) -> Result<DecryptOutcome, DecryptError> {
    let class = classify_latched(&mut *src)?;
    screen_class(&class, limits)?;
    src.seek(SeekFrom::Start(0)).map_err(DecryptError::Io)?;
    let mut archive =
        open_archive(&mut *src).map_err(|e| DecryptError::Zip(zip_err::message(&e)))?;
    match class.mode {
        Mode::Wholesome => {
            let row = crate::decrypt::wholesome_row(&class)?;
            wholesome(&mut archive, row, writer, password, limits, Sizes::Streamed)?;
            Ok(DecryptOutcome {
                integrity: IntegrityOutcome::Verified,
            })
        }
        _ => {
            let mut zip = ZipStreamWriter::new(writer);
            let outcome = crate::decrypt_entries::per_entry(
                &mut archive,
                &class,
                &mut zip,
                password,
                limits,
                Sizes::Streamed,
            )?;
            zip.finish()
                .map_err(crate::decrypt_entries::zip_stream_error(limits))?;
            Ok(outcome)
        }
    }
}

/// The whole-buffer [`crate::decrypt_with_limits`], on the streaming core: the
/// same refusals in the same order, the same ciphers, the same rebuild. Two
/// things differ from [`decrypt_with_limits_to`], both because this path
/// returns its output in memory:
///
/// - `manifest:size` keeps the 1 GiB ceiling (`inflated_len`) it had in rc.9.
/// - The output is one buffer, allocated fallibly at a computed bound before
///   any member is decrypted, and never grown: a grown `Vec` would leave
///   reallocated copies of the plaintext behind, unwiped. A per-entry rebuild
///   is framed by `zip`'s own writer, configured as 2.4.2's was in rc.9
///   ([`crate::zip_stream::file_options`]), so the bytes are rc.9's bytes.
pub(crate) fn decrypt_slice(
    bytes: &[u8],
    password: &str,
    limits: &DecryptLimits,
) -> Result<Vec<u8>, DecryptError> {
    if password.is_empty() {
        return Err(DecryptError::EmptyPassword);
    }
    let class = crate::classify::classify(bytes)?;
    screen_class(&class, limits)?;
    let mut archive = open_archive(io::Cursor::new(bytes))
        .map_err(|e| DecryptError::Zip(zip_err::message(&e)))?;
    let mut out;
    let len = match class.mode {
        Mode::Wholesome => {
            let row = crate::decrypt::wholesome_row(&class)?;
            let n = crate::decrypt::inflated_len(row.1.size)?;
            out = crate::decrypt::try_zeroed(n, AllocationSite::PackagePlaintext)?;
            let mut slot = SliceWriter::new(&mut out[..]);
            wholesome(
                &mut archive,
                row,
                &mut slot,
                password,
                limits,
                Sizes::WholeBuffer,
            )
            .map_err(ours)?;
            slot.len
        }
        _ => {
            let bound = rebuild_bound(&mut archive, &class)?;
            out = crate::decrypt::try_zeroed(bound, AllocationSite::PackagePlaintext)?;
            let mut slot = SliceWriter::new(&mut out[..]);
            let mut zip = SeekableZipSink::new(&mut slot);
            crate::decrypt_entries::per_entry(
                &mut archive,
                &class,
                &mut zip,
                password,
                limits,
                Sizes::WholeBuffer,
            )
            .map_err(ours)?;
            zip.finish()
                .map_err(crate::decrypt_entries::zip_stream_error(limits))
                .map_err(ours)?;
            slot.len
        }
    };
    out.truncate(len);
    Ok(out)
}

/// A writer over a fixed slice that cannot grow -- a write past its end is an
/// error, not a reallocation. Unlike `io::Cursor<&mut [u8]>`, its end for
/// `SeekFrom::End` is the furthest byte written, not the slice's capacity:
/// `zip`'s writer seeks to the end to write its central directory, and over a
/// cursor that put the directory after a run of unwritten zeros.
struct SliceWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
    /// The high-water mark: the output's length.
    len: usize,
}

impl<'a> SliceWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            len: 0,
        }
    }
}

impl Write for SliceWriter<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let end = self
            .pos
            .checked_add(data.len())
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::WriteZero, "output bound exceeded"))?;
        self.buf[self.pos..end].copy_from_slice(data);
        self.pos = end;
        self.len = self.len.max(end);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for SliceWriter<'_> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let base = match to {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(d) => (self.len as u64).checked_add_signed(d),
            SeekFrom::Current(d) => (self.pos as u64).checked_add_signed(d),
        };
        self.pos = base
            .and_then(|n| usize::try_from(n).ok())
            .filter(|&n| n <= self.buf.len())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "seek outside the output")
            })?;
        Ok(self.pos as u64)
    }
}

/// On the whole-buffer path the writer is ours, so an I/O failure is a broken
/// invariant of ours -- the computed bound was too small -- not the caller's.
fn ours(e: DecryptError) -> DecryptError {
    match e {
        DecryptError::Io(e) => DecryptError::Internal(format!("output buffer: {e}")),
        other => other,
    }
}

/// An upper bound on a per-entry rebuild's size: every member's headers in
/// both directories with room to spare, its body at DEFLATE's worst case, the
/// end record. Each `manifest:size` counts at most the 1 GiB the rows are held
/// to, so a row about to be refused for its size cannot make this allocation
/// fail first and change which error the caller sees.
fn rebuild_bound<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    class: &crate::Classification,
) -> Result<usize, DecryptError> {
    const PER_MEMBER: u64 = 30 + 46 + 2 * 64 + 1024;
    let ceiling = crate::limits::INFLATE_CEILING as u64;
    let mut bound = 22u64 + 1024;
    for i in 0..archive.len() {
        let f = archive
            .by_index_raw(i)
            .map_err(|e| DecryptError::Zip(zip_err::message(&e)))?;
        let body = f.size().max(f.compressed_size()).min(ceiling);
        bound += PER_MEMBER + 2 * f.name_raw().len() as u64 + deflate_bound(body);
    }
    for row in &class.encrypted_entries {
        let declared = u64::try_from(row.size).unwrap_or(0).min(ceiling);
        bound += deflate_bound(declared);
    }
    // Only a 32-bit host fails this: a limit of the host, not of the manifest
    // (#105), so it is the allocation refusal rather than a bad parameter.
    usize::try_from(bound).map_err(|_| DecryptError::HostCannotAllocate {
        site: AllocationSite::PackagePlaintext,
        requested_bytes: usize::MAX,
    })
}

/// `manifest:size` as a byte count. Negative is meaningless and refused, as in
/// the whole-buffer path; there is no 1 GiB ceiling here, because nothing is
/// allocated from it. [`DecryptLimits::max_output_bytes`] bounds it instead.
pub(crate) fn declared_size(size: i64) -> Result<u64, DecryptError> {
    u64::try_from(size).map_err(|_| {
        DecryptError::BadParameters(crate::BadParameter::OutOfRange {
            field: crate::ManifestField::Size,
            got: size,
            min: 0,
            max: i64::MAX,
        })
    })
}

/// Which rule bounds `manifest:size`: the streaming path's (any non-negative
/// size, the output limit does the rest), or the whole-buffer path's 1 GiB
/// ceiling, which exists because that path allocates its output.
#[derive(Clone, Copy)]
pub(crate) enum Sizes {
    Streamed,
    WholeBuffer,
}

impl Sizes {
    pub(crate) fn declared(self, size: i64) -> Result<u64, DecryptError> {
        match self {
            Sizes::Streamed => declared_size(size),
            Sizes::WholeBuffer => crate::decrypt::inflated_len(size).map(|n| n as u64),
        }
    }
}

/// Find the key the password opens `row` with: the row's own start key, then,
/// for a SHA-1 row, LibreOffice's legacy ladder -- the same walk as
/// `decrypt::decrypt_member`. `accepts` is the member's own check (a GCM verify
/// pass, a 1K digest); it returns `Ok(false)` for a wrong key, and any `Err`
/// ends the walk with that error, as upstream catches only
/// `WrongPasswordException`.
pub(crate) fn find_key(
    row: &EntryEncryption,
    password: &str,
    limits: &DecryptLimits,
    mut accepts: impl FnMut(&[u8]) -> Result<bool, DecryptError>,
) -> Result<DerivedKey, DecryptError> {
    let mut attempt = |sk| -> Result<Option<DerivedKey>, DecryptError> {
        let key = derive_key(row, sk, limits)?;
        let ok = key.with_secret(|k| accepts(k))?;
        Ok(ok.then_some(key))
    };
    if let Some(key) = attempt(crate::kdf::start_key(password, row.start_key))? {
        return Ok(key);
    }
    if row.start_key == StartKeyAlg::Sha1 {
        for rung in crate::kdf::SHA1_LADDER {
            if let Some(key) = attempt(crate::kdf::legacy_start_key(password, rung))? {
                return Ok(key);
            }
        }
    }
    Err(DecryptError::WrongPassword)
}

/// A member's length and its first `AES_GCM_IV_LEN` bytes, for [`screen_shape`].
pub(crate) fn member_shape<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
) -> Result<(u64, Vec<u8>), DecryptError> {
    let mut file = archive
        .by_index(index)
        .map_err(|e| DecryptError::Zip(zip_err::message(&e)))?;
    let len = file.size();
    let mut head = [0u8; AES_GCM_IV_LEN];
    let n = read_full(&mut file, &mut head).map_err(read_error)?;
    Ok((len, head[..n].to_vec()))
}

/// Stream the wholesome package: verify the tag, then decrypt, inflate and
/// write. The inner package is written verbatim, as `decrypt` returns it.
fn wholesome<R: Read + Seek, W: Write>(
    archive: &mut ZipArchive<R>,
    (row_index, row): (usize, &EntryEncryption),
    writer: &mut W,
    password: &str,
    limits: &DecryptLimits,
    sizes: Sizes,
) -> Result<(), DecryptError> {
    let expected = sizes.declared(row.size)?;
    let (index, _) = member_for_archive(archive, &row.path, no_member(row_index))?;
    let (len, head) = member_shape(archive, index)?;
    screen_shape(row, len, &head)?;
    gcm_member(archive, index, row, len, password, limits, |plain| {
        copy_out(plain, writer, expected, limits)
    })
}

/// The two passes over one AES-GCM member at `index`, `len` bytes long, laid out
/// as IV || ciphertext || tag. `release` receives the decrypted, still-deflated
/// stream only after the first pass accepted the key.
pub(crate) fn gcm_member<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
    row: &EntryEncryption,
    len: u64,
    password: &str,
    limits: &DecryptLimits,
    release: impl FnOnce(&mut dyn Read) -> Result<(), DecryptError>,
) -> Result<(), DecryptError> {
    let ct_len = len - (AES_GCM_IV_LEN + AES_GCM_TAG_LEN) as u64;
    let key = gcm_key(archive, index, row, len, password, limits)?;
    let mut file = open_after_iv(archive, index)?;
    key.with_secret(|k| -> Result<(), DecryptError> {
        let gcm = GcmStream::new(k, &row.iv).ok_or_else(|| {
            DecryptError::Internal("an AES-GCM key length screen_shape passed".into())
        })?;
        let mut plain = GcmDecryptReader::new(&mut file, gcm, ct_len);
        release(&mut plain)?;
        // The inflater stops at the DEFLATE end marker, which can come before
        // the end of the ciphertext. Drain the rest so the tag is still checked
        // on this pass: what follows the marker is ignored, as upstream, but
        // the input must not have changed underneath.
        drain(&mut plain)
    })?;
    ensure_end(&mut file)
}

/// The verify pass alone: the key whose tag matches, found by [`find_key`].
/// Nothing is decrypted.
pub(crate) fn gcm_key<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
    row: &EntryEncryption,
    len: u64,
    password: &str,
    limits: &DecryptLimits,
) -> Result<DerivedKey, DecryptError> {
    let ct_len = len - (AES_GCM_IV_LEN + AES_GCM_TAG_LEN) as u64;
    find_key(row, password, limits, |k| {
        let mut file = open_after_iv(archive, index)?;
        let ok = gcm_verify(k, &row.iv, &mut file, ct_len).map_err(read_error)?;
        ensure_end(&mut file)?;
        Ok(ok)
    })
}

pub(crate) fn open_after_iv<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
) -> Result<zip::read::ZipFile<'_, R>, DecryptError> {
    let mut file = archive
        .by_index(index)
        .map_err(|e| DecryptError::Zip(zip_err::message(&e)))?;
    let mut iv = [0u8; AES_GCM_IV_LEN];
    if read_full(&mut file, &mut iv).map_err(read_error)? != AES_GCM_IV_LEN {
        return Err(DecryptError::BadParameters(crate::BadParameter::Member(
            crate::MemberFault::ShorterThanIvAndTag,
        )));
    }
    Ok(file)
}

/// The member must end where its header says. Reading one byte past the
/// expected end also makes the zip layer check the member's CRC, as the
/// whole-buffer path's `read_to_end` does.
fn ensure_end<R: Read>(file: &mut R) -> Result<(), DecryptError> {
    let mut one = [0u8; 1];
    match read_full(file, &mut one).map_err(read_error)? {
        0 => Ok(()),
        _ => Err(DecryptError::BadParameters(crate::BadParameter::Member(
            crate::MemberFault::LongerThanHeader,
        ))),
    }
}

/// Inflate `deflated` to `writer`, holding it to `manifest:size` and the
/// output limit.
pub(crate) fn copy_out<W: Write + ?Sized>(
    deflated: &mut dyn Read,
    writer: &mut W,
    expected: u64,
    limits: &DecryptLimits,
) -> Result<(), DecryptError> {
    let mut inflate = InflateReader::new(deflated, expected, limits.max_output_bytes)
        .map_err(fault_error(limits))?;
    let mut buf = buffer()?;
    loop {
        let n = buf
            .with_secret_mut(|b| inflate.read(b))
            .map_err(|e| read_error_with(e, limits))?;
        if n == 0 {
            return Ok(());
        }
        buf.with_secret(|b| writer.write_all(&b[..n]))
            .map_err(DecryptError::Io)?;
    }
}

/// Read `r` to its end into a wiped buffer, discarding what it yields.
fn drain(r: &mut dyn Read) -> Result<(), DecryptError> {
    let mut buf = buffer()?;
    while buf.with_secret_mut(|b| r.read(b)).map_err(read_error)? > 0 {}
    Ok(())
}

pub(crate) fn buffer() -> Result<ChunkBuffer, DecryptError> {
    chunk_buffer(CHUNK).map_err(|_| DecryptError::HostCannotAllocate {
        site: AllocationSite::StreamBuffer,
        requested_bytes: CHUNK,
    })
}

pub(crate) fn read_full<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// An error raised while reading the package. A [`Fault`] is about the member;
/// anything else came out of the zip layer -- a CRC mismatch, a short member --
/// and is reported as `Zip`, as the whole-buffer path's `read_to_end` does. The
/// caller's own reader failures never reach here as themselves: the latch in
/// [`decrypt_with_limits_to`] reports those, and takes precedence.
pub(crate) fn read_error(e: io::Error) -> DecryptError {
    read_error_with(e, &DecryptLimits::default())
}

fn read_error_with(e: io::Error, limits: &DecryptLimits) -> DecryptError {
    match Fault::take(e) {
        Ok(fault) => fault_error(limits)(fault),
        Err(e) => DecryptError::Zip(e.to_string()),
    }
}

pub(crate) fn fault_error(limits: &DecryptLimits) -> impl Fn(Fault) -> DecryptError + '_ {
    move |fault| match fault {
        Fault::WrongPassword => DecryptError::WrongPassword,
        Fault::Changed => DecryptError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "the input changed between the verify and release passes",
        )),
        Fault::BadParameters(b) => DecryptError::BadParameters(b),
        Fault::Internal(s) => DecryptError::Internal(s.to_string()),
        Fault::Inflate(s) => DecryptError::Inflate(s),
        Fault::OutputLimit => DecryptError::OutputLimit {
            limit: limits.max_output_bytes,
        },
        Fault::Alloc(n) => DecryptError::HostCannotAllocate {
            site: AllocationSite::StreamBuffer,
            requested_bytes: n,
        },
        // Only the rebuild's own re-deflate can raise it: an invariant of
        // ours, not a property of the package.
        Fault::Deflate(s) => DecryptError::Internal(format!("deflate failed: {s}")),
    }
}

#[cfg(test)]
#[path = "decrypt_stream_tests.rs"]
mod tests;
