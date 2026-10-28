//! `reencrypt_to`: change an encrypted package's password without its plaintext
//! ever being written anywhere -- decrypt and encrypt joined into one stream.
//!
//! The output is what [`crate::encrypt`] writes (wholesome AES-256-GCM under
//! Argon2id), whatever the source's profile. See
//! `docs/plans/odf-streaming-2026-10-15.md`, §2 and §4.

use std::io::{self, Read, Seek, SeekFrom, Write};

use secure_gate::{RevealSecret, RevealSecretMut};
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::classify::{classify_latched, open_archive};
use crate::decrypt::{
    member_for_archive, no_member, screen_class, screen_shape, DecryptError, DecryptLimits,
};
use crate::decrypt_stream::{
    declared_size, fault_error, gcm_key, member_shape, open_after_iv, DecryptOutcome,
    IntegrityOutcome, Sizes,
};
use crate::encrypt::{
    build_manifest, derive_write_key, random_bytes, resolve_mimetype, Argon2Params, EncryptError,
    WHOLESOME,
};
use crate::io_latch::{Latch, Latched};
use crate::limits::{AES_GCM_IV_LEN, AES_GCM_TAG_LEN};
use crate::sensitive::DerivedKey;
use crate::stream::{
    chunk_buffer, DeflateWriter, Fault, GcmDecryptReader, GcmEncryptWriter, GcmStream,
    InflateReader, CHUNK,
};
use crate::zip_err;
use crate::zip_stream::{self, deflate_bound, ZipStreamWriter};
use crate::{Classification, Mode};

const MANIFEST_PATH: &str = "META-INF/manifest.xml";

/// Failures from [`reencrypt_to`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReencryptError {
    /// The source could not be decrypted with the old password: every
    /// [`DecryptError`] it can be, except [`DecryptError::Io`], which is
    /// reported as [`ReencryptError::Io`].
    #[error("decrypting the source failed: {0}")]
    Decrypt(DecryptError),
    /// The output could not be encrypted with the new password -- an empty one,
    /// say, or an unaffordable Argon2id cost. [`EncryptError::Io`] is reported
    /// as [`ReencryptError::Io`].
    #[error("encrypting the result failed: {0}")]
    Encrypt(EncryptError),
    /// A per-entry source in which some listed content is not encrypted: a
    /// manifest row with no complete `encryption-data`
    /// ([`crate::Classification::has_non_encrypted_entries`]), or encrypted
    /// rows with no row on `content.xml` to latch the package as encrypted.
    ///
    /// Re-encrypting would carry that plaintext into a container whose AEAD
    /// tag then vouches for it. **This crate's policy, not LibreOffice's**:
    /// [`crate::decrypt_to`] still decrypts the package, as LibreOffice opens
    /// it, after a warning (`ERRCODE_SFX_INCOMPLETE_ENCRYPTION`).
    #[error("refused: the source has listed content that is not encrypted")]
    PartiallyEncrypted,
    /// A per-entry source with zip members its manifest does not list. Not
    /// fatal to LibreOffice below ODF 1.2, but carried into the output they
    /// would be authenticated by its tag. Policy, as above.
    #[error("refused: the source has members its manifest does not list")]
    UnexpectedStreams,
    /// The caller's reader or writer failed. A reader failure is the reader's
    /// own error and takes precedence, so a cancel is reported as a cancel.
    #[error("I/O failed: {0}")]
    Io(#[source] io::Error),
}

impl From<DecryptError> for ReencryptError {
    fn from(e: DecryptError) -> Self {
        match e {
            DecryptError::Io(e) => ReencryptError::Io(e),
            other => ReencryptError::Decrypt(other),
        }
    }
}

impl From<EncryptError> for ReencryptError {
    fn from(e: EncryptError) -> Self {
        match e {
            EncryptError::Io(e) => ReencryptError::Io(e),
            other => ReencryptError::Encrypt(other),
        }
    }
}

/// Decrypt `reader` with `old` and write it to `writer` encrypted with `new`,
/// in bounded memory and with no plaintext written anywhere.
///
/// - **A wholesome source** is re-keyed without recompressing: its tag is
///   checked first, as [`crate::decrypt_to`] checks it, then its deflated
///   stream is decrypted and re-encrypted chunk by chunk, while a side inflate
///   confirms it still inflates to its `manifest:size`. The inner package is
///   carried over byte for byte.
/// - **A per-entry source** is refused if it has listed content that is not
///   encrypted, or unlisted members (see [`ReencryptError`]). Otherwise it is
///   rebuilt as [`crate::decrypt_to`] rebuilds it, and the rebuilt package is
///   encrypted as [`crate::encrypt`] would, all in one stream.
///
/// The outcome reports what the **source** was checked with, as
/// [`crate::decrypt_to`]'s does. The output is AES-256-GCM, so the new
/// package will verify fully, whatever the old one did.
///
/// **On any `Err`, `writer`'s contents are unspecified and must be
/// discarded.**
///
/// # Errors
///
/// [`ReencryptError::Decrypt`] for what [`crate::decrypt_to`] would refuse,
/// in its order; the two refusals above; [`ReencryptError::Encrypt`] for what
/// [`crate::encrypt_to`] would refuse of the new password and cost; and
/// [`ReencryptError::Io`].
///
/// # Examples
///
/// ```
/// use std::fs::File;
/// use std::io::Cursor;
/// use odf_crypto::{decrypt, reencrypt_to, Argon2Params, DecryptLimits};
///
/// let path = "tests/goldens/lo-wholesome-gcm-argon2.odt";
/// let mut rekeyed = Cursor::new(Vec::new());
/// reencrypt_to(
///     File::open(path)?,
///     &mut rekeyed,
///     "password",
///     "a new one",
///     DecryptLimits::default(),
///     Argon2Params::LIBREOFFICE_DEFAULT,
/// )?;
///
/// let rekeyed = rekeyed.into_inner();
/// assert_eq!(decrypt(&rekeyed, "a new one")?, decrypt(&std::fs::read(path)?, "password")?);
/// assert!(decrypt(&rekeyed, "password").is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn reencrypt_to<R: Read + Seek, W: Write + Seek>(
    reader: R,
    writer: W,
    old: &str,
    new: &str,
    limits: DecryptLimits,
    params: Argon2Params,
) -> Result<DecryptOutcome, ReencryptError> {
    if old.is_empty() {
        return Err(DecryptError::EmptyPassword.into());
    }
    if new.is_empty() {
        return Err(EncryptError::EmptyPassword.into());
    }
    let latch = Latch::default();
    let mut src = Latched::new(reader, &latch);
    let result = run(&mut src, writer, old, new, &limits, params);
    match latch.take() {
        Some(err) => Err(ReencryptError::Io(err)),
        None => result,
    }
}

fn run<R: Read + Seek, W: Write + Seek>(
    src: &mut R,
    writer: W,
    old: &str,
    new: &str,
    limits: &DecryptLimits,
    params: Argon2Params,
) -> Result<DecryptOutcome, ReencryptError> {
    let class = classify_latched(&mut *src).map_err(DecryptError::from)?;
    screen_class(&class, limits)?;
    if class.mode == Mode::PerEntry {
        screen_per_entry(&class)?;
    }
    src.seek(SeekFrom::Start(0)).map_err(ReencryptError::Io)?;
    let mut archive =
        open_archive(&mut *src).map_err(|e| DecryptError::Zip(zip_err::message(&e)))?;
    let mimetype = resolve_mimetype(&mut archive, class.media_type.as_deref())?;
    match class.mode {
        Mode::Wholesome => wholesome(
            &mut archive,
            &class,
            writer,
            old,
            new,
            limits,
            params,
            mimetype,
        ),
        _ => per_entry(
            &mut archive,
            &class,
            writer,
            old,
            new,
            limits,
            params,
            mimetype,
        ),
    }
}

/// The plan's §4 refusals, all read from the classification, before any key
/// is derived or any byte written.
fn screen_per_entry(class: &Classification) -> Result<(), ReencryptError> {
    if class.has_non_encrypted_entries {
        return Err(ReencryptError::PartiallyEncrypted);
    }
    if class.has_unexpected_streams {
        return Err(ReencryptError::UnexpectedStreams);
    }
    if !class.package_encrypted {
        return Err(ReencryptError::PartiallyEncrypted);
    }
    Ok(())
}

/// The new package's three members around `payload`, which writes the
/// `encrypted-package` body after its IV and returns the inner package's
/// length for `manifest:size`.
#[allow(clippy::too_many_arguments)]
fn write_package<W: Write + Seek>(
    writer: W,
    new: &str,
    params: Argon2Params,
    mimetype: Option<String>,
    could_reach: u64,
    payload: impl FnOnce(&mut dyn Write, &[u8]) -> Result<u64, ReencryptError>,
) -> Result<(), ReencryptError> {
    let salt = random_bytes(WHOLESOME.salt_len)?;
    let iv = random_bytes(WHOLESOME.iv_len)?;
    let key = derive_write_key(new, &salt, params)?;

    let to_zip = |e: zip::result::ZipError| -> ReencryptError {
        match e {
            zip::result::ZipError::Io(e) => ReencryptError::Io(e),
            other => EncryptError::Zip(zip_err::message(&other)).into(),
        }
    };
    let stored = zip_stream::file_options(CompressionMethod::Stored);
    let mut out = ZipWriter::new(writer);
    out.start_file("mimetype", stored).map_err(to_zip)?;
    out.write_all(mimetype.as_deref().map(str::as_bytes).unwrap_or(&[]))
        .map_err(ReencryptError::Io)?;
    let worst = (AES_GCM_IV_LEN + AES_GCM_TAG_LEN) as u64 + could_reach;
    out.start_file(
        "encrypted-package",
        stored.large_file(worst >= u64::from(u32::MAX)),
    )
    .map_err(to_zip)?;
    out.write_all(&iv).map_err(ReencryptError::Io)?;
    let size = key.with_secret(|k| -> Result<u64, ReencryptError> {
        let gcm = GcmStream::new(k, &iv)
            .ok_or_else(|| EncryptError::Internal("AES-256-GCM key".into()))?;
        let mut sealer = GcmEncryptWriter::new(&mut out, gcm).map_err(alloc)?;
        let size = payload(&mut sealer, k)?;
        sealer.finish().map_err(ReencryptError::Io)?;
        Ok(size)
    })?;
    let size = i64::try_from(size)
        .map_err(|_| EncryptError::Internal(format!("inner package of {size} bytes")))?;
    let manifest = build_manifest(size, &iv, &salt, mimetype.as_deref(), params)?;
    let deflated = zip_stream::file_options(CompressionMethod::Deflated);
    out.start_file(MANIFEST_PATH, deflated).map_err(to_zip)?;
    out.write_all(&manifest).map_err(ReencryptError::Io)?;
    out.finish().map_err(to_zip)?;
    Ok(())
}

fn alloc(f: Fault) -> ReencryptError {
    match f {
        Fault::Alloc(n) => EncryptError::HostCannotAllocate { requested_bytes: n }.into(),
        other => EncryptError::Internal(other.to_string()).into(),
    }
}

/// Reads `src` and writes every byte it yields to `dst` as well: the old
/// stream's deflated plaintext goes on to the new cipher while the inflater
/// beside it checks it. The bytes pass through the reader's own buffer, which
/// the inflater owns and wipes.
struct Tee<R, W> {
    src: R,
    dst: W,
}

/// A failure of the tee's output, marked so [`read_error`] reports it as the
/// caller's writer rather than as the source.
#[derive(Debug)]
struct OutputFailed(io::Error);

impl std::fmt::Display for OutputFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "writing the output failed: {}", self.0)
    }
}

impl std::error::Error for OutputFailed {}

impl<R: Read, W: Write> Read for Tee<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.src.read(buf)?;
        self.dst
            .write_all(&buf[..n])
            .map_err(|e| io::Error::other(OutputFailed(e)))?;
        Ok(n)
    }
}

#[allow(clippy::too_many_arguments)]
fn wholesome<R: Read + Seek, W: Write + Seek>(
    archive: &mut ZipArchive<R>,
    class: &Classification,
    writer: W,
    old: &str,
    new: &str,
    limits: &DecryptLimits,
    params: Argon2Params,
    mimetype: Option<String>,
) -> Result<DecryptOutcome, ReencryptError> {
    let (row_index, row) = crate::decrypt::wholesome_row(class)?;
    let expected = declared_size(row.size)?;
    let (index, _) = member_for_archive(archive, &row.path, no_member(row_index))?;
    let (len, head) = member_shape(archive, index)?;
    screen_shape(row, len, &head)?;
    // The verify pass, under the old key, before anything is derived for the
    // new one or written.
    let old_key: DerivedKey = gcm_key(archive, index, row, len, old, limits)?;
    let ct_len = len - (AES_GCM_IV_LEN + AES_GCM_TAG_LEN) as u64;

    write_package(writer, new, params, mimetype, len, |sealer, _| {
        let mut file = open_after_iv(archive, index)?;
        old_key.with_secret(|k| -> Result<u64, ReencryptError> {
            let gcm = GcmStream::new(k, &row.iv).ok_or_else(|| {
                DecryptError::Internal("an AES-GCM key length screen_shape passed".into())
            })?;
            let plain = GcmDecryptReader::new(&mut file, gcm, ct_len);
            let mut tee = Tee {
                src: plain,
                dst: sealer,
            };
            {
                let mut check = InflateReader::new(&mut tee, expected, limits.max_output_bytes)
                    .map_err(fault_error(limits))?;
                drain(&mut check, limits)?;
            }
            // Past the DEFLATE end marker: still part of the member, so still
            // re-encrypted, and the old tag is still checked at its end.
            drain(&mut tee, limits)?;
            Ok(expected)
        })
    })?;
    Ok(DecryptOutcome {
        integrity: IntegrityOutcome::Verified,
    })
}

#[allow(clippy::too_many_arguments)]
fn per_entry<R: Read + Seek, W: Write + Seek>(
    archive: &mut ZipArchive<R>,
    class: &Classification,
    writer: W,
    old: &str,
    new: &str,
    limits: &DecryptLimits,
    params: Argon2Params,
    mimetype: Option<String>,
) -> Result<DecryptOutcome, ReencryptError> {
    // The rebuilt package is at most every member inflated, plus headers; the
    // bound only decides whether the outer member needs Zip64.
    let mut could_reach = 1 << 20;
    for i in 0..archive.len() {
        let f = archive
            .by_index_raw(i)
            .map_err(|e| DecryptError::Zip(zip_err::message(&e)))?;
        could_reach += f.size().max(f.compressed_size()) + 1024;
    }
    for row in &class.encrypted_entries {
        could_reach += declared_size(row.size)?;
    }
    let mut outcome = None;
    write_package(
        writer,
        new,
        params,
        mimetype,
        deflate_bound(could_reach),
        |sealer, _| {
            let mut deflate = DeflateWriter::adaptive(sealer).map_err(alloc)?;
            let mut zip = ZipStreamWriter::new(&mut deflate);
            outcome = Some(crate::decrypt_entries::per_entry(
                archive,
                class,
                &mut zip,
                old,
                limits,
                Sizes::Streamed,
            )?);
            zip.finish()
                .map_err(crate::decrypt_entries::zip_stream_error(limits))?;
            let size = deflate.consumed();
            deflate.finish().map_err(write_error)?;
            Ok(size)
        },
    )?;
    outcome.ok_or_else(|| {
        EncryptError::Internal("per-entry rebuild produced no outcome".into()).into()
    })
}

fn write_error(e: io::Error) -> ReencryptError {
    match Fault::take(e) {
        Ok(Fault::Deflate(s)) => EncryptError::Deflate(s).into(),
        Ok(other) => alloc(other),
        Err(e) => ReencryptError::Io(e),
    }
}

/// Read `r` to its end through a wiped buffer, discarding what it yields.
fn drain(r: &mut dyn Read, limits: &DecryptLimits) -> Result<(), ReencryptError> {
    let mut buf = chunk_buffer(CHUNK).map_err(alloc)?;
    loop {
        let n = buf
            .with_secret_mut(|b| r.read(b))
            .map_err(|e| read_error(e, limits))?;
        if n == 0 {
            return Ok(());
        }
    }
}

/// A read failed somewhere along decrypt, tee and inflate. A [`Fault`] is
/// about the source; a failure of the new cipher's writer (the tee's `dst`) is
/// the caller's output, and anything else is the zip layer.
fn read_error(e: io::Error, limits: &DecryptLimits) -> ReencryptError {
    let e = match Fault::take(e) {
        Ok(f) => return fault_error(limits)(f).into(),
        Err(e) => e,
    };
    if !e.get_ref().is_some_and(|inner| inner.is::<OutputFailed>()) {
        return DecryptError::Zip(e.to_string()).into();
    }
    match e.into_inner().map(|inner| inner.downcast::<OutputFailed>()) {
        Some(Ok(failed)) => ReencryptError::Io(failed.0),
        Some(Err(other)) => ReencryptError::Io(io::Error::other(other)),
        None => DecryptError::Zip("reading the source failed".into()).into(),
    }
}

#[cfg(test)]
#[path = "reencrypt_tests.rs"]
mod tests;
