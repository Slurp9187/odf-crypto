//! `encrypt_to`: [`crate::encrypt`] from a reader to a writer, with peak memory
//! that does not grow with the document.
//!
//! The same refusals, the same mimetype rules, the same key derivation and the
//! same manifest as the whole-buffer path -- each shared, not copied. What
//! differs is the payload: read, deflated, encrypted and written a chunk at a
//! time, so neither the document nor its ciphertext is ever held whole. See
//! `docs/plans/odf-streaming-2026-10-15.md`, §2.

use std::io::{self, Read, Seek, SeekFrom, Write};

use secure_gate::{RevealSecret, RevealSecretMut};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::classify::classify_latched;
use crate::encrypt::{
    build_manifest, derive_write_key, random_bytes, resolve_mimetype, screen_input, Argon2Params,
    EncryptError, WHOLESOME,
};
use crate::io_latch::{Latch, Latched};
use crate::limits::AES_GCM_TAG_LEN;
use crate::stream::{chunk_buffer, DeflateWriter, Fault, GcmEncryptWriter, GcmStream, CHUNK};
use crate::zip_err;
use crate::zip_stream::deflate_bound;

const MANIFEST_PATH: &str = "META-INF/manifest.xml";

/// [`crate::encrypt`], reading the plaintext package from `reader` and
/// writing the encrypted package to `writer`, in bounded memory.
///
/// The output is the profile `encrypt` writes -- wholesome AES-256-GCM under
/// Argon2id -- and LibreOffice opens it the same way. Only the salt and IV
/// differ between two calls, as they do between two `encrypt` calls.
///
/// `reader` must seek: it is classified first, from its central directory,
/// then read again from the start. `writer` must seek too, because the zip
/// writer patches the `encrypted-package` header once its size is known.
///
/// **On any `Err`, `writer`'s contents are unspecified and must be
/// discarded.**
///
/// # Errors
///
/// Those of [`crate::encrypt`], in the same order, plus
/// [`EncryptError::Io`] when `reader` or `writer` fails. A reader failure
/// takes precedence over whatever the zip layer made of it, so a cancel is
/// reported as a cancel. The whole-buffer path's 1 GiB deflate ceiling does
/// not apply: nothing is held whole.
///
/// # Examples
///
/// ```
/// use std::fs::File;
/// use std::io::Cursor;
/// use odf_crypto::{classify, decrypt, encrypt_to, Mode};
///
/// let path = "tests/goldens/lo-unencrypted.odt";
/// let mut sealed = Cursor::new(Vec::new());
/// encrypt_to(File::open(path)?, &mut sealed, "hunter2")?;
///
/// let sealed = sealed.into_inner();
/// assert_eq!(classify(&sealed)?.mode, Mode::Wholesome);
/// assert_eq!(decrypt(&sealed, "hunter2")?, std::fs::read(path)?);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn encrypt_to<R: Read + Seek, W: Write + Seek>(
    reader: R,
    writer: W,
    password: &str,
) -> Result<(), EncryptError> {
    encrypt_with_params_to(reader, writer, password, Argon2Params::LIBREOFFICE_DEFAULT)
}

/// [`encrypt_to`] with a caller-chosen Argon2id cost. See
/// [`crate::encrypt_with_params`] for what that trades.
///
/// # Errors
///
/// As [`encrypt_to`].
pub fn encrypt_with_params_to<R: Read + Seek, W: Write + Seek>(
    reader: R,
    writer: W,
    password: &str,
    params: Argon2Params,
) -> Result<(), EncryptError> {
    if password.is_empty() {
        return Err(EncryptError::EmptyPassword);
    }
    let latch = Latch::default();
    let mut src = Latched::new(reader, &latch);
    let result = run(&mut src, writer, password, params);
    match latch.take() {
        Some(err) => Err(EncryptError::Io(err)),
        None => result,
    }
}

fn run<R: Read + Seek, W: Write + Seek>(
    src: &mut R,
    writer: W,
    password: &str,
    params: Argon2Params,
) -> Result<(), EncryptError> {
    let class = classify_latched(&mut *src)?;
    screen_input(&class)?;
    let mimetype = {
        src.seek(SeekFrom::Start(0)).map_err(EncryptError::Io)?;
        let mut archive =
            ZipArchive::new(&mut *src).map_err(|e| EncryptError::Zip(zip_err::message(&e)))?;
        resolve_mimetype(&mut archive, class.media_type.as_deref())?
    };

    // `manifest:size` is the plaintext package's length, as in `encrypt`.
    let size = src.seek(SeekFrom::End(0)).map_err(EncryptError::Io)?;
    src.seek(SeekFrom::Start(0)).map_err(EncryptError::Io)?;
    let manifest_size = i64::try_from(size)
        .map_err(|_| EncryptError::Internal(format!("input of {size} bytes")))?;

    let salt = random_bytes(WHOLESOME.salt_len)?;
    let iv = random_bytes(WHOLESOME.iv_len)?;
    let key = derive_write_key(password, &salt, params)?;
    let manifest_xml = build_manifest(manifest_size, &iv, &salt, mimetype.as_deref(), params)?;

    let to_zip = |e: zip::result::ZipError| match e {
        zip::result::ZipError::Io(e) => EncryptError::Io(e),
        other => EncryptError::Zip(zip_err::message(&other)),
    };
    let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let mut out = ZipWriter::new(writer);
    out.start_file("mimetype", stored).map_err(to_zip)?;
    out.write_all(mimetype.as_deref().map(str::as_bytes).unwrap_or(&[]))
        .map_err(EncryptError::Io)?;

    // Zip64 only when the member could reach 4 GiB: IV, DEFLATE's worst case
    // over the input, and the tag. Below that, the header is what `encrypt`
    // writes, so the two outputs have the same shape.
    let worst = (iv.len() + AES_GCM_TAG_LEN) as u64 + deflate_bound(size);
    let payload_options = stored.large_file(worst >= u64::from(u32::MAX));
    out.start_file("encrypted-package", payload_options)
        .map_err(to_zip)?;
    out.write_all(&iv).map_err(EncryptError::Io)?;
    key.with_secret(|k| -> Result<(), EncryptError> {
        let gcm = GcmStream::new(k, &iv)
            .ok_or_else(|| EncryptError::Internal("AES-256-GCM key".into()))?;
        let sealer = GcmEncryptWriter::new(&mut out, gcm).map_err(fault)?;
        let mut deflate = DeflateWriter::new(sealer).map_err(fault)?;
        pump(src, &mut deflate)?;
        if deflate.consumed() != size {
            return Err(EncryptError::Internal(format!(
                "read {} bytes of a {size}-byte input",
                deflate.consumed()
            )));
        }
        deflate
            .finish()
            .map_err(write_error)?
            .finish()
            .map_err(write_error)?;
        Ok(())
    })?;

    let deflated = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    out.start_file(MANIFEST_PATH, deflated).map_err(to_zip)?;
    out.write_all(&manifest_xml).map_err(EncryptError::Io)?;
    out.finish().map_err(to_zip)?;
    Ok(())
}

/// Copy the plaintext package into the deflater through a wiped buffer.
fn pump<R: Read, W: Write>(src: &mut R, dst: &mut W) -> Result<(), EncryptError> {
    let mut buf = chunk_buffer(CHUNK).map_err(fault)?;
    loop {
        let n = buf
            .with_secret_mut(|b| src.read(b))
            .map_err(EncryptError::Io)?;
        if n == 0 {
            return Ok(());
        }
        buf.with_secret(|b| dst.write_all(&b[..n]))
            .map_err(write_error)?;
    }
}

/// A failure on the output side: a [`Fault`] is ours (the deflater's refusal
/// is `Deflate`); anything else is the caller's writer.
fn write_error(e: io::Error) -> EncryptError {
    match Fault::take(e) {
        Ok(f) => fault(f),
        Err(e) => EncryptError::Io(e),
    }
}

fn fault(f: Fault) -> EncryptError {
    match f {
        Fault::Alloc(n) => EncryptError::HostCannotAllocate { requested_bytes: n },
        Fault::Deflate(s) => EncryptError::Deflate(s),
        other => EncryptError::Internal(other.to_string()),
    }
}

#[cfg(test)]
#[path = "encrypt_stream_tests.rs"]
mod tests;
