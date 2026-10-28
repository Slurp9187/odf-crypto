//! The per-entry half of `decrypt_to`: AES-CBC, Blowfish and per-member AES-GCM
//! packages, rebuilt member by member into a zip that cannot seek.
//!
//! The rebuilt package has the same members, in the same order, with the same
//! contents as the whole-buffer `decrypt` returns: the manifest with its
//! `encryption-data` stripped, each encrypted member decrypted and inflated,
//! every other member as it was. The zip framing differs -- deflated members
//! carry data descriptors, because this writer cannot seek back -- so the two
//! outputs are equal member for member, not byte for byte.
//!
//! Since rc.15 the bytes inside deflated members differ too. A member that
//! arrives deflated -- every encrypted member, and a plain one stored with
//! DEFLATE -- is copied through still compressed, and checked by inflating
//! beside the copy ([`PlainDeflated`], [`EncryptedDeflated`]). The whole-buffer
//! `decrypt` keeps compressing again, because its output is pinned to rc.9's.

use std::collections::HashMap;
use std::io::{self, Read, Seek, Write};

use secure_gate::{RevealSecret, RevealSecretMut};
use zip::{CompressionMethod, ZipArchive};

use crate::classify::{member_matches_path, zip_entry_name};
use crate::decrypt::{
    member_for_archive, no_member, screen_shape, strip_manifest, DecryptError, DecryptLimits,
};
use crate::decrypt_stream::{
    fault_error, find_key, gcm_key, gcm_member, member_shape, read_error, DecryptOutcome,
    IntegrityOutcome, Sizes,
};
use crate::limits::MANIFEST_READ_CAP;
use crate::stream::{
    chunk_buffer, BlowfishDecryptReader, CbcDecryptReader, ChecksumGate, Fault, InflateReader,
    CHUNK,
};
use crate::types::{Cipher, EntryEncryption};
use crate::zip_err;
use crate::zip_stream::{DeflatedSource, ZipSink, ZipStreamError};
use crate::Classification;

const MANIFEST_PATH: &str = "META-INF/manifest.xml";

/// A GCM tag covers its whole member; anything else is checked on its first
/// 1024 deflated bytes. A non-GCM row always carries that checksum: `classify`
/// does not admit one without it (`ZipPackage.cxx:365-367`).
fn integrity_of(row: &EntryEncryption) -> IntegrityOutcome {
    match row.cipher {
        Cipher::AesGcmW3c => IntegrityOutcome::Verified,
        Cipher::AesCbcW3c | Cipher::BlowfishCfb8 => IntegrityOutcome::PasswordCheckOnly,
    }
}

/// One encrypted member, screened and ready to decrypt.
struct Plan<'a> {
    row: &'a EntryEncryption,
    expected: u64,
    len: u64,
}

/// Rebuild a per-entry package into `out`, which the caller finishes.
pub(crate) fn per_entry<R: Read + Seek, S: ZipSink>(
    archive: &mut ZipArchive<R>,
    class: &Classification,
    out: &mut S,
    password: &str,
    limits: &DecryptLimits,
    sizes: Sizes,
) -> Result<DecryptOutcome, DecryptError> {
    // Every refusal that needs no key, for every row, before anything is
    // derived or written: the whole-buffer path refuses these before deriving
    // too, row by row.
    let mut plans: HashMap<String, Plan<'_>> = HashMap::new();
    let mut superseded: Vec<(usize, Plan<'_>)> = Vec::new();
    for (row_index, row) in class.encrypted_entries.iter().enumerate() {
        let expected = sizes.declared(row.size)?;
        let (index, name) = member_for_archive(archive, &row.path, no_member(row_index))?;
        let (len, head) = member_shape(archive, index)?;
        screen_shape(row, len, &head)?;
        let plan = Plan { row, expected, len };
        // Two rows resolving to one member: the whole-buffer path decrypts both
        // and keeps the later. Keep the later here too, and still check the
        // password against the earlier one, so the same packages are refused.
        if let Some(earlier) = plans.insert(name, plan) {
            superseded.push((index, earlier));
        }
    }
    for (index, plan) in &superseded {
        key_for(archive, *index, plan, password, limits)?;
    }

    let manifest = read_manifest(archive)?;
    let stripped = strip_manifest(&manifest)?;
    let mut weakest = IntegrityOutcome::Verified;
    let mut produced = 0u64;

    for index in 0..archive.len() {
        let (name, method, crc, size) = {
            let file = archive
                .by_index(index)
                .map_err(|e| DecryptError::Zip(zip_err::message(&e)))?;
            (
                zip_entry_name(file.name_raw()),
                file.compression(),
                file.crc32(),
                file.size(),
            )
        };
        if member_matches_path(&name, MANIFEST_PATH) {
            let n = stripped.len() as u64;
            out.deflated(&name, n, &mut stripped.as_slice())
                .map_err(zip_stream_error(limits))?;
        } else if let Some(plan) = plans.get(&name) {
            let budget = limits.max_output_bytes.saturating_sub(produced);
            let row_limits = DecryptLimits {
                max_output_bytes: budget,
                ..*limits
            };
            decrypt_member(archive, index, &name, plan, out, password, &row_limits)
                .map_err(|e| with_total_limit(e, limits))?;
            produced += plan.expected;
            if integrity_of(plan.row) == IntegrityOutcome::PasswordCheckOnly {
                weakest = IntegrityOutcome::PasswordCheckOnly;
            }
        } else {
            match method {
                CompressionMethod::Stored => {
                    let mut file = archive
                        .by_index(index)
                        .map_err(|e| DecryptError::Zip(zip_err::message(&e)))?;
                    out.stored(&name, crc, size, &mut file)
                        .map_err(zip_stream_error(limits))?
                }
                CompressionMethod::Deflated => {
                    let mut src = PlainDeflated { archive, index };
                    out.deflated_from(&name, size, &mut src)
                        .map_err(zip_stream_error(limits))?;
                }
                other => {
                    return Err(DecryptError::Zip(format!(
                        "member {name:?} uses compression {other:?}, which cannot be re-written"
                    )))
                }
            }
        }
    }
    Ok(DecryptOutcome { integrity: weakest })
}

/// An `OutputLimit` raised against a member's remaining budget names the
/// caller's limit, not the remainder.
fn with_total_limit(e: DecryptError, limits: &DecryptLimits) -> DecryptError {
    match e {
        DecryptError::OutputLimit { .. } => DecryptError::OutputLimit {
            limit: limits.max_output_bytes,
        },
        other => other,
    }
}

fn read_manifest<R: Read + Seek>(archive: &mut ZipArchive<R>) -> Result<Vec<u8>, DecryptError> {
    // `classify` read this member a moment ago, so its absence is ours.
    let (index, _) = member_for_archive(archive, MANIFEST_PATH, || {
        DecryptError::Internal("the manifest classify read is not in the archive".into())
    })?;
    let file = archive
        .by_index(index)
        .map_err(|e| DecryptError::Zip(zip_err::message(&e)))?;
    // `classify` has already refused a manifest past this cap, so the read is
    // bounded by a constant, not by the package.
    let mut buf = Vec::new();
    file.take(MANIFEST_READ_CAP as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(read_error)?;
    if buf.len() > MANIFEST_READ_CAP {
        return Err(DecryptError::Zip("zip entry too large".into()));
    }
    Ok(buf)
}

/// The key that opens one CBC or Blowfish member: each candidate is tried on
/// the member's checked window only, never the whole member.
pub(crate) fn checksum_key<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
    row: &EntryEncryption,
    password: &str,
    limits: &DecryptLimits,
) -> Result<crate::sensitive::DerivedKey, DecryptError> {
    find_key(row, password, limits, |k| {
        let file = archive
            .by_index(index)
            .map_err(|e| DecryptError::Zip(zip_err::message(&e)))?;
        let mut gate = gated(file, row, k).map_err(fault_error(limits))?;
        match gate.verify() {
            Ok(()) => Ok(true),
            Err(e) => match Fault::take(e) {
                Ok(Fault::WrongPassword) => Ok(false),
                Ok(other) => Err(fault_error(limits)(other)),
                Err(e) => Err(DecryptError::Zip(e.to_string())),
            },
        }
    })
}

/// Only checks the password; used for a row whose member a later row
/// replaces.
fn key_for<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
    plan: &Plan<'_>,
    password: &str,
    limits: &DecryptLimits,
) -> Result<(), DecryptError> {
    match plan.row.cipher {
        Cipher::AesGcmW3c => {
            gcm_key(archive, index, plan.row, plan.len, password, limits).map(|_| ())
        }
        _ => checksum_key(archive, index, plan.row, password, limits).map(|_| ()),
    }
}

/// The decrypting reader for a CBC or Blowfish member, behind its 1K gate.
pub(crate) fn gated<'a>(
    file: impl Read + 'a,
    row: &EntryEncryption,
    key: &[u8],
) -> Result<ChecksumGate<Box<dyn Read + 'a>>, Fault> {
    let plain: Box<dyn Read + 'a> = match row.cipher {
        Cipher::AesCbcW3c => Box::new(CbcDecryptReader::new(file, key, &row.iv)?),
        Cipher::BlowfishCfb8 => Box::new(BlowfishDecryptReader::new(file, key, &row.iv)?),
        Cipher::AesGcmW3c => {
            return Err(Fault::Internal(
                "an AES-GCM member reached the checksum path",
            ))
        }
    };
    ChecksumGate::new(plain, row.checksum.clone())
}

#[allow(clippy::too_many_arguments)]
fn decrypt_member<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    index: usize,
    name: &str,
    plan: &Plan<'_>,
    out: &mut dyn ZipSink,
    password: &str,
    limits: &DecryptLimits,
) -> Result<(), DecryptError> {
    let row = plan.row;
    if row.cipher == Cipher::AesGcmW3c {
        return gcm_member(archive, index, row, plan.len, password, limits, |plain| {
            write_inflated(out, name, plain, plan.expected, limits)
        });
    }
    let key = checksum_key(archive, index, row, password, limits)?;
    let file = archive
        .by_index(index)
        .map_err(|e| DecryptError::Zip(zip_err::message(&e)))?;
    use secure_gate::RevealSecret;
    key.with_secret(|k| -> Result<(), DecryptError> {
        let mut plain = gated(file, row, k).map_err(fault_error(limits))?;
        write_inflated(out, name, &mut plain, plan.expected, limits)?;
        // The inflater stops at the DEFLATE end marker. Read on to the end of
        // the member, as the whole-buffer path's full decrypt does: the CBC
        // padding is checked there, and so is the member's zip CRC.
        let mut sink = crate::decrypt_stream::buffer()?;
        use secure_gate::RevealSecretMut;
        while sink
            .with_secret_mut(|b| plain.read(b))
            .map_err(read_error)?
            > 0
        {}
        Ok(())
    })
}

fn write_inflated(
    out: &mut dyn ZipSink,
    name: &str,
    deflated: &mut dyn Read,
    expected: u64,
    limits: &DecryptLimits,
) -> Result<(), DecryptError> {
    let mut src = EncryptedDeflated {
        deflated,
        expected,
        limit: limits.max_output_bytes,
    };
    out.deflated_from(name, expected, &mut src)
        .map_err(zip_stream_error(limits))?;
    Ok(())
}

/// A plain member the source zip stores with DEFLATE.
///
/// The copy takes the raw bytes (`by_index_raw`); the check then reads the
/// member again through `zip`'s own inflating reader, the very read the rebuild
/// made before rc.15. Its CRC check and its errors are therefore unchanged, and
/// so is the set of packages refused -- only the output's compression moved.
/// Reading the member twice costs an inflate, against the level-6 deflate it
/// replaces.
struct PlainDeflated<'a, R> {
    archive: &'a mut ZipArchive<R>,
    index: usize,
}

impl<R: Read + Seek> PlainDeflated<'_, R> {
    fn open(&mut self) -> Result<zip::read::ZipFile<'_, R>, ZipStreamError> {
        self.archive
            .by_index(self.index)
            .map_err(|e| ZipStreamError::Corrupt(zip_err::message(&e)))
    }
}

impl<R: Read + Seek> DeflatedSource for PlainDeflated<'_, R> {
    fn inflated(
        &mut self,
        take: &mut dyn FnMut(&mut dyn Read) -> Result<u64, ZipStreamError>,
    ) -> Result<u64, ZipStreamError> {
        take(&mut self.open()?)
    }

    fn copy_deflated(&mut self, out: &mut dyn Write) -> Result<(u32, u64), ZipStreamError> {
        {
            let mut raw = self
                .archive
                .by_index_raw(self.index)
                .map_err(|e| ZipStreamError::Corrupt(zip_err::message(&e)))?;
            let mut buf = chunk_buffer(CHUNK).map_err(|f| ZipStreamError::Read(f.into_io()))?;
            loop {
                let n = buf
                    .with_secret_mut(|b| raw.read(b))
                    .map_err(ZipStreamError::Read)?;
                if n == 0 {
                    break;
                }
                buf.with_secret(|b| out.write_all(&b[..n]))
                    .map_err(ZipStreamError::Write)?;
            }
        }
        crc_to_end(&mut self.open()?)
    }
}

/// An encrypted member's deflated plaintext, behind its cipher's check.
///
/// One pass: [`InflateReader`] enforces what it always has (the end marker,
/// `manifest:size`, the output budget) and its tap copies out exactly the
/// DEFLATE bytes it consumed, so nothing past the end marker reaches the
/// output, as nothing past it ever did.
struct EncryptedDeflated<'a> {
    deflated: &'a mut dyn Read,
    expected: u64,
    limit: u64,
}

impl DeflatedSource for EncryptedDeflated<'_> {
    fn inflated(
        &mut self,
        take: &mut dyn FnMut(&mut dyn Read) -> Result<u64, ZipStreamError>,
    ) -> Result<u64, ZipStreamError> {
        let mut inflate = InflateReader::new(&mut *self.deflated, self.expected, self.limit)
            .map_err(|f| ZipStreamError::Read(f.into_io()))?;
        take(&mut inflate)
    }

    fn copy_deflated(&mut self, out: &mut dyn Write) -> Result<(u32, u64), ZipStreamError> {
        let mut tap = LatchedWrite { out, failed: None };
        let result =
            InflateReader::with_tap(&mut *self.deflated, self.expected, self.limit, &mut tap)
                .map_err(|f| ZipStreamError::Read(f.into_io()))
                .and_then(|mut inflate| crc_to_end(&mut inflate));
        // The tap's failure surfaces through the inflater as a read error;
        // report it as the output's, which is what it was.
        match tap.failed.take() {
            Some(e) => Err(ZipStreamError::Write(e)),
            None => result,
        }
    }
}

/// A writer that keeps its first failure, so a failure inside a reader's tap
/// is not mistaken for the reader's own.
struct LatchedWrite<'a> {
    out: &'a mut dyn Write,
    failed: Option<io::Error>,
}

impl Write for LatchedWrite<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.out.write(buf).map_err(|e| {
            let stand_in = io::Error::new(e.kind(), "writing the output failed");
            self.failed.get_or_insert(e);
            stand_in
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Read `r` to its end through a wiped buffer: the CRC-32 and length of what it
/// yields.
fn crc_to_end(r: &mut dyn Read) -> Result<(u32, u64), ZipStreamError> {
    let mut hasher = crc32fast::Hasher::new();
    let mut total = 0u64;
    let mut buf = chunk_buffer(CHUNK).map_err(|f| ZipStreamError::Read(f.into_io()))?;
    loop {
        let n = buf
            .with_secret_mut(|b| r.read(b))
            .map_err(ZipStreamError::Read)?;
        if n == 0 {
            return Ok((hasher.finalize(), total));
        }
        buf.with_secret(|b| hasher.update(&b[..n]));
        total += n as u64;
    }
}

pub(crate) fn zip_stream_error(
    limits: &DecryptLimits,
) -> impl Fn(ZipStreamError) -> DecryptError + '_ {
    move |e| match e {
        ZipStreamError::Read(e) => match Fault::take(e) {
            Ok(fault) => fault_error(limits)(fault),
            Err(e) => DecryptError::Zip(e.to_string()),
        },
        ZipStreamError::Write(e) => DecryptError::Io(e),
        ZipStreamError::Corrupt(s) => DecryptError::Zip(s),
    }
}
