//! The per-entry half of `decrypt_to`: AES-CBC, Blowfish and per-member AES-GCM
//! packages, rebuilt member by member into a zip that cannot seek.
//!
//! The rebuilt package has the same members, in the same order, with the same
//! contents as the whole-buffer `decrypt` returns: the manifest with its
//! `encryption-data` stripped, each encrypted member decrypted and inflated,
//! every other member as it was. The zip framing differs -- deflated members
//! carry data descriptors, because this writer cannot seek back -- so the two
//! outputs are equal member for member, not byte for byte.

use std::collections::HashMap;
use std::io::{Read, Seek, Write};

use zip::{CompressionMethod, ZipArchive};

use crate::classify::{member_matches_path, zip_entry_name};
use crate::decrypt::{
    member_for_archive, screen_shape, strip_manifest, DecryptError, DecryptLimits,
};
use crate::decrypt_stream::{
    declared_size, fault_error, find_key, gcm_key, gcm_member, member_shape, read_error,
    DecryptOutcome, IntegrityOutcome,
};
use crate::limits::MANIFEST_READ_CAP;
use crate::stream::{BlowfishDecryptReader, CbcDecryptReader, ChecksumGate, Fault, InflateReader};
use crate::types::{Cipher, EntryEncryption};
use crate::zip_err;
use crate::zip_stream::{ZipStreamError, ZipStreamWriter};
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

pub(crate) fn per_entry<R: Read + Seek, W: Write>(
    archive: &mut ZipArchive<R>,
    class: &Classification,
    writer: &mut W,
    password: &str,
    limits: &DecryptLimits,
) -> Result<DecryptOutcome, DecryptError> {
    // Every refusal that needs no key, for every row, before anything is
    // derived or written: the whole-buffer path refuses these before deriving
    // too, row by row.
    let mut plans: HashMap<String, Plan<'_>> = HashMap::new();
    let mut superseded: Vec<(usize, Plan<'_>)> = Vec::new();
    for row in &class.encrypted_entries {
        let expected = declared_size(row.size)?;
        let (index, name) = member_for_archive(archive, &row.path)?;
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
    let mut out = ZipStreamWriter::new(writer);
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
            decrypt_member(archive, index, &name, plan, &mut out, password, &row_limits)
                .map_err(|e| with_total_limit(e, limits))?;
            produced += plan.expected;
            if integrity_of(plan.row) == IntegrityOutcome::PasswordCheckOnly {
                weakest = IntegrityOutcome::PasswordCheckOnly;
            }
        } else {
            let mut file = archive
                .by_index(index)
                .map_err(|e| DecryptError::Zip(zip_err::message(&e)))?;
            match method {
                CompressionMethod::Stored => out
                    .stored(&name, crc, size, &mut file)
                    .map_err(zip_stream_error(limits))?,
                CompressionMethod::Deflated => {
                    out.deflated(&name, size, &mut file)
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
    out.finish().map_err(zip_stream_error(limits))?;
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
    let (index, _) = member_for_archive(archive, MANIFEST_PATH)?;
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
fn gated<'a>(
    file: impl Read + 'a,
    row: &EntryEncryption,
    key: &[u8],
) -> Result<ChecksumGate<Box<dyn Read + 'a>>, Fault> {
    let plain: Box<dyn Read + 'a> = match row.cipher {
        Cipher::AesCbcW3c => Box::new(CbcDecryptReader::new(file, key, &row.iv)?),
        Cipher::BlowfishCfb8 => Box::new(BlowfishDecryptReader::new(file, key, &row.iv)?),
        Cipher::AesGcmW3c => {
            return Err(Fault::BadParameters(
                "GCM member reached the checksum path".into(),
            ))
        }
    };
    ChecksumGate::new(plain, row.checksum.clone())
}

#[allow(clippy::too_many_arguments)]
fn decrypt_member<R: Read + Seek, W: Write>(
    archive: &mut ZipArchive<R>,
    index: usize,
    name: &str,
    plan: &Plan<'_>,
    out: &mut ZipStreamWriter<W>,
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

fn write_inflated<W: Write>(
    out: &mut ZipStreamWriter<W>,
    name: &str,
    deflated: &mut dyn Read,
    expected: u64,
    limits: &DecryptLimits,
) -> Result<(), DecryptError> {
    let mut inflate = InflateReader::new(deflated, expected, limits.max_output_bytes)
        .map_err(fault_error(limits))?;
    out.deflated(name, expected, &mut inflate)
        .map_err(zip_stream_error(limits))?;
    Ok(())
}

fn zip_stream_error(limits: &DecryptLimits) -> impl Fn(ZipStreamError) -> DecryptError + '_ {
    move |e| match e {
        ZipStreamError::Read(e) => match Fault::take(e) {
            Ok(fault) => fault_error(limits)(fault),
            Err(e) => DecryptError::Zip(e.to_string()),
        },
        ZipStreamError::Write(e) => DecryptError::Io(e),
        ZipStreamError::Corrupt(s) => DecryptError::Zip(s),
    }
}
