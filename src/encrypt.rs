//! Password encryption for ODF packages.
//!
//! `encrypt` turns a plaintext ODF package (`classify` reports [`Mode::Plain`])
//! into what current LibreOffice writes for that same input under that password:
//! one `encrypted-package` member, Argon2id-derived AES-256-GCM, no checksum,
//! `manifest:version="1.4"`. Modern (wholesome) only -- per-entry write and PGP
//! wrap are later, out-of-scope arcs. See
//! `docs/plans/odf-encryption-encrypt-2026-09-03.md`.

use std::io::{Cursor, Read, Write};

use aes_gcm::{
    aead::{rand_core::RngCore as _, AeadInPlace, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, Event};
use quick_xml::Writer;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::classify::classify;
use crate::types::{Mode, StartKeyAlg};
use crate::uris;
use crate::DetectError;

/// Ceiling on the plaintext buffer [`encrypt`] will deflate, matching decrypt's
/// `INFLATE_CEILING` (1 GiB) in shape but not in purpose: decrypt's ceiling
/// defends against an attacker-controlled `manifest:size`, whereas `encrypt`'s
/// caller supplies the plaintext directly -- there is no attacker on the other
/// end. This is hygiene against an unbounded allocation on a pathological
/// input, not a security boundary.
const DEFLATE_CEILING: usize = 1 << 30;

/// Ceiling on the input's own `mimetype` member. `classify` admits a package
/// after reading only its first 1024 bytes (`classify.rs`'s `read_mimetype`),
/// so copying an unbounded member here would be a side door around
/// [`DEFLATE_CEILING`] -- and any member past this length would also push the
/// emitted `manifest.xml` towards `classify`'s own `MANIFEST_READ_CAP`, making
/// output this crate's own `decrypt` would refuse. 1024 is exactly what
/// `classify` looked at, so nothing it judged goes unexamined here.
const MIMETYPE_CEILING: usize = 1024;

const MANIFEST_PATH: &str = "META-INF/manifest.xml";

/// The one profile this arc writes (plan §1's last row, §2's emit table).
///
/// Spelled once and consumed by both the KDF call and the manifest emit, so
/// the two cannot drift: a key derived under one `m` while the manifest
/// promises another is a bug no round-trip test would catch if the two were
/// separate literals, because `decrypt` reads the manifest's copy.
struct Profile {
    /// Argon2 `(t, m, p)` in the manifest's own `sal_Int32` type, in the
    /// order `manifest:` writes them -- *not* `Params::new`'s `(m, t, p)`.
    argon2_t: i32,
    argon2_m_kib: i32,
    argon2_p: i32,
    derived_key_len: usize,
    salt_len: usize,
    iv_len: usize,
    odf_version: &'static str,
}

/// `SetupStorage`'s wholesome row: Argon2id `(3, 65536, 4)`, AES-256-GCM,
/// SHA-256 start key, no checksum (`objstor.cxx:349-399`); salt 16 bytes and
/// IV 12 bytes per `ZipPackageStream.cxx:587-607`.
const WHOLESOME: Profile = Profile {
    argon2_t: 3,
    argon2_m_kib: 65536,
    argon2_p: 4,
    derived_key_len: 32,
    salt_len: 16,
    iv_len: 12,
    odf_version: "1.4",
};

// The invariants that make this arc's Argon2id and AES-GCM calls infallible,
// checked at compile time rather than asserted in a comment: argon2 requires
// `m >= 8p` and a salt of at least 8 bytes, AES-256 needs a 32-byte key, and
// GCM's nonce is 96 bits. `uris::AESGCM256_URL` in `build_manifest` is keyed
// to `derived_key_len == 32`; the assert below is what ties them together.
const _: () = assert!(WHOLESOME.argon2_m_kib >= 8 * WHOLESOME.argon2_p);
const _: () = assert!(WHOLESOME.salt_len >= 8);
const _: () = assert!(WHOLESOME.derived_key_len == 32);
const _: () = assert!(WHOLESOME.iv_len == 12);

/// Failures from [`encrypt`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EncryptError {
    /// `classify()` itself rejected the input (not a zip, no manifest, ...).
    #[error("classification failed: {0}")]
    Classify(#[from] DetectError),
    /// `classify(bytes)?.mode != Mode::Plain` -- covers `PerEntry`, `Wholesome`,
    /// and PGP rows alike.
    #[error("package is already encrypted")]
    AlreadyEncrypted,
    /// Mirrors `decrypt::DecryptError::EmptyPassword` /
    /// `CreatePackageEncryptionData`'s empty sequence.
    #[error("password is empty")]
    EmptyPassword,
    /// CSPRNG failure -- vanishingly rare, but a library must not panic for it.
    #[error("random number generation failed: {0}")]
    Random(String),
    /// The input buffer cannot be deflated. `compress_to_vec` itself is
    /// infallible, so in practice this is the [`DEFLATE_CEILING`] rejection.
    #[error("deflate failed: {0}")]
    Deflate(String),
    /// The input's own `mimetype` member cannot be carried into the output:
    /// over [`MIMETYPE_CEILING`], not UTF-8, or containing a byte that is not
    /// an XML 1.0 `Char`. `classify` admits such a package (its check is
    /// `starts_with("application/vnd.")` over the first 1024 bytes), but
    /// copying it verbatim would emit a `manifest.xml` real LibreOffice's
    /// expat rejects -- so this fails closed rather than writing a package
    /// that classifies but will not open.
    #[error("unusable mimetype member: {0}")]
    Mimetype(String),
    /// Building the outer zip container failed.
    #[error("zip error: {0}")]
    Zip(String),
}

/// Encrypt a plaintext ODF package with `password`, producing what current
/// LibreOffice writes for that input under that password (plan §6): wholesome
/// Argon2id-derived AES-256-GCM, one `encrypted-package` member, no checksum.
///
/// Refuses before any crypto runs: an empty password is rejected first
/// (mirroring `decrypt`'s own ordering), then anything `classify` does not
/// report as [`Mode::Plain`] (already encrypted, in any of the three `Mode`s
/// classify can report), then an unusable `mimetype` member -- so no caller
/// pays for a 64 MiB Argon2id before learning the input was never eligible.
pub fn encrypt(bytes: &[u8], password: &str) -> Result<Vec<u8>, EncryptError> {
    if password.is_empty() {
        return Err(EncryptError::EmptyPassword);
    }
    let class = classify(bytes)?;
    if class.mode != Mode::Plain {
        return Err(EncryptError::AlreadyEncrypted);
    }

    // Plan §3's mimetype fallback chain, resolved before any crypto: it
    // depends only on `bytes` and `class`, and a rejection here should not
    // cost a whole-input deflate plus a 64 MiB Argon2id first.
    let mimetype = resolve_mimetype(bytes, class.media_type.as_deref())?;

    // Plan §6 step 3: raw-deflate the whole input buffer, unparsed.
    let mut payload = raw_deflate(bytes)?;

    // Plan §6 step 5 / `ZipPackageStream.cxx:587-607`: fresh salt and IV per
    // save (moot here -- wholesome writes exactly one row).
    let salt = random_bytes(WHOLESOME.salt_len)?;
    let iv = random_bytes(WHOLESOME.iv_len)?;

    // Plan §6 step 4/6: start key, then Argon2id over it with `salt`. Both
    // are `Zeroizing` -- `kdf::start_key` returns one, and `derived_key` is
    // wrapped here, so an early return below still wipes them.
    let start_key = crate::kdf::start_key(password, StartKeyAlg::Sha256);
    let mut derived_key = zeroize::Zeroizing::new(vec![0u8; WHOLESOME.derived_key_len]);
    // `encrypt` only ever passes `WHOLESOME`'s own constants, whose validity
    // is asserted at compile time above, so this cannot fail for any input
    // `classify` accepted. Unlike decrypt, there is no attacker-supplied
    // tuple here and so no `BadParameters` analogue in `EncryptError`.
    crate::kdf::derive_argon2id(
        &start_key,
        &salt,
        WHOLESOME.argon2_t,
        WHOLESOME.argon2_m_kib,
        WHOLESOME.argon2_p,
        &mut derived_key,
    )
    .expect("WHOLESOME's Argon2id params are valid by the const asserts above");

    // Plan §6 step 7 / `ciphercontext.cxx`'s encrypt branch: AES-256-GCM,
    // empty AAD, the 16-byte tag appended to the ciphertext. Encrypting in
    // place keeps one buffer rather than copying the whole payload again;
    // NSS does not prepend the IV, so LO does, and so do we -- in
    // `assemble_zip`, which writes `IV || ciphertext || tag` without
    // materialising a concatenation.
    Aes256Gcm::new_from_slice(&derived_key)
        .expect("derived_key is WHOLESOME.derived_key_len == 32 bytes")
        .encrypt_in_place(Nonce::from_slice(&iv), b"", &mut payload)
        .expect("plaintext is bounded by DEFLATE_CEILING, far under AES-GCM's per-key limit");

    // Plan §2/§6 step 8: manifest.xml exactly per the emit table.
    let manifest_xml = build_manifest(bytes.len() as i64, &iv, &salt, mimetype.as_deref());

    // Plan §3/§6 step 9: the three-member outer zip.
    assemble_zip(
        mimetype.as_deref().unwrap_or(&[]),
        &iv,
        &payload,
        &manifest_xml,
    )
}

/// Raw DEFLATE of the whole input buffer (mirrors `decrypt::raw_inflate`'s
/// shape in the opposite direction). No zlib wrapper -- LO's own
/// `ZipOutputEntryBase` deflates raw too (`ZipOutputEntry.cxx`).
fn raw_deflate(bytes: &[u8]) -> Result<Vec<u8>, EncryptError> {
    if bytes.len() > DEFLATE_CEILING {
        return Err(EncryptError::Deflate(format!(
            "input {} bytes exceeds ceiling {DEFLATE_CEILING}",
            bytes.len()
        )));
    }
    Ok(miniz_oxide::deflate::compress_to_vec(bytes, 6))
}

/// `len` random bytes via a CSPRNG (`ZipPackageStream.cxx:590,594` -- LO's
/// `rtl_random_getBytes`, here `aes_gcm::aead::OsRng`, reachable through the
/// `aes-gcm` dependency the crate already has; plan OQ2). Uses the fallible
/// `try_fill_bytes`, not `fill_bytes`, which panics -- a library must not
/// panic for an ordinary CSPRNG failure (plan §4).
fn random_bytes(len: usize) -> Result<Vec<u8>, EncryptError> {
    let mut buf = vec![0u8; len];
    OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| EncryptError::Random(e.to_string()))?;
    Ok(buf)
}

/// Plan §3's mimetype fallback chain, shared by the `mimetype` zip member's
/// bytes and the manifest `media-type` attribute: the input's own `mimetype`
/// member, read verbatim (never re-derived from `classify`'s recovered
/// string, since the two can diverge on a trailing newline or encoding
/// nuance); else `classify`'s `media_type` as raw UTF-8 with no trailing
/// newline; else `None`, and the attribute is omitted entirely.
///
/// Verbatim, but not unconditionally: a member over [`MIMETYPE_CEILING`], or
/// carrying bytes that cannot go into an XML attribute, is
/// [`EncryptError::Mimetype`] rather than a package that classifies and then
/// fails to open. Every real producer's `mimetype` is a short ASCII media
/// type, so the §3 ruling still governs every file that exists.
fn resolve_mimetype(
    bytes: &[u8],
    classify_media_type: Option<&str>,
) -> Result<Option<Vec<u8>>, EncryptError> {
    if let Some(raw) = read_input_mimetype_member(bytes)? {
        check_xml_attribute_text(&raw)?;
        return Ok(Some(raw));
    }
    Ok(classify_media_type.map(|s| s.as_bytes().to_vec()))
}

/// Reject anything that cannot be written into `manifest:media-type` and
/// still parse: invalid UTF-8, or a character outside XML 1.0's `Char`
/// production (`#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] |
/// [#x10000-#x10FFFF]`). quick-xml escapes the five markup characters but
/// emits a C0 control byte as-is, and expat -- LO's own `ManifestReader` --
/// rejects the result, discarding every row.
fn check_xml_attribute_text(raw: &[u8]) -> Result<(), EncryptError> {
    let text = std::str::from_utf8(raw)
        .map_err(|e| EncryptError::Mimetype(format!("not valid UTF-8: {e}")))?;
    if let Some(c) = text.chars().find(|&c| !is_xml_char(c)) {
        return Err(EncryptError::Mimetype(format!(
            "contains U+{:04X}, not an XML 1.0 Char",
            c as u32
        )));
    }
    Ok(())
}

fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | ' '..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

/// Read the input zip's own `mimetype` member, verbatim, straight off the
/// archive -- not through `Classification` (plan §3). Bounded by
/// [`MIMETYPE_CEILING`]: `zip` bounds only the *compressed* size, so an
/// unguarded `read_to_end` here would inflate whatever a crafted member
/// claims, although `classify` admitted the package on its first 1024 bytes.
///
/// A root `mimetype` member is exactly `"mimetype"` -- `collapse_slashes`
/// cannot turn any other name into it -- so this is `zip`'s own O(1)
/// name lookup rather than decrypt's `member_matches_path` scan.
fn read_input_mimetype_member(bytes: &[u8]) -> Result<Option<Vec<u8>>, EncryptError> {
    let mut archive =
        ZipArchive::new(Cursor::new(bytes)).map_err(|e| EncryptError::Zip(e.to_string()))?;
    let Ok(mut file) = archive.by_name("mimetype") else {
        return Ok(None);
    };
    let mut buf = Vec::new();
    file.by_ref()
        .take(MIMETYPE_CEILING as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| EncryptError::Zip(e.to_string()))?;
    if buf.len() > MIMETYPE_CEILING {
        return Err(EncryptError::Mimetype(format!(
            "member exceeds ceiling {MIMETYPE_CEILING}, which is all classify itself read"
        )));
    }
    Ok(Some(buf))
}

/// Build `META-INF/manifest.xml` exactly per plan §2's emit table: one
/// `file-entry` for `encrypted-package`, no checksum attributes at all
/// (`SetupStorage`'s `Value.clear()` for GCM), `manifest:version` fixed at
/// [`WHOLESOME`]`.odf_version`, and no root `/` file-entry
/// (`ManifestExport.cxx:297` -- wholesome `continue`s past the per-entry
/// write loop for that sequence). Child order inside `encryption-data`:
/// algorithm, start-key-generation, key-derivation.
///
/// Every parameter it writes comes from [`WHOLESOME`] or from this call's own
/// salt/IV, so the manifest cannot promise a tuple the key was not derived
/// under.
fn build_manifest(size: i64, iv: &[u8], salt: &[u8], media_type: Option<&[u8]>) -> Vec<u8> {
    // `ManifestExport.cxx:145-153`: `xmlns:loext` and `manifest:version` are
    // both written together, gated on the same ODF >= 1.2 check -- always
    // true for wholesome, which only exists at ODFSVER_LATEST_EXTENDED.
    let mut root = BytesStart::new(uris::ELEMENT_MANIFEST);
    root.push_attribute(("xmlns:manifest", uris::MANIFEST_NS_OASIS));
    root.push_attribute(("xmlns:loext", uris::MANIFEST_NS_LOEXT));
    root.push_attribute((uris::ATTR_VERSION, WHOLESOME.odf_version));

    let size_str = size.to_string();
    // Checked by `check_xml_attribute_text` before we got here; the `classify`
    // fallback tier is a `&str` to begin with.
    let media_type = media_type.map(|b| String::from_utf8_lossy(b).into_owned());
    let mut file_entry = BytesStart::new(uris::ELEMENT_FILE_ENTRY);
    file_entry.push_attribute((uris::ATTR_FULL_PATH, "encrypted-package"));
    file_entry.push_attribute((uris::ATTR_SIZE, size_str.as_str()));
    if let Some(mt) = media_type.as_deref() {
        file_entry.push_attribute((uris::ATTR_MEDIA_TYPE, mt));
    }

    let iv_b64 = crate::manifest::encode_b64(iv);
    let mut algorithm = BytesStart::new(uris::ELEMENT_ALGORITHM);
    algorithm.push_attribute((uris::ATTR_ALGORITHM_NAME, uris::AESGCM256_URL));
    algorithm.push_attribute((uris::ATTR_IV, iv_b64.as_str()));

    // `ManifestExport.cxx:437-475`: GCM picks the W3C SHA-256 URL
    // (`SHA256_URL`), not the "bad ODF URL" (`SHA256_URL_ODF12`) CBC keeps for
    // ODF <= 1.4 interop -- "new encryption is incompatible anyway, use W3C URL".
    let key_size = WHOLESOME.derived_key_len.to_string();
    let mut start_key_gen = BytesStart::new(uris::ELEMENT_START_KEY_GENERATION);
    start_key_gen.push_attribute((uris::ATTR_START_KEY_NAME, uris::SHA256_URL));
    start_key_gen.push_attribute((uris::ATTR_KEY_SIZE, key_size.as_str()));

    let (t, m, p) = (
        WHOLESOME.argon2_t.to_string(),
        WHOLESOME.argon2_m_kib.to_string(),
        WHOLESOME.argon2_p.to_string(),
    );
    let salt_b64 = crate::manifest::encode_b64(salt);
    let mut key_derivation = BytesStart::new(uris::ELEMENT_KEY_DERIVATION);
    key_derivation.push_attribute((uris::ATTR_KEY_DERIVATION_NAME, uris::ARGON2ID_URL_LO));
    key_derivation.push_attribute((uris::ATTR_ARGON2_T_LO, t.as_str()));
    key_derivation.push_attribute((uris::ATTR_ARGON2_M_LO, m.as_str()));
    key_derivation.push_attribute((uris::ATTR_ARGON2_P_LO, p.as_str()));
    key_derivation.push_attribute((uris::ATTR_SALT, salt_b64.as_str()));
    // `ManifestExport.cxx:517-522`: key-derivation's own `key-size` is written
    // only when `bStoreStartKeyGeneration` -- always true here.
    key_derivation.push_attribute((uris::ATTR_KEY_SIZE, key_size.as_str()));

    let events = [
        Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)),
        Event::Start(root),
        Event::Start(file_entry),
        Event::Start(BytesStart::new(uris::ELEMENT_ENCRYPTION_DATA)),
        Event::Empty(algorithm),
        Event::Empty(start_key_gen),
        Event::Empty(key_derivation),
        Event::End(BytesEnd::new(uris::ELEMENT_ENCRYPTION_DATA)),
        Event::End(BytesEnd::new(uris::ELEMENT_FILE_ENTRY)),
        Event::End(BytesEnd::new(uris::ELEMENT_MANIFEST)),
    ];

    let mut writer = Writer::new(Vec::new());
    for event in events {
        writer
            .write_event(event)
            .expect("writing to an in-memory Vec<u8> cannot fail");
    }
    writer.into_inner()
}

/// Assemble the outer zip: exactly three members, in order -- `mimetype`
/// (STORED), `encrypted-package` (STORED, no data descriptor -- the whole
/// ciphertext is already in memory, so `ZipWriter` over a `Cursor<Vec<u8>>`
/// can write ordinary STORED headers with size/CRC known upfront, the same
/// reasoning `decrypt::rebuild_zip` already relies on), `META-INF/manifest.xml`
/// (DEFLATED, via the `zip` crate's existing `deflate` feature).
///
/// `iv` and `ciphertext` are written back to back into the one member rather
/// than concatenated first: the payload is the largest thing in play and
/// there is no reason to hold two copies of it.
fn assemble_zip(
    mimetype: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    manifest_xml: &[u8],
) -> Result<Vec<u8>, EncryptError> {
    let capacity = mimetype.len() + iv.len() + ciphertext.len() + manifest_xml.len() + 512;
    let mut out = ZipWriter::new(Cursor::new(Vec::with_capacity(capacity)));
    let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let deflated = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let zip_err = |e: zip::result::ZipError| EncryptError::Zip(e.to_string());
    let io_err = |e: std::io::Error| EncryptError::Zip(e.to_string());

    out.start_file("mimetype", stored).map_err(zip_err)?;
    out.write_all(mimetype).map_err(io_err)?;

    out.start_file("encrypted-package", stored).map_err(zip_err)?;
    out.write_all(iv).map_err(io_err)?;
    out.write_all(ciphertext).map_err(io_err)?;

    out.start_file(MANIFEST_PATH, deflated).map_err(zip_err)?;
    out.write_all(manifest_xml).map_err(io_err)?;

    Ok(out.finish().map_err(zip_err)?.into_inner())
}

#[cfg(test)]
#[path = "encrypt_tests.rs"]
mod tests;
