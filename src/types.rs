//! Classification types: the public result surface of [`crate::classify`], plus
//! the `pub(crate)` Stage A / Stage B intermediates it is built from.

/// Zip-shape outcome. PGP is a [`Kdf`], not a mode.
///
/// ```
/// use odf_crypto::{classify, Mode};
///
/// let bytes = include_bytes!("../tests/goldens/lo-unencrypted.odt");
/// let class = classify(bytes)?;
///
/// match class.mode {
///     Mode::Plain => println!("not encrypted"),
///     Mode::PerEntry => println!("{} encrypted members", class.encrypted_entries.len()),
///     Mode::Wholesome => println!("one encrypted-package member"),
/// }
/// assert_eq!(class.mode, Mode::Plain);
/// # Ok::<(), odf_crypto::DetectError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No stream in the zip resolved to a complete `encryption-data` row — the
    /// state `encrypt` requires and `decrypt` refuses.
    Plain,
    /// Ordinary members carry complete `encryption-data`, and no root
    /// `encrypted-package` entry does. Also reached when an `encrypted-package`
    /// row is complete but exists only as an XML path, with no such zip entry.
    PerEntry,
    /// A root `encrypted-package` zip member whose `encryption-data` is
    /// complete. The whole document is one encrypted stream.
    Wholesome,
}

/// Start-key digest. Omitted `start-key-generation` defaults to SHA-1 on the
/// password path. PGP clamps to SHA-256 (`ZipPackage.cxx` 339).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartKeyAlg {
    /// SHA-1, and the default when the row omits `start-key-generation`.
    Sha1,
    /// SHA-256, written explicitly by every modern LibreOffice row.
    Sha256,
}

/// LibreOffice `CipherID`: three values. 128/192/256 survives only as
/// [`EntryEncryption::derived_key_len`] (`sal_Int32`).
///
/// ```
/// use odf_crypto::{classify, Cipher, Kdf, Mode};
///
/// let bytes = include_bytes!("../tests/goldens/aoo-blowfish-pbkdf2.odt");
/// let class = classify(bytes)?;
///
/// assert_eq!(class.mode, Mode::PerEntry);
/// let row = &class.encrypted_entries[0];
/// assert_eq!(row.cipher, Cipher::BlowfishCfb8);
/// assert!(matches!(row.kdf, Kdf::Pbkdf2 { .. }));
/// # Ok::<(), odf_crypto::DetectError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// Blowfish in CFB. The name mirrors LibreOffice's
    /// `CipherID::BLOWFISH_CFB_8`, but the wire mode is 64-bit-segment CFB
    /// (`BF_updateCFB` / `EVP_bf_cfb`), not CFB-8.
    BlowfishCfb8,
    /// AES-CBC. All three `xmlenc#aes{128,192,256}-cbc` URIs collapse here —
    /// only [`EntryEncryption::derived_key_len`] says which AES.
    AesCbcW3c,
    /// AES-GCM, the W3C URI current LibreOffice writes.
    AesGcmW3c,
}

/// Key-derivation function recorded on a complete row.
///
/// ```
/// use odf_crypto::Kdf;
///
/// fn describe(kdf: &Kdf) -> String {
///     match kdf {
///         Kdf::Pbkdf2 { iterations, .. } => format!("PBKDF2, {iterations} iterations"),
///         Kdf::Argon2id { t, m, p, .. } => format!("Argon2id t={t} m={m}KiB p={p}"),
///         Kdf::PgpRsaOaepMgf1p => "PGP".to_string(),
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kdf {
    /// PBKDF2. Its HMAC is SHA-1 whatever [`StartKeyAlg`] the row asked for —
    /// the start-key digest and the PBKDF2 PRF are separate choices.
    Pbkdf2 {
        /// `manifest:iteration-count`, an `sal_Int32` the file controls.
        iterations: i32,
        /// `manifest:salt`, base64-decoded.
        salt: Vec<u8>,
    },
    /// Argon2id, written by current LibreOffice.
    Argon2id {
        /// Time cost (`manifest:argon2-t`), an `sal_Int32` the file controls.
        t: i32,
        /// Memory cost in **KiB** (`manifest:argon2-m`), not bytes.
        m: i32,
        /// Parallelism (`manifest:argon2-p`), an `sal_Int32` the file controls.
        p: i32,
        /// `manifest:salt`, base64-decoded.
        salt: Vec<u8>,
    },
    /// PGP key wrapping. Reported by `classify`, refused by `decrypt`; the
    /// wrapped material is in [`Classification::pgp_keys`].
    PgpRsaOaepMgf1p,
}

/// Checksum on a complete row. GCM (and PGP+GCM) may omit it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checksum {
    /// No checksum. The AEAD tag is the only integrity check.
    None,
    /// SHA-1 over the first 1 KiB of the decrypted but **still-deflated** bytes.
    Sha1_1K(Vec<u8>),
    /// SHA-256 over the first 1 KiB of the decrypted but **still-deflated** bytes.
    Sha256_1K(Vec<u8>),
}

/// One complete encryption-data tuple after Stage B.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryEncryption {
    /// The **resolved** tree path, which is not necessarily the row's
    /// `manifest:full-path`: LibreOffice's own lookup can land a row on a
    /// stream its path does not name.
    pub path: String,
    /// Cipher the row declares.
    pub cipher: Cipher,
    /// Key-derivation function and its parameters.
    pub kdf: Kdf,
    /// Digest applied to the password before the KDF runs.
    pub start_key: StartKeyAlg,
    /// Integrity check, if the row carries one.
    pub checksum: Checksum,
    /// `manifest:size` (`sal_Int64`): the **uncompressed plaintext** length,
    /// which `decrypt` enforces after inflating.
    pub size: i64,
    /// Initialisation vector or nonce, base64-decoded.
    pub iv: Vec<u8>,
    /// `manifest:key-size` in bytes (`sal_Int32`), and the only thing that says
    /// which AES a [`Cipher::AesCbcW3c`] row means. PGP uses
    /// `GetDefaultDerivedKeySize`.
    pub derived_key_len: i32,
}

/// Result of [`crate::classify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// Which zip shape the package is in.
    pub mode: Mode,
    /// LibreOffice `HasEncryptedEntries` — the latch, not “any encryption-data”.
    pub package_encrypted: bool,
    /// The package's ODF version, from the root folder — the first non-empty
    /// `manifest:version` in the manifest, falling back to the one implied by
    /// the `mimetype` member.
    ///
    /// `None` when no row declares one, which is normal for older packages.
    /// Compared **byte-lexicographically**, not numerically, when deciding
    /// [`Classification::odf12_fatal`] — so `"1.10"` sorts below `"1.2"`, as it
    /// does in LibreOffice.
    pub odf_version: Option<String>,
    /// Root **entry** named `encrypted-package` in the zip's folder tree, not an
    /// XML-only path — a member path such as `encrypted-package/x` synthesizes
    /// that entry as a folder and also sets this. Feeds the unexpected-streams
    /// test and root media-type selection, so it is not inert.
    pub zip_has_encrypted_package: bool,
    /// Root-folder `manifest:media-type`, the document's MIME type.
    pub media_type: Option<String>,
    /// The row that decided the package is encrypted, and the one to read when
    /// you want the package's encryption parameters without walking
    /// [`Classification::encrypted_entries`].
    ///
    /// It is the first accepted row resolving to `content.xml` or
    /// `encrypted-package` — the same row that sets
    /// [`Classification::package_encrypted`], so the two are `Some`/`true`
    /// together. A clone, not a borrow: the same entry also appears in
    /// `encrypted_entries`.
    ///
    /// `None` for a [`Mode::Plain`] package, and also for one whose only
    /// complete rows sit on other members — encrypted entries can exist with no
    /// latch row, which is why `package_encrypted` is not
    /// `!encrypted_entries.is_empty()`.
    pub common: Option<EntryEncryption>,
    /// Every member that resolved to a complete `encryption-data` row, in
    /// manifest order.
    pub encrypted_entries: Vec<EntryEncryption>,
    /// `LookForUnexpectedODF12Streams`. Always computed.
    pub has_unexpected_streams: bool,
    /// `has_unexpected_streams && root version >= "1.2"` (byte-lexicographic).
    /// LibreOffice throws rather than opening; `decrypt` and `encrypt` refuse
    /// the same packages so they do not unwrap or wrap something LO would reject.
    pub odf12_fatal: bool,
    /// PGP `encrypted-key` material from the first file-entry's key info, if any.
    /// Present so a caller can hand it to an OpenPGP implementation; this crate
    /// refuses such packages.
    pub pgp_keys: Vec<EncryptedKey>,
}

/// Failures that stop `classify` before a [`Classification`].
///
/// Does not implement `PartialEq` — match with [`matches!`] rather than
/// comparing, or compare the `Display` output.
///
/// ```
/// use odf_crypto::{classify, DetectError};
///
/// let err = classify(b"this is not a zip file").unwrap_err();
/// assert!(matches!(err, DetectError::NotZip));
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DetectError {
    /// The bytes are not a zip archive at all.
    #[error("not a zip archive")]
    NotZip,
    /// A zip, but with no `META-INF/manifest.xml`, so not an ODF package.
    #[error("not an ODF package: META-INF/manifest.xml is missing")]
    MissingManifest,
    /// A zip entry could not be read. The string is a diagnostic; do not match
    /// on its content.
    #[error("failed to read zip entry: {0}")]
    Zip(String),
    /// The package is one LibreOffice itself would not open — a duplicate or
    /// invalid entry name, or a stream/folder collision.
    #[error("inconsistent package: {0}")]
    Inconsistent(String),
}

/// Internal checksum-type after Stage A (digest bytes live on the bag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChecksumAlg {
    Sha1_1K,
    Sha256_1K,
}

/// Internal KDF id after Stage A, before accept predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KdfId {
    Pbkdf2,
    Argon2id,
    PgpRsaOaepMgf1p,
}

/// One `encrypted-key` collected by Stage A.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EncryptedKey {
    /// OpenPGP key id the packet is addressed to, base64-decoded.
    pub key_id: Vec<u8>,
    /// The `PGPKeyPacket` bytes, base64-decoded.
    pub key_packet: Vec<u8>,
    /// The RSA-wrapped session key (`CipherValue`), base64-decoded.
    pub cipher_value: Vec<u8>,
}

/// `KeyInfo` attached only to the first file-entry bag (`ManifestImport.cxx` 468).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyInfo {
    pub keys: Vec<EncryptedKey>,
}

/// Stage A property bag. Fields are present only when ManifestImport wrote them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PropertyBag {
    pub full_path: String,
    pub media_type: Option<String>,
    pub version: Option<String>,
    pub size: Option<i64>,
    pub salt: Option<Vec<u8>>,
    pub iv: Option<Vec<u8>>,
    pub iteration_count: Option<i32>,
    pub derived_key_size: Option<i32>,
    pub digest: Option<Vec<u8>>,
    pub digest_alg: Option<ChecksumAlg>,
    pub enc_alg: Option<Cipher>,
    pub start_key_alg: Option<StartKeyAlg>,
    pub kdf: Option<KdfId>,
    pub argon2_args: Option<(i32, i32, i32)>,
    pub key_info: Option<KeyInfo>,
}
