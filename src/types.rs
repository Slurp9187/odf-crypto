//! Public classification types from plan §5.

/// Zip-shape outcome. PGP is a [`Kdf`], not a mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No complete encryption-data on a latchable member.
    Plain,
    /// Ordinary members carry encryption-data; no `encrypted-package` zip member
    /// with a complete bag.
    PerEntry,
    /// Zip has a root `encrypted-package` member whose bag is complete.
    Wholesome,
}

/// Start-key digest. Omitted `start-key-generation` defaults to SHA-1 on the
/// password path. PGP clamps to SHA-256 (`ZipPackage.cxx` 339).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartKeyAlg {
    Sha1,
    Sha256,
}

/// LibreOffice `CipherID`: three values. 128/192/256 survives only as
/// [`EntryEncryption::derived_key_len`] (`sal_Int32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    BlowfishCfb8,
    AesCbcW3c,
    AesGcmW3c,
}

/// Key-derivation function recorded on a complete row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kdf {
    Pbkdf2 {
        iterations: i32,
        salt: Vec<u8>,
    },
    Argon2id {
        t: i32,
        m: i32,
        p: i32,
        salt: Vec<u8>,
    },
    PgpRsaOaepMgf1p,
}

/// Checksum on a complete row. GCM (and PGP+GCM) may omit it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checksum {
    None,
    Sha1_1K(Vec<u8>),
    Sha256_1K(Vec<u8>),
}

/// One complete encryption-data tuple after Stage B.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryEncryption {
    pub path: String,
    pub cipher: Cipher,
    pub kdf: Kdf,
    pub start_key: StartKeyAlg,
    pub checksum: Checksum,
    /// `manifest:size` is `sal_Int64`.
    pub size: i64,
    pub iv: Vec<u8>,
    /// The one LO value (`sal_Int32`). PGP uses `GetDefaultDerivedKeySize`.
    pub derived_key_len: i32,
}

/// Result of [`crate::classify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub mode: Mode,
    /// LibreOffice `HasEncryptedEntries` — the latch, not “any encryption-data”.
    pub package_encrypted: bool,
    /// Root-folder version after the `/` row and mimetype fallback.
    pub odf_version: Option<String>,
    /// Zip root member named `encrypted-package`, not an XML-only path.
    pub zip_has_encrypted_package: bool,
    pub media_type: Option<String>,
    /// First-wins latch member.
    pub common: Option<EntryEncryption>,
    pub encrypted_entries: Vec<EntryEncryption>,
    /// `LookForUnexpectedODF12Streams`. Always computed.
    pub has_unexpected_streams: bool,
    /// `has_unexpected_streams && root version >= "1.2"` (byte-lexicographic).
    pub odf12_fatal: bool,
}

/// Failures that stop `classify` before a [`Classification`].
#[derive(Debug, thiserror::Error)]
pub enum DetectError {
    #[error("not a zip archive")]
    NotZip,
    #[error("not an ODF package: META-INF/manifest.xml is missing")]
    MissingManifest,
    #[error("failed to read zip entry: {0}")]
    Zip(String),
    #[error("failed to parse manifest.xml: {0}")]
    Manifest(String),
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

/// One `encrypted-key` collected by Stage A. Typed further in S5.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EncryptedKey {
    pub key_id: Vec<u8>,
    pub key_packet: Vec<u8>,
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
