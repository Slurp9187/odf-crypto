//! What [`crate::DecryptError::BadParameters`] carries: which manifest setting
//! a package declares wrongly, the value it declares, and what was allowed.
//!
//! **No byte of the file is in it** (the owner, 2026-10-19 UTC; plan
//! `docs/plans/structured-bad-parameters-2026-10-19.md`). Every payload is a
//! fieldless enum or an integer, and every `Display` renders only those. The
//! string this replaced could carry text the file chose: a row's
//! `manifest:full-path`, up to the 8 MiB manifest cap, reached a terminal through
//! the CLI's `report()` unbounded. A consumer can now write its own sentence
//! from `got`, `min` and `max` instead of quoting ours.
//!
//! The write side's [`crate::ParamsReason`] is mirrored, not reused. That type
//! is a verdict on a caller's own tuple and the CLI pins it to exit 1 (usage);
//! a [`BadParameter`] is a verdict on a file and maps to exit 6 (malformed). One
//! type with two exit codes would read wrong in a `match`.

use crate::{Argon2Axis, Cipher};

/// Which manifest setting a [`BadParameter`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestField {
    /// `manifest:iteration-count`, the PBKDF2 iteration count.
    IterationCount,
    /// `loext:argon2-iterations`, `-memory` or `-lanes`.
    Argon2(Argon2Axis),
    /// `manifest:key-size`, the derived key's length in bytes.
    KeySize,
    /// `manifest:size`, the member's declared plaintext length.
    Size,
    /// `manifest:initialisation-vector`, its decoded length in bytes.
    IvLen,
    /// `manifest:salt`, its decoded length in bytes.
    SaltLen,
    /// How many encrypted rows the manifest lists.
    EncryptedEntries,
}

impl core::fmt::Display for ManifestField {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Exhaustive, with no `_` arm, as `Argon2Axis` is: a new field fails
        // to compile here until it is given a name.
        match self {
            Self::IterationCount => f.write_str("manifest:iteration-count"),
            Self::Argon2(Argon2Axis::T) => f.write_str("loext:argon2-iterations"),
            Self::Argon2(Argon2Axis::MKib) => f.write_str("loext:argon2-memory (KiB)"),
            Self::Argon2(Argon2Axis::P) => f.write_str("loext:argon2-lanes"),
            Self::KeySize => f.write_str("manifest:key-size"),
            Self::Size => f.write_str("manifest:size"),
            Self::IvLen => f.write_str("manifest:initialisation-vector length"),
            Self::SaltLen => f.write_str("manifest:salt length"),
            Self::EncryptedEntries => f.write_str("encrypted row count"),
        }
    }
}

/// The primitive whose own requirement a [`BadParameter::CipherRejects`]
/// names: not a bound of this crate's, and not adjustable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Primitive {
    /// The `argon2` crate (and libargon2, which LibreOffice uses): `m >= 8p`,
    /// `p <= 0xFFFFFF`, a salt of at least 8 bytes.
    Argon2,
    /// AES-GCM: a 12-byte IV.
    AesGcm,
    /// AES-CBC: a 16-byte IV.
    AesCbc,
    /// Blowfish CFB: an 8-byte IV.
    Blowfish,
}

impl core::fmt::Display for Primitive {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Argon2 => "argon2",
            Self::AesGcm => "AES-GCM",
            Self::AesCbc => "AES-CBC",
            Self::Blowfish => "Blowfish",
        })
    }
}

/// A member's bytes disagree with its manifest row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemberFault {
    /// An AES-GCM member is shorter than its IV and tag together (28 bytes).
    ShorterThanIvAndTag,
    /// An AES-GCM member's first 12 bytes are not the manifest's IV.
    IvMismatch,
    /// An AES-CBC member is empty or not a whole number of 16-byte blocks.
    NotBlockMultiple,
    /// A member holds more bytes than its zip header says.
    LongerThanHeader,
}

impl core::fmt::Display for MemberFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::ShorterThanIvAndTag => "an AES-GCM member is shorter than its IV and tag",
            Self::IvMismatch => "an AES-GCM member does not begin with its manifest IV",
            Self::NotBlockMultiple => "an AES-CBC member is not a whole number of blocks",
            Self::LongerThanHeader => "a member is longer than its zip header says",
        })
    }
}

/// Why a package's own encryption settings were refused, and **whose rule**
/// they broke. Every field is an enum or an integer; nothing in it came from
/// the file as text.
///
/// `#[non_exhaustive]`: more reasons may be added, so match with a `_` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BadParameter {
    /// Outside the range this crate acts on: a [`crate::DecryptLimits`]
    /// ceiling or a `limits.rs` policy bound, or below a floor the format sets
    /// (`positiveInteger`, `nonNegativeInteger`). A file the format and
    /// LibreOffice allow can land here, so this is never evidence the file is
    /// malformed.
    #[error("{field} is {got}, outside {min}..={max}, the range this crate acts on")]
    OutOfRange {
        /// Which setting.
        field: ManifestField,
        /// The value the file declares.
        got: i64,
        /// Inclusive floor.
        min: i64,
        /// Inclusive ceiling.
        max: i64,
    },
    /// A primitive cannot run it, so no limit of this crate's could help.
    #[error("{field} is {got}, outside {min}..={max}, which {by} itself requires")]
    CipherRejects {
        /// Which setting.
        field: ManifestField,
        /// Whose requirement it is.
        by: Primitive,
        /// The value the file declares.
        got: i64,
        /// Inclusive floor.
        min: i64,
        /// Inclusive ceiling.
        max: i64,
    },
    /// `manifest:key-size` cannot be used with the row's cipher. AES takes the
    /// set {16, 24, 32}, which a range would misstate; Blowfish takes 4..=56.
    #[error("manifest:key-size {got} cannot be used with {cipher:?}")]
    KeySizeForCipher {
        /// The key size the file declares.
        got: i32,
        /// The row's cipher.
        cipher: Cipher,
    },
    /// A member's bytes disagree with its manifest row.
    #[error("{0}")]
    Member(MemberFault),
    /// A manifest row names no zip member. The row is given by its index among
    /// the encrypted rows ([`crate::Classification::encrypted_entries`]),
    /// never by its `manifest:full-path`, which is text the file chose.
    #[error("encrypted row {row} names no zip member")]
    NoMember {
        /// Index into the encrypted rows.
        row: usize,
    },
}

/// `n` as an `i64`, saturating: a count or length that does not fit is
/// reported as `i64::MAX` rather than panicking.
pub(crate) fn wide<T: TryInto<i64>>(n: T) -> i64 {
    n.try_into().unwrap_or(i64::MAX)
}
