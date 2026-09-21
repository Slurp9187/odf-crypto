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
use secure_gate::{RevealSecret, RevealSecretMut};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::classify::classify;
use crate::limits::{
    AES_GCM_IV_LEN, ARGON2_MAX_M_COST_KIB, ARGON2_MAX_T_COST, ARGON2_MIN_M_COST_KIB,
    ARGON2_MIN_P_COST, ARGON2_MIN_T_COST, DEFLATE_CEILING, MIMETYPE_CEILING,
};
use crate::sensitive::{DeflatedPlaintext, DerivedKey};
use crate::types::{Mode, StartKeyAlg};
use crate::uris;
use crate::zip_err;
use crate::DetectError;

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

// The invariants that make this arc's Argon2id and AES-GCM calls reject
// nothing about their PARAMETERS, checked at compile time rather than
// asserted in a comment: argon2 requires `m >= 8p` and a salt of at least 8
// bytes, AES-256 needs a 32-byte key, and GCM's nonce is 96 bits.
// `uris::AESGCM256_URL` in `build_manifest` is keyed to `derived_key_len ==
// 32`; the assert below is what ties them together. Not a claim that the
// Argon2id call cannot fail at all -- it can still fail on the host's
// available memory; see `EncryptError::HostCannotAllocate`, which is about
// the machine, not the tuple these asserts cover.
//
// The Argon2 `m >= 8p` assert still covers the DEFAULT tuple, but it is no
// longer the whole story: `encrypt_with_params` takes `(t, m, p)` from a
// caller, and a value that arrives at run time cannot be checked at compile
// time. `Argon2Params::new` carries that same invariant to the constructor,
// which is why it returns a `Result` and why `encrypt_with_params` cannot
// fail on its parameters' VALIDITY. Their COST is a different axis: however
// small the tuple, no `(t, m, p)` can guarantee in advance that this host has
// the memory to run it.
const _: () = assert!(WHOLESOME.argon2_m_kib >= 8 * WHOLESOME.argon2_p);
const _: () = assert!(WHOLESOME.salt_len >= 8);
const _: () = assert!(WHOLESOME.derived_key_len == 32);
const _: () = assert!(WHOLESOME.iv_len == AES_GCM_IV_LEN);

/// Which axis of an Argon2id tuple a [`ParamsReason`] is about.
///
/// Named rather than positional for the same reason [`Argon2Params`] has named
/// fields: the manifest orders these `(t, m, p)` and `argon2::Params` orders
/// them `(m, t, p)`, so an index would be a transposition waiting to happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Argon2Axis {
    /// Time cost, `manifest:argon2-iterations`.
    T,
    /// Memory cost in KiB, `manifest:argon2-memory`.
    MKib,
    /// Parallelism, `manifest:argon2-lanes`.
    P,
}

impl core::fmt::Display for Argon2Axis {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Exhaustive on purpose, with no `_` arm: `#[non_exhaustive]` binds
        // downstream crates, not this one, so adding an axis fails to compile
        // here until it is given a name. A wildcard would silently render it
        // as something else.
        f.write_str(match self {
            Self::T => "t",
            Self::MKib => "m",
            Self::P => "p",
        })
    }
}

/// Why an [`Argon2Params`] tuple was refused — specifically, **whose rule it
/// broke**.
///
/// That distinction is the reason this is a type rather than a string. A
/// consumer telling a user "the format does not allow this" when the truth is
/// "this crate declined" has said something false with a straight face, and a
/// free-text message gives them no way to tell the two apart. Each variant
/// names the authority.
///
/// Neither variant means *weak*. A cheap-but-runnable tuple is accepted; see
/// [`Argon2Params`].
///
/// `#[non_exhaustive]`: more reasons may be added, so match with a `_` arm.
///
/// A host that cannot allocate the requested memory is deliberately **not**
/// one of them -- see [`EncryptError::HostCannotAllocate`], a top-level
/// variant rather than a `ParamsReason`. `ParamsReason` is raised by
/// [`Argon2Params::new`], before `encrypt_with_params` -- let alone the
/// package -- is ever touched; it is `Copy + Eq`, a reproducible verdict on
/// three integers that gives the same answer on every machine; and the CLI
/// pins it to exit 1, usage. A host-capacity failure has none of those
/// properties: it surfaces mid-`encrypt_with_params`, the same tuple can
/// succeed on a machine with more free memory, and reporting it as exit 1
/// would send someone to fix a command line that was never wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParamsReason {
    /// **This crate declined.** The value is outside the range `odf-crypto`
    /// acts on.
    ///
    /// This is a policy bound of ours, and it is worth being blunt about that:
    /// the ODF manifest schema types these attributes as unbounded
    /// `positiveInteger`, and LibreOffice validates the Argon2 triple only as
    /// `0 < t && 0 < m && 0 < p`. So a tuple refused here may be perfectly
    /// legal and perfectly openable elsewhere. Do not report it as a format
    /// violation.
    #[error("{axis} = {got} is outside {min}..={max}, the range this crate acts on")]
    OutOfRange {
        /// Which axis was out of range.
        axis: Argon2Axis,
        /// The value supplied.
        got: i32,
        /// Inclusive floor.
        min: u32,
        /// Inclusive ceiling.
        max: u32,
    },
    /// **`argon2` cannot run it.** Not this crate's decision, and widening our
    /// own bounds would not help.
    ///
    /// Today this is `m >= 8 * p` (argon2 cannot allocate fewer than 8 KiB per
    /// lane) and `p <= argon2::Params::MAX_P_COST`.
    #[error("{axis} = {got} is outside {min}..={max}, which argon2 itself requires")]
    CipherRejects {
        /// Which axis was rejected.
        axis: Argon2Axis,
        /// The value supplied.
        got: i32,
        /// Inclusive floor `argon2` requires.
        min: u32,
        /// Inclusive ceiling `argon2` requires.
        max: u32,
    },
}

/// Argon2id cost parameters for [`encrypt_with_params`].
///
/// # These are a property of the file, not of the machine that wrote it
///
/// The three values are written into `META-INF/manifest.xml` and travel with
/// the document. Choosing a low cost to suit a constrained device therefore
/// weakens that document **permanently, for every future reader on every
/// device** — the file cannot be re-derived at a higher cost without being
/// decrypted and re-encrypted. It is a deliberate, irreversible trade and this
/// crate does not make it for you: nothing here refuses a weak-but-valid
/// tuple, and nothing silently substitutes a stronger one.
///
/// [`Argon2Params::LIBREOFFICE_DEFAULT`] is what current LibreOffice writes.
/// Prefer it unless you have a reason you could defend to the person whose
/// document it is.
///
/// # Why a struct rather than three integers
///
/// Two orderings of the same three `i32`s are already in play: the manifest
/// writes `(t, m, p)` and `argon2::Params` orders them `(m, t, p)`. A tuple or
/// array makes transposing them type-check, look plausible and still produce a
/// file. Named fields make the mistake unrepresentable.
///
/// Fields are private and reached through [`t`](Self::t), [`m_kib`](Self::m_kib)
/// and [`p`](Self::p), so a value of this type has always been validated.
///
/// # Examples
///
/// ```
/// use odf_crypto::Argon2Params;
///
/// let default = Argon2Params::LIBREOFFICE_DEFAULT;
/// assert_eq!((default.t(), default.m_kib(), default.p()), (3, 65536, 4));
///
/// // An eighth of the default memory: weaker, allowed, and yours to justify.
/// let low = Argon2Params::new(2, 8192, 2)?;
/// assert_eq!(low.m_kib(), 8192);
///
/// // Refused because argon2 cannot run it, not because it is weak.
/// assert!(Argon2Params::new(3, 8, 4).is_err());
/// # Ok::<(), odf_crypto::EncryptError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    t: i32,
    m_kib: i32,
    p: i32,
}

impl Argon2Params {
    /// What current LibreOffice writes: `t = 3`, `m = 65536` KiB (64 MiB),
    /// `p = 4` — `oArgon2Args.emplace(3, (1<<16), 4)` in
    /// `package/source/zippackage/ZipPackage.cxx`, on the branch taken when the
    /// KDF is Argon2id. The tuple [`encrypt`] uses.
    ///
    /// This used to cite `objstor.cxx:349-399`, which is where LibreOffice
    /// chooses Argon2id *over PBKDF2* and never names a tuple at all. The
    /// numbers were right and the citation was not, which is the failure mode
    /// `CLAUDE.md` means by *check the code, not the doc* — a reader following
    /// it to confirm `65536` would not have found it.
    pub const LIBREOFFICE_DEFAULT: Self = Self {
        t: WHOLESOME.argon2_t,
        m_kib: WHOLESOME.argon2_m_kib,
        p: WHOLESOME.argon2_p,
    };

    /// Validate a `(t, m, p)` tuple, in the manifest's own order.
    ///
    /// `m_kib` is **kibibytes**, matching `manifest:argon2-memory` — 65536 is
    /// 64 MiB, not 64 KiB.
    ///
    /// # Errors
    ///
    /// [`EncryptError::Params`] when the tuple cannot be run, never when it is
    /// merely weak. Two reasons, and the distinction is the point:
    ///
    /// - a value outside the range this crate acts on at all, which is the
    ///   same range `decrypt` accepts off a manifest, so anything `encrypt`
    ///   writes can be read back;
    /// - `m_kib < 8 * p`, which `argon2` itself rejects — the invariant the
    ///   default tuple checks with a `const` assert.
    pub fn new(t: i32, m_kib: i32, p: i32) -> Result<Self, EncryptError> {
        // Ours. The schema and LibreOffice both permit more; see
        // `ParamsReason::OutOfRange`.
        let ours = |axis, got, min, max| {
            EncryptError::Params(ParamsReason::OutOfRange {
                axis,
                got,
                min,
                max,
            })
        };
        if !(ARGON2_MIN_T_COST..=ARGON2_MAX_T_COST).contains(&u32::try_from(t).unwrap_or(0)) {
            return Err(ours(Argon2Axis::T, t, ARGON2_MIN_T_COST, ARGON2_MAX_T_COST));
        }
        if !(ARGON2_MIN_M_COST_KIB..=ARGON2_MAX_M_COST_KIB)
            .contains(&u32::try_from(m_kib).unwrap_or(0))
        {
            return Err(ours(
                Argon2Axis::MKib,
                m_kib,
                ARGON2_MIN_M_COST_KIB,
                ARGON2_MAX_M_COST_KIB,
            ));
        }
        // `argon2::Params::MAX_P_COST`, not a bound of ours -- the same
        // ceiling `kdf::derive_argon2id` applies on the read side, so the two
        // directions cannot disagree about which tuples exist. Reported as
        // `CipherRejects` for that reason: widening our own range would not
        // make this tuple runnable.
        if !(ARGON2_MIN_P_COST..=argon2::Params::MAX_P_COST)
            .contains(&u32::try_from(p).unwrap_or(0))
        {
            return Err(EncryptError::Params(ParamsReason::CipherRejects {
                axis: Argon2Axis::P,
                got: p,
                min: ARGON2_MIN_P_COST,
                max: argon2::Params::MAX_P_COST,
            }));
        }
        // argon2's own requirement, not a policy of ours: it cannot allocate
        // fewer than 8 KiB per lane. Checked here because a caller-supplied
        // tuple cannot be checked by the `const` assert above. `p` is already
        // bounded by MAX_P_COST above, so `8 * p` cannot overflow `i32`.
        if m_kib < 8 * p {
            return Err(EncryptError::Params(ParamsReason::CipherRejects {
                axis: Argon2Axis::MKib,
                got: m_kib,
                min: u32::try_from(8 * p).unwrap_or(u32::MAX),
                max: ARGON2_MAX_M_COST_KIB,
            }));
        }
        Ok(Self { t, m_kib, p })
    }

    /// Time cost, `manifest:argon2-iterations`.
    #[must_use]
    pub fn t(&self) -> i32 {
        self.t
    }

    /// Memory cost in **KiB**, `manifest:argon2-memory`.
    #[must_use]
    pub fn m_kib(&self) -> i32 {
        self.m_kib
    }

    /// Parallelism, `manifest:argon2-lanes`.
    #[must_use]
    pub fn p(&self) -> i32 {
        self.p
    }

    /// Whether **any** axis is below what LibreOffice writes.
    ///
    /// Reported, never enforced — [`encrypt_with_params`] accepts a tuple for
    /// which this is `true`. It exists so a front end can say so: the CLI
    /// prints a warning on this, and a library consumer can do the same
    /// rather than re-deriving the comparison.
    ///
    /// # It is a warning trigger, not a strength ordering
    ///
    /// "Any axis below" is the right question for *should I warn about this*
    /// and the wrong one for *is this cryptographically weaker*, because the
    /// three axes do not trade off linearly and this collapses them to a bool.
    /// A tuple can be below on one axis and well above on another:
    ///
    /// ```
    /// use odf_crypto::Argon2Params;
    ///
    /// // One fewer pass, but twice LibreOffice's memory. Reported weaker.
    /// let mixed = Argon2Params::new(2, 131_072, 4)?;
    /// assert!(mixed.is_weaker_than_libreoffice());
    ///
    /// // Stronger on t, identical elsewhere. Not reported weaker.
    /// let stronger = Argon2Params::new(4, 65536, 4)?;
    /// assert!(!stronger.is_weaker_than_libreoffice());
    /// # Ok::<(), odf_crypto::EncryptError>(())
    /// ```
    ///
    /// Warning on the first is deliberate — it is below the reference on an
    /// axis, and a caller deserves to be told before that is frozen into a
    /// document — but do not read it as "this file is weaker overall". If you
    /// need a per-axis decision, compare [`t`](Self::t), [`m_kib`](Self::m_kib)
    /// and [`p`](Self::p) against [`Self::LIBREOFFICE_DEFAULT`] yourself;
    /// `m_kib` is usually the axis a memory-constrained device cares about.
    #[must_use]
    pub fn is_weaker_than_libreoffice(&self) -> bool {
        let d = Self::LIBREOFFICE_DEFAULT;
        self.t < d.t || self.m_kib < d.m_kib || self.p < d.p
    }
}

/// Failures from [`encrypt`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EncryptError {
    /// `classify()` itself rejected the input (not a zip, no manifest, ...).
    #[error("classification failed: {0}")]
    Classify(#[from] DetectError),
    /// The package is encrypted and LibreOffice would prompt for a password:
    /// `classify` set [`crate::Classification::package_encrypted`], the latch
    /// LibreOffice calls `HasEncryptedEntries`. Covers `Wholesome`, `PerEntry`
    /// with a latch row, and PGP rows alike.
    ///
    /// Split from [`EncryptError::PartiallyEncrypted`] in `0.1.0-rc.5`, because
    /// one variant was making a claim about the file that LibreOffice does not
    /// make -- see that variant.
    #[error("package is already encrypted")]
    AlreadyEncrypted,
    /// The package holds complete `encryption-data` rows but **no latch row**,
    /// so `classify` reports [`crate::Mode::PerEntry`] with
    /// `package_encrypted == false`.
    ///
    /// **LibreOffice opens this without prompting for a password.** The latch is
    /// set only by a row resolving to `content.xml` or `encrypted-package`
    /// (`ZipPackage.cxx:435-446`), so a package whose only complete rows sit on
    /// other members is not, to LibreOffice, an encrypted document -- it is a
    /// document with encrypted streams in it. Reporting that as *"package is
    /// already encrypted"* told a caller something the specifying implementation
    /// contradicts.
    ///
    /// Still refused, and the refusal is the same one: wrapping a package whose
    /// members are already ciphertext produces a file whose inner members
    /// nothing can open. What changed is the name of what was detected, not the
    /// decision. Both map to CLI exit 5.
    ///
    /// LibreOffice's own answer to this shape is worth knowing, because this
    /// crate cannot give it: on ODF >= 1.2 with the latch *also* set, it raises
    /// `ERRCODE_SFX_INCOMPLETE_ENCRYPTION` and disables macro execution
    /// (`sfx2/source/doc/objmisc.cxx:1028-1063`).
    #[error(
        "package has encrypted entries but no latch row: LibreOffice opens it without prompting"
    )]
    PartiallyEncrypted,
    /// LibreOffice would not open this plaintext package (`odf12_fatal`):
    /// unexpected streams and a root version `>= 1.2`. Refuse before Argon2id
    /// rather than wrapping a document LO rejects.
    #[error("LibreOffice would refuse this package: unexpected ODF 1.2 streams")]
    Odf12Fatal,
    /// Mirrors [`crate::DecryptError::EmptyPassword`] /
    /// `CreatePackageEncryptionData`'s empty sequence.
    #[error("password is empty")]
    EmptyPassword,
    /// CSPRNG failure -- vanishingly rare, but a library must not panic for it.
    #[error("random number generation failed: {0}")]
    Random(String),
    /// An [`Argon2Params`] tuple that cannot be used, carrying **whose rule**
    /// it broke — see [`ParamsReason`].
    ///
    /// **Never returned for a tuple that is merely weak.** Cost is the
    /// caller's decision and this crate does not overrule it; see
    /// [`Argon2Params`].
    ///
    /// Deliberately distinct from [`EncryptError::Internal`]: this reports a
    /// value that came from the caller, which they can correct, where
    /// `Internal` reports an invariant of ours. It quotes only the caller's own
    /// numbers and this crate's bounds, never anything read out of a package.
    ///
    /// # Do not render this as a problem with the document
    ///
    /// It is a **usage** error: the tuple was wrong, the input package was
    /// never examined. It is raised by [`Argon2Params::new`] before
    /// [`encrypt_with_params`] is even called, so it says nothing about the
    /// bytes a caller passed. A consumer that renders it as "this file is
    /// damaged" tells the user the one thing it does not mean, and sends them
    /// looking at the wrong thing. The `odf-crypto` binary maps it to exit 1
    /// (usage), not 6 (malformed), for the same reason.
    #[error("invalid Argon2 parameters: {0}")]
    Params(ParamsReason),
    /// This host could not allocate the working memory Argon2id needs.
    ///
    /// **Not an invalid tuple.** `params` was validated when it was
    /// constructed; this is the machine declining, and the same call may
    /// succeed on a machine with more free memory. Lowering
    /// [`Argon2Params::m_kib`] is a legitimate response, but read
    /// [`Argon2Params`] first: the cost is stored in the file and binds
    /// every future reader on every device, so trading it away to fit
    /// today's host is irreversible.
    #[error("host could not allocate {requested_bytes} bytes for key derivation")]
    HostCannotAllocate {
        /// The size, in bytes, of the working buffer Argon2id could not
        /// obtain: `params.m_kib` rounded up to whole blocks.
        requested_bytes: usize,
    },
    /// The input buffer cannot be deflated. `compress_to_vec` itself is
    /// infallible, so in practice this is the 1 GiB input-size rejection.
    #[error("deflate failed: {0}")]
    Deflate(String),
    /// The input's own `mimetype` member cannot be carried into the output.
    /// Four reasons, all of which `classify` itself tolerates (its check is
    /// `starts_with("application/vnd.")` over the first 1024 bytes):
    ///
    /// - over 1 KiB, which is all `classify` ever looked at;
    /// - not valid UTF-8;
    /// - containing a character outside XML 1.0's `Char` production, which
    ///   would emit a `manifest.xml` real LibreOffice's expat rejects;
    /// - containing a tab, LF or CR. Those are legal `Char`s, but XML
    ///   attribute-value normalization rewrites each to a space on the way
    ///   back in, so the verbatim `mimetype` zip member and the parsed
    ///   `manifest:media-type` would then disagree.
    ///
    /// All four fail closed rather than writing a package that classifies but
    /// will not open.
    #[error("unusable mimetype member: {0}")]
    Mimetype(String),
    /// A zip failure on either side: reading the input's own `mimetype`
    /// member, or building the outer container `encrypt` writes. The string
    /// is a diagnostic; do not match on its content.
    #[error("zip error: {0}")]
    Zip(String),
    /// A crypto primitive rejected parameters `encrypt` chose *itself* -- the
    /// wholesome profile's Argon2id tuple, its 32-byte key, its 12-byte nonce.
    /// Unreachable today: every one of those is a compile-time constant
    /// guarded by `const` asserts beside the profile, which is why this
    /// carries no recovery advice.
    ///
    /// **Not** where a host's inability to allocate Argon2id's working memory
    /// lands: that is [`EncryptError::HostCannotAllocate`], a distinct
    /// variant because it blames the machine, not a parameter a crypto
    /// primitive refused.
    ///
    /// Also covers a supposedly infallible write failing: `io::Write for
    /// Vec<u8>` through quick-xml, when building the manifest.
    ///
    /// It exists because the alternative is a panic in a library. This is
    /// deliberately not a `BadParameters` analogue: that variant would report
    /// an *untrusted manifest field*, which `encrypt` never reads. This
    /// reports an internal invariant a dependency bump could invalidate under
    /// us -- if `argon2` or `aes-gcm` ever narrows what it accepts, the
    /// failure surfaces as an `Err` a caller can handle rather than an abort
    /// it cannot.
    #[error("internal invariant violated: {0}")]
    Internal(String),
}

/// Encrypt a plaintext ODF package with `password`, producing what current
/// LibreOffice writes for that input under that password.
///
/// One profile only: wholesome Argon2id-derived AES-256-GCM, a single
/// `encrypted-package` member, no checksum. The salt and IV are fresh per call,
/// so two calls on the same input never produce the same bytes — assert on a
/// round trip, never on the output.
///
/// # Errors
///
/// Refused before any crypto runs, in this order, so no caller pays for a
/// 64 MiB Argon2id before learning the input was never eligible:
/// [`EncryptError::EmptyPassword`] (mirroring [`crate::decrypt`]'s own ordering),
/// [`EncryptError::AlreadyEncrypted`] for anything [`classify`] does not report
/// as [`Mode::Plain`], [`EncryptError::Classify`] if classification itself
/// fails, [`EncryptError::Odf12Fatal`] for a package LibreOffice would refuse,
/// and [`EncryptError::Mimetype`] for a `mimetype` member that cannot be
/// carried into the output.
///
/// [`EncryptError::HostCannotAllocate`] is different from every entry above:
/// it is not a pre-crypto screen. It surfaces mid-derivation, after the
/// whole-input deflate has already run, if the host cannot supply Argon2id's
/// working memory.
///
/// Then [`EncryptError::Deflate`] (in practice, an input over 1 GiB),
/// [`EncryptError::Random`], [`EncryptError::Zip`] and
/// [`EncryptError::Internal`].
///
/// [`EncryptError`] is `#[non_exhaustive]` and does not implement `PartialEq`;
/// match with a `_` arm and [`matches!`].
///
/// # Examples
///
/// ```
/// use odf_crypto::{classify, decrypt, encrypt, Mode};
///
/// let plain = include_bytes!("../tests/goldens/lo-unencrypted.odt");
/// assert_eq!(classify(plain)?.mode, Mode::Plain);
///
/// let sealed = encrypt(plain, "correct horse battery staple")?;
/// assert_eq!(classify(&sealed)?.mode, Mode::Wholesome);
///
/// // Round trips byte for byte.
/// let back = decrypt(&sealed, "correct horse battery staple")?;
/// assert_eq!(back, plain.as_slice());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn encrypt(bytes: &[u8], password: &str) -> Result<Vec<u8>, EncryptError> {
    encrypt_with_params(bytes, password, Argon2Params::LIBREOFFICE_DEFAULT)
}

/// [`encrypt`] with the Argon2id cost chosen by the caller.
///
/// Identical in every other respect: one `encrypted-package` member,
/// AES-256-GCM, a SHA-256 start key, no checksum, `manifest:version="1.4"`.
/// Only `(t, m, p)` moves, and it moves into both the key derivation and the
/// `loext:argon2-*` attributes, so the file describes how it was actually
/// derived.
///
/// # This can produce a deliberately weak file, and will not stop you
///
/// `params` is accepted whenever `argon2` can run it — see [`Argon2Params`]
/// for what is refused and why. A cost below
/// [`Argon2Params::LIBREOFFICE_DEFAULT`] is not an error here, and this
/// function does not warn: a library has no terminal to warn on. Call
/// [`Argon2Params::is_weaker_than_libreoffice`] if you want to tell someone.
///
/// The cost travels **with the document**, so it is not a local performance
/// setting. A file written at a low cost stays that weak for every future
/// reader, including on hardware that could have afforded more.
///
/// # Real LibreOffice reads these back
///
/// Verified against LibreOffice 26.2.1.2 rather than inferred from the format:
/// packages written at `(3, 65536, 4)`, `(2, 8192, 2)` and `(1, 1024, 1)` all
/// open with the correct text recovered.
///
/// Its source bounds every tuple, not just those three. `ManifestImport.cxx:257`
/// checks the attributes for positivity and nothing else — no floor, no ceiling,
/// no clamp — and `ZipFile.cxx:184-186` passes the file's own values straight
/// into `argon2_context`, with `:192` saying why there is no range check there
/// either: *"libargon2 validates all the arguments so don't need to do it
/// here."* What this crate will write is a strict subset of what libargon2
/// accepts, so no tuple it produces is refusable by LibreOffice on parameter
/// grounds.
///
/// # Errors
///
/// Exactly [`encrypt`]'s. `params`' *validity* was checked when it was
/// constructed, so this still cannot fail on that: [`EncryptError::Params`]
/// comes from [`Argon2Params::new`], not from here.
///
/// `params`' *cost* is a different question, and construction cannot have
/// checked it: [`EncryptError::HostCannotAllocate`] can still occur here,
/// scaling with `params.m_kib()` -- the one axis of the tuple a caller
/// chooses and the one no validation can guarantee a given host can afford.
///
/// # Examples
///
/// ```
/// use odf_crypto::{classify, decrypt, encrypt_with_params, Argon2Params, Kdf};
///
/// let plain = include_bytes!("../tests/goldens/lo-unencrypted.odt");
/// let cheap = Argon2Params::new(2, 8192, 2)?;
/// assert!(cheap.is_weaker_than_libreoffice());
///
/// let sealed = encrypt_with_params(plain, "hunter2", cheap)?;
///
/// // The file records the cost it was actually derived at.
/// let row = classify(&sealed)?.common.expect("wholesome carries a latch row");
/// assert!(matches!(row.kdf, Kdf::Argon2id { t: 2, m: 8192, p: 2, .. }));
/// assert_eq!(decrypt(&sealed, "hunter2")?, plain.as_slice());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn encrypt_with_params(
    bytes: &[u8],
    password: &str,
    params: Argon2Params,
) -> Result<Vec<u8>, EncryptError> {
    if password.is_empty() {
        return Err(EncryptError::EmptyPassword);
    }
    let class = classify(bytes)?;
    if class.mode != Mode::Plain {
        // The latch, not the row count. `package_encrypted` is LibreOffice's
        // `HasEncryptedEntries`, and it is what decides whether LO prompts --
        // so it is what decides which refusal is true of this file.
        return Err(if class.package_encrypted {
            EncryptError::AlreadyEncrypted
        } else {
            EncryptError::PartiallyEncrypted
        });
    }
    if class.odf12_fatal {
        return Err(EncryptError::Odf12Fatal);
    }

    // Plan §3's mimetype fallback chain, resolved before any crypto: it
    // depends only on `bytes` and `class`, and a rejection here should not
    // cost a whole-input deflate plus a 64 MiB Argon2id first.
    let mimetype = resolve_mimetype(bytes, class.media_type.as_deref())?;

    // Plan §6 step 3: raw-deflate the whole input buffer, unparsed. Wrapped
    // before the cipher runs, mirroring how the in-place read-side ciphers
    // wrap before the first block turns into plaintext: this is the crate's
    // own copy of the caller's document, so it is zeroized on drop even
    // though the caller's original stays plain.
    let mut payload = DeflatedPlaintext::new(raw_deflate(bytes)?);

    // Plan §6 step 5 / `ZipPackageStream.cxx:587-607`: fresh salt and IV per
    // save (moot here -- wholesome writes exactly one row). Neither is
    // wrapped: both are written to the manifest in the clear.
    let salt = random_bytes(WHOLESOME.salt_len)?;
    let iv = random_bytes(WHOLESOME.iv_len)?;

    // Plan §6 step 4/6: start key, then Argon2id over it with `salt` --
    // `crate::kdf`'s helpers, shared verbatim with `decrypt`, so the two
    // directions cannot derive keys differently.
    let start_key = crate::kdf::start_key(password, StartKeyAlg::Sha256);
    let mut derived_key = DerivedKey::new(vec![0u8; WHOLESOME.derived_key_len]);
    start_key.with_secret(|sk| {
        derived_key.with_secret_mut(|key| {
            crate::kdf::derive_argon2id(sk, &salt, params.t, params.m_kib, params.p, key).map_err(
                // Exhaustive, no `_` arm: the next `KdfError` variant must be
                // given a deliberate mapping here rather than silently
                // inheriting one -- the same discipline `Argon2Axis`'s
                // `Display` impl follows at its own match, above.
                |e| match e {
                    crate::kdf::KdfError::Params(s) => EncryptError::Internal(s),
                    crate::kdf::KdfError::HostCannotAllocate { requested_bytes } => {
                        EncryptError::HostCannotAllocate { requested_bytes }
                    }
                },
            )
        })
    })?;

    // Plan §6 step 7 / `ciphercontext.cxx`'s encrypt branch: AES-256-GCM,
    // empty AAD, the 16-byte tag appended to the ciphertext. Sealing in place
    // means the plaintext is overwritten rather than copied into a second
    // buffer, and what the wrapper holds afterwards is ciphertext. NSS does
    // not prepend the IV, so LO does, and so do we -- in `assemble_zip`,
    // which writes `IV || ciphertext || tag` without materialising a
    // concatenation.
    //
    // `Nonce::from_slice` panics on a length mismatch, so the length is
    // checked first: `WHOLESOME.iv_len` is const-asserted to be 12 above, but
    // a checked error beats a panic reachable only by editing that constant.
    if iv.len() != AES_GCM_IV_LEN {
        return Err(EncryptError::Internal(format!(
            "GCM nonce must be {AES_GCM_IV_LEN} bytes, WHOLESOME.iv_len gave {}",
            iv.len()
        )));
    }
    derived_key.with_secret(|key| {
        payload.with_secret_mut(|pt| {
            Aes256Gcm::new_from_slice(key)
                .map_err(|e| EncryptError::Internal(format!("AES-256-GCM key: {e}")))?
                .encrypt_in_place(Nonce::from_slice(&iv), b"", pt)
                .map_err(|e| EncryptError::Internal(format!("AES-256-GCM seal: {e}")))
        })
    })?;

    // Plan §2/§6 step 8: manifest.xml exactly per the emit table.
    let manifest_xml = build_manifest(bytes.len() as i64, &iv, &salt, mimetype.as_deref(), params)?;

    // Plan §3/§6 step 9: the three-member outer zip. `unwrap_or(&[])` writes a
    // zero-length `mimetype` member when neither fallback tier produced one --
    // deliberately, not as an oversight: LO's `ZipPackage::WriteMimetypeMagicFile`
    // (`ZipPackage.cxx:1125-1160`) is called unconditionally for the ZIP format
    // and writes an entry of `GetMediaType().getLength()` bytes, which is zero
    // when the root folder carries no media type. Omitting the member instead
    // would be the divergence.
    assemble_zip(
        mimetype.as_deref().map(str::as_bytes).unwrap_or(&[]),
        &iv,
        &payload,
        &manifest_xml,
    )
}

/// Raw DEFLATE of the whole input buffer (the opposite direction to
/// `decrypt::inflate_into`, though not its shape: deflate has no declared
/// output length to size a slot from, so this still returns a grown `Vec`). No zlib wrapper -- LO's own
/// `ZipOutputEntryBase` deflates raw too (`ZipOutputEntry.cxx`).
fn raw_deflate(bytes: &[u8]) -> Result<Vec<u8>, EncryptError> {
    raw_deflate_with_ceiling(bytes, DEFLATE_CEILING)
}

/// The body of [`raw_deflate`], with the ceiling as a parameter so a test can
/// exercise the rejection without allocating a gigabyte to reach the real one.
fn raw_deflate_with_ceiling(bytes: &[u8], ceiling: usize) -> Result<Vec<u8>, EncryptError> {
    if bytes.len() > ceiling {
        return Err(EncryptError::Deflate(format!(
            "input {} bytes exceeds ceiling {ceiling}",
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
/// Returns a `String`, not the raw bytes, so the UTF-8 validity established
/// here is carried in the type rather than re-derived downstream: the manifest
/// writer takes `&str` and has nothing left to unwrap. Copying stays verbatim
/// -- `String::from_utf8` does not transform the bytes, and `as_bytes()` hands
/// back exactly what the input member held.
fn resolve_mimetype(
    bytes: &[u8],
    classify_media_type: Option<&str>,
) -> Result<Option<String>, EncryptError> {
    if let Some(raw) = read_input_mimetype_member(bytes)? {
        return Ok(Some(validate_media_type(raw)?));
    }
    Ok(classify_media_type.map(str::to_owned))
}

/// Reject anything that cannot be written into `manifest:media-type` and read
/// back unchanged. Two separate reasons:
///
/// 1. **Invalid UTF-8, or a character outside XML 1.0's `Char` production**
///    (`#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] |
///    [#x10000-#x10FFFF]`). quick-xml escapes the five markup characters but
///    emits a C0 control byte as-is, and expat -- LO's own `ManifestReader` --
///    rejects the result, discarding every row.
/// 2. **Tab, LF or CR**, which *are* legal `Char`s but are not attribute
///    stable: XML 1.0 §3.3.3 attribute-value normalization replaces each with
///    a space on the way back in (this crate's own `manifest::normalize_attr_value`
///    implements exactly that). The `mimetype` zip member is copied verbatim,
///    so the member bytes and the parsed attribute would then disagree --
///    two things we write that are supposed to say the same thing.
///
/// Measured, not assumed: a package whose `mimetype` ends in a newline
/// reaches `encrypt` only if its manifest declares no root media type (with
/// one, `classify` already refuses the input as inconsistent), and real
/// LibreOffice cannot open such a document *before* encryption either. So no
/// loadable input is affected, and refusing costs nothing real -- every
/// producer writes a bare ASCII media type. It closes the divergence rather
/// than leaving it to be discovered from the other side.
fn validate_media_type(raw: Vec<u8>) -> Result<String, EncryptError> {
    let text = String::from_utf8(raw)
        .map_err(|e| EncryptError::Mimetype(format!("not valid UTF-8: {e}")))?;
    if let Some(c) = text.chars().find(|&c| !is_xml_char(c)) {
        return Err(EncryptError::Mimetype(format!(
            "contains U+{:04X}, not an XML 1.0 Char",
            c as u32
        )));
    }
    if let Some(c) = text.chars().find(|&c| matches!(c, '\t' | '\n' | '\r')) {
        return Err(EncryptError::Mimetype(format!(
            "contains U+{:04X}, which XML attribute-value normalization would \
             turn into a space, making the manifest attribute disagree with the \
             verbatim mimetype member",
            c as u32
        )));
    }
    Ok(text)
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
        ZipArchive::new(Cursor::new(bytes)).map_err(|e| EncryptError::Zip(zip_err::message(&e)))?;
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
fn build_manifest(
    size: i64,
    iv: &[u8],
    salt: &[u8],
    media_type: Option<&str>,
    params: Argon2Params,
) -> Result<Vec<u8>, EncryptError> {
    // `ManifestExport.cxx:145-153`: `xmlns:loext` and `manifest:version` are
    // both written together, gated on the same ODF >= 1.2 check -- always
    // true for wholesome, which only exists at ODFSVER_LATEST_EXTENDED.
    let mut root = BytesStart::new(uris::ELEMENT_MANIFEST);
    root.push_attribute(("xmlns:manifest", uris::MANIFEST_NS_OASIS));
    root.push_attribute(("xmlns:loext", uris::MANIFEST_NS_LOEXT));
    root.push_attribute((uris::ATTR_VERSION, WHOLESOME.odf_version));

    let size_str = size.to_string();
    let mut file_entry = BytesStart::new(uris::ELEMENT_FILE_ENTRY);
    file_entry.push_attribute((uris::ATTR_FULL_PATH, "encrypted-package"));
    file_entry.push_attribute((uris::ATTR_SIZE, size_str.as_str()));
    if let Some(mt) = media_type {
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
        params.t.to_string(),
        params.m_kib.to_string(),
        params.p.to_string(),
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
        // `io::Write for Vec<u8>` is infallible, so this cannot fail today --
        // but quick-xml's signature says it can, and an `.expect()` here would
        // abort a caller's process to report that quick-xml had changed its
        // mind. Same reasoning as every other Internal in this file.
        writer
            .write_event(event)
            .map_err(|e| EncryptError::Internal(format!("manifest XML write: {e}")))?;
    }
    Ok(writer.into_inner())
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
    sealed: &DeflatedPlaintext,
    manifest_xml: &[u8],
) -> Result<Vec<u8>, EncryptError> {
    let sealed_len = sealed.with_secret(|s| s.len());
    let capacity = mimetype.len() + iv.len() + sealed_len + manifest_xml.len() + 512;
    let mut out = ZipWriter::new(Cursor::new(Vec::with_capacity(capacity)));
    let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let deflated = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let to_zip_err = |e: zip::result::ZipError| EncryptError::Zip(zip_err::message(&e));
    let io_err = |e: std::io::Error| EncryptError::Zip(e.to_string());

    out.start_file("mimetype", stored).map_err(to_zip_err)?;
    out.write_all(mimetype).map_err(io_err)?;

    out.start_file("encrypted-package", stored)
        .map_err(to_zip_err)?;
    out.write_all(iv).map_err(io_err)?;
    // Written straight from the wrapper, the way `rebuild_zip` writes members
    // on the read side -- no unwrapped copy on the way out. By now the buffer
    // holds ciphertext, but it stays wrapped until it is written, so no
    // window exists where a plain copy of it could outlive the call.
    sealed.with_secret(|s| out.write_all(s)).map_err(io_err)?;

    out.start_file(MANIFEST_PATH, deflated)
        .map_err(to_zip_err)?;
    out.write_all(manifest_xml).map_err(io_err)?;

    Ok(out.finish().map_err(to_zip_err)?.into_inner())
}

#[cfg(test)]
#[path = "encrypt_tests.rs"]
mod tests;
