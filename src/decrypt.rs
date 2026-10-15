//! Password decryption for LO-encrypted ODF packages.

use std::io::Read;

use pbkdf2::pbkdf2_hmac;
use secure_gate::{RevealSecret, RevealSecretMut};
use sha1::Sha1;
use zip::ZipArchive;

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, Writer};

fn is_manifest_size_attr(key: &[u8]) -> bool {
    key.ends_with(b":size") || key == b"size"
}

use crate::classify::{member_matches_path, zip_entry_name};
use crate::kdf::KdfError;
use crate::limits::{
    AES_BLOCK_LEN, AES_CBC_IV_LEN, AES_GCM_IV_LEN, AES_GCM_TAG_LEN, ARGON2_MAX_M_COST_KIB_READ,
    ARGON2_MAX_P_COST_READ, ARGON2_MAX_T_COST_READ, BLOWFISH_IV_LEN, DERIVED_KEY_MAX_LEN,
    DERIVED_KEY_MIN_LEN, INFLATE_CEILING, MAX_ENCRYPTED_ENTRIES, MAX_OUTPUT_BYTES, PBKDF2_MAX_ITER,
    PBKDF2_MIN_ITER,
};
use crate::sensitive::{DerivedKey, PasswordDigest};
use crate::types::{Cipher, EntryEncryption, Kdf, Mode};
use crate::zip_err;
use crate::DetectError;

/// Failures from [`decrypt`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecryptError {
    /// [`classify`] refused the package before decryption began.
    #[error("classification failed: {0}")]
    Classify(#[from] DetectError),
    /// The package classified as [`Mode::Plain`] — there is nothing to decrypt.
    ///
    /// A malformed `META-INF/manifest.xml` also arrives here rather than as a
    /// parse error: LibreOffice discards every row on an XML failure and still
    /// opens the package, so this crate classifies it plain.
    #[error("package is not encrypted")]
    NotEncrypted,
    /// The password was empty. Checked before [`classify`] runs, so it implies
    /// nothing about whether `bytes` is a valid or encrypted package.
    #[error("password is empty")]
    EmptyPassword,
    /// The package is PGP-wrapped. Screened across every encrypted row, not
    /// only the latch row. The wrapped key material is available from
    /// [`crate::Classification::pgp_keys`] for handing to an OpenPGP implementation.
    ///
    /// **Not "a later arc".** The plans said that for a while and it was the
    /// wrong reason, because it implies the work is merely unscheduled. Two
    /// things make it infeasible in *this* function rather than unscheduled:
    ///
    /// - **There is no surface to pass a key through.** The signature is
    ///   `decrypt(bytes: &[u8], password: &str)`. A PGP-wrapped package is
    ///   opened with a private key, which arrives as a keyring path, a
    ///   passphrase over that key, an agent socket, or a smartcard PIN
    ///   prompt -- none of which a `&str` password can carry, and none of
    ///   which a library should invent a side channel for.
    /// - **The cost is the crate's whole premise.** Detection-only is 25
    ///   crates and the point of the default; an OpenPGP implementation is a
    ///   dependency tree of a different order, for a path `classify` already
    ///   reports without it.
    ///
    /// So the honest scope statement is *this API shape cannot express it*,
    /// and the honest offer is the one above: `classify` surfaces the wrapped
    /// key material, and a caller who has an OpenPGP stack does the unwrap.
    #[error("PGP-encrypted packages are not supported")]
    UnsupportedPgp,
    /// LibreOffice `LookForUnexpectedODF12Streams` plus a root version `>= 1.2`.
    /// `classify` reports the flag without failing; decrypt refuses so it does
    /// not return a zip LO would not open.
    #[error("LibreOffice would refuse this package: unexpected ODF 1.2 streams")]
    Odf12Fatal,
    /// The key did not open the package.
    ///
    /// Cannot distinguish a wrong password from corrupted ciphertext. On
    /// AES-CBC and Blowfish it is decided by a checksum over only the first
    /// 1 KiB of the decrypted stream, so damage past that window surfaces as
    /// [`DecryptError::Inflate`] instead.
    #[error("wrong password")]
    WrongPassword,
    /// A manifest field is outside the range this crate will act on — an
    /// iteration count, Argon2 cost or key size beyond its floor or ceiling, or
    /// more encrypted rows than will be processed. The string is a diagnostic;
    /// do not match on its content.
    ///
    /// A verdict on the manifest, and the same verdict on every machine. A cost
    /// this crate accepted and the host then could not meet is
    /// [`DecryptError::HostCannotAllocate`], not a bad parameter.
    #[error("invalid encryption parameters: {0}")]
    BadParameters(String),
    /// Deliberately NOT the `BadParameters` analogue: that reports a hostile
    /// value read out of the manifest, and this reports an invariant of our own
    /// that something upstream was supposed to have enforced. Reaching it means
    /// a guard moved, not that the input was bad.
    ///
    /// It exists for the same reason `EncryptError::Internal` does: a library
    /// must not abort its caller's process to report a condition it could
    /// return.
    #[error("internal invariant violated: {0}")]
    Internal(String),
    /// This host could not allocate the working memory key derivation needs.
    ///
    /// **Not a statement about the package.** The manifest may be entirely
    /// legal, and the same bytes may decrypt on a machine with more free memory
    /// — so retrying, or retrying elsewhere, is meaningful, and re-downloading
    /// the file is not. Deliberately not [`DecryptError::BadParameters`], which
    /// reports a manifest field this crate refuses to act on at all, and
    /// deliberately not [`DecryptError::Internal`], which reports an invariant
    /// of ours; how much memory this machine had free at this moment is
    /// neither.
    ///
    /// The shortfall is returned rather than aborted on because an abort skips
    /// unwinding, and `Drop` is this crate's only zeroizing primitive — the
    /// allocation happens with the password digest and the derived key both
    /// live.
    ///
    /// Key derivation was the first allocation here to become fallible, and an
    /// earlier version of this doc predicted that when the others followed, the
    /// variant would want a field naming which one failed. They followed in
    /// `0.1.0-rc.5`, and [`AllocationSite`] is that field. It was a breaking
    /// change to the variant and was accepted.
    ///
    /// [`DecryptError`] itself is `#[non_exhaustive]`, but the variant is not,
    /// deliberately: a variant nobody outside the crate can construct is a
    /// variant nobody outside the crate can write a test against, and the
    /// binary's own exit-code test needs to construct it.
    #[error("host could not allocate {requested_bytes} bytes for {site}")]
    HostCannotAllocate {
        /// Which allocation could not be made.
        site: AllocationSite,
        /// The size that could not be obtained — in every case a number the
        /// package itself supplied, not a ceiling of this crate's:
        /// `manifest:argon2-memory` rounded to whole blocks, `manifest:size`,
        /// `manifest:key-size`, or a member's own length.
        requested_bytes: usize,
    },
    /// The decrypted stream was not valid DEFLATE, or did not inflate to the
    /// length `manifest:size` promised.
    ///
    /// Never means "wrong password": it is reached only after a GCM tag or a
    /// checksum has already accepted the key. It means the ciphertext is
    /// damaged past the point those checks cover.
    #[error("inflate failed: {0}")]
    Inflate(String),
    /// A zip failure, either reading the input or writing the rebuilt package
    /// — plus the manifest rewrite's *parse* failure, which is the one thing
    /// here that is not a zip error.
    ///
    /// The rewrite's *serialization* failures are no longer among them: they are
    /// [`DecryptError::Internal`] as of `0.1.0-rc.5`, because they can only ever
    /// report a broken invariant of ours, never anything about the package. The
    /// doc used to say this variant carried *"every quick-xml failure"*, and
    /// that sentence is what prompted the split — a name needing a disclaimer
    /// is usually a name covering two things. The string is a diagnostic; do not
    /// match on it.
    ///
    /// It may quote package-controlled text, so treat it as untrusted when
    /// logging or displaying it. The zip half cannot: those are rendered by an
    /// internal helper that quotes only text this crate chose, never the zip
    /// crate's own `Display`. The quick-xml half can —
    /// `IllFormedError::UnmatchedEndTag` carries an element name taken from the
    /// manifest — and unlike [`crate::DetectError::Inconsistent`] it is **not**
    /// elided to a bound.
    ///
    /// # Why it is not elided
    ///
    /// Because the path is unreachable, and an elision would imply a live threat
    /// where there is none. The argument, since a claim of unreachability has to
    /// carry one:
    ///
    /// `strip_manifest` can only return this from its *read* side — its writer
    /// is a `Vec<u8>`, whose `write_all` cannot fail. So a `Zip` from the rewrite
    /// means `read_event_into` errored. But `manifest::parse_manifest` maps
    /// **any** read error to an empty row list, plus three more conditions
    /// `strip_manifest` does not have, so `parse_manifest` returning rows means
    /// no read error occurred. Empty rows means `classify` reports
    /// [`Mode::Plain`], and `decrypt` refuses that with
    /// [`DecryptError::NotEncrypted`] long before the rewrite runs.
    ///
    /// The two readers are configured differently — `parse_manifest` sets
    /// `expand_empty_elements`, the rewrite leaves it at its default — which is
    /// the only way they could disagree about what is ill-formed. They cannot:
    /// in quick-xml 0.38.4 an expanded empty element pushes onto `opened_starts`
    /// and is popped by the next read *without consuming input*, so the stack
    /// every end-tag check consults is identical in both modes at every byte
    /// boundary.
    ///
    /// **That argument is version-scoped to quick-xml 0.38.4**, which is why
    /// `classify_accepting_a_manifest_implies_the_rewrite_accepts_it` pins it
    /// rather than leaving it as prose a dependency bump could quietly falsify.
    /// If that test ever fails, this variant needs the elision
    /// [`crate::DetectError::Inconsistent`] already has.
    #[error("zip error: {0}")]
    Zip(String),
    /// The plaintext inflated from encrypted members would exceed
    /// [`DecryptLimits::max_output_bytes`].
    ///
    /// Raised before key derivation when `manifest:size` already says so, and
    /// otherwise as the running count passes the limit. Members stored
    /// unencrypted are copied, not inflated by this crate, and do not count:
    /// they are bounded by the input.
    ///
    /// **A policy of this crate, not a rule of the format.** ODF bounds no
    /// size; the limit exists because a few kilobytes of DEFLATE can claim
    /// gigabytes, and a caller writing to disk wants that refused rather than
    /// discovered. Raise it with [`DecryptLimits::with_max_output_bytes`].
    #[error("decrypted output would exceed the {limit}-byte limit")]
    OutputLimit {
        /// The limit in force, from [`DecryptLimits::max_output_bytes`].
        limit: u64,
    },
    /// The caller's reader or writer failed. Nothing is implied about the
    /// package. The error is the caller's own value, so a cancellation can be
    /// recognized in it.
    #[error("I/O failed: {0}")]
    Io(#[source] std::io::Error),
}

/// Which allocation a [`DecryptError::HostCannotAllocate`] refers to.
///
/// Diagnostic, not a decision: every site means the same thing to a caller —
/// retrying, or retrying on a machine with more free memory, is meaningful, and
/// re-downloading the file is not. It exists because the message was wrong
/// without it. Until `0.1.0-rc.5` the variant's `Display` read *"for key
/// derivation"* unconditionally, which was true while key derivation was the
/// only fallible allocation here and became a false statement the moment the
/// others followed.
///
/// Deliberately not shaped like [`ParamsReason`]. That type answers *whose rule
/// refused this* — a policy bound of ours against a requirement of the cipher's
/// — which a consumer renders differently and may act on. This answers *where*,
/// which nobody acts on.
///
/// [`ParamsReason`]: crate::ParamsReason
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AllocationSite {
    /// The KDF's own working memory: Argon2id's block buffer, sized from
    /// `manifest:argon2-memory`.
    KeyDerivation,
    /// The derived-key buffer, sized from `manifest:key-size`.
    ///
    /// Bounded to `1..=64` before it is allocated, so on any host that can run
    /// this crate at all it is unreachable — and it is allocated fallibly
    /// anyway, because that bound is the thing under review. A ceiling that
    /// happens to keep an infallible allocation from failing is not a reason
    /// for the allocation to be infallible: widening it would make this
    /// reachable again with no diff at this line to notice.
    DerivedKey,
    /// The inflate slot for one member of a per-entry package, sized from that
    /// row's `manifest:size`.
    ///
    /// The one site where the **sum** matters rather than the individual
    /// request: each row is bounded at 1 GiB, a package may hold up to
    /// `MAX_ENCRYPTED_ENTRIES` of them, and every earlier member's plaintext is
    /// still wrapped and live when a later one is allocated.
    MemberPlaintext,
    /// The inflate slot for a wholesome package's `encrypted-package` member,
    /// sized from `manifest:size`.
    PackagePlaintext,
    /// The buffer a member's ciphertext is copied into so it can be decrypted
    /// in place, sized from that member's own length.
    CipherBuffer,
    /// A fixed-size buffer of the streaming entry points (`decrypt_to`): a
    /// chunk, the inflate window or the 1K hold-back. Never sized from the
    /// package.
    StreamBuffer,
}

impl core::fmt::Display for AllocationSite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Exhaustive on purpose, with no `_` arm, for the reason
        // `Argon2Axis`'s Display gives: `#[non_exhaustive]` binds downstream
        // crates and not this one, so a new site fails to compile here until it
        // is given a name rather than rendering as something else.
        f.write_str(match self {
            Self::KeyDerivation => "key derivation",
            Self::DerivedKey => "the derived-key buffer",
            Self::MemberPlaintext => "a decrypted package member",
            Self::PackagePlaintext => "the decrypted package",
            Self::CipherBuffer => "a cipher buffer",
            Self::StreamBuffer => "a streaming buffer",
        })
    }
}

/// A zero-filled `Vec<u8>` of exactly `n` bytes, allocated **fallibly**.
///
/// `vec![0u8; n]` and `Vec::with_capacity(n)` route failure through
/// `handle_alloc_error`, which *aborts* — whatever the panic strategy, because
/// an abort is not a panic. Every caller of this function is inside at least one
/// live `secure-gate` wrapper, and an abort skips unwinding, so `Drop` never
/// runs and the crate's only zeroizing primitive does not happen. See
/// `CLAUDE.md`, *The library does not panic*.
///
/// `n` comes from the package in every case, which is why a ceiling is not the
/// fix: a guessed one refuses a host that could have coped and still aborts one
/// that could not.
pub(crate) fn try_zeroed(n: usize, site: AllocationSite) -> Result<Vec<u8>, DecryptError> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)
        .map_err(|_| DecryptError::HostCannotAllocate {
            site,
            requested_bytes: n,
        })?;
    // Load-bearing: `try_reserve_exact` has already secured the capacity, so
    // this only sets the length. It cannot reallocate, so it cannot reach the
    // infallible path this function exists to avoid.
    v.resize(n, 0);
    Ok(v)
}

/// Ceilings [`decrypt`] applies to cost parameters **a package chose**.
///
/// A manifest names how much work its key derivation takes, and `decrypt` must
/// do that work before it can tell whether the password is even right. So the
/// file, not the caller, picks the cost of an attempt. These are the defaults
/// that bounds it, and [`decrypt_with_limits`] is how a caller who knows what
/// they are opening raises them.
///
/// **The defaults refuse nothing any real producer writes.** LibreOffice's own
/// output is `t = 3`, `m = 64 MiB`, `p = 4`, and at most 600,000 PBKDF2
/// iterations — every one comfortably inside these.
///
/// | field | default | LibreOffice writes |
/// | --- | --- | --- |
/// | [`argon2_max_t`](Self::argon2_max_t) | 10 | 3 |
/// | [`argon2_max_m_kib`](Self::argon2_max_m_kib) | 1 GiB | 64 MiB |
/// | [`argon2_max_p`](Self::argon2_max_p) | 16 | 4 |
/// | [`pbkdf2_max_iter`](Self::pbkdf2_max_iter) | 10,000,000 | 600,000 |
///
/// The Argon2 defaults are Bitwarden's published maxima. They are an
/// application's limits on its own user's slider, adopted here for the one case
/// where this crate is in the same position: a number arriving from outside.
///
/// # Why `t` and `m` are not independent
///
/// Argon2's cost is roughly `t × m`, and bounding each alone does not bound the
/// product. Before `0.1.0-rc.6` this crate allowed `t ≤ 65536` with
/// `m ≤ 1 GiB` — about **350,000× LibreOffice's own work**, extrapolating to
/// ~33 hours from a measured 54.5 s at `t = 30, m = 1 GiB`. Neither ceiling
/// looked wrong on its own. At `t = 10` the product is ~53×, which is seconds.
///
/// # Raising them
///
/// ```
/// # #[cfg(feature = "crypto-ops")] {
/// use odf_crypto::{decrypt_with_limits, DecryptLimits};
///
/// # fn demo(bytes: &[u8], pw: &str) -> Result<(), odf_crypto::DecryptError> {
/// // A file from a tool that derives harder than LibreOffice does.
/// let limits = DecryptLimits::default().with_argon2_max_t(64);
/// let plain = decrypt_with_limits(bytes, pw, limits)?;
///
/// // Or: accept anything the format can express. Opt in knowingly --
/// // on an untrusted file this is a decision to spend whatever it asks for.
/// let plain = decrypt_with_limits(bytes, pw, DecryptLimits::PERMISSIVE)?;
/// # let _ = plain;
/// # Ok(())
/// # }
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecryptLimits {
    /// Inclusive ceiling on `loext:argon2-iterations`.
    pub argon2_max_t: u32,
    /// Inclusive ceiling on `loext:argon2-memory`, in KiB.
    pub argon2_max_m_kib: u32,
    /// Inclusive ceiling on `loext:argon2-lanes`.
    pub argon2_max_p: u32,
    /// Inclusive ceiling on `manifest:iteration-count` for a PBKDF2 row.
    pub pbkdf2_max_iter: u32,
    /// Inclusive ceiling, in bytes, on the plaintext inflated from encrypted
    /// members, summed across the package. Default 16 GiB. Exceeding it is
    /// [`DecryptError::OutputLimit`].
    ///
    /// A policy of this crate, not of the format; see `OutputLimit`. The
    /// whole-buffer [`decrypt`] is also held to 1 GiB per inflated buffer by
    /// the memory it must allocate, whatever this says.
    pub max_output_bytes: u64,
}

impl Default for DecryptLimits {
    fn default() -> Self {
        Self {
            argon2_max_t: ARGON2_MAX_T_COST_READ,
            argon2_max_m_kib: ARGON2_MAX_M_COST_KIB_READ,
            argon2_max_p: ARGON2_MAX_P_COST_READ,
            pbkdf2_max_iter: PBKDF2_MAX_ITER,
            max_output_bytes: MAX_OUTPUT_BYTES,
        }
    }
}

impl DecryptLimits {
    /// Everything the format can express: each field at the width of the
    /// manifest attribute behind it.
    ///
    /// **This is not "no limits".** The cipher still refuses what it cannot run
    /// (`m >= 8p`, `p <= argon2::Params::MAX_P_COST`) and the host still refuses
    /// what it cannot allocate, as [`DecryptError::HostCannotAllocate`]. What it
    /// removes is this crate's judgement about how much work a file may ask for.
    ///
    /// Measured on one laptop, with these: a single Argon2 row at
    /// `t = 65536, m = 1 GiB` extrapolates to ~33 hours, and `decrypt` cannot be
    /// interrupted. Reach for it when you know the producer, not to make a
    /// stubborn file open.
    pub const PERMISSIVE: Self = Self {
        argon2_max_t: i32::MAX as u32,
        argon2_max_m_kib: i32::MAX as u32,
        argon2_max_p: i32::MAX as u32,
        pbkdf2_max_iter: i32::MAX as u32,
        // `manifest:size` is read as an `i64`, so this is wider than any size a
        // package can declare.
        max_output_bytes: u64::MAX,
    };

    /// Raise or lower the Argon2 `t` ceiling.
    #[must_use]
    pub fn with_argon2_max_t(mut self, t: u32) -> Self {
        self.argon2_max_t = t;
        self
    }

    /// Raise or lower the Argon2 `m` ceiling, in KiB.
    #[must_use]
    pub fn with_argon2_max_m_kib(mut self, m_kib: u32) -> Self {
        self.argon2_max_m_kib = m_kib;
        self
    }

    /// Raise or lower the Argon2 `p` ceiling.
    #[must_use]
    pub fn with_argon2_max_p(mut self, p: u32) -> Self {
        self.argon2_max_p = p;
        self
    }

    /// Raise or lower the PBKDF2 iteration ceiling.
    #[must_use]
    pub fn with_pbkdf2_max_iter(mut self, iter: u32) -> Self {
        self.pbkdf2_max_iter = iter;
        self
    }

    /// Raise or lower the ceiling on inflated plaintext, in bytes.
    #[must_use]
    pub fn with_max_output_bytes(mut self, bytes: u64) -> Self {
        self.max_output_bytes = bytes;
        self
    }
}

/// Decrypt an LO-encrypted ODF package to the plaintext ODF zip LibreOffice
/// would open after a correct password.
///
/// The two modes have different contracts:
///
/// - [`Mode::Wholesome`] — the inner `encrypted-package` member is decrypted and
///   inflated, and returned verbatim. Nothing is stripped or recompressed.
/// - [`Mode::PerEntry`] — the package is rebuilt: `encryption-data` elements are
///   stripped from `META-INF/manifest.xml` and `manifest:size` is dropped from
///   its `file-entry` elements. The rewritten manifest and each decrypted member
///   are written DEFLATED; every other member is copied through with its
///   original compression method, so a STORED member stays STORED.
///
/// # Errors
///
/// Refused before any key derivation, in this order, so no caller pays for
/// PBKDF2 or a 64 MiB Argon2id to learn the input was never eligible:
/// [`DecryptError::EmptyPassword`], [`DecryptError::Classify`],
/// [`DecryptError::NotEncrypted`], [`DecryptError::Odf12Fatal`],
/// [`DecryptError::UnsupportedPgp`], then [`DecryptError::BadParameters`] if the
/// package declares more encrypted rows than will be processed, then
/// [`DecryptError::OutputLimit`] if its `manifest:size` values sum past
/// [`DecryptLimits::max_output_bytes`].
///
/// During derivation, and alone in this list in blaming neither the package nor
/// this crate: [`DecryptError::HostCannotAllocate`], when the host cannot
/// allocate Argon2id's working buffer. The same bytes may decrypt on a machine
/// with more free memory.
///
/// After derivation: [`DecryptError::WrongPassword`],
/// [`DecryptError::BadParameters`] for a hostile KDF or key-size field,
/// [`DecryptError::Inflate`], [`DecryptError::Zip`], and
/// [`DecryptError::Internal`].
///
/// [`DecryptError`] is `#[non_exhaustive]` and does not implement `PartialEq`;
/// match with a `_` arm and [`matches!`].
///
/// # Examples
///
/// ```
/// use odf_crypto::{classify, decrypt, Mode};
///
/// let sealed = include_bytes!("../tests/goldens/lo-wholesome-gcm-argon2.odt");
/// assert_eq!(classify(sealed)?.mode, Mode::Wholesome);
///
/// let plain = decrypt(sealed, "password")?;
/// assert_eq!(classify(&plain)?.mode, Mode::Plain);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn decrypt(bytes: &[u8], password: &str) -> Result<Vec<u8>, DecryptError> {
    decrypt_with_limits(bytes, password, DecryptLimits::default())
}

/// [`decrypt`], with the ceilings on what a package may ask for under the
/// caller's control. See [`DecryptLimits`].
///
/// # Errors
///
/// Identical to [`decrypt`]. A cost parameter outside `limits` is
/// [`DecryptError::BadParameters`], which says *this crate declined*, not that
/// the file is malformed — with `limits` raised, the same file may open.
pub fn decrypt_with_limits(
    bytes: &[u8],
    password: &str,
    limits: DecryptLimits,
) -> Result<Vec<u8>, DecryptError> {
    crate::decrypt_stream::decrypt_slice(bytes, password, &limits)
}

/// Every refusal that needs only the classification, in the order `decrypt`
/// documents. Shared by the whole-buffer and streaming paths, so the two
/// refuse the same packages for the same reasons.
pub(crate) fn screen_class(
    class: &crate::Classification,
    limits: &DecryptLimits,
) -> Result<(), DecryptError> {
    if class.mode == Mode::Plain {
        return Err(DecryptError::NotEncrypted);
    }
    if class.odf12_fatal {
        return Err(DecryptError::Odf12Fatal);
    }
    if class
        .encrypted_entries
        .iter()
        .any(|e| matches!(e.kdf, Kdf::PgpRsaOaepMgf1p))
    {
        return Err(DecryptError::UnsupportedPgp);
    }
    ensure_encrypted_entry_count(class.encrypted_entries.len(), MAX_ENCRYPTED_ENTRIES)?;
    screen_output_limit(class, limits.max_output_bytes)
}

/// Refuse, before any key derivation, a package whose `manifest:size` values
/// already promise more inflated plaintext than `limit`.
///
/// Sums only the rows `decrypt` will inflate: the wholesome row for a wholesome
/// package, every encrypted row otherwise. A size `inflated_len` would refuse is
/// skipped here rather than reported, so that refusal keeps the position in the
/// error order it had before this screen existed; only `OutputLimit` is new.
fn screen_output_limit(class: &crate::Classification, limit: u64) -> Result<(), DecryptError> {
    let declared = |row: &EntryEncryption| u64::try_from(row.size).unwrap_or(0);
    let total = match class.mode {
        Mode::Wholesome => class.wholesome_row().map_or(0, declared),
        _ => class
            .encrypted_entries
            .iter()
            .fold(0u64, |sum, row| sum.saturating_add(declared(row))),
    };
    if total > limit {
        return Err(DecryptError::OutputLimit { limit });
    }
    Ok(())
}

fn ensure_encrypted_entry_count(n: usize, cap: usize) -> Result<(), DecryptError> {
    if n > cap {
        return Err(DecryptError::BadParameters(format!(
            "encrypted entry count {n} exceeds ceiling {cap}"
        )));
    }
    Ok(())
}

/// First member whose raw or slash-collapsed name matches - the rule `classify`
/// itself uses, because a row path is a folder-tree path, not a namelist key.
pub(crate) fn member_for_archive<R: Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    path: &str,
) -> Result<(usize, String), DecryptError> {
    for i in 0..archive.len() {
        let file = archive
            .by_index(i)
            .map_err(|e| DecryptError::Zip(zip_err::message(&e)))?;
        let name = zip_entry_name(file.name_raw());
        if member_matches_path(&name, path) {
            return Ok((i, name));
        }
    }
    Err(DecryptError::BadParameters(format!(
        "row path {path:?} has no zip member"
    )))
}

/// Give a [`KdfError`] its verdict on this side.
///
/// The two arms land in opposite halves of [`DecryptError`] — the package's
/// fault and nobody's — so the match is exhaustive with no `_` arm, for the
/// reason `impl Display for Argon2Axis` has none either: a third `KdfError`
/// must be given a deliberate verdict here rather than inheriting whichever of
/// these two it happens to be declared next to.
///
/// [`KdfError::Params`] is a manifest field — `t`, `m`, `p` or the key size
/// this crate or `argon2` will not run — so it is a [`DecryptError::BadParameters`]
/// here even though `encrypt`, which chose its own tuple, calls the identical
/// error an invariant of its own. Both are right; the package author picked
/// these numbers and this side is reading them.
fn kdf_error(e: KdfError) -> DecryptError {
    match e {
        KdfError::Params(s) => DecryptError::BadParameters(s),
        KdfError::HostCannotAllocate { requested_bytes } => DecryptError::HostCannotAllocate {
            site: AllocationSite::KeyDerivation,
            requested_bytes,
        },
    }
}

pub(crate) fn derive_key(
    row: &EntryEncryption,
    sk: PasswordDigest,
    limits: &DecryptLimits,
) -> Result<DerivedKey, DecryptError> {
    let n = row.derived_key_len;
    // Unreachable from the only current caller, and kept deliberately. Since #79
    // `decrypt_member` screens this same field against the row's cipher, and every
    // length that screen admits -- 16/24/32, or Blowfish's 4..=56 -- already sits
    // inside this range, so nothing gets here to fail it.
    //
    // It stays because it is *this function's* precondition rather than that one's:
    // `try_zeroed(n)` below allocates from `n`, and a second caller added later
    // would otherwise inherit an unguarded `i32` straight from a manifest. Said
    // out loud rather than left to be rediscovered, because an unreachable guard
    // that reads as live is how the next person concludes the length is checked
    // here and removes the screen.
    if !(DERIVED_KEY_MIN_LEN..=DERIVED_KEY_MAX_LEN).contains(&n) {
        return Err(DecryptError::BadParameters(format!(
            "derived_key_len {n} outside {DERIVED_KEY_MIN_LEN}..={DERIVED_KEY_MAX_LEN}"
        )));
    }
    let n = n as usize;
    let mut derived = DerivedKey::new(try_zeroed(n, AllocationSite::DerivedKey)?);
    sk.with_secret(|sk_bytes| {
        derived.with_secret_mut(|derived_bytes| -> Result<(), DecryptError> {
            match &row.kdf {
                Kdf::Pbkdf2 { iterations, salt } => {
                    let iters = u32::try_from(*iterations).map_err(|_| {
                        DecryptError::BadParameters(format!("iterations {iterations}"))
                    })?;
                    if !(PBKDF2_MIN_ITER..=limits.pbkdf2_max_iter).contains(&iters) {
                        return Err(DecryptError::BadParameters(format!(
                            "iterations {iters} outside {PBKDF2_MIN_ITER}..={}",
                            limits.pbkdf2_max_iter
                        )));
                    }
                    pbkdf2_hmac::<Sha1>(sk_bytes, salt, iters, derived_bytes);
                    Ok(())
                }
                Kdf::Argon2id { t, m, p, salt } => {
                    // Shared with `encrypt`, which chooses the same tuple rather
                    // than reading it: `crate::kdf` is where the manifest's
                    // hostile-parameter guards live, so both directions get them.
                    crate::kdf::derive_argon2id(sk_bytes, salt, *t, *m, *p, limits, derived_bytes)
                        .map_err(kdf_error)
                }
                // Screened out at the top of `decrypt`, ~140 lines and one
                // function away. That distance is the whole argument for a
                // returned error over a panic: nothing local keeps the two in
                // step, so a future edit to the screen turns an `unreachable!`
                // into an abort inside somebody else's library call.
                Kdf::PgpRsaOaepMgf1p => Err(DecryptError::Internal(
                    "PGP row reached derive_key; decrypt screens PGP before deriving".into(),
                )),
            }
        })
    })?;
    Ok(derived)
}

/// Can `cipher` take a derived key of `n` bytes?
///
/// Knowable from the manifest alone, which is the whole point: the cipher's own
/// refusal arrives *after* the key derivation that produced the key it refuses,
/// and a row is free to make that derivation expensive. PBKDF2 emits
/// `ceil(dkLen / 20)` HMAC-SHA1 blocks, so `manifest:key-size="64"` against an
/// AES row costs twice what 32 does and is then thrown away -- a multiplier the
/// file was never entitled to spend. See issue #79.
///
/// **This is a cost screen, not a fidelity change.** It accepts and refuses
/// exactly the set the cipher does, so no package's outcome moves; only the
/// moment of the refusal does. LibreOffice derives first too -- `StaticGetCipher`
/// tests `m_nDerivedKeySize < 0` and nothing else before deriving
/// (`ZipFile.cxx:154-157`) -- and that is not a reason to keep the ordering,
/// because what its behaviour binds is which packages are accepted, and the
/// timing of an error inside this function is not something a package can
/// observe.
///
/// Kept in step with the cipher by `screen_matches_what_the_cipher_accepts`,
/// which constructs every variant at every length rather than trusting this
/// list. A hand-maintained copy of another crate's constraint is a proxy, and
/// proxies here drift silently.
fn cipher_accepts_key_len(cipher: Cipher, n: i32) -> bool {
    match cipher {
        // NSS picks AES-128/192/256 from the derived key length, so these are the
        // three the dispatch below can name -- see `decrypt_aes_gcm`.
        Cipher::AesGcmW3c | Cipher::AesCbcW3c => matches!(n, 16 | 24 | 32),
        // Blowfish takes a variable key. Measured against `blowfish` 0.9 rather
        // than read off the algorithm: `4..=56`, which is what
        // `DERIVED_KEY_MAX_LEN`'s own doc means by "56 is Blowfish's maximum key;
        // 64 rounds it up".
        Cipher::BlowfishCfb8 => (4..=56).contains(&n),
    }
}

/// Everything a row can be refused for **without deriving a key**.
///
/// `decrypt` must derive before it can tell whether the password is even right,
/// so a manifest names the cost of its own rejection. Any check whose inputs are
/// already in hand therefore belongs in front of the KDF, not behind it — and all
/// of these were behind it: the cipher's key length (issue #79), the IV length,
/// and the two member-shape tests. Each cost a full derivation to report
/// something knowable from an integer comparison.
///
/// **The messages are unchanged, deliberately.** Only the moment of the refusal
/// moves, so no outcome and no error text a caller might already be matching on
/// changes with it.
///
/// The cipher functions still carry these checks. They are unreachable through
/// this path and kept anyway, because `decrypt_aes_gcm` indexes `blob` by a
/// length one of them establishes — a non-local invariant is a poor thing to hang
/// "the library does not panic" on. Each is labelled where it sits.
#[cfg(test)]
fn screen_before_deriving(row: &EntryEncryption, blob: &[u8]) -> Result<(), DecryptError> {
    let head = &blob[..blob.len().min(AES_GCM_IV_LEN)];
    screen_shape(row, blob.len() as u64, head)
}

/// [`screen_before_deriving`] for a member that is not in memory: its length,
/// and its first bytes (at most `AES_GCM_IV_LEN` are looked at). The streaming
/// path calls this; the whole-buffer one reaches it through the function above,
/// so both refuse the same members with the same messages.
pub(crate) fn screen_shape(
    row: &EntryEncryption,
    len: u64,
    head: &[u8],
) -> Result<(), DecryptError> {
    if !cipher_accepts_key_len(row.cipher, row.derived_key_len) {
        return Err(DecryptError::BadParameters(format!(
            "key length {} cannot be used with {:?}",
            row.derived_key_len, row.cipher
        )));
    }
    match row.cipher {
        Cipher::AesGcmW3c => {
            if row.iv.len() != AES_GCM_IV_LEN {
                return Err(DecryptError::BadParameters("GCM IV length".into()));
            }
            if len < (AES_GCM_IV_LEN + AES_GCM_TAG_LEN) as u64 || head.len() < AES_GCM_IV_LEN {
                return Err(DecryptError::BadParameters("shorter than IV+tag".into()));
            }
            if head[..AES_GCM_IV_LEN] != row.iv[..] {
                return Err(DecryptError::BadParameters("inconsistent IV".into()));
            }
        }
        Cipher::AesCbcW3c => {
            if row.iv.len() != AES_CBC_IV_LEN {
                return Err(DecryptError::BadParameters("CBC IV length".into()));
            }
            if len == 0 || len % AES_BLOCK_LEN as u64 != 0 {
                return Err(DecryptError::BadParameters("not a block multiple".into()));
            }
        }
        Cipher::BlowfishCfb8 => {
            if row.iv.len() != BLOWFISH_IV_LEN {
                return Err(DecryptError::BadParameters("Blowfish IV length".into()));
            }
        }
    }
    Ok(())
}

/// Bound `manifest:size` before it becomes an allocation length.
///
/// **Its original reason is gone, and the same thing happened here as to
/// `ARGON2_MAX_M_COST_KIB_READ`.** This doc used to argue the ceiling like this: a
/// sized slot moves the allocation ahead of the decode, `size` is an `i64` the
/// manifest controls, and `vec![0u8; huge]` aborts the caller's process rather
/// than returning an error. The first two clauses still hold. The third does
/// not: the slot is allocated by [`try_zeroed`] now, so an unaffordable `size`
/// returns [`DecryptError::HostCannotAllocate`] and the abort it was guarding
/// against cannot happen.
///
/// What the check still does, and it is not nothing:
///
/// - **`size < 0` and the `i64` -> `usize` cast.** A negative `manifest:size`
///   has no meaning and a 64-bit value cast on a 32-bit host truncates. That
///   half is a correctness bound and is not up for review.
/// - **Refusing absurd sizes before any work.** A row claiming a petabyte is
///   answered by a comparison rather than by an allocation attempt and a KDF.
///
/// What it no longer does is prevent an abort, so `INFLATE_CEILING` itself is
/// now a **policy** cap in exactly the sense `src/limits.rs` means, with the
/// same open question over it: it refuses a host that could have coped, and no
/// longer saves one that could not. Not widened here -- that is the same
/// decision, and it belongs with the others rather than being taken quietly in
/// a doc comment.
pub(crate) fn inflated_len(size: i64) -> Result<usize, DecryptError> {
    if !(0..=INFLATE_CEILING as i64).contains(&size) {
        return Err(DecryptError::BadParameters(format!(
            "manifest:size {size} outside 0..={INFLATE_CEILING}"
        )));
    }
    // Bounded above by INFLATE_CEILING, itself a `usize`, so this cannot truncate.
    Ok(size as usize)
}

/// Rebuild a start tag without `manifest:size`, which an LO plaintext save never writes.
fn without_size(e: &BytesStart<'_>) -> BytesStart<'static> {
    let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
    let mut out = BytesStart::new(name);
    let strip_size = e.local_name().as_ref() == b"file-entry";
    for attr in e.attributes().flatten() {
        if strip_size && is_manifest_size_attr(attr.key.as_ref()) {
            continue;
        }
        out.push_attribute((attr.key.as_ref(), attr.value.as_ref()));
    }
    out.into_owned()
}

pub(crate) fn strip_manifest(xml: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);
    // `io::Write for Vec<u8>` is infallible -- its `write_all` is
    // `extend_from_slice` then `Ok(())` -- so the four `write_event` calls below
    // cannot fail today. quick-xml's signature says they can (`writer.rs:193`
    // returns `io::Result<()>`), and an `.expect()` here would abort a caller's
    // process to report that quick-xml had changed its mind.
    //
    // `Internal`, not `Zip`: no manifest byte can make `extend_from_slice` fail,
    // so a failure here would blame the package for a broken invariant of ours
    // -- and the CLI would print exit 6, "malformed or hostile package", for it.
    // Deliberately the same mapping, message and reasoning as
    // `encrypt::build_manifest`, which had it right; two files making one call
    // and giving two answers was the defect.
    let mut writer = Writer::new(Vec::new());
    let mut buf = Vec::new();
    let mut skip_depth = 0u32;

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                if skip_depth > 0 {
                    skip_depth += 1;
                    continue;
                }
                if e.local_name().as_ref() == b"encryption-data" {
                    skip_depth = 1;
                    continue;
                }
                writer
                    .write_event(Event::Start(without_size(&e)))
                    .map_err(|e| DecryptError::Internal(format!("manifest XML write: {e}")))?;
            }
            Ok(Event::End(e)) => {
                if skip_depth > 0 {
                    skip_depth -= 1;
                    continue;
                }
                writer
                    .write_event(Event::End(e.into_owned()))
                    .map_err(|e| DecryptError::Internal(format!("manifest XML write: {e}")))?;
            }
            Ok(Event::Empty(e)) => {
                if skip_depth > 0 {
                    continue;
                }
                if e.local_name().as_ref() == b"encryption-data" {
                    continue;
                }
                // A file-entry with no children is an Empty event, and it can still
                // carry manifest:size. Filtering only Start would leave those behind.
                writer
                    .write_event(Event::Empty(without_size(&e)))
                    .map_err(|e| DecryptError::Internal(format!("manifest XML write: {e}")))?;
            }
            Ok(other) => {
                if skip_depth > 0 {
                    continue;
                }
                writer
                    .write_event(other)
                    .map_err(|e| DecryptError::Internal(format!("manifest XML write: {e}")))?;
            }
            // Stays `Zip`, and stays un-elided. This is the READ side: its
            // payload is document-derived, and it is the half #48 was about.
            // The path is unreachable -- see `DecryptError::Zip`'s rustdoc for
            // the argument and the test that keeps it honest.
            Err(e) => return Err(DecryptError::Zip(e.to_string())),
        }
    }
    Ok(writer.into_inner())
}

/// Compare metadata that must survive per-entry decrypt (for tests).
#[cfg(test)]
pub(crate) fn classification_metadata_unchanged(
    before: &crate::Classification,
    after: &crate::Classification,
) -> bool {
    before.odf_version == after.odf_version
        && before.media_type == after.media_type
        && before.zip_has_encrypted_package == after.zip_has_encrypted_package
}

#[cfg(test)]
#[path = "decrypt_tests.rs"]
mod tests;
