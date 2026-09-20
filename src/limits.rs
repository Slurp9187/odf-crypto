//! Shared numeric bounds for classify, decrypt, and encrypt.
//!
//! # Whose rule is each of these?
//!
//! Every bound here is labelled, because the recurring defect in this area is
//! not a wrong number — it is a number whose *authority* nobody can name. A
//! policy cap of ours reported as a format rule tells a user their file is
//! invalid when it is not, which is the mistake `ParamsReason` was added to
//! prevent one layer up.
//!
//! Four labels, and they are not interchangeable:
//!
//! - **`spec`** — OASIS says so. Not ours to have an opinion about.
//! - **`LibreOffice`** — the implementation says so, and for the `loext:`
//!   fields it *is* the specifying authority (see `CLAUDE.md`).
//! - **`hard`** — physics, the cipher, or the host. Refusing is the only
//!   option.
//! - **`policy`** — ours. The format permits more; we decline. **These must be
//!   reported as ours**, never as the format's.
//!
//! | bound | label | authority |
//! | --- | --- | --- |
//! | `AES_*`, `BLOWFISH_IV_LEN` | hard | the ciphers' own block/IV/tag sizes |
//! | `CHECKSUM_WINDOW` | LibreOffice | `n_ConstDigestLength` |
//! | `DERIVED_KEY_MAX_LEN` | hard | 56 is Blowfish's maximum key; 64 rounds it up |
//! | `DIAGNOSTIC_ELISION` | policy | measured against the data, not the cap |
//! | `ARGON2_MIN_*` | spec | `positiveInteger`, and LO checks `0 < x` |
//! | `PBKDF2_MIN_ITER`, `DERIVED_KEY_MIN_LEN` | **policy** | the schema permits `0` and LO accepts it |
//! | `ARGON2_MAX_M_COST_KIB` | **policy** | see below — its original basis is gone |
//! | `ARGON2_MAX_T_COST` | **policy** | time, not memory; a different argument |
//! | `PBKDF2_MAX_ITER` | **policy** | derived from LO's *write* default, not any read limit |
//! | `MAX_ENCRYPTED_ENTRIES` | policy | nothing in the format caps manifest rows |
//! | `MANIFEST_READ_CAP`, `MIMETYPE_CEILING` | policy | resource bounds of ours |
//! | `PAYLOAD_CEILING` and its aliases | policy | see the note at its definition |
//!
//! Where OASIS *does* specify these fields it specifies **structure and no
//! ranges**: `iteration-count` and `key-size` are unbounded
//! `nonNegativeInteger` with no `minInclusive`/`maxInclusive` facet, and
//! LibreOffice bounds neither on read (`ManifestImport.cxx:272-274` does not
//! check `iteration-count` at all; `ZipFile.cxx:155` checks `key-size` only for
//! `< 0`). So every MAX in this file is ours.
//!
//! ## `ARGON2_MAX_M_COST_KIB` lost its justification in `0.1.0-rc.5`
//!
//! `docs/plans/odf-encryption-decrypt-2026-09-02.md` §9 records why it exists:
//! *"LO's own libargon2 returns `ARGON2_MEMORY_ALLOCATION_ERROR` where the Rust
//! crate's `vec!` aborts the process … the ceilings sit exactly where the two
//! behaviours diverge."* That divergence is **closed**: `kdf::derive_argon2id`
//! now allocates with `try_reserve_exact` and returns `HostCannotAllocate`
//! exactly where libargon2 returns its error. The stated reason for the cap no
//! longer holds, and widening it to match LibreOffice is now a decision on its
//! merits rather than a safety question.
//!
//! **`ARGON2_MAX_T_COST` is not in the same position**, and the plan conflated
//! them. `t` allocates nothing — it buys time. `try_reserve` cannot help, and
//! there is no failure to catch: a large `t` is slow, exactly as it is in
//! LibreOffice. Any argument for keeping it is about how long a caller will
//! wait, which is a policy question with no physics behind it.
//!
//! Attacker-controlled manifest fields (`iteration-count`, Argon2 `t`/`m`/`p`,
//! `key-size`, complete-row count) get a MIN and a MAX. Size ceilings are a
//! single named cap, shared wherever the same 1 GiB / 8 MiB / 1 KiB figure
//! used to be spelled as a local literal.
//!
//! Two bounds are what `classify` reads and are compiled in every
//! configuration. The rest exist solely for a `crypto-ops` path and live in
//! [`crypto`] behind one gate, so `dead_code` stays live everywhere rather than
//! being silenced by a module-wide `allow` that would hide a genuinely unused
//! bound as readily as an expected one.

/// `META-INF/manifest.xml` read cap in [`crate::classify`].
pub(crate) const MANIFEST_READ_CAP: usize = 8 * 1024 * 1024;

/// Bytes of the `mimetype` member classify inspects, and the ceiling above
/// which encrypt refuses to carry that member into the outer zip.
pub(crate) const MIMETYPE_CEILING: usize = 1024;

/// Bytes of an untrusted manifest string that may appear in a [`DetectError`]
/// diagnostic.
///
/// Not a parsing bound — it limits only what is *rendered*. The two sides of
/// the mimetype comparison both come out of the package, and only one of them
/// was ever bounded: the `mimetype` member is capped at [`MIMETYPE_CEILING`],
/// but nothing caps an individual `manifest:media-type` attribute, so it was
/// bounded only by [`MANIFEST_READ_CAP`] — 8 MiB of attacker-chosen text
/// interpolated verbatim into an error a consumer may log or show in a dialog.
/// Measured before this existed: padding that attribute by 512 KiB produced a
/// 524,447-character `Display`, growing linearly to the manifest cap.
///
/// 96 is chosen against the data, not the limit: a real media type is around
/// 40 characters (`application/vnd.oasis.opendocument.text` is 39), so this
/// shows any legitimate value whole and elides only what is already anomalous.
///
/// [`DetectError`]: crate::DetectError
pub(crate) const DIAGNOSTIC_ELISION: usize = 96;

#[cfg(feature = "crypto-ops")]
pub(crate) use crypto::*;

/// Bounds no detection-only build can reach. One gate on the module covers all
/// of them: `crypto-ops` is a single feature, so there is no configuration in
/// which some of these are live and others are not.
#[cfg(feature = "crypto-ops")]
mod crypto {
    /// Inclusive floor on `manifest:iteration-count` for a PBKDF2 row. Zero is
    /// what a missing attribute becomes (`""` → `toInt32` → 0); classify still
    /// accepts that row, decrypt must not run HMAC-SHA1 zero times.
    pub(crate) const PBKDF2_MIN_ITER: u32 = 1;
    /// Inclusive ceiling on `manifest:iteration-count`. **Policy, and the
    /// weakest-founded bound in this file.**
    ///
    /// The 600_000 it is derived from is what LibreOffice *writes*
    /// (`ZipPackage.cxx:1400`, inside the save path); LibreOffice imposes no
    /// ceiling at all on *read* — `ManifestImport.cxx:272-274` stores
    /// `toInt32()` with no comparison, and `rtl_digest_PBKDF2`
    /// (`sal/rtl/digest.cxx:1825-1838`) validates only pointers. A write-side
    /// default does not constrain readers, and deriving a read ceiling from one
    /// was the error.
    ///
    /// An earlier version of this comment also justified the exponent by
    /// analogy to [`ARGON2_MAX_M_COST_KIB`] being "the same order of margin".
    /// That analogy now points at nothing: the Argon2 cap's own basis was
    /// removed in `0.1.0-rc.5` (see the module docs), and it was never the same
    /// kind of thing — `m` bought memory, which could abort; iterations buy
    /// time, which cannot.
    ///
    /// What would justify a number here is a measured time budget — "N seconds
    /// of HMAC-SHA1 on reference hardware is the longest single-row stall this
    /// crate accepts". That measurement has not been taken, and until it is,
    /// this is a round number.
    pub(crate) const PBKDF2_MAX_ITER: u32 = 1 << 23;

    /// Inclusive floor on Argon2 `t` / `m` / `p`. Manifest import already
    /// requires all three `> 0` for a complete row; decrypt re-checks so a
    /// future caller of [`crate::kdf::derive_argon2id`] cannot skip that.
    pub(crate) const ARGON2_MIN_T_COST: u32 = 1;
    /// Inclusive ceiling on Argon2 `t`. **Policy**, and unlike
    /// [`ARGON2_MAX_M_COST_KIB`] it never had a memory-safety basis: `t` buys
    /// time, allocates nothing, and a large one is slow in LibreOffice too.
    /// `65536` is ~21,800× the `t=3` LibreOffice writes, so the "each >16×
    /// anything LO writes" line in the decrypt plan describes `m` and was
    /// stretched over `t`. Same missing measurement as
    /// [`PBKDF2_MAX_ITER`]: a time budget, not a round number.
    pub(crate) const ARGON2_MAX_T_COST: u32 = 1 << 16;
    pub(crate) const ARGON2_MIN_M_COST_KIB: u32 = 1;
    pub(crate) const ARGON2_MAX_M_COST_KIB: u32 = 1 << 20;
    pub(crate) const ARGON2_MIN_P_COST: u32 = 1;

    /// Inclusive floor/ceiling on `manifest:key-size` before the derived-key
    /// buffer is allocated. AES-256 needs 32 and Blowfish accepts at most 56.
    pub(crate) const DERIVED_KEY_MIN_LEN: i32 = 1;
    pub(crate) const DERIVED_KEY_MAX_LEN: i32 = 64;

    /// Inclusive ceiling on complete encryption-data rows `decrypt` will run a
    /// KDF for. Per-entry packages multiply PBKDF2/Argon2 cost by this count.
    pub(crate) const MAX_ENCRYPTED_ENTRIES: usize = 4096;

    /// LO `n_ConstDigestLength`: checksum covers at most this many bytes of
    /// compressed plaintext.
    pub(crate) const CHECKSUM_WINDOW: usize = 1024;

    /// 1 GiB. Decrypt's inflate and ciphertext-read caps, and encrypt's deflate
    /// cap, all share this figure so a hostile `manifest:size` or STORED member
    /// cannot allocate past it on one path while another still would.
    pub(crate) const PAYLOAD_CEILING: usize = 1 << 30;
    pub(crate) const INFLATE_CEILING: usize = PAYLOAD_CEILING;
    pub(crate) const CIPHERTEXT_READ_CEILING: usize = PAYLOAD_CEILING;
    pub(crate) const DEFLATE_CEILING: usize = PAYLOAD_CEILING;

    /// `AES_GCM_IV_LEN` is also encrypt's nonce length; `encrypt.rs`
    /// const-asserts that the two agree.
    pub(crate) const AES_GCM_IV_LEN: usize = 12;
    pub(crate) const AES_GCM_TAG_LEN: usize = 16;
    pub(crate) const AES_CBC_IV_LEN: usize = 16;
    pub(crate) const AES_BLOCK_LEN: usize = 16;
    pub(crate) const BLOWFISH_IV_LEN: usize = 8;
}
