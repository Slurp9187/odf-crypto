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
//! | `ARGON2_MAX_M_COST_KIB_WRITE` | hard | `i32::MAX`, the manifest field's width — a caller's own choice |
//! | `ARGON2_MAX_M_COST_KIB_READ` | **policy** | 1 GiB — what an *untrusted* manifest may spend |
//! | `ARGON2_MAX_T_COST` | **policy** | kept deliberately: a DoS bound on `t × m`, not a margin |
//! | `PBKDF2_MAX_ITER` | **policy** | ~19–33 s for one row, measured — see its own docs |
//! | `MAX_ENCRYPTED_ENTRIES` | policy | nothing in the format caps manifest rows |
//! | `MANIFEST_READ_CAP`, `MIMETYPE_CEILING` | policy | resource bounds of ours |
//! | `PAYLOAD_CEILING` and its aliases | policy | see the note at its definition |
//!
//! Where OASIS *does* specify these fields it specifies **structure and no
//! ranges**: `iteration-count` and `key-size` are unbounded
//! `nonNegativeInteger` with no `minInclusive`/`maxInclusive` facet, and
//! LibreOffice bounds neither on read (`ManifestImport.cxx:272-274` does not
//! check `iteration-count` at all; `ZipFile.cxx:155` checks `key-size` only for
//! `< 0`). So every MAX in this file is ours — with one exception added in
//! `0.1.0-rc.6`: `ARGON2_MAX_M_COST_KIB_WRITE` is the manifest field's own
//! width, which is the format's rule rather than a choice of ours.
//!
//! ## The Argon2 memory cap lost its justification in `0.1.0-rc.5`, and split in `rc.6`
//!
//! `docs/plans/odf-encryption-decrypt-2026-09-02.md` §9 records why it exists:
//! *"LO's own libargon2 returns `ARGON2_MEMORY_ALLOCATION_ERROR` where the Rust
//! crate's `vec!` aborts the process … the ceilings sit exactly where the two
//! behaviours diverge."* That divergence is **closed**: `kdf::derive_argon2id`
//! now allocates with `try_reserve_exact` and returns `HostCannotAllocate`
//! exactly where libargon2 returns its error. The stated reason for the cap no
//! longer holds.
//!
//! **Resolved in `0.1.0-rc.6`, by splitting it in two.** What the missing basis
//! actually showed was that one constant was answering two questions. On the
//! *write* path `1 << 20` refused RFC 9106's own FIRST RECOMMENDED option
//! (`t=1, p=4, m=2^21`, 2 GiB) for a cost the caller chose to pay, so that side
//! is now bounded by the manifest field's width and the host. On the *read* path
//! the number comes from the package and is acted on before any password is
//! verified, so the cap stays — with a reason it never had. See the two
//! constants.
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
    /// Inclusive ceiling on `manifest:iteration-count`. **Policy, and as of
    /// `0.1.0-rc.6` it finally has the measured budget it always lacked.**
    ///
    /// LibreOffice imposes no read ceiling at all — `ManifestImport.cxx:272-274`
    /// stores `toInt32()` with no comparison, and `rtl_digest_PBKDF2`
    /// (`sal/rtl/digest.cxx:1825-1838`) validates only pointers. The old value
    /// was derived from the 600_000 LibreOffice *writes*
    /// (`ZipPackage.cxx:1400`, inside the save path), and a write-side default
    /// does not constrain readers. That was the error.
    ///
    /// # The budget, measured
    ///
    /// `pbkdf2` 0.12.2 / `sha1` 0.10.7 through this crate's own `derive_key`,
    /// release profile, Intel i7-10510U (4C/8T, 15 W mobile):
    ///
    /// | `iteration-count` | one row, 32-byte key |
    /// | --- | --- |
    /// | 100_000 — LibreOffice per-entry write | 0.14–0.19 s |
    /// | 600_000 — LibreOffice wholesome write | ~1.1 s |
    /// | 10_000_000 — **this ceiling** | **~19–33 s** |
    ///
    /// **So the budget is: one row, tens of seconds, on a slow laptop.** That is
    /// the sentence this constant needed and did not have.
    ///
    /// # Why one row is the whole threat
    ///
    /// A per-entry package may carry up to [`MAX_ENCRYPTED_ENTRIES`] rows and
    /// `decrypt` derives a key for each, so the arithmetic suggests a 4096×
    /// multiplier. **It is not reachable.** The loop propagates with `?`, so a
    /// caller without the password pays for exactly one derivation and then
    /// stops. Measured through the public API with a wrong password: 1 row
    /// 24–30 s, 8 rows 37.8 s, 64 rows 21.8 s — i.e. flat. On a real golden the
    /// correct password runs all five rows (15.70 s) and a wrong one runs a
    /// single KDF (2.47 s).
    ///
    /// The aggregate is therefore a cost paid by someone who already holds the
    /// password, which is not a threat. Recorded because the multiplier is the
    /// obvious argument for a tighter cap and it does not survive measurement.
    ///
    /// # Why 10_000_000 and not `1 << 23`
    ///
    /// The old `1 << 23` = 8_388_608 refused NIST SP 800-132 §5.2's own example
    /// — *"an iteration count of 10,000,000 may be appropriate"* — for a file
    /// LibreOffice would open, to save about two seconds. A round exponent that
    /// rejects a cited figure is the same shape of mistake as deriving a read
    /// ceiling from a write default. Nothing real writes above 600_000, so this
    /// refuses no current producer either way; the difference is which number
    /// can be defended.
    ///
    /// # The second dial, which this constant does not bound
    ///
    /// `manifest:key-size` multiplies the same work: PBKDF2 emits
    /// `ceil(dkLen / 20)` HMAC-SHA1 blocks, so 16/32/64 bytes cost 1/2/4×.
    /// At this ceiling a 64-byte key is ~29–39 s rather than ~19–33 s. Bounded
    /// separately by [`DERIVED_KEY_MAX_LEN`], and worth knowing when reading the
    /// table above as though it were the worst case. It is the worst case for
    /// *this* dial only.
    pub(crate) const PBKDF2_MAX_ITER: u32 = 10_000_000;

    /// Inclusive floor on Argon2 `t` / `m` / `p`. Manifest import already
    /// requires all three `> 0` for a complete row; decrypt re-checks so a
    /// future caller of [`crate::kdf::derive_argon2id`] cannot skip that.
    pub(crate) const ARGON2_MIN_T_COST: u32 = 1;
    /// Inclusive ceiling on Argon2 `t`. **Policy, kept deliberately** — a
    /// sanity bound against the expensive direction, not a margin.
    ///
    /// It never had a memory-safety basis: `t` buys time, allocates nothing,
    /// and `try_reserve` cannot help. `65536` is ~21,800× the `t=3` LibreOffice
    /// writes, so the decrypt plan's "each >16× anything LO writes" line
    /// described `m` and was stretched over `t`. It is not a margin and this
    /// no longer claims to be one.
    ///
    /// **Why keep a bound nothing legitimate reaches.** Because the question is
    /// `t = 3` against `t = u32::MAX`, and the answer changed when
    /// [`ARGON2_MAX_M_COST_KIB_WRITE`] stopped being a policy cap. Argon2's cost
    /// is roughly `t × m`, so on the **write** path — where `m` is now bounded
    /// only by the host — this is the finite one.
    ///
    /// It is **not** the read path's defence, and an earlier draft of this doc
    /// claimed it was. `t = 65536` is ~21,800× LibreOffice's `t = 3`, and the
    /// paragraph below argues nothing legitimate reaches it; a bound nothing
    /// reaches bounds no attacker either. What protects `decrypt` from a hostile
    /// cost is [`ARGON2_MAX_M_COST_KIB_READ`], which is why that one stayed.
    ///
    /// **Not lowered to a "plausible" range**, though RFC 9106 recommends `t`
    /// of 1 or 3 and OWASP 1–5. Picking 32 or 64 would mint a fresh
    /// under-founded number and would start refusing a caller who followed
    /// RFC 9106 step 10 — *raise `t` until the time budget is met* — on a
    /// machine with CPU to spare. The owner's *never block a construct* ruling
    /// is about **weak** tuples; a ceiling on the expensive direction is
    /// denial-of-service defence, which is a different axis. Lowering is the
    /// option that needs a measurement; keeping does not.
    pub(crate) const ARGON2_MAX_T_COST: u32 = 1 << 16;
    /// Inclusive floor on Argon2 `m`, in KiB. **Spec**: `positiveInteger`, and
    /// LibreOffice checks `0 < m`. Deliberately looser than argon2's own
    /// `MIN_M_COST` of 8, so *"zero is not a positive integer"* (the format's
    /// rule) stays distinguishable from *"argon2 needs 8 KiB per lane"* (the
    /// cipher's), which arrives as [`crate::ParamsReason::CipherRejects`].
    pub(crate) const ARGON2_MIN_M_COST_KIB: u32 = 1;
    /// Inclusive ceiling on Argon2 `m` when **this crate's caller** chose it:
    /// `Argon2Params::new`, on the way to `encrypt`. **`hard`** — `i32::MAX` is
    /// the manifest field's own width, since `manifest:argon2-memory` is read
    /// with `toInt32()` upstream, so no package can express more.
    ///
    /// **There is no policy cap on this side, and that is the fix `0.1.0-rc.6`
    /// made.** It was `1 << 20` (1 GiB), which refused RFC 9106's own FIRST
    /// RECOMMENDED option — §4 names `t=1, p=4, m=2^21` (2 GiB), twice that —
    /// so a caller following the RFC could not use this crate. Raising it to
    /// 2 GiB was considered and rejected: that still refuses the RFC's 4 GiB
    /// and 6 GiB examples and is a guessed number wearing a citation.
    ///
    /// Spending a caller's own memory on a tuple the caller picked is the
    /// owner's *never block a construct* case. What bounds it is the host, via
    /// `try_reserve_exact` and `HostCannotAllocate`, and the cipher, via
    /// `m >= 8p`.
    ///
    /// **Nothing reports that a tuple is expensive**, and this doc deliberately
    /// does not pretend otherwise. `Argon2Params::is_weaker_than_libreoffice`
    /// is the only predicate there is and it answers the opposite question — it
    /// would call RFC 9106's `t=1, m=2 GiB, p=4` *weaker*, because `t = 1 < 3`,
    /// which is true on that axis and misleading as a summary. A
    /// heavier-than-LibreOffice predicate would be the honest counterpart and
    /// does not exist yet.
    pub(crate) const ARGON2_MAX_M_COST_KIB_WRITE: u32 = i32::MAX as u32;
    /// Inclusive ceiling on Argon2 `m` when **a package** chose it: a manifest
    /// reaching `decrypt`. **Policy, and kept** — 1 GiB, 16× the 64 MiB
    /// LibreOffice writes.
    ///
    /// **The two directions are not the same question, which is what rc.6 got
    /// wrong before it got right.** Uncapping both was tried first, on the
    /// argument that the cap's original basis — a `vec!` abort that
    /// `try_reserve_exact` replaced in rc.5 — was gone. That argument is sound
    /// and it is about the *write* path. It says nothing about a number the
    /// reader did not choose.
    ///
    /// **`try_reserve_exact` bounds the abort. It does not bound the cost.** It
    /// grants whatever the allocator will grant, and then `resize` and argon2's
    /// fill touch every page. `decrypt` cannot verify a password without first
    /// deriving the key, so the manifest's `m` is acted on *before* anything
    /// about the file is trusted. Measured on the uncapped build, rewriting
    /// only `loext:argon2-memory` in a golden and passing a **wrong** password:
    ///
    /// | `m` | one `decrypt` attempt |
    /// | --- | --- |
    /// | 2 GiB | `WrongPassword` after 13 seconds |
    /// | 8 GiB | `WrongPassword` after 29 minutes, 8.2 GiB committed |
    ///
    /// A 7,363-byte file buys that. With this cap both are `BadParameters`
    /// immediately.
    ///
    /// So the cap was never the wrong idea — its stated *reason* was wrong, and
    /// it was applied to both paths when only one of them faces an untrusted
    /// number. 1 GiB is still a policy figure with no measured budget behind it
    /// (see the note on [`PBKDF2_MAX_ITER`], which has the same gap); what is no
    /// longer true is that it lacks a reason.
    pub(crate) const ARGON2_MAX_M_COST_KIB_READ: u32 = 1 << 20;
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
    ///
    /// **Policy, and its basis moved in `0.1.0-rc.5` the same way
    /// [`ARGON2_MAX_M_COST_KIB_READ`]'s did.** `decrypt`'s inflate slot is allocated
    /// with `try_reserve_exact` now, so an unaffordable `manifest:size` returns
    /// `HostCannotAllocate` rather than aborting, and this ceiling is no longer
    /// what stands between a hostile size and the allocator. What survives is
    /// screening a negative or untruncatable `i64` before the cast, and
    /// answering an absurd claim with a comparison instead of an allocation
    /// attempt. See `decrypt::inflated_len`.
    pub(crate) const PAYLOAD_CEILING: usize = 1 << 30;
    /// Decrypt's inflate cap. `manifest:size` is attacker-chosen, so this one
    /// screens an untrusted number.
    pub(crate) const INFLATE_CEILING: usize = PAYLOAD_CEILING;
    /// Decrypt's ciphertext-read cap. Same: a zip member's length is the
    /// package's number, not ours.
    pub(crate) const CIPHERTEXT_READ_CEILING: usize = PAYLOAD_CEILING;
    /// Encrypt's deflate cap — **hygiene, not a security boundary**, and it
    /// shares the figure above only for shape.
    ///
    /// The distinction is the encrypt plan's, which asked for it to be written
    /// here *"so nobody 'fixes' it into a security claim it isn't"*
    /// (`odf-encryption-encrypt-2026-09-03.md`, §4). Sharing one constant with
    /// the two above is what made that easy to lose: the paragraph on
    /// `PAYLOAD_CEILING` argues all three at once, in terms of a hostile
    /// `manifest:size`, and `encrypt` has no such thing — its caller hands it
    /// the plaintext directly. There is no attacker-supplied length on this
    /// path to defend against; there is only an unbounded allocation on a
    /// pathological input, which is a different and much smaller claim.
    pub(crate) const DEFLATE_CEILING: usize = PAYLOAD_CEILING;

    /// `AES_GCM_IV_LEN` is also encrypt's nonce length; `encrypt.rs`
    /// const-asserts that the two agree.
    pub(crate) const AES_GCM_IV_LEN: usize = 12;
    pub(crate) const AES_GCM_TAG_LEN: usize = 16;
    pub(crate) const AES_CBC_IV_LEN: usize = 16;
    pub(crate) const AES_BLOCK_LEN: usize = 16;
    pub(crate) const BLOWFISH_IV_LEN: usize = 8;
}
