//! Shared numeric bounds for classify, decrypt, and encrypt.
//!
//! Attacker-controlled manifest fields (`iteration-count`, Argon2 `t`/`m`/`p`,
//! `key-size`, complete-row count) get a MIN and a MAX. Size ceilings are a
//! single named cap, shared wherever the same 1 GiB / 8 MiB / 1 KiB figure
//! used to be spelled as a local literal.

// The default build is detection-only, where `classify` uses just the manifest
// and mimetype caps and every cryptographic bound below is dead. Gating them
// one by one would put a `#[cfg]` on nearly every line to say something the
// module doc already says. Dead-code checking still applies in the `decrypt`
// and `encrypt` builds, which is where these are live.
#![cfg_attr(not(feature = "decrypt"), allow(dead_code))]

/// Inclusive floor on `manifest:iteration-count` for a PBKDF2 row. Zero is
/// what a missing attribute becomes (`""` → `toInt32` → 0); classify still
/// accepts that row, decrypt must not run HMAC-SHA1 zero times.
pub(crate) const PBKDF2_MIN_ITER: u32 = 1;
/// Inclusive ceiling on `manifest:iteration-count`. LibreOffice writes at most
/// 600_000 (`ZipPackage.cxx:1400`, wholesome PBKDF2) or 100_000 (per-entry).
/// `1 << 23` is ~14× that 600_000 — the same order of margin as
/// [`ARGON2_MAX_M_COST_KIB`] (`1 << 20` = 16× LO's `m=65536`).
pub(crate) const PBKDF2_MAX_ITER: u32 = 1 << 23;

/// Inclusive floor on Argon2 `t` / `m` / `p`. Manifest import already requires
/// all three `> 0` for a complete row; decrypt re-checks so a future caller of
/// [`crate::kdf::derive_argon2id`] cannot skip that.
pub(crate) const ARGON2_MIN_T_COST: u32 = 1;
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

/// 1 GiB. Decrypt's inflate and ciphertext-read caps, and encrypt's deflate
/// cap, all share this figure so a hostile `manifest:size` or STORED member
/// cannot allocate past it on one path while another still would.
pub(crate) const PAYLOAD_CEILING: usize = 1 << 30;
pub(crate) const INFLATE_CEILING: usize = PAYLOAD_CEILING;
pub(crate) const DEFLATE_CEILING: usize = PAYLOAD_CEILING;
pub(crate) const CIPHERTEXT_READ_CEILING: usize = PAYLOAD_CEILING;

/// `META-INF/manifest.xml` read cap in [`crate::classify`].
pub(crate) const MANIFEST_READ_CAP: usize = 8 * 1024 * 1024;

/// Bytes of the `mimetype` member classify inspects, and the copy ceiling
/// encrypt will carry into the outer zip.
pub(crate) const MIMETYPE_CEILING: usize = 1024;

/// LO `n_ConstDigestLength`: checksum covers at most this many bytes of
/// compressed plaintext.
pub(crate) const CHECKSUM_WINDOW: usize = 1024;

pub(crate) const AES_GCM_IV_LEN: usize = 12;
pub(crate) const AES_GCM_TAG_LEN: usize = 16;
pub(crate) const AES_CBC_IV_LEN: usize = 16;
pub(crate) const AES_BLOCK_LEN: usize = 16;
pub(crate) const BLOWFISH_IV_LEN: usize = 8;
