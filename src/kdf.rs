//! Shared key derivation for [`crate::decrypt`] and [`crate::encrypt`].
//!
//! Key derivation does not depend on direction: `decrypt` reads a KDF tuple
//! off the manifest and derives a key from it, `encrypt` chooses the tuple
//! and derives a key the same way. Both directions call these same helpers
//! rather than each carrying its own copy of the primitive -- the duplication
//! that let decrypt's AES-256-only bug ship once already (decrypt arc audit,
//! `3c3bc33`; plan `docs/plans/odf-encryption-encrypt-2026-09-03.md` §4).
//! Only the start key and Argon2id live here; the AES-GCM call itself is one
//! line in each direction and is not shared.
//!
//! Secret material uses [`crate::sensitive`]'s `secure-gate` wrappers, this
//! crate's only zeroizing primitive.

use argon2::{Algorithm, Argon2, Params, Version};
use sha1::digest::Output;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::limits::{
    ARGON2_MAX_M_COST_KIB, ARGON2_MAX_T_COST, ARGON2_MIN_M_COST_KIB, ARGON2_MIN_P_COST,
    ARGON2_MIN_T_COST,
};
use crate::sensitive::PasswordDigest;
use crate::types::StartKeyAlg;

/// LO's start-key selector, both directions (`ZipPackage::GetEncryptionKey`,
/// `package/source/zippackage/ZipPackage.cxx:1751-1778`): SHA-1 or SHA-256
/// over the UTF-8 password bytes, nothing else.
///
/// `finalize_into` writes the digest straight into the wrapper's heap buffer,
/// so no stack copy of it is left behind (a plain `finalize().to_vec()` would
/// return it through a stack `GenericArray` first). What this cannot reach:
/// the hasher buffers the raw password bytes internally until finalize, and
/// `compress` spills its message schedule on the stack; the 0.10 digest /
/// sha1 / sha2 crates offer no zeroize feature for either. That residual is
/// inherent to the hash crates at this version -- see the secure-gate skill.
pub(crate) fn start_key(password: &str, alg: StartKeyAlg) -> PasswordDigest {
    fn digest_into<D: Digest>(password: &str) -> PasswordDigest {
        let mut h = D::new();
        h.update(password.as_bytes());
        PasswordDigest::new_with(|v| {
            v.resize(<D as Digest>::output_size(), 0);
            h.finalize_into(Output::<D>::from_mut_slice(v));
        })
    }
    match alg {
        StartKeyAlg::Sha1 => digest_into::<Sha1>(password),
        StartKeyAlg::Sha256 => digest_into::<Sha256>(password),
    }
}

/// Argon2id `(t, m, p)` over `start_key` with `salt`, filling `out` (whose
/// length is the derived key length) -- the same shape as `pbkdf2_hmac`, so a
/// caller allocates its key buffer exactly once and both KDF arms write into
/// the same wrapped allocation. Shared by decrypt's `Kdf::Argon2id` arm (which
/// reads `t`/`m`/`p`/`salt` off the manifest) and encrypt's one-and-only KDF
/// (plan §6 step 6, which chooses `t=3, m=65536, p=4` itself).
///
/// Returns a plain `String` error rather than either caller's own error type:
/// decrypt maps it to `DecryptError::BadParameters`; encrypt only ever passes
/// its own compile-time constants, so it maps a failure to
/// `EncryptError::Internal` rather than treating it as unreachable.
///
/// Both slices are already inside their callers' `with_secret`/
/// `with_secret_mut` closures, so this takes bare slices and never holds
/// secret material of its own.
///
/// The `i32`s are the manifest's own type (`sal_Int32`). Anything that does
/// not fit `u32`, falls outside [`ARGON2_MIN_T_COST`]..=[`ARGON2_MAX_T_COST`]
/// (and the matching `m`/`p` bounds), or fails the crate's own parameter
/// check (`m >= 8p`, `p <= 0xFFFFFF`) is an error here rather than a panic
/// inside `Params::new`, whose `m_cost < p_cost * 8` test overflows on
/// `p >= 2^29` *before* it range-checks `p` (argon2 0.5.3 `params.rs:119`).
pub(crate) fn derive_argon2id(
    start_key: &[u8],
    salt: &[u8],
    t: i32,
    m: i32,
    p: i32,
    out: &mut [u8],
) -> Result<(), String> {
    let t = u32::try_from(t).map_err(|_| format!("argon2 iterations {t}"))?;
    let m = u32::try_from(m).map_err(|_| format!("argon2 memory {m}"))?;
    let p = u32::try_from(p).map_err(|_| format!("argon2 lanes {p}"))?;
    if !(ARGON2_MIN_T_COST..=ARGON2_MAX_T_COST).contains(&t) {
        return Err(format!(
            "argon2 iterations {t} outside {ARGON2_MIN_T_COST}..={ARGON2_MAX_T_COST}"
        ));
    }
    if !(ARGON2_MIN_M_COST_KIB..=ARGON2_MAX_M_COST_KIB).contains(&m) {
        return Err(format!(
            "argon2 memory {m} KiB outside {ARGON2_MIN_M_COST_KIB}..={ARGON2_MAX_M_COST_KIB}"
        ));
    }
    if !(ARGON2_MIN_P_COST..=Params::MAX_P_COST).contains(&p) {
        return Err(format!("argon2 lanes {p}"));
    }
    let params =
        Params::new(m, t, p, Some(out.len())).map_err(|e| format!("argon2 params: {e}"))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(start_key, salt, out)
        .map_err(|e| format!("argon2: {e}"))
}
