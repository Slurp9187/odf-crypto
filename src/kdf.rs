//! Shared key derivation for [`crate::decrypt`] and [`crate::encrypt`].
//!
//! Key derivation does not depend on direction: `decrypt` reads a KDF tuple
//! off the manifest and derives a key from it, `encrypt` chooses the tuple
//! and derives a key the same way. Both directions call these same helpers
//! rather than each carrying its own copy of the primitive -- the duplication
//! that let decrypt's AES-256-only bug ship once already (decrypt arc audit,
//! `3c3bc33`; plan `docs/plans/odf-encryption-encrypt-2026-09-03.md` §4).
//! Only the start key and Argon2id live here; the AES-GCM call itself is
//! one line in each direction and is not shared.

use argon2::{Algorithm, Argon2, Params, Version};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::types::StartKeyAlg;

/// Ceiling on `argon2-memory` (KiB) and `argon2-iterations` accepted from a
/// manifest. LibreOffice itself has no cap (decrypt plan §9, settled) -- but
/// LO's libargon2 returns `ARGON2_MEMORY_ALLOCATION_ERROR` when the block
/// array cannot be allocated, whereas the `argon2` crate's `vec!` aborts the
/// process, and a huge `t` simply pins a CPU. The ceilings sit where the two
/// behaviours would otherwise diverge: 1 GiB of blocks and 65536 passes,
/// each more than 16x anything LO has ever written (`m=65536`, `t=3`,
/// `ZipPackage.cxx:1405`). Rejecting past them is `BadParameters` on the
/// decrypt side, the same fail-closed answer as any other malformed tuple.
pub(crate) const ARGON2_MAX_M_COST_KIB: u32 = 1 << 20;
pub(crate) const ARGON2_MAX_T_COST: u32 = 1 << 16;

/// LO's start-key selector, both directions (`ZipPackage::GetEncryptionKey`,
/// `package/source/zippackage/ZipPackage.cxx:1751-1778`): SHA-1 or SHA-256
/// over the UTF-8 password bytes, nothing else. Returned already wrapped in
/// [`Zeroizing`] so no caller can forget to wipe the password digest.
pub(crate) fn start_key(password: &str, alg: StartKeyAlg) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(match alg {
        StartKeyAlg::Sha1 => {
            let mut h = Sha1::new();
            h.update(password.as_bytes());
            h.finalize().to_vec()
        }
        StartKeyAlg::Sha256 => {
            let mut h = Sha256::new();
            h.update(password.as_bytes());
            h.finalize().to_vec()
        }
    })
}

/// Argon2id `(t, m, p)` over `start_key` with `salt`, filling `out` (whose
/// length is the derived key length) -- the same shape as `pbkdf2_hmac`, so a
/// caller allocates its key buffer exactly once. Shared by decrypt's
/// `Kdf::Argon2id` arm (which reads `t`/`m`/`p`/`salt` off the manifest) and
/// encrypt's one-and-only KDF (plan §6 step 6, which chooses `t=3, m=65536,
/// p=4` itself). Returns a plain `String` error rather than either caller's
/// own error type: decrypt maps it to `DecryptError::BadParameters`; encrypt
/// only ever passes its own fixed constants and treats it as unreachable.
///
/// The `i32`s are the manifest's own type (`sal_Int32`). Anything that does
/// not fit `u32`, exceeds [`ARGON2_MAX_M_COST_KIB`] / [`ARGON2_MAX_T_COST`],
/// or fails the crate's own parameter check (`m >= 8p`, `p <= 0xFFFFFF`) is
/// an error here rather than a panic inside `Params::new`, whose
/// `m_cost < p_cost * 8` test overflows on `p >= 2^29` before it range-checks
/// `p` (argon2 0.5.3 `params.rs:119`).
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
    if m > ARGON2_MAX_M_COST_KIB {
        return Err(format!("argon2 memory {m} KiB exceeds ceiling {ARGON2_MAX_M_COST_KIB}"));
    }
    if t > ARGON2_MAX_T_COST {
        return Err(format!("argon2 iterations {t} exceeds ceiling {ARGON2_MAX_T_COST}"));
    }
    if p > Params::MAX_P_COST {
        return Err(format!("argon2 lanes {p}"));
    }
    let params = Params::new(m, t, p, Some(out.len())).map_err(|e| format!("argon2 params: {e}"))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(start_key, salt, out)
        .map_err(|e| format!("argon2: {e}"))
}
