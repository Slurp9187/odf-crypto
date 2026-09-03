//! Shared key derivation for [`crate::decrypt`] and [`crate::encrypt`].
//!
//! Key derivation does not depend on direction: `decrypt` reads a KDF tuple
//! off the manifest and derives a key from it, `encrypt` chooses the tuple
//! and derives a key the same way. Both directions call these same helpers
//! rather than each carrying its own copy of the primitive -- the duplication
//! that let decrypt's AES-256-only bug ship once already (decrypt arc audit,
//! `3c3bc33`; plan `docs/plans/odf-encryption-encrypt-2026-09-03.md` §4).

use argon2::{Algorithm, Argon2, Params, Version};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::types::StartKeyAlg;

/// LO's start-key selector, both directions (`ZipPackage::GetEncryptionKey`
/// on read, `ZipPackage::GetEncryptionKey` write-side per the encrypt plan's
/// `package/source/zippackage/ZipPackage.cxx:1751-1778` citation): SHA-1 or
/// SHA-256 over the UTF-8 password bytes, nothing else.
pub(crate) fn start_key(password: &str, alg: StartKeyAlg) -> Vec<u8> {
    match alg {
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
    }
}

/// Argon2id `(t, m, p)` over `start_key` with `salt`, producing a
/// `derived_key_len`-byte key. Shared by decrypt's `Kdf::Argon2id` arm (which
/// reads `t`/`m`/`p`/`salt` off the manifest) and encrypt's one-and-only KDF
/// (plan §6 step 6, which chooses `t=3, m=65536, p=4` itself). Returns a
/// plain `String` error rather than either caller's own error type so both
/// sides can map it independently (`DecryptError::BadParameters` /
/// `EncryptError::Random`-adjacent, per each module's own variants).
pub(crate) fn derive_argon2id(
    start_key: &[u8],
    salt: &[u8],
    t: i32,
    m: i32,
    p: i32,
    derived_key_len: usize,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let params = Params::new(m as u32, t as u32, p as u32, Some(derived_key_len))
        .map_err(|e| format!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived = Zeroizing::new(vec![0u8; derived_key_len]);
    argon2
        .hash_password_into(start_key, salt, &mut derived)
        .map_err(|e| format!("argon2: {e}"))?;
    Ok(derived)
}
