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

use argon2::{Algorithm, Argon2, Block, Params, Version};
use sha1::digest::Output;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::limits::{
    ARGON2_MAX_T_COST, ARGON2_MIN_M_COST_KIB, ARGON2_MIN_P_COST, ARGON2_MIN_T_COST,
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
///
/// The slot is exactly `output_size()` bytes, so `from_mut_slice` cannot
/// mismatch: both read the same associated constant. secure-gate zeroes the
/// slot before the closure runs, and `finalize_into` overwrites all of it.
pub(crate) fn start_key(password: &str, alg: StartKeyAlg) -> PasswordDigest {
    fn digest_into<D: Digest>(password: &str) -> PasswordDigest {
        let mut h = D::new();
        h.update(password.as_bytes());
        PasswordDigest::new_with(<D as Digest>::output_size(), |slot| {
            h.finalize_into(Output::<D>::from_mut_slice(slot));
        })
    }
    match alg {
        StartKeyAlg::Sha1 => digest_into::<Sha1>(password),
        StartKeyAlg::Sha256 => digest_into::<Sha256>(password),
    }
}

/// Why [`derive_argon2id`] could not produce a key. Two kinds, and the
/// difference is what the caller can do about it.
#[derive(Debug)]
pub(crate) enum KdfError {
    /// The `(t, m, p)` tuple or the requested output length is one this
    /// crate -- or `argon2` itself -- will not run. Deterministic: it
    /// fails identically on every machine. Carries the diagnostic text
    /// both directions already render today.
    Params(String),
    /// This host could not allocate argon2's `block_count() * Block::SIZE`
    /// working buffer. Says nothing about the tuple: the same tuple may
    /// derive fine on a machine with more free memory.
    HostCannotAllocate { requested_bytes: usize },
}

/// Argon2id `(t, m, p)` over `start_key` with `salt`, filling `out` (whose
/// length is the derived key length) -- the same shape as `pbkdf2_hmac`, so a
/// caller allocates its key buffer exactly once and both KDF arms write into
/// the same wrapped allocation. Shared by decrypt's `Kdf::Argon2id` arm (which
/// reads `t`/`m`/`p`/`salt` off the manifest) and encrypt's one-and-only KDF
/// (plan §6 step 6, which chooses `t=3, m=65536, p=4` itself).
///
/// Returns [`KdfError`] rather than either caller's own error type, because
/// the two callers want different things from the same tuple failure and both
/// are right: a [`KdfError::Params`] is a hostile manifest field to decrypt,
/// which maps it to `DecryptError::BadParameters`, and a broken invariant of
/// ours to encrypt, which maps it to `EncryptError::Internal` -- encrypt only
/// ever passes a tuple `Argon2Params::new` already validated, so a rejection
/// here means that guard failed, not that a caller was wrong.
/// [`KdfError::HostCannotAllocate`] is the one axis they render identically:
/// each maps it to its own `HostCannotAllocate`, same name on both sides.
///
/// # The block buffer is ours on purpose
///
/// `Argon2::hash_password_into` allocates argon2's working memory itself, with
/// `vec![Block::default(); self.params.block_count()]` (argon2 0.5.3
/// `src/lib.rs:230`), sized from `m` -- which on the decrypt side is
/// `manifest:argon2-memory`, a field the package author chose. An allocation
/// that cannot be satisfied does not return and does not unwind: Rust *aborts*
/// through `handle_alloc_error`, whatever the panic strategy, because an abort
/// is not a panic. An abort skips unwinding, so `Drop` never runs -- and `Drop`
/// is this crate's only zeroizing primitive. Both callers reach this function
/// from inside nested `with_secret`/`with_secret_mut` closures, so at the
/// moment of the abort `PasswordDigest` and `DerivedKey` are live and are left
/// unwiped: key material surviving in memory a process that has already died.
///
/// So the buffer is allocated here instead, with [`Vec::try_reserve_exact`],
/// which returns `Err` where `vec!` aborts, and handed to
/// `hash_password_into_with_memory` (argon2 0.5.3 `src/lib.rs:243`), whose
/// `impl AsMut<[Block]>` parameter exists for exactly this.
///
/// What this does **not** fix: `blocks` is a plain `Vec<Block>`, not a
/// secure-gate wrapper, so argon2's working memory -- which is derived from the
/// password -- is not zeroized when it drops, on this path or on the default
/// one. That residual is unchanged by this function and is a separate question
/// from the abort; conflating the two would claim a wipe that does not happen.
///
/// Both slices are already inside their callers' `with_secret`/
/// `with_secret_mut` closures, so this takes bare slices and never holds
/// secret material of its own.
///
/// The `i32`s are the manifest's own type (`sal_Int32`). Anything that does
/// not fit `u32`, falls outside [`ARGON2_MIN_T_COST`]..=[`ARGON2_MAX_T_COST`]
/// (and the matching `m`/`p` bounds), or fails the crate's own parameter
/// check (`m >= 8p`, `p <= 0xFFFFFF`) is a [`KdfError::Params`] here rather
/// than a panic inside `Params::new`, whose `m_cost < p_cost * 8` test
/// overflows on `p >= 2^29` *before* it range-checks `p` (argon2 0.5.3
/// `params.rs:119`). The working buffer now joins that list: it is a
/// [`KdfError::HostCannotAllocate`] here rather than an abort inside
/// `hash_password_into`.
pub(crate) fn derive_argon2id(
    start_key: &[u8],
    salt: &[u8],
    t: i32,
    m: i32,
    p: i32,
    max_m_kib: u32,
    out: &mut [u8],
) -> Result<(), KdfError> {
    let t = u32::try_from(t).map_err(|_| KdfError::Params(format!("argon2 iterations {t}")))?;
    let m = u32::try_from(m).map_err(|_| KdfError::Params(format!("argon2 memory {m}")))?;
    let p = u32::try_from(p).map_err(|_| KdfError::Params(format!("argon2 lanes {p}")))?;
    if !(ARGON2_MIN_T_COST..=ARGON2_MAX_T_COST).contains(&t) {
        return Err(KdfError::Params(format!(
            "argon2 iterations {t} outside {ARGON2_MIN_T_COST}..={ARGON2_MAX_T_COST}"
        )));
    }
    // `max_m_kib` is the caller's, not this function's, and that asymmetry is
    // the point: `decrypt` passes `ARGON2_MAX_M_COST_KIB_READ` because a
    // manifest chose the number and is acted on before any password is
    // verified; `encrypt` passes `..._WRITE`, the field's own width, because
    // the caller chose to spend their own memory. This function cannot know
    // which threat model it is in. Its callers can.
    if !(ARGON2_MIN_M_COST_KIB..=max_m_kib).contains(&m) {
        return Err(KdfError::Params(format!(
            "argon2 memory {m} KiB outside {ARGON2_MIN_M_COST_KIB}..={max_m_kib}"
        )));
    }
    if !(ARGON2_MIN_P_COST..=Params::MAX_P_COST).contains(&p) {
        return Err(KdfError::Params(format!("argon2 lanes {p}")));
    }
    let params = Params::new(m, t, p, Some(out.len()))
        .map_err(|e| KdfError::Params(format!("argon2 params: {e}")))?;

    // Read off `params` BEFORE it is moved into `Argon2::new` below -- the
    // count and the byte figure the error carries are both unreachable after
    // the move.
    //
    // The `saturating_mul` is the whole overflow story and always was; it does
    // not depend on any ceiling holding.
    //
    // What the ceiling does affect is whether `requested_bytes` is HONEST. On a
    // 32-bit target the product overflows a `usize` once `block_count` passes
    // ~4.19M -- `m` above roughly 4 GiB -- and every larger value then reports
    // exactly `u32::MAX` bytes. Unreachable from `decrypt`, whose cap is 1 GiB,
    // but reachable from `encrypt_with_params` where the caller may name
    // `i32::MAX`. The figure is a diagnostic, so a saturated one is a worse
    // message rather than a safety problem -- recorded because the old 1 GiB
    // cap kept it exact on both paths and no longer does on one.
    let block_count = params.block_count();
    let requested_bytes = block_count.saturating_mul(Block::SIZE);

    let mut blocks: Vec<Block> = Vec::new();
    blocks
        .try_reserve_exact(block_count)
        .map_err(|_| KdfError::HostCannotAllocate { requested_bytes })?;
    // Load-bearing: `try_reserve_exact` has already secured capacity for
    // `block_count` elements, so this fill only writes into capacity that
    // exists. `Vec::resize` grows the allocation only when capacity is short,
    // and it is not -- were it short, the grow would be the infallible one
    // this function exists to avoid, put straight back where it was removed.
    blocks.resize(block_count, Block::default());

    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(start_key, salt, out, &mut blocks)
        .map_err(|e| KdfError::Params(format!("argon2: {e}")))
}
