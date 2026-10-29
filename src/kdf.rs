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
use secure_gate::{Dynamic, RevealSecret, RevealSecretMut};
use sha1::digest::Output;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::limits::{ARGON2_MIN_M_COST_KIB, ARGON2_MIN_P_COST, ARGON2_MIN_T_COST};
use crate::sensitive::{PasswordBytes, PasswordDigest};
use crate::types::StartKeyAlg;

/// LO's start-key selector, both directions (`ZipPackage::GetEncryptionKey`,
/// `package/source/zippackage/ZipPackage.cxx:1751-1778`): SHA-1 or SHA-256
/// over the UTF-8 password bytes, nothing else.
///
/// `finalize_into` writes the digest straight into the wrapper's heap buffer,
/// so no stack copy of it is left behind (a plain `finalize().to_vec()` would
/// return it through a stack array first). The hasher buffers the raw password
/// bytes internally until finalize; sha1/sha2 0.11's `zeroize` feature wipes
/// that buffer and the chaining state when the hasher drops. What it cannot
/// reach is `compress`'s message schedule, spilled on the stack and left
/// there -- see the secure-gate skill.
///
/// The slot is exactly `output_size()` bytes, so the `try_from` cannot fail:
/// both read the same associated constant. It is fallible only because
/// digest 0.11 deprecated the panicking `from_mut_slice`; were it ever to
/// fail, the slot would stay the zeroes secure-gate wrote, the derived key
/// would be wrong, and the caller would see a wrong password -- not a panic.
/// secure-gate zeroes the slot before the closure runs, and `finalize_into`
/// overwrites all of it.
pub(crate) fn start_key(password: &str, alg: StartKeyAlg) -> PasswordDigest {
    fn digest_into<D: Digest>(password: &str) -> PasswordDigest {
        let mut h = D::new();
        h.update(password.as_bytes());
        PasswordDigest::new_with(<D as Digest>::output_size(), |slot| {
            if let Ok(out) = <&mut Output<D>>::try_from(slot) {
                h.finalize_into(out);
            }
        })
    }
    match alg {
        StartKeyAlg::Sha1 => digest_into::<Sha1>(password),
        StartKeyAlg::Sha256 => digest_into::<Sha256>(password),
    }
}

/// A rung of LibreOffice's legacy SHA-1 read ladder, tried only after the
/// correct start key has failed with a wrong-password result on a row whose
/// manifest names SHA-1.
///
/// `ZipPackageStream::getDataStream` (`package/source/zippackage/ZipPackageStream.cxx:1013-1074`)
/// catches `WrongPasswordException` and retries, per stream, in this order. Its
/// own comment says who needs it: ODF 1.2 files written by OOo < 3.4beta /
/// LO < 3.5, and ODF 1.1 / OOoXML files written by any version. The keys come
/// from `OStorageHelper::CreatePackageEncryptionData`
/// (`comphelper/source/misc/storagehelper.cxx`), which makes both StarOffice
/// digests with `rtl_digest_SHA1` -- "StarOffice not-quite-SHA1".
///
/// Current LibreOffice writes the correct UTF-8 SHA-1 (decrypt plan OQ1,
/// measured), so no file it writes needs any of these. They exist for older
/// writers, and to agree with LibreOffice about which passwords open them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LegacyStartKey {
    /// `Bugs::WrongSHA1`: StarOffice SHA-1 of the UTF-8 password (tdf#114939).
    StarOfficeUtf8,
    /// rhbz#1013844 / fdo#47482: SHA-256 of the UTF-8 password **although the
    /// manifest says SHA-1**. LibreOffice <= 3.6 wrote OOo 1.0-format files
    /// with a SHA-256 start key and no start-key element to say so.
    ForcedSha256,
    /// `Bugs::WinEncodingWrongSHA1`: StarOffice SHA-1 of the password as
    /// MS-1252 -- the buggy digest, not the correct one, over
    /// [`crate::ms1252::encode`]'s bytes.
    StarOfficeMs1252,
}

/// The ladder in LibreOffice's order. Upstream restores SHA-1 after the forced
/// SHA-256 fails, so the MS-1252 rung is SHA-1 again.
pub(crate) const SHA1_LADDER: [LegacyStartKey; 3] = [
    LegacyStartKey::StarOfficeUtf8,
    LegacyStartKey::ForcedSha256,
    LegacyStartKey::StarOfficeMs1252,
];

/// The start key a ladder rung tries.
pub(crate) fn legacy_start_key(password: &str, rung: LegacyStartKey) -> PasswordDigest {
    match rung {
        LegacyStartKey::StarOfficeUtf8 => staroffice_sha1(password.as_bytes()),
        LegacyStartKey::ForcedSha256 => start_key(password, StartKeyAlg::Sha256),
        LegacyStartKey::StarOfficeMs1252 => {
            crate::ms1252::encode(password).with_secret(|b| staroffice_sha1(b))
        }
    }
}

const SHA1_INIT: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];
const SHA1_BLOCK: usize = 64;

/// `rtl_digest_SHA1`, which is **knowingly not SHA-1** and must stay that way.
///
/// `sal/rtl/digest.cxx`, `endSHA`, with LibreOffice's own comment:
///
/// ```text
/// // tdf#114939 NB: this is WRONG and should be ">" not ">=" but is not
/// // fixed as this buggy SHA1 implementation is needed for compatibility
/// if (i >= (DIGEST_LBLOCK_SHA - 2))
/// ```
///
/// `i` is the word index just past the `0x80` terminator, so the final block is
/// split in two -- a spurious all-zero-padded block, then the length -- whenever
/// `len % 64` is 52..=55, where real SHA-1 still fits the length in one. Outside
/// that window this agrees with SHA-1, which is why only a password of the right
/// length can tell the rungs apart. `tests/goldens/sha1_star.py` is the reference
/// model, self-tested against `hashlib`.
///
/// Padding is done here; compression is the `sha1` crate's. Full blocks are
/// compressed straight from `msg` without a copy; the tail and its padding sit
/// in a [`PasswordBytes`] buffer, since they are password bytes too.
fn staroffice_sha1(msg: &[u8]) -> PasswordDigest {
    let mut state = SHA1_INIT;
    let full = msg.len() - msg.len() % SHA1_BLOCK;
    let (blocks, tail) = msg.split_at(full);
    sha1::block_api::compress(&mut state, blocks.as_chunks::<SHA1_BLOCK>().0);
    // Real SHA-1 needs a second block only when the terminator and the 8-byte
    // length do not fit: tail >= 56. rtl's `i >= 14` makes it tail >= 52.
    let padded_len = if tail.len() >= 52 {
        2 * SHA1_BLOCK
    } else {
        SHA1_BLOCK
    };
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    let padded = PasswordBytes::new_with(padded_len, |buf| {
        if let Some(dst) = buf.get_mut(..tail.len()) {
            dst.copy_from_slice(tail);
        }
        if let Some(b) = buf.get_mut(tail.len()) {
            *b = 0x80;
        }
        if let Some(dst) = buf.get_mut(padded_len - 8..) {
            dst.copy_from_slice(&bit_len.to_be_bytes());
        }
    });
    padded.with_secret(|buf| {
        sha1::block_api::compress(&mut state, buf.as_chunks::<SHA1_BLOCK>().0);
    });
    PasswordDigest::new_with(20, |slot| {
        for (dst, word) in slot.as_chunks_mut::<4>().0.iter_mut().zip(state) {
            dst.copy_from_slice(&word.to_be_bytes());
        }
    })
}

/// Why [`derive_argon2id`] could not produce a key. Two kinds, and the
/// difference is what the caller can do about it.
#[derive(Debug)]
pub(crate) enum KdfError {
    /// The `(t, m, p)` tuple, or the salt's length, is one this crate -- or
    /// `argon2` itself -- will not run. Deterministic: it fails identically on
    /// every machine. Structured, with no text from the manifest
    /// ([`crate::BadParameter`]).
    Params(crate::BadParameter),
    /// `argon2` refused something no manifest field reaches past the checks
    /// above (an output length outside 4..=2^32-1, a password or secret too
    /// long): an invariant of ours. Matched by name, never formatted from
    /// `argon2`'s own message.
    Internal(&'static str),
    /// This host could not allocate argon2's `block_count() * Block::SIZE`
    /// working buffer. Says nothing about the tuple: the same tuple may
    /// derive fine on a machine with more free memory.
    HostCannotAllocate { requested_bytes: usize },
    /// This host could not start even one thread to run the lanes on
    /// ([`on_lane_threads`]). Like `HostCannotAllocate`, about the machine
    /// and not the tuple; `requested_bytes` is the one thread's stack.
    HostCannotSpawn { requested_bytes: usize },
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
/// which maps it to `DecryptError::BadParameters` with its structured
/// [`crate::BadParameter`], and a broken invariant of ours to encrypt, which
/// renders it into `EncryptError::Internal` -- encrypt only
/// ever passes a tuple `Argon2Params::new` already validated, so a rejection
/// here means that guard failed, not that a caller was wrong.
/// [`KdfError::HostCannotAllocate`] is the one axis they render identically:
/// each maps it to its own `HostCannotAllocate`, same name on both sides.
///
/// # The block buffer is ours on purpose
///
/// Through argon2 0.5.3, `Argon2::hash_password_into` allocated argon2's working
/// memory itself, with `vec![Block::default(); self.params.block_count()]`
/// (argon2 0.5.3 `src/lib.rs:230`), sized from `m` -- which on the decrypt side is
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
/// `hash_password_into_with_memory` (argon2 0.6.0 `src/lib.rs:307`), whose
/// `impl AsMut<[Block]>` parameter exists for exactly this.
///
/// argon2 0.6 made its own allocation fallible too (`Blocks::new` over
/// `alloc_zeroed`, returning `Error::OutOfMemory`, `src/lib.rs:286-287`). The
/// buffer stays ours anyway: it is what lets the error carry the byte count,
/// and this crate's no-abort guarantee should not rest on a dependency staying
/// fallible.
///
/// # Lanes run in parallel
///
/// argon2 0.6's `parallel` feature fills each slice's lanes on rayon threads,
/// on a pool [`on_lane_threads`] builds for the call. Beneath
/// `hash_password_into_with_memory` the only heap use is rayon's: the local
/// pool's registry and per-thread deques, and job bookkeeping. All of it is
/// sized by the thread count, which is at most the host's cores, and none of
/// it by `m`. It allocates infallibly, like miniz's boxed state elsewhere in
/// this crate: a fixed cost, not one a manifest can raise.
///
/// # The working memory is wiped
///
/// `blocks` is derived from the password, all `m` KiB of it. It is built as a
/// plain `Vec<Block>`, because the fallible reservation needs one, then moved
/// into a secure-gate `Dynamic<Vec<Block>>` before the hash writes a byte of
/// it, so it is wiped on drop on every path out, error and unwind included.
/// argon2's `zeroize` feature is what makes `Block: Zeroize`, and so the
/// wrapper possible; the same feature wipes argon2's own `initial_hash` and
/// per-block hash temporaries. Not covered: an abort, which skips every
/// `Drop` (see above), and whatever the lane threads spill onto their own
/// stacks.
///
/// Both slices are already inside their callers' `with_secret`/
/// `with_secret_mut` closures, so this takes bare slices. The only secret
/// material it holds of its own is `blocks`, wrapped as above.
///
/// The `i32`s are the manifest's own type (`sal_Int32`). Anything that does
/// not fit `u32`, falls outside [`ARGON2_MIN_T_COST`]..=[`ARGON2_MAX_T_COST`]
/// (and the matching `m`/`p` bounds), or fails the crate's own parameter
/// check (`m >= 8p`, `p <= 0xFFFFFF`) is a [`KdfError::Params`] here rather
/// than a panic inside `Params::new`, whose `m_cost < p_cost * 8` test
/// overflowed on `p >= 2^29` *before* it range-checked `p` (argon2 0.5.3
/// `params.rs:119`). 0.6 checks `p` first (`params.rs:139-145`), so the
/// overflow is gone upstream; the screen stays, because it is what gives the
/// structured [`crate::BadParameter`]. The working buffer joins that list: it is a
/// [`KdfError::HostCannotAllocate`] here rather than an abort inside
/// `hash_password_into`.
pub(crate) fn derive_argon2id(
    start_key: &[u8],
    salt: &[u8],
    t: i32,
    m: i32,
    p: i32,
    limits: &crate::DecryptLimits,
    out: &mut [u8],
) -> Result<(), KdfError> {
    use crate::bad_parameter::{wide, BadParameter, ManifestField, Primitive};
    use crate::Argon2Axis;
    // Each axis's range: the format's floor (`positiveInteger`) to the caller's
    // ceiling. A negative manifest value is outside it too, and reported with
    // its own sign.
    let out_of_range = |axis, got: i64, min: u32, max: u32| {
        KdfError::Params(BadParameter::OutOfRange {
            field: ManifestField::Argon2(axis),
            got,
            min: min.into(),
            max: max.into(),
        })
    };
    let argon2_rejects = |field, got: i64, min: i64, max: i64| {
        KdfError::Params(BadParameter::CipherRejects {
            field,
            by: Primitive::Argon2,
            got,
            min,
            max,
        })
    };
    let (t_max, m_max) = (limits.argon2_max_t, limits.argon2_max_m_kib);
    let t = u32::try_from(t)
        .map_err(|_| out_of_range(Argon2Axis::T, t.into(), ARGON2_MIN_T_COST, t_max))?;
    let m = u32::try_from(m)
        .map_err(|_| out_of_range(Argon2Axis::MKib, m.into(), ARGON2_MIN_M_COST_KIB, m_max))?;
    let p_wide = i64::from(p);
    let p = u32::try_from(p).map_err(|_| {
        out_of_range(
            Argon2Axis::P,
            p_wide,
            ARGON2_MIN_P_COST,
            limits.argon2_max_p,
        )
    })?;
    if !(ARGON2_MIN_T_COST..=t_max).contains(&t) {
        return Err(out_of_range(
            Argon2Axis::T,
            t.into(),
            ARGON2_MIN_T_COST,
            t_max,
        ));
    }
    // `max_m_kib` is the caller's, not this function's, and that asymmetry is
    // the point: `decrypt` passes `ARGON2_MAX_M_COST_KIB_READ` because a
    // manifest chose the number and is acted on before any password is
    // verified; `encrypt` passes `..._WRITE`, the field's own width, because
    // the caller chose to spend their own memory. This function cannot know
    // which threat model it is in. Its callers can.
    if !(ARGON2_MIN_M_COST_KIB..=m_max).contains(&m) {
        return Err(out_of_range(
            Argon2Axis::MKib,
            m.into(),
            ARGON2_MIN_M_COST_KIB,
            m_max,
        ));
    }
    // Both: ours (a judgement about untrusted input, overridable) and argon2's
    // (what the cipher can run, not overridable). The one that is tighter is
    // the one named, so the reason says whose rule it actually was.
    let p_max = limits.argon2_max_p.min(Params::MAX_P_COST);
    if !(ARGON2_MIN_P_COST..=p_max).contains(&p) {
        return Err(
            if p > Params::MAX_P_COST && Params::MAX_P_COST <= limits.argon2_max_p {
                argon2_rejects(
                    ManifestField::Argon2(Argon2Axis::P),
                    p.into(),
                    ARGON2_MIN_P_COST.into(),
                    Params::MAX_P_COST.into(),
                )
            } else {
                out_of_range(
                    Argon2Axis::P,
                    p.into(),
                    ARGON2_MIN_P_COST,
                    limits.argon2_max_p,
                )
            },
        );
    }
    // argon2's own two requirements a manifest can break, checked here so the
    // KDF never starts and so its message is never passed through: at least
    // 8 KiB per lane (`params.rs`'s `m_cost < p_cost * 8`), and a salt of at
    // least `MIN_SALT_LEN` bytes, which nothing screened before (libargon2,
    // which LibreOffice links, has the same 8-byte floor).
    if u64::from(m) < 8 * u64::from(p) {
        return Err(argon2_rejects(
            ManifestField::Argon2(Argon2Axis::MKib),
            m.into(),
            8 * i64::from(p),
            m_max.into(),
        ));
    }
    if !(argon2::MIN_SALT_LEN..=argon2::MAX_SALT_LEN).contains(&salt.len()) {
        return Err(argon2_rejects(
            ManifestField::SaltLen,
            wide(salt.len()),
            wide(argon2::MIN_SALT_LEN),
            wide(argon2::MAX_SALT_LEN),
        ));
    }
    let params = Params::new(m, t, p, Some(out.len())).map_err(argon2_internal)?;

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

    let lanes = params.p_cost() as usize;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // A move: the box takes the Vec's header, and the block buffer behind it,
    // filled once at its final size above, is the one the wrapper wipes.
    let mut blocks = Dynamic::<Vec<Block>>::new(blocks);
    on_lane_threads(lanes, || {
        blocks.with_secret_mut(|b| {
            argon2.hash_password_into_with_memory(start_key, salt, out, b.as_mut_slice())
        })
    })?
    .map_err(argon2_internal)
}

/// The stack each Argon2 lane thread asks for: `std`'s own default, named so
/// [`KdfError::HostCannotSpawn`] can say what was refused.
const LANE_THREAD_STACK: usize = 2 * 1024 * 1024;

/// Run `hash` on a thread pool built for this one call, with as many threads
/// as there are lanes, up to the host's parallelism. argon2 0.6's `parallel`
/// feature fills each slice's lanes with `into_par_iter`
/// (`memory.rs:57`), on whichever rayon pool it is running in.
///
/// **Never rayon's global pool.** Its first use builds it, and a host that
/// cannot spawn its threads makes that a panic, not an error. A local pool's
/// `build` returns a `Result` instead. That is the no-panic rule: rayon is a
/// dependency, but this crate chooses which of its doors to use.
///
/// The pool is dropped when the call returns, so a library leaves no threads
/// behind. Spawning per call costs microseconds against a KDF that is tuned to
/// take tens of milliseconds. `use_current_thread` would avoid the spawn, but
/// rayon documents that a local pool built with it leaks its registry.
///
/// If `lanes` threads cannot be spawned, one is tried; if that fails too, it
/// is [`KdfError::HostCannotSpawn`]. One thread computes the same output as
/// many, only slower.
fn on_lane_threads<T: Send>(lanes: usize, hash: impl FnOnce() -> T + Send) -> Result<T, KdfError> {
    let cores = std::thread::available_parallelism().map_or(1, usize::from);
    let want = lanes.clamp(1, cores);
    let pool = |n: usize| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .stack_size(LANE_THREAD_STACK)
            .build()
    };
    let pool = pool(want)
        .or_else(|_| pool(1))
        .map_err(|_| KdfError::HostCannotSpawn {
            requested_bytes: LANE_THREAD_STACK,
        })?;
    Ok(pool.install(hash))
}

/// An `argon2::Error` the checks in [`derive_argon2id`] leave reachable only
/// through an invariant of ours, named by variant. Its own message is never
/// passed through.
fn argon2_internal(e: argon2::Error) -> KdfError {
    KdfError::Internal(match e {
        argon2::Error::OutputTooShort | argon2::Error::OutputTooLong => {
            "argon2 refused the derived key length"
        }
        argon2::Error::PwdTooLong | argon2::Error::SecretTooLong => {
            "argon2 refused the start key's length"
        }
        argon2::Error::SaltTooShort | argon2::Error::SaltTooLong => {
            "argon2 refused a salt length the screen passed"
        }
        argon2::Error::MemoryTooLittle | argon2::Error::MemoryTooMuch => {
            "argon2 refused a memory cost the screen passed"
        }
        _ => "argon2 refused parameters the screen passed",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(msg: &[u8]) -> Vec<u8> {
        staroffice_sha1(msg).with_secret(|d| d.to_vec())
    }

    fn msg(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + 3) as u8).collect()
    }

    /// Vectors from `tests/goldens/sha1_star.py`'s `staroffice_sha1`, the
    /// reference model, on the same `(i * 7 + 3) & 0xFF` messages its self-test
    /// uses. 52..=55 mod 64 are inside the window, at one and two blocks.
    #[test]
    fn staroffice_sha1_matches_the_reference_model_inside_the_window() {
        for (n, want) in [
            (52, "e43b7c9b5d04760bc10659c3b67558bf2ca2fb39"),
            (55, "c61212f6827fa5ee15e4b421ce9e81ae554c3e84"),
            (116, "7ad0ef8d27d013d9df5c9f4ffc2f24e6ef9b8ca6"),
            (119, "cf36aca5f9366e17bf93f4f4b7cc205a6873c2dd"),
        ] {
            let got: String = digest(&msg(n)).iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(got, want, "len {n}");
            assert_ne!(digest(&msg(n)), Sha1::digest(msg(n)).to_vec(), "len {n}");
        }
    }

    /// And it *is* SHA-1 everywhere else, which is what makes the window the
    /// only place the rungs differ.
    #[test]
    fn staroffice_sha1_is_sha1_outside_the_window() {
        for n in (0..200).filter(|n| !(52..=55).contains(&(n % 64))) {
            assert_eq!(digest(&msg(n)), Sha1::digest(msg(n)).to_vec(), "len {n}");
        }
    }

    #[test]
    fn the_rungs_are_distinct_for_a_password_built_to_separate_them() {
        // 52 chars, one of them outside ASCII: UTF-8 is 53 bytes and MS-1252 is
        // 52, both inside the window (the OQ1 probe's construction).
        let pw = format!("{}\u{e4}", "x".repeat(51));
        let mut keys: Vec<Vec<u8>> = SHA1_LADDER
            .iter()
            .map(|&r| legacy_start_key(&pw, r).with_secret(|d| d.to_vec()))
            .collect();
        keys.push(start_key(&pw, StartKeyAlg::Sha1).with_secret(|d| d.to_vec()));
        let n = keys.len();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), n);
    }

    /// Known answers from libargon2, the reference implementation LibreOffice
    /// links, through argon2-cffi 25's `hash_secret_raw` (Argon2id, v0x13, no
    /// secret or associated data -- the shape ODF uses). Several lanes in each,
    /// so the parallel fill is what is being checked, at LibreOffice's own
    /// tuple among them.
    #[test]
    fn argon2id_matches_the_reference_implementation() {
        let start = b"start key bytes, 32 long........";
        let salt = b"saltsaltsaltsalt";
        let limits = crate::DecryptLimits::default();
        for (t, m, p, want) in [
            (
                2,
                256,
                4,
                "a4022fe20744a918661506e69a8cd366d894c11359ce49ffec42c75caa26ffc5",
            ),
            (
                3,
                65536,
                4,
                "cb0e4d45be1b5338783f5f3fea374cd1a705e6d84131e3a7930cadcdd3074677",
            ),
            (
                1,
                64,
                8,
                "26c3f9dd5063a88489e501c23dc687ee72a57fc141b8069237a5e6c2d1956603",
            ),
        ] {
            let mut out = [0u8; 32];
            derive_argon2id(start, salt, t, m, p, &limits, &mut out).unwrap();
            let got: String = out.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(got, want, "(t, m, p) = ({t}, {m}, {p})");
        }
    }

    /// The fallback is a one-thread pool, so one thread must compute what many
    /// do. Run directly on pools of 1 and 8 threads: same lanes, same bytes.
    #[test]
    fn one_lane_thread_derives_what_many_do() {
        let params = Params::new(256, 2, 8, Some(32)).unwrap();
        let run = |threads: usize| {
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
            let mut blocks = vec![Block::default(); params.block_count()];
            let mut out = [0u8; 32];
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
                    argon2.hash_password_into_with_memory(
                        b"pw",
                        b"saltsaltsaltsalt",
                        &mut out,
                        &mut blocks,
                    )
                })
                .unwrap();
            out
        };
        assert_eq!(run(1), run(8));
    }
}
