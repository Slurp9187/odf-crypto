//! Streaming primitives: every cipher and codec `decrypt` and `encrypt` use,
//! reworked to process a member in bounded chunks rather than as one buffer.
//!
//! Crate-private. The public `*_to` entry points (S3-S6 of
//! `docs/plans/odf-streaming-2026-10-15.md`) assemble these; nothing here
//! touches a zip or a manifest.
//!
//! # Verify before release
//!
//! Each reader here releases plaintext only once LibreOffice would have
//! accepted the member (plan §2):
//!
//! - **GCM** is checked in a separate pass over the ciphertext ([`GcmStream::absorb`])
//!   before any [`GcmDecryptReader`] exists. The reader recomputes the tag as it
//!   goes and fails at the end if the input changed between the two passes.
//! - **CBC and Blowfish** go through [`ChecksumGate`], which holds back the
//!   first 1024 bytes of deflated plaintext until their SHA-1/SHA-256 digest
//!   matches -- the window LibreOffice checks, and the only one it checks.
//!
//! # Secrets
//!
//! Every buffer that ever holds plaintext, deflated or not, is allocated once
//! at its final size, fallibly, as a `secure-gate` `Dynamic<[u8]>` that wipes
//! it on drop. A boxed slice cannot grow, so no reallocation can abandon an
//! unwiped copy -- by construction, not by care. 16-byte secrets are `Fixed`.
//! The cipher states use their crates' `zeroize` features.
//!
//! **Named residual (plan §5, the #39 class).** miniz's `DecompressorOxide` and
//! `CompressorOxide` keep internal state derived from the plaintext -- Huffman
//! tables for the first, the LZ dictionary and hash chains for the second. Neither
//! type offers a way to wipe it, and `unsafe_code = "forbid"` rules out doing it
//! from outside. A consumer that must close this installs a zero-on-dealloc
//! global allocator.

use std::io::{self, Read, Write};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, InnerIvInit, KeyInit, StreamCipher};
use aes::{Aes128, Aes192, Aes256};
use blowfish::Blowfish;
use cbc::cipher::{BlockDecryptMut, KeyIvInit as CbcKeyIvInit};
use cfb_mode::BufDecryptor;
use ctr::{flavors, Ctr32BE, CtrCore};
use ghash::universal_hash::UniversalHash;
use ghash::GHash;
use miniz_oxide::deflate::core::{
    compress, create_comp_flags_from_zip_params, CompressorOxide, TDEFLFlush, TDEFLStatus,
};
use miniz_oxide::inflate::core::{decompress, inflate_flags, DecompressorOxide};
use miniz_oxide::inflate::TINFLStatus;
use secure_gate::{Dynamic, Fixed, RevealSecret, RevealSecretMut};
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::limits::{AES_BLOCK_LEN, AES_GCM_IV_LEN, AES_GCM_TAG_LEN, CHECKSUM_WINDOW};
use crate::types::Checksum;

/// Bytes moved per step. Every buffer below is this size or smaller, so peak
/// memory does not depend on the member.
pub(crate) const CHUNK: usize = 64 * 1024;

/// The DEFLATE dictionary is 32 KiB. A wrapping output buffer must be a power
/// of two at least that large, and this is the smallest.
const INFLATE_WINDOW: usize = 32 * 1024;

/// A plaintext-bearing buffer: allocated once, wiped on drop, and **unable to
/// grow** -- a boxed slice has no `push` or `extend`, so an edit that tried to
/// grow one would not compile, rather than abandon an unwiped reallocation.
/// Heap-allocated, so a 64 KiB buffer is never an array moved on the stack.
pub(crate) type ChunkBuffer = Dynamic<[u8]>;

/// Failures a stream raises about the *member*, as opposed to an `io::Error`
/// from the caller's reader or writer. They travel through `io::Read` wrapped
/// in an `io::Error` and are recovered with [`Fault::take`].
#[derive(Debug)]
pub(crate) enum Fault {
    /// The checksum or GCM tag rejected the key.
    WrongPassword,
    /// The GCM tag matched in the verify pass and not in the release pass, so
    /// the input changed between them.
    Changed,
    /// A structural problem with the ciphertext, e.g. not a block multiple.
    BadParameters(crate::BadParameter),
    /// An invariant of ours that an earlier screen enforces (a key or IV
    /// length `screen_shape` already checked): not a property of the member.
    Internal(&'static str),
    /// Not valid DEFLATE, or not the declared length.
    Inflate(String),
    /// Inflating past the caller's output limit.
    OutputLimit,
    /// A buffer could not be allocated.
    Alloc(usize),
    /// The compressor refused its input. Not expected from miniz on any
    /// input; reported rather than assumed away.
    Deflate(String),
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fault::WrongPassword => f.write_str("wrong password"),
            Fault::Changed => f.write_str("input changed between passes"),
            Fault::BadParameters(b) => write!(f, "{b}"),
            Fault::Internal(s) => f.write_str(s),
            Fault::Inflate(s) => f.write_str(s),
            Fault::OutputLimit => f.write_str("output limit exceeded"),
            Fault::Alloc(n) => write!(f, "could not allocate {n} bytes"),
            Fault::Deflate(s) => write!(f, "deflate failed: {s}"),
        }
    }
}

impl std::error::Error for Fault {}

impl Fault {
    fn into_io(self) -> io::Error {
        io::Error::other(self)
    }

    /// Recover a `Fault` raised by a stream here. Anything else is the
    /// caller's I/O error and comes back unchanged.
    pub(crate) fn take(err: io::Error) -> Result<Fault, io::Error> {
        if !err.get_ref().is_some_and(|e| e.is::<Fault>()) {
            return Err(err);
        }
        let kind = err.kind();
        match err.into_inner() {
            Some(inner) => inner
                .downcast::<Fault>()
                .map(|f| *f)
                .map_err(|other| io::Error::new(kind, other)),
            None => Err(kind.into()),
        }
    }
}

/// A zeroed [`ChunkBuffer`] of exactly `n` bytes, allocated fallibly.
pub(crate) fn chunk_buffer(n: usize) -> Result<ChunkBuffer, Fault> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Fault::Alloc(n))?;
    // Capacity is secured, so this sets the length without reallocating, and
    // with length equal to capacity `into_boxed_slice` does not reallocate
    // either: the box takes over the one allocation made above.
    v.resize(n, 0);
    Ok(Dynamic::from(v.into_boxed_slice()))
}

/// Read until `buf` is full or the reader ends. `Ok(n < buf.len())` means the
/// reader ended.
fn read_full<R: Read + ?Sized>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Constant-time equality, for tags and digests.
pub(crate) fn ct_eq(got: &[u8], want: &[u8]) -> bool {
    if got.len() != want.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&a, &b) in got.iter().zip(want.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

// --- AES-GCM -----------------------------------------------------------------

/// CTR-32 over whichever AES the key length selects. NSS picks the variant from
/// the derived key's length, and so does `decrypt_aes_gcm`; this follows both.
enum Ctr {
    A128(Ctr32BE<Aes128>),
    A192(Ctr32BE<Aes192>),
    A256(Ctr32BE<Aes256>),
}

impl Ctr {
    fn apply(&mut self, buf: &mut [u8]) {
        match self {
            Ctr::A128(c) => c.apply_keystream(buf),
            Ctr::A192(c) => c.apply_keystream(buf),
            Ctr::A256(c) => c.apply_keystream(buf),
        }
    }
}

/// GHASH over a ciphertext that arrives in arbitrary pieces, with no AAD (ODF
/// passes none). Carries a partial block between calls; the partial block is
/// ciphertext, so it is not secret.
struct GhashStream {
    h: GHash,
    partial: [u8; 16],
    partial_len: usize,
    ct_len: u64,
}

impl GhashStream {
    fn update(&mut self, mut data: &[u8]) {
        self.ct_len += data.len() as u64;
        if self.partial_len > 0 {
            let take = (16 - self.partial_len).min(data.len());
            self.partial[self.partial_len..self.partial_len + take].copy_from_slice(&data[..take]);
            self.partial_len += take;
            data = &data[take..];
            if self.partial_len < 16 {
                return;
            }
            self.h.update(&[*GenericArray::from_slice(&self.partial)]);
            self.partial_len = 0;
        }
        let whole = data.len() - data.len() % 16;
        for block in data[..whole].as_chunks::<16>().0 {
            self.h.update(&[*GenericArray::from_slice(block)]);
        }
        let rest = &data[whole..];
        self.partial[..rest.len()].copy_from_slice(rest);
        self.partial_len = rest.len();
    }

    /// GHASH(H, {}, C): the padded tail, then the length block -- 0 bits of
    /// AAD, then the ciphertext length in bits, both big-endian 64-bit.
    fn finalize(mut self) -> [u8; 16] {
        if self.partial_len > 0 {
            self.h.update_padded(&self.partial[..self.partial_len]);
        }
        let mut lengths = [0u8; 16];
        lengths[8..].copy_from_slice(&(self.ct_len * 8).to_be_bytes());
        self.h.update(&[*GenericArray::from_slice(&lengths)]);
        self.h.finalize().into()
    }
}

/// AES-GCM with a 96-bit IV and no AAD, the only shape ODF writes, processed
/// in pieces. `aes-gcm` 0.10 offers only whole-buffer calls, so this composes
/// the same crates it is built from -- `aes`, `ctr`, `ghash` -- and is proved
/// against it in `stream_tests.rs`.
///
/// The construction (NIST SP 800-38D, §7): `J0 = IV || 0^31 || 1`; the data
/// is CTR-32 from `J0 + 1`; the tag is `GHASH(H, {}, C) xor E(K, J0)` with
/// `H = E(K, 0^128)`.
pub(crate) struct GcmStream {
    ctr: Ctr,
    ghash: GhashStream,
    /// `E(K, J0)`. Keystream, so key-derived; wiped on drop.
    tag_mask: Fixed<[u8; 16]>,
}

impl GcmStream {
    /// `None` if `key` is not 16, 24 or 32 bytes or `iv` is not 12.
    pub(crate) fn new(key: &[u8], iv: &[u8]) -> Option<Self> {
        if iv.len() != AES_GCM_IV_LEN {
            return None;
        }
        let mut j0 = GenericArray::default();
        j0[..AES_GCM_IV_LEN].copy_from_slice(iv);
        j0[15] = 1;
        let mut h = GenericArray::default();
        let ctr = match key.len() {
            16 => {
                let c = Aes128::new_from_slice(key).ok()?;
                c.encrypt_block(&mut h);
                Ctr::A128(Ctr32BE::from_core(
                    CtrCore::<_, flavors::Ctr32BE>::inner_iv_init(c, &j0),
                ))
            }
            24 => {
                let c = Aes192::new_from_slice(key).ok()?;
                c.encrypt_block(&mut h);
                Ctr::A192(Ctr32BE::from_core(
                    CtrCore::<_, flavors::Ctr32BE>::inner_iv_init(c, &j0),
                ))
            }
            32 => {
                let c = Aes256::new_from_slice(key).ok()?;
                c.encrypt_block(&mut h);
                Ctr::A256(Ctr32BE::from_core(
                    CtrCore::<_, flavors::Ctr32BE>::inner_iv_init(c, &j0),
                ))
            }
            _ => return None,
        };
        let ghash = GhashStream {
            h: GHash::new(&h),
            partial: [0; 16],
            partial_len: 0,
            ct_len: 0,
        };
        h.iter_mut().for_each(|b| *b = 0);
        let mut stream = GcmStream {
            ctr,
            ghash,
            tag_mask: Fixed::new([0; 16]),
        };
        // The counter starts at J0: its first block of keystream is the tag
        // mask, and the data begins at J0 + 1.
        let ctr = &mut stream.ctr;
        stream.tag_mask.with_secret_mut(|m| ctr.apply(m));
        Some(stream)
    }

    /// Hash ciphertext without decrypting it: the verify pass.
    pub(crate) fn absorb(&mut self, ciphertext: &[u8]) {
        self.ghash.update(ciphertext);
    }

    /// Hash `buf` as ciphertext, then decrypt it in place.
    pub(crate) fn decrypt(&mut self, buf: &mut [u8]) {
        self.ghash.update(buf);
        self.ctr.apply(buf);
    }

    /// Encrypt `buf` in place, then hash the ciphertext.
    pub(crate) fn encrypt(&mut self, buf: &mut [u8]) {
        self.ctr.apply(buf);
        self.ghash.update(buf);
    }

    pub(crate) fn tag(self) -> [u8; AES_GCM_TAG_LEN] {
        let GcmStream {
            ghash, tag_mask, ..
        } = self;
        let mut tag = ghash.finalize();
        tag_mask.with_secret(|m| {
            for (t, m) in tag.iter_mut().zip(m) {
                *t ^= m;
            }
        });
        tag
    }
}

/// The verify pass: hash `ct_len` bytes of ciphertext from `r`, then read the
/// 16-byte tag after them and compare in constant time. Nothing is decrypted.
pub(crate) fn gcm_verify<R: Read>(
    key: &[u8],
    iv: &[u8],
    r: &mut R,
    ct_len: u64,
) -> io::Result<bool> {
    let mut gcm = GcmStream::new(key, iv)
        .ok_or_else(|| Fault::Internal("an AES-GCM key length the screen passed").into_io())?;
    // Ciphertext is not secret, but the buffer is the same size as the others
    // and reusing the type costs nothing.
    let mut buf = vec![0u8; CHUNK.min(ct_len as usize).max(AES_GCM_TAG_LEN)];
    let mut left = ct_len;
    while left > 0 {
        let want = (left as usize).min(buf.len());
        if read_full(r, &mut buf[..want])? != want {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        gcm.absorb(&buf[..want]);
        left -= want as u64;
    }
    let mut want_tag = [0u8; AES_GCM_TAG_LEN];
    if read_full(r, &mut want_tag)? != AES_GCM_TAG_LEN {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(ct_eq(&gcm.tag(), &want_tag))
}

/// The release pass: decrypt `ct_len` bytes of ciphertext from `src`, then
/// check the tag that follows them again. A mismatch at the end is
/// [`Fault::Changed`], because [`gcm_verify`] already accepted it once.
pub(crate) struct GcmDecryptReader<R> {
    src: R,
    /// `None` once the tag has been checked.
    gcm: Option<GcmStream>,
    left: u64,
}

impl<R: Read> GcmDecryptReader<R> {
    pub(crate) fn new(src: R, gcm: GcmStream, ct_len: u64) -> Self {
        Self {
            src,
            gcm: Some(gcm),
            left: ct_len,
        }
    }
}

impl<R: Read> Read for GcmDecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            let Some(gcm) = self.gcm.take() else {
                return Ok(0);
            };
            let mut want = [0u8; AES_GCM_TAG_LEN];
            if read_full(&mut self.src, &mut want)? != AES_GCM_TAG_LEN {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            if !ct_eq(&gcm.tag(), &want) {
                return Err(Fault::Changed.into_io());
            }
            return Ok(0);
        }
        let Some(gcm) = self.gcm.as_mut() else {
            return Ok(0);
        };
        let want = (self.left.min(out.len() as u64)) as usize;
        let n = self.src.read(&mut out[..want])?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        gcm.decrypt(&mut out[..n]);
        self.left -= n as u64;
        Ok(n)
    }
}

/// The write side of [`GcmStream`]: plaintext in, ciphertext out to `dst`, a
/// chunk at a time. [`GcmEncryptWriter::finish`] writes the tag after the last
/// chunk and must be called.
///
/// What arrives here is deflated plaintext. It is copied into a wiped
/// [`ChunkBuffer`] and encrypted there, so the only plaintext this type ever
/// holds is inside that buffer.
pub(crate) struct GcmEncryptWriter<W: Write> {
    dst: W,
    gcm: GcmStream,
    buf: ChunkBuffer,
}

impl<W: Write> GcmEncryptWriter<W> {
    pub(crate) fn new(dst: W, gcm: GcmStream) -> Result<Self, Fault> {
        Ok(Self {
            dst,
            gcm,
            buf: chunk_buffer(CHUNK)?,
        })
    }

    /// Write the tag and return the inner writer.
    pub(crate) fn finish(self) -> io::Result<W> {
        let GcmEncryptWriter { mut dst, gcm, .. } = self;
        dst.write_all(&gcm.tag())?;
        Ok(dst)
    }
}

impl<W: Write> Write for GcmEncryptWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let n = data.len().min(CHUNK);
        let (gcm, dst) = (&mut self.gcm, &mut self.dst);
        self.buf.with_secret_mut(|b| {
            b[..n].copy_from_slice(&data[..n]);
            gcm.encrypt(&mut b[..n]);
            dst.write_all(&b[..n])
        })?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.dst.flush()
    }
}

// --- CBC and Blowfish, behind the 1K checksum gate ---------------------------

enum CbcDec {
    A128(cbc::Decryptor<Aes128>),
    A192(cbc::Decryptor<Aes192>),
    A256(cbc::Decryptor<Aes256>),
}

impl CbcDec {
    fn decrypt_blocks(&mut self, buf: &mut [u8]) {
        macro_rules! run {
            ($d:expr, $aes:ty) => {
                for block in buf.chunks_exact_mut(AES_BLOCK_LEN) {
                    $d.decrypt_block_mut(cbc::cipher::Block::<$aes>::from_mut_slice(block));
                }
            };
        }
        match self {
            CbcDec::A128(d) => run!(d, Aes128),
            CbcDec::A192(d) => run!(d, Aes192),
            CbcDec::A256(d) => run!(d, Aes256),
        }
    }
}

/// AES-CBC with PKCS#7 padding, decrypted a chunk at a time. The last block is
/// always held back until the source ends, because only then is it known to
/// carry the padding.
pub(crate) struct CbcDecryptReader<R> {
    src: R,
    dec: CbcDec,
    buf: ChunkBuffer,
    /// `buf[start..end]` is decrypted plaintext not yet handed out.
    start: usize,
    end: usize,
    /// The held-back last block, decrypted.
    held: Fixed<[u8; AES_BLOCK_LEN]>,
    have_held: bool,
    finished: bool,
}

impl<R: Read> CbcDecryptReader<R> {
    pub(crate) fn new(src: R, key: &[u8], iv: &[u8]) -> Result<Self, Fault> {
        let bad = |_| Fault::Internal("an AES-CBC key or IV length the screen passed");
        let dec = match key.len() {
            16 => CbcDec::A128(cbc::Decryptor::new_from_slices(key, iv).map_err(bad)?),
            24 => CbcDec::A192(cbc::Decryptor::new_from_slices(key, iv).map_err(bad)?),
            32 => CbcDec::A256(cbc::Decryptor::new_from_slices(key, iv).map_err(bad)?),
            _ => return Err(Fault::Internal("an AES key length the screen passed")),
        };
        Ok(Self {
            src,
            dec,
            buf: chunk_buffer(CHUNK)?,
            start: 0,
            end: 0,
            held: Fixed::new([0; AES_BLOCK_LEN]),
            have_held: false,
            finished: false,
        })
    }

    /// Refill `buf` with the next chunk of plaintext, keeping the newest block
    /// back. Returns false once everything has been produced.
    fn refill(&mut self) -> io::Result<bool> {
        if self.finished {
            return Ok(false);
        }
        // Room for the previously held block in front of a fresh read.
        let held = self.have_held;
        let prev = &self.held;
        let src = &mut self.src;
        let dec = &mut self.dec;
        let (n, at_end) = self.buf.with_secret_mut(|b| -> io::Result<(usize, bool)> {
            let off = if held { AES_BLOCK_LEN } else { 0 };
            if held {
                prev.with_secret(|p| b[..AES_BLOCK_LEN].copy_from_slice(p));
            }
            let room = (b.len() - off) / AES_BLOCK_LEN * AES_BLOCK_LEN;
            let n = read_full(src, &mut b[off..off + room])?;
            if n % AES_BLOCK_LEN != 0 {
                return Err(Fault::BadParameters(crate::BadParameter::Member(crate::MemberFault::NotBlockMultiple)).into_io());
            }
            dec.decrypt_blocks(&mut b[off..off + n]);
            Ok((off + n, n < room))
        })?;
        if n == 0 {
            // An empty member, as the whole-buffer path also refuses.
            return Err(Fault::BadParameters(crate::BadParameter::Member(crate::MemberFault::NotBlockMultiple)).into_io());
        }
        self.start = 0;
        if at_end {
            // Everything is in: the last block carries the padding.
            let pad = self.buf.with_secret(|b| b[n - 1]) as usize;
            if !(1..=AES_BLOCK_LEN).contains(&pad) || n < pad {
                return Err(Fault::WrongPassword.into_io());
            }
            self.end = n - pad;
            self.have_held = false;
            self.finished = true;
        } else {
            self.end = n - AES_BLOCK_LEN;
            let held = &mut self.held;
            self.buf.with_secret(|b| {
                held.with_secret_mut(|h| h.copy_from_slice(&b[n - AES_BLOCK_LEN..n]))
            });
            self.have_held = true;
        }
        Ok(true)
    }
}

impl<R: Read> Read for CbcDecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.start == self.end {
            if !self.refill()? {
                return Ok(0);
            }
        }
        let n = (self.end - self.start).min(out.len());
        let start = self.start;
        self.buf
            .with_secret(|b| out[..n].copy_from_slice(&b[start..start + n]));
        self.start += n;
        Ok(n)
    }
}

/// Blowfish CFB-64, decrypted in place as it streams. No padding.
pub(crate) struct BlowfishDecryptReader<R> {
    src: R,
    dec: BufDecryptor<Blowfish>,
}

impl<R: Read> BlowfishDecryptReader<R> {
    pub(crate) fn new(src: R, key: &[u8], iv: &[u8]) -> Result<Self, Fault> {
        let dec = BufDecryptor::<Blowfish>::new_from_slices(key, iv)
            .map_err(|_| Fault::Internal("a Blowfish key or IV length the screen passed"))?;
        Ok(Self { src, dec })
    }
}

impl<R: Read> Read for BlowfishDecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.src.read(out)?;
        self.dec.decrypt(&mut out[..n]);
        Ok(n)
    }
}

/// Holds back the first [`CHECKSUM_WINDOW`] bytes of deflated plaintext until
/// they match the manifest's digest, then releases everything.
///
/// The same comparison as `decrypt::verify_checksum`, over the same bytes:
/// the first `min(len, 1024)` of the padding-stripped deflated stream.
/// [`Checksum::None`] passes, as it does upstream (`ZipFile.cxx:522`).
pub(crate) struct ChecksumGate<R> {
    src: R,
    checksum: Checksum,
    window: ChunkBuffer,
    /// `window[pos..len]` is verified and not yet handed out.
    pos: usize,
    len: usize,
    verified: bool,
}

impl<R: Read> ChecksumGate<R> {
    pub(crate) fn new(src: R, checksum: Checksum) -> Result<Self, Fault> {
        Ok(Self {
            src,
            checksum,
            window: chunk_buffer(CHECKSUM_WINDOW)?,
            pos: 0,
            len: 0,
            verified: false,
        })
    }

    /// Fill the window and check its digest, releasing nothing. `read` does
    /// this on first use; a caller that only wants to know whether a key is
    /// right calls it directly. Idempotent.
    pub(crate) fn verify(&mut self) -> io::Result<()> {
        if self.verified {
            return Ok(());
        }
        let src = &mut self.src;
        let len = self
            .window
            .with_secret_mut(|w| read_full(src, &mut w[..]))?;
        self.len = len;
        let ok = self.window.with_secret(|w| {
            let window = &w[..len];
            match &self.checksum {
                Checksum::Sha1_1K(want) => ct_eq(Sha1::digest(window).as_slice(), want),
                Checksum::Sha256_1K(want) => ct_eq(Sha256::digest(window).as_slice(), want),
                Checksum::None => true,
            }
        });
        if !ok {
            return Err(Fault::WrongPassword.into_io());
        }
        self.verified = true;
        Ok(())
    }
}

impl<R: Read> Read for ChecksumGate<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if !self.verified {
            self.verify()?;
        }
        if self.pos < self.len {
            let n = (self.len - self.pos).min(out.len());
            let pos = self.pos;
            self.window
                .with_secret(|w| out[..n].copy_from_slice(&w[pos..pos + n]));
            self.pos += n;
            return Ok(n);
        }
        self.src.read(out)
    }
}

// --- Inflate -------------------------------------------------------------------

/// Raw DEFLATE, inflated a chunk at a time into a wrapping 32 KiB window this
/// type owns, so the dictionary is ours to wipe.
///
/// Holds the same two post-conditions as `decrypt::inflate_into`: the stream
/// must reach its end marker, and it must inflate to exactly `expected` bytes.
/// It also stops at `limit`, the caller's output budget.
pub(crate) struct InflateReader<R> {
    src: R,
    dec: Box<DecompressorOxide>,
    input: ChunkBuffer,
    in_start: usize,
    in_end: usize,
    src_done: bool,
    window: ChunkBuffer,
    /// Where the next inflated byte goes in `window`.
    out_pos: usize,
    /// `window[pending..pending + pending_len]` is inflated, not yet handed out.
    pending: usize,
    pending_len: usize,
    produced: u64,
    expected: u64,
    limit: u64,
    done: bool,
}

impl<R: Read> InflateReader<R> {
    pub(crate) fn new(src: R, expected: u64, limit: u64) -> Result<Self, Fault> {
        Ok(Self {
            src,
            dec: Box::default(),
            input: chunk_buffer(CHUNK)?,
            in_start: 0,
            in_end: 0,
            src_done: false,
            window: chunk_buffer(INFLATE_WINDOW)?,
            out_pos: 0,
            pending: 0,
            pending_len: 0,
            produced: 0,
            expected,
            limit,
            done: false,
        })
    }

    fn step(&mut self) -> io::Result<()> {
        if self.in_start == self.in_end && !self.src_done {
            let src = &mut self.src;
            let n = self.input.with_secret_mut(|b| read_full(src, &mut b[..]))?;
            self.in_start = 0;
            self.in_end = n;
            self.src_done = n < CHUNK;
        }
        let flags = if self.src_done {
            0
        } else {
            inflate_flags::TINFL_FLAG_HAS_MORE_INPUT
        };
        let (in_start, in_end, out_pos) = (self.in_start, self.in_end, self.out_pos);
        let dec = &mut self.dec;
        let window = &mut self.window;
        let (status, consumed, written) = self.input.with_secret(|input| {
            window.with_secret_mut(|w| decompress(dec, &input[in_start..in_end], w, out_pos, flags))
        });
        self.in_start += consumed;
        self.pending = out_pos;
        self.pending_len = written;
        self.out_pos = (out_pos + written) & (INFLATE_WINDOW - 1);
        self.produced += written as u64;
        if self.produced > self.limit {
            return Err(Fault::OutputLimit.into_io());
        }
        if self.produced > self.expected {
            return Err(
                Fault::Inflate(format!("inflates past manifest:size {}", self.expected)).into_io(),
            );
        }
        match status {
            TINFLStatus::Done => {
                self.done = true;
                if self.produced != self.expected {
                    return Err(Fault::Inflate(format!(
                        "inflated {} != manifest:size {}",
                        self.produced, self.expected
                    ))
                    .into_io());
                }
            }
            TINFLStatus::HasMoreOutput => {}
            TINFLStatus::NeedsMoreInput => {
                if self.src_done && self.in_start == self.in_end && written == 0 {
                    return Err(Fault::Inflate("truncated DEFLATE stream".into()).into_io());
                }
            }
            other => return Err(Fault::Inflate(format!("{other:?}")).into_io()),
        }
        Ok(())
    }
}

impl<R: Read> Read for InflateReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pending_len == 0 {
            if self.done {
                return Ok(0);
            }
            self.step()?;
        }
        let n = self.pending_len.min(out.len());
        let at = self.pending;
        self.window
            .with_secret(|w| out[..n].copy_from_slice(&w[at..at + n]));
        self.pending += n;
        self.pending_len -= n;
        Ok(n)
    }
}

// --- Deflate -------------------------------------------------------------------

/// Raw DEFLATE at level 6 -- the level and framing of `encrypt::raw_deflate`
/// -- written to `dst` a chunk at a time. [`DeflateWriter::finish`] must be
/// called; dropping it without does not end the stream.
pub(crate) struct DeflateWriter<W: Write> {
    dst: W,
    comp: Box<CompressorOxide>,
    out: ChunkBuffer,
    consumed: u64,
}

impl<W: Write> DeflateWriter<W> {
    pub(crate) fn new(dst: W) -> Result<Self, Fault> {
        // `0` window bits: raw DEFLATE, no zlib header -- what `compress_to_vec`
        // passes, so the flags are identical.
        let flags = create_comp_flags_from_zip_params(6, 0, 0);
        Ok(Self {
            dst,
            comp: Box::new(CompressorOxide::new(flags)),
            out: chunk_buffer(CHUNK)?,
            consumed: 0,
        })
    }

    /// Uncompressed bytes accepted so far -- `manifest:size` once finished.
    pub(crate) fn consumed(&self) -> u64 {
        self.consumed
    }

    fn pump(&mut self, mut input: &[u8], flush: TDEFLFlush) -> io::Result<()> {
        loop {
            let comp = &mut self.comp;
            let (status, used, made) = self
                .out
                .with_secret_mut(|o| compress(comp, input, &mut o[..], flush));
            input = &input[used..];
            self.consumed += used as u64;
            let dst = &mut self.dst;
            self.out.with_secret(|o| dst.write_all(&o[..made]))?;
            match status {
                TDEFLStatus::Done => return Ok(()),
                TDEFLStatus::Okay => {
                    let finishing = matches!(flush, TDEFLFlush::Finish);
                    if input.is_empty() && made < CHUNK && !finishing {
                        return Ok(());
                    }
                    if used == 0 && made == 0 && !finishing {
                        return Err(Fault::Deflate("no progress".into()).into_io());
                    }
                }
                other => {
                    return Err(Fault::Deflate(format!("{other:?}")).into_io());
                }
            }
        }
    }

    /// End the DEFLATE stream and return the inner writer.
    pub(crate) fn finish(mut self) -> io::Result<W> {
        self.pump(&[], TDEFLFlush::Finish)?;
        Ok(self.dst)
    }
}

impl<W: Write> Write for DeflateWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pump(buf, TDEFLFlush::None)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.dst.flush()
    }
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;
