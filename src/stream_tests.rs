//! S2 (#88): each streaming primitive against the whole-buffer code it
//! replaces, at lengths that straddle every chunk and block boundary.

use super::*;

use aes_gcm::aead::{AeadInPlace, KeyInit as AeadKeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm, Nonce};
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use cfb_mode::BufEncryptor;
use miniz_oxide::deflate::compress_to_vec;
use std::io::Cursor;

type Aes192Gcm = AesGcm<Aes192, aes_gcm::aead::consts::U12>;

/// Deterministic bytes, so a failure reproduces.
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Lengths around every boundary these streams have: empty, one block, the
/// 1 KiB window, a chunk, and a few bytes either side of each.
fn lengths() -> Vec<usize> {
    let mut out = vec![0, 1, 15, 16, 17, 1023, 1024, 1025, 1039, 1040, 1041];
    for k in 1..=3 {
        out.extend([
            k * CHUNK - 17,
            k * CHUNK - 1,
            k * CHUNK,
            k * CHUNK + 1,
            k * CHUNK + 17,
        ]);
    }
    out
}

/// A reader that hands out at most a few bytes per call, so every stream is
/// exercised on short reads, not only on full chunks.
struct Dribble<R> {
    inner: R,
    rng: XorShift,
}
impl<R: Read> Read for Dribble<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = 1 + self.rng.below(buf.len().clamp(1, 7000));
        let n = n.min(buf.len());
        self.inner.read(&mut buf[..n])
    }
}

fn drain<R: Read>(mut r: R) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    r.read_to_end(&mut out)?;
    Ok(out)
}

fn fault(err: io::Error) -> Fault {
    Fault::take(err).unwrap_or_else(|e| panic!("expected a Fault, got {e}"))
}

// --- GCM -----------------------------------------------------------------------

fn aead_seal(key: &[u8], iv: &[u8], pt: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let mut buf = pt.to_vec();
    let nonce = Nonce::from_slice(iv);
    let tag = match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .unwrap()
            .encrypt_in_place_detached(nonce, b"", &mut buf),
        24 => Aes192Gcm::new_from_slice(key)
            .unwrap()
            .encrypt_in_place_detached(nonce, b"", &mut buf),
        32 => Aes256Gcm::new_from_slice(key)
            .unwrap()
            .encrypt_in_place_detached(nonce, b"", &mut buf),
        _ => unreachable!(),
    }
    .unwrap();
    (buf, tag.into())
}

/// Same bytes and tag as `aes-gcm` itself, for every AES width, every length,
/// with the plaintext fed in uneven pieces.
#[test]
fn gcm_stream_matches_aes_gcm_both_ways() {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    for key_len in [16, 24, 32] {
        for len in lengths() {
            let key = rng.bytes(key_len);
            let iv = rng.bytes(12);
            let pt = rng.bytes(len);
            let (want_ct, want_tag) = aead_seal(&key, &iv, &pt);

            let mut enc = GcmStream::new(&key, &iv).unwrap();
            let mut ct = pt.clone();
            let mut at = 0;
            while at < ct.len() {
                let step = 1 + rng.below(3 * AES_BLOCK_LEN + 5).min(ct.len() - at - 1 + 1);
                let end = (at + step).min(ct.len());
                enc.encrypt(&mut ct[at..end]);
                at = end;
            }
            assert_eq!(ct, want_ct, "ciphertext, key {key_len}, len {len}");
            assert_eq!(enc.tag(), want_tag, "tag, key {key_len}, len {len}");

            let mut sealed = want_ct.clone();
            sealed.extend_from_slice(&want_tag);
            let verified = gcm_verify(&key, &iv, &mut Cursor::new(&sealed), len as u64).unwrap();
            assert!(verified, "verify, key {key_len}, len {len}");

            let reader = GcmDecryptReader::new(
                Dribble {
                    inner: Cursor::new(&sealed),
                    rng: XorShift(len as u64 + 1),
                },
                GcmStream::new(&key, &iv).unwrap(),
                len as u64,
            );
            assert_eq!(
                drain(reader).unwrap(),
                pt,
                "decrypt, key {key_len}, len {len}"
            );
        }
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// NIST GCM test cases 1, 3, 9 and 15 (the 96-bit-IV, no-AAD ones), from
/// McGrew & Viega, "The Galois/Counter Mode of Operation", Appendix B. Not
/// only `aes-gcm`'s word for it.
#[test]
fn gcm_stream_matches_the_nist_vectors() {
    let p = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
    let iv = "cafebabefacedbaddecaf888";
    let cases = [
        (
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a",
        ),
        (
            "feffe9928665731c6d6a8f9467308308",
            iv,
            p,
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
            "4d5c2af327cd64a62cf35abd2ba6fab4",
        ),
        (
            "feffe9928665731c6d6a8f9467308308feffe9928665731c",
            iv,
            p,
            "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c\
             7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
            "9924a7c8587336bfb118024db8674a14",
        ),
        (
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            iv,
            p,
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
            "b094dac5d93471bdec1a502270e3cc6c",
        ),
    ];
    for (k, iv, p, c, t) in cases {
        let mut buf = hex(p);
        let mut gcm = GcmStream::new(&hex(k), &hex(iv)).unwrap();
        gcm.encrypt(&mut buf);
        assert_eq!(buf, hex(c), "C for key {k}");
        assert_eq!(gcm.tag().to_vec(), hex(t), "T for key {k}");
    }
}

/// A changed ciphertext byte or tag byte fails the verify pass; nothing is
/// decrypted to find out.
#[test]
fn gcm_verify_rejects_any_flipped_bit() {
    let mut rng = XorShift(7);
    let (key, iv, pt) = (rng.bytes(32), rng.bytes(12), rng.bytes(3000));
    let (ct, tag) = aead_seal(&key, &iv, &pt);
    let mut sealed = ct;
    sealed.extend_from_slice(&tag);
    for at in [0, 1500, sealed.len() - 17, sealed.len() - 1] {
        let mut bad = sealed.clone();
        bad[at] ^= 0x01;
        let ok = gcm_verify(&key, &iv, &mut Cursor::new(&bad), 3000).unwrap();
        assert!(!ok, "flip at {at} passed");
    }
}

/// The release pass recomputes the tag: input that changed after the verify
/// pass is [`Fault::Changed`] at the end, not silently released.
#[test]
fn gcm_release_pass_reports_input_changed_between_passes() {
    let mut rng = XorShift(11);
    let (key, iv, pt) = (rng.bytes(16), rng.bytes(12), rng.bytes(2 * CHUNK + 5));
    let (ct, tag) = aead_seal(&key, &iv, &pt);
    let mut sealed = ct;
    sealed.extend_from_slice(&tag);
    assert!(gcm_verify(&key, &iv, &mut Cursor::new(&sealed), pt.len() as u64).unwrap());
    sealed[CHUNK + 3] ^= 0x80; // the "file" changes now
    let reader = GcmDecryptReader::new(
        Cursor::new(&sealed),
        GcmStream::new(&key, &iv).unwrap(),
        pt.len() as u64,
    );
    let err = drain(reader).unwrap_err();
    assert!(matches!(fault(err), Fault::Changed));
}

// --- CBC / Blowfish behind the gate ------------------------------------------

fn sha256_1k(deflated: &[u8]) -> Checksum {
    let window = &deflated[..deflated.len().min(CHECKSUM_WINDOW)];
    Checksum::Sha256_1K(Sha256::digest(window).to_vec())
}

fn cbc_seal(key: &[u8], iv: &[u8], pt: &[u8]) -> Vec<u8> {
    let pad = AES_BLOCK_LEN - pt.len() % AES_BLOCK_LEN;
    let mut buf = pt.to_vec();
    buf.extend(std::iter::repeat_n(pad as u8, pad));
    let mut enc = cbc::Encryptor::<Aes256>::new_from_slices(key, iv).unwrap();
    for block in buf.as_chunks_mut::<AES_BLOCK_LEN>().0 {
        enc.encrypt_block_mut(cbc::cipher::Block::<Aes256>::from_mut_slice(block));
    }
    buf
}

fn cbc_open(
    key: &[u8],
    iv: &[u8],
    ct: &[u8],
    checksum: Checksum,
    seed: u64,
) -> io::Result<Vec<u8>> {
    let src = Dribble {
        inner: Cursor::new(ct.to_vec()),
        rng: XorShift(seed),
    };
    let reader = CbcDecryptReader::new(src, key, iv).map_err(Fault::into_io)?;
    drain(ChecksumGate::new(reader, checksum).map_err(Fault::into_io)?)
}

/// Every length releases exactly the plaintext once the 1K digest matches, as
/// `decrypt_aes_cbc` + `verify_checksum` do over the whole buffer.
#[test]
fn cbc_reader_with_gate_matches_the_whole_buffer_result() {
    let mut rng = XorShift(23);
    for len in lengths() {
        let (key, iv, pt) = (rng.bytes(32), rng.bytes(16), rng.bytes(len));
        let ct = cbc_seal(&key, &iv, &pt);
        let got = cbc_open(&key, &iv, &ct, sha256_1k(&pt), len as u64 + 3).unwrap();
        assert_eq!(got, pt, "len {len}");
    }
}

/// A wrong key fails the gate before anything is released: the first `read`
/// returns the fault, so no plaintext byte reaches the caller.
#[test]
fn cbc_gate_releases_nothing_under_a_wrong_key() {
    let mut rng = XorShift(29);
    for len in [0, 100, 1024, 5000, 2 * CHUNK + 9] {
        let (key, iv, pt) = (rng.bytes(32), rng.bytes(16), rng.bytes(len));
        let ct = cbc_seal(&key, &iv, &pt);
        let mut wrong = key.clone();
        wrong[0] ^= 1;
        let reader = CbcDecryptReader::new(Cursor::new(ct), &wrong, &iv).unwrap();
        let mut gate = ChecksumGate::new(reader, sha256_1k(&pt)).unwrap();
        let mut first = [0u8; 1];
        let err = gate.read(&mut first).unwrap_err();
        assert!(matches!(fault(err), Fault::WrongPassword), "len {len}");
    }
}

/// Padding is checked on its own: with no checksum to fail first, a final
/// block whose pad byte is out of range is still a wrong key.
#[test]
fn cbc_reader_refuses_bad_padding_without_a_checksum() {
    let (key, iv) = ([7u8; 32], [9u8; 16]);
    for pad in [0u8, 17, 255] {
        let mut block = [0u8; AES_BLOCK_LEN];
        block[AES_BLOCK_LEN - 1] = pad;
        let mut enc = cbc::Encryptor::<Aes256>::new_from_slices(&key, &iv).unwrap();
        enc.encrypt_block_mut(cbc::cipher::Block::<Aes256>::from_mut_slice(&mut block));
        let reader = CbcDecryptReader::new(Cursor::new(block.to_vec()), &key, &iv).unwrap();
        let gate = ChecksumGate::new(reader, Checksum::None).unwrap();
        let err = drain(gate).unwrap_err();
        assert!(matches!(fault(err), Fault::WrongPassword), "pad {pad}");
    }
}

/// A ciphertext that is not a whole number of blocks is a parameter fault, as
/// in `decrypt_aes_cbc`.
#[test]
fn cbc_reader_refuses_a_partial_block() {
    let reader = CbcDecryptReader::new(Cursor::new(vec![0u8; 33]), &[0; 32], &[0; 16]).unwrap();
    assert!(matches!(
        fault(drain(reader).unwrap_err()),
        Fault::BadParameters(_)
    ));
}

#[test]
fn blowfish_reader_with_gate_matches_cfb64() {
    let mut rng = XorShift(31);
    for len in lengths() {
        let (key, iv, pt) = (rng.bytes(16), rng.bytes(8), rng.bytes(len));
        let mut ct = pt.clone();
        BufEncryptor::<Blowfish>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt(&mut ct);
        let src = Dribble {
            inner: Cursor::new(ct),
            rng: XorShift(len as u64 + 5),
        };
        let reader = BlowfishDecryptReader::new(src, &key, &iv).unwrap();
        let got = drain(ChecksumGate::new(reader, sha256_1k(&pt)).unwrap()).unwrap();
        assert_eq!(got, pt, "len {len}");
    }
}

/// `Checksum::None` passes, as `ZipFile.cxx:522` does upstream.
#[test]
fn gate_without_a_checksum_releases_everything() {
    let pt = XorShift(37).bytes(3000);
    let got = drain(ChecksumGate::new(Cursor::new(pt.clone()), Checksum::None).unwrap()).unwrap();
    assert_eq!(got, pt);
}

// --- Inflate / deflate ---------------------------------------------------------

/// Compressible and incompressible inputs, so both stored and Huffman blocks
/// and long back-references across the 32 KiB window are covered.
fn deflate_inputs() -> Vec<Vec<u8>> {
    let mut rng = XorShift(41);
    let mut out = Vec::new();
    for len in lengths() {
        out.push(rng.bytes(len));
        out.push((0..len).map(|i| b"odf-crypto streaming "[i % 21]).collect());
    }
    // A repeat 40 KiB back: farther than one window, nearer than two.
    let mut far = rng.bytes(40 * 1024);
    far.extend_from_within(..20 * 1024);
    out.push(far);
    out
}

#[test]
fn inflate_reader_matches_whole_buffer_inflate() {
    for (i, plain) in deflate_inputs().into_iter().enumerate() {
        let deflated = compress_to_vec(&plain, 6);
        let src = Dribble {
            inner: Cursor::new(deflated),
            rng: XorShift(i as u64 + 1),
        };
        let got = drain(InflateReader::new(src, plain.len() as u64, u64::MAX).unwrap()).unwrap();
        assert_eq!(got.len(), plain.len(), "input {i}");
        assert!(got == plain, "input {i}: bytes differ");
    }
}

/// The two post-conditions of `inflate_into`, and the output limit.
#[test]
fn inflate_reader_enforces_size_and_limit() {
    let plain: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let deflated = compress_to_vec(&plain, 6);
    let n = plain.len() as u64;
    let run = |expected: u64, limit: u64, input: &[u8]| {
        drain(InflateReader::new(Cursor::new(input.to_vec()), expected, limit).unwrap())
    };

    assert!(run(n, n, &deflated).is_ok(), "exact size, limit at size");
    assert!(matches!(
        fault(run(n - 1, u64::MAX, &deflated).unwrap_err()),
        Fault::Inflate(_)
    ));
    assert!(matches!(
        fault(run(n + 1, u64::MAX, &deflated).unwrap_err()),
        Fault::Inflate(_)
    ));
    assert!(matches!(
        fault(run(n, n - 1, &deflated).unwrap_err()),
        Fault::OutputLimit
    ));
    let cut = &deflated[..deflated.len() / 2];
    assert!(matches!(
        fault(run(n, u64::MAX, cut).unwrap_err()),
        Fault::Inflate(_)
    ));
}

/// Fed in uneven pieces, the writer emits the same bytes as
/// `compress_to_vec(_, 6)`. The per-entry rebuild's comparison with `zip`'s own
/// writer depends on it. Encrypt's payload has used the adaptive mode since
/// rc.15, so this no longer describes encrypt.
#[test]
fn deflate_writer_matches_compress_to_vec() {
    let mut rng = XorShift(43);
    for (i, plain) in deflate_inputs().into_iter().enumerate() {
        let mut w = DeflateWriter::new(Vec::new()).unwrap();
        let mut at = 0;
        while at < plain.len() {
            let end = (at + 1 + rng.below(3 * CHUNK)).min(plain.len());
            w.write_all(&plain[at..end]).unwrap();
            at = end;
        }
        assert_eq!(w.consumed(), plain.len() as u64);
        let got = w.finish().unwrap();
        assert!(
            got == compress_to_vec(&plain, 6),
            "input {i}: deflate bytes differ"
        );
    }
}

/// Text, then noise, then the same text: the third chunk's best matches are in
/// the first, across the stored noise the compressor never saw.
fn text_noise_text() -> Vec<u8> {
    let line = b"<text:p>odf-crypto adaptive deflate</text:p>\n";
    let text: Vec<u8> = (0..CHUNK).map(|i| line[i % line.len()]).collect();
    let mut plain = text.clone();
    plain.extend(XorShift(7).bytes(CHUNK));
    plain.extend(&text);
    plain
}

/// Inflated with miniz's own whole-buffer decoder: the reference, not ours.
fn inflate_ref(deflated: &[u8]) -> Vec<u8> {
    miniz_oxide::inflate::decompress_to_vec(deflated).unwrap()
}

/// Also pins `consumed` before `finish`, which both callers read for
/// `manifest:size` while a partial chunk may still be held.
fn adaptive(plain: &[u8], rng: &mut XorShift) -> Vec<u8> {
    let mut w = DeflateWriter::adaptive(Vec::new()).unwrap();
    let mut at = 0;
    while at < plain.len() {
        let end = (at + 1 + rng.below(3 * CHUNK)).min(plain.len());
        w.write_all(&plain[at..end]).unwrap();
        at = end;
    }
    assert_eq!(w.consumed(), plain.len() as u64);
    w.finish().unwrap()
}

/// Whatever mix of stored and compressed chunks it chooses, the adaptive
/// writer's output inflates to its input. The text-noise-text case is the one
/// a missing full flush breaks: without the dictionary reset, the third
/// chunk's matches point at the wrong bytes.
#[test]
fn adaptive_deflate_round_trips() {
    let mut rng = XorShift(44);
    let mut inputs = deflate_inputs();
    inputs.push(text_noise_text());
    inputs.push(XorShift(9).bytes(5 * CHUNK + 3));
    // The most switches: every chunk flips mode, so every stored chunk pays a
    // full flush on top of its block headers.
    let mut alternating = Vec::new();
    for _ in 0..8 {
        alternating.extend_from_slice(&text_noise_text()[..2 * CHUNK]);
    }
    inputs.push(alternating);
    for (i, plain) in inputs.into_iter().enumerate() {
        let got = adaptive(&plain, &mut rng);
        assert!(inflate_ref(&got) == plain, "input {i}: round trip differs");
        // Encrypt decides Zip64 from this bound before writing a byte, so the
        // adaptive mode's headers and flushes must stay inside it.
        assert!(
            got.len() as u64 <= crate::zip_stream::deflate_bound(plain.len() as u64),
            "input {i}: {} bytes exceed deflate_bound({})",
            got.len(),
            plain.len()
        );
    }
}

/// The decision itself: noise is stored, close to its own size and nowhere
/// near what level 6 spends on it, and text is still compressed.
#[test]
fn adaptive_deflate_stores_noise_and_compresses_text() {
    let mut rng = XorShift(45);
    let noise = XorShift(10).bytes(8 * CHUNK);
    let stored = adaptive(&noise, &mut rng);
    // A 64 KiB chunk is two stored blocks (65535 + 1 bytes), 5 header bytes
    // each, and the stream ends with a final empty block.
    assert!(
        stored.len() <= noise.len() + 2 * 5 * (noise.len() / CHUNK) + 8,
        "noise grew to {} from {}",
        stored.len(),
        noise.len()
    );
    // A stored block is the bytes themselves, so the output contains them.
    assert!(stored.windows(64).any(|w| w == &noise[..64]));
    let text = &text_noise_text()[..CHUNK];
    let squeezed = adaptive(text, &mut rng);
    assert!(squeezed.len() < text.len() / 10, "text was not compressed");
}

#[test]
fn fault_take_returns_foreign_errors_unchanged() {
    let err = Fault::take(io::Error::other("the caller's")).unwrap_err();
    assert_eq!(err.to_string(), "the caller's");
    assert!(matches!(
        Fault::take(Fault::Changed.into_io()),
        Ok(Fault::Changed)
    ));
}

/// The non-test code of `src/<name>`: comment lines dropped, and everything
/// from the file's `#[cfg(test)]` test-module hook on cut off.
fn code_of(name: &str, src: &str) -> String {
    let body = src
        .rsplit_once("#[cfg(test)]\n#[path")
        .map_or(src, |(code, _)| code);
    assert!(!body.is_empty(), "{name}");
    body.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// #39 and #51, held by source rather than by memory: every module that
/// touches plaintext or a member body.
///
/// - **#39**: no whole-buffer codec. `compress_to_vec` grew its output while
///   deflating the caller's document and abandoned each old block unwiped;
///   the inflate counterparts would do the same on the way out. Plaintext now
///   moves only through `ChunkBuffer`s, which are boxed slices and cannot
///   grow -- a type fact -- and `tests/streaming_memory.rs` measures that no
///   buffer grows with the payload.
/// - **#51**: every `read_to_end` reads through a `.take(..)` cap, so nothing
///   is sized by a length the package claims. The three that remain read the
///   manifest (8 MiB cap) and `mimetype` (1 KiB), never a member body.
///
/// What a scan cannot see, and the plan names instead: miniz's own compressor
/// and decompressor state, and copies the compiler makes on the stack.
#[test]
fn no_grown_plaintext_buffer_and_no_uncapped_read() {
    let sources = [
        ("classify.rs", include_str!("classify.rs")),
        ("decrypt.rs", include_str!("decrypt.rs")),
        ("decrypt_entries.rs", include_str!("decrypt_entries.rs")),
        ("decrypt_stream.rs", include_str!("decrypt_stream.rs")),
        ("encrypt.rs", include_str!("encrypt.rs")),
        ("encrypt_stream.rs", include_str!("encrypt_stream.rs")),
        ("reencrypt.rs", include_str!("reencrypt.rs")),
        ("stream.rs", include_str!("stream.rs")),
        ("zip_stream.rs", include_str!("zip_stream.rs")),
    ];
    let mut capped_reads = 0;
    for (name, src) in sources {
        let code = code_of(name, src);
        for codec in [
            "compress_to_vec",
            "decompress_to_vec",
            "decompress_slice_iter_to_slice",
        ] {
            assert!(!code.contains(codec), "{name} calls {codec}");
        }
        let lines: Vec<&str> = code.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.contains("read_to_end") {
                let window = lines[i.saturating_sub(3)..=i].join("\n");
                assert!(
                    window.contains(".take("),
                    "{name}: uncapped read_to_end:\n{window}"
                );
                capped_reads += 1;
            }
        }
    }
    assert_eq!(capped_reads, 3, "the manifest twice and mimetype once");
}
