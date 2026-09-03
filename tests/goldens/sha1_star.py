"""StarOffice not-quite-SHA1, and the OQ1 measurement it settles.

LibreOffice derives four SHA-1 start-key candidates from a password and walks them as
a fallback ladder on read (`ZipPackageStream::getDataStream`, 1014-1070): correct and
StarOffice digests, over UTF-8 and MS-1252. Two of the four use `rtl_digest_SHA1`, which
is not SHA-1. From `sal/rtl/digest.cxx` `endSHA()`, with LibreOffice's own comment:

    // tdf#114939 NB: this is WRONG and should be ">" not ">=" but is not
    // fixed as this buggy SHA1 implementation is needed for compatibility
    if (i >= (DIGEST_LBLOCK_SHA - 2))

`i` is the word index just past the 0x80 terminator, so rtl emits one spurious
all-zero-padded block exactly when `len(msg) % 64` is in {52, 53, 54, 55}. Outside that
window it agrees with real SHA-1, which is why an ASCII `password` cannot tell the rungs
apart and `lo-odf11-nonascii-password.odt` exists.

Run it to re-derive the decrypt plan's OQ1 conclusion rather than taking it on trust:

    python sha1_star.py

Self-tests the implementation against hashlib, then decrypts the probe golden under each
rung. Exits non-zero if the implementation drifts or if the golden stops answering to the
correct UTF-8 SHA-1. Needs the same packages as ref_decrypt.py, which it imports for
manifest parsing: pip install cryptography argon2-cffi
"""

from __future__ import annotations

import hashlib
import io
import pathlib
import struct
import warnings
import zipfile

warnings.filterwarnings("ignore")

from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish
from cryptography.hazmat.primitives.ciphers import Cipher, modes

import ref_decrypt

MASK = 0xFFFFFFFF
WINDOW = {52, 53, 54, 55}  # len % 64 where rtl_digest_SHA1 diverges from SHA-1
HERE = pathlib.Path(__file__).resolve().parent
GOLDEN = "lo-odf11-nonascii-password.odt"


def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def _compress(h, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 80):
        w.append(_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
    a, b, c, d, e = h
    for i in range(80):
        if i < 20:
            f, k = (b & c) | (~b & MASK & d), 0x5A827999
        elif i < 40:
            f, k = b ^ c ^ d, 0x6ED9EBA1
        elif i < 60:
            f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
        else:
            f, k = b ^ c ^ d, 0xCA62C1D6
        a, b, c, d, e = (_rotl(a, 5) + f + e + k + w[i]) & MASK, a, _rotl(b, 30), c, d
    return [(x + y) & MASK for x, y in zip(h, (a, b, c, d, e))]


def _sha1(data: bytes, buggy: bool) -> bytes:
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    full = len(data) - len(data) % 64
    for off in range(0, full, 64):
        h = _compress(h, data[off:off + 64])
    tail = data[full:]
    blk = bytearray(tail) + b"\x80"
    i = (len(tail) >> 2) + 1                    # word index past the terminator
    limit = 14 if buggy else 15                 # rtl tests `i >= 14`; SHA-1 needs `i > 14`
    if i >= limit:
        h = _compress(h, bytes(blk).ljust(64, b"\x00"))
        blk = bytearray()
    h = _compress(h, bytes(blk).ljust(56, b"\x00") + struct.pack(">Q", len(data) * 8))
    return b"".join(struct.pack(">I", x) for x in h)


def staroffice_sha1(data: bytes) -> bytes:
    """`rtl_digest_SHA1` - PACKAGE_ENCRYPTIONDATA_SHA1UTF8 / ...SHA1MS1252."""
    return _sha1(data, buggy=True)


def selftest() -> bool:
    """Correct mode must equal hashlib everywhere; buggy mode must differ only in WINDOW."""
    ok = True
    for n in range(0, 200):
        msg = bytes((i * 7 + 3) & 0xFF for i in range(n))
        correct = hashlib.sha1(msg).digest()
        if _sha1(msg, False) != correct:
            print(f"  [FAIL] len {n}: correct mode disagrees with hashlib")
            ok = False
        if (staroffice_sha1(msg) != correct) != ((n % 64) in WINDOW):
            print(f"  [FAIL] len {n}: buggy mode diverges outside the window")
            ok = False
    print(f"  [{'PASS' if ok else 'FAIL'}] correct mode == hashlib for 0..199 B; "
          f"buggy mode diverges exactly on len%64 in {sorted(WINDOW)}")
    return ok


def oq1() -> bool:
    """Decrypt the probe golden under every rung of LibreOffice's SHA-1 ladder."""
    pw = ref_decrypt.NONASCII_PASSWORD
    u, w = pw.encode("utf-8"), pw.encode("cp1252")
    print(f"  password: {len(pw)} chars | UTF-8 {len(u)} B (%64={len(u) % 64}) | "
          f"MS-1252 {len(w)} B (%64={len(w) % 64})")
    if (len(u) % 64) not in WINDOW or (len(w) % 64) not in WINDOW:
        print("  [FAIL] password no longer lands both encodings in the window; "
              "the correct/StarOffice rungs are no longer distinguishable")
        return False

    z = zipfile.ZipFile(io.BytesIO((HERE / GOLDEN).read_bytes()))
    row = next(r for r in ref_decrypt._rows(z.read("META-INF/manifest.xml"))
               if r["path"] == "content.xml")
    blob = z.read("content.xml")

    candidates = [
        ("correct SHA-1(UTF-8)", hashlib.sha1(u).digest(), "Bugs::None - what this arc ships"),
        ("StarOffice SHA-1(UTF-8)", staroffice_sha1(u), "Bugs::WrongSHA1"),
        ("SHA-256(UTF-8)", hashlib.sha256(u).digest(), "rhbz#1013844 force-SHA256"),
        ("StarOffice SHA-1(MS-1252)", staroffice_sha1(w), "Bugs::WinEncodingWrongSHA1"),
        ("correct SHA-1(MS-1252)", hashlib.sha1(w).digest(), "not a rung; control"),
    ]
    if len({c[1] for c in candidates}) != len(candidates):
        print("  [FAIL] candidates are not all distinct")
        return False

    hits = []
    for label, start, note in candidates:
        key = hashlib.pbkdf2_hmac("sha1", start, row["salt"], row["iters"], row["dklen"])
        d = Cipher(Blowfish(key), modes.CFB(row["iv"])).decryptor()
        pt = d.update(blob) + d.finalize()
        hit = hashlib.sha1(pt[:1024]).digest() == row["digest"]
        print(f"  [{'MATCH' if hit else '  no '}] {label:26s} {start.hex()[:16]}...  {note}")
        if hit:
            hits.append(label)
    ok = hits == ["correct SHA-1(UTF-8)"]
    if ok:
        print(f"  [PASS] only the correct UTF-8 SHA-1 decrypts {GOLDEN}")
    else:
        print(f"  [FAIL] rungs that decrypt: {hits or 'none'}")
    return ok


def main() -> int:
    print("self-test")
    a = selftest()
    print(f"\nOQ1 ladder against {GOLDEN}")
    b = oq1()
    print("\n" + ("all checks passed" if a and b else "FAILED"))
    return 0 if a and b else 1


if __name__ == "__main__":
    raise SystemExit(main())
