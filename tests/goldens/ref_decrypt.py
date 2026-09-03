"""Reference `decrypt`, for cross-checking the Rust port.

Not a port target and not shipped. This is an independent second implementation of
[the decrypt plan](../../docs/plans/odf-encryption-decrypt-2026-09-02.md), used to
pre-validate a slice's close-when before the Rust exists and to diff against when a
slice disagrees with a golden. Steps cite the plan section they implement, so a
disagreement points at a paragraph rather than at a guess.

It has already earned its keep: the sweep below is what found that a member truncated
*past* the 1 KiB digest window decrypts "successfully" with a matching checksum, which
is why plan section 2 now enforces the deflate end marker and `manifest:size` instead of
calling the size a sanity check.

Needs two packages that are deliberately not crate dependencies:

    pip install cryptography argon2-cffi

    python ref_decrypt.py                      # sweep every golden + the S5 negatives
    python ref_decrypt.py FILE PASSWORD [OUT]  # decrypt one file

The sweep exits non-zero if any check fails.
"""

from __future__ import annotations

import base64
import hashlib
import io
import pathlib
import sys
import warnings
import zipfile
import zlib
from xml.etree import ElementTree as ET

warnings.filterwarnings("ignore")  # cryptography's Blowfish/CFB deprecation notices

from argon2.low_level import ARGON2_VERSION, Type, hash_secret_raw
from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

M = "{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}"
L = "{urn:org:documentfoundation:names:experimental:office:xmlns:loext:1.0}"
ET.register_namespace("manifest", M[1:-1])
ET.register_namespace("loext", L[1:-1])

INFLATE_CEILING = 1 << 30  # plan section 2: never preallocate from manifest:size
HERE = pathlib.Path(__file__).resolve().parent
PASSWORD = "password"
NONASCII_PASSWORD = "äbcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP"


class NotEncrypted(Exception): pass
class EmptyPassword(Exception): pass
class UnsupportedPgp(Exception): pass
class WrongPassword(Exception): pass
class BadParameters(Exception): pass
class Inflate(Exception): pass


def _rows(manifest_xml):
    """The complete-tuple rows `classify` would return, password path only."""
    out = []
    for fe in ET.fromstring(manifest_xml).findall(M + "file-entry"):
        ed = fe.find(M + "encryption-data")
        if ed is None:
            continue
        alg, kd = ed.find(M + "algorithm"), ed.find(M + "key-derivation")
        sk = ed.find(M + "start-key-generation")
        kdf_name = kd.get(M + "key-derivation-name")
        out.append(dict(
            path=fe.get(M + "full-path"),
            size=int(fe.get(M + "size")),
            cipher=alg.get(M + "algorithm-name"),
            iv=base64.b64decode(alg.get(M + "initialisation-vector")),
            kdf=kdf_name,
            salt=base64.b64decode(kd.get(M + "salt")),
            iters=int(kd.get(M + "iteration-count")) if kd.get(M + "iteration-count") else None,
            argon=(int(kd.get(L + "argon2-iterations")), int(kd.get(L + "argon2-memory")),
                   int(kd.get(L + "argon2-lanes"))) if "argon2id" in kdf_name else None,
            dklen=int(kd.get(M + "key-size")) if kd.get(M + "key-size") else 16,
            start=(sk.get(M + "start-key-generation-name") if sk is not None
                   else "http://www.w3.org/2000/09/xmldsig#sha1"),
            digest=base64.b64decode(ed.get(M + "checksum")) if ed.get(M + "checksum") else None,
            dalg=ed.get(M + "checksum-type")))
    return out


def _start_key(row, password):
    """plan section 2, Start key. Correct UTF-8 only - OQ1 measured that is what LO writes."""
    if row["start"].endswith("sha256"):
        return hashlib.sha256(password.encode()).digest()
    return hashlib.sha1(password.encode()).digest()


def _derive(row, password):
    """plan section 2, KDF."""
    start, n = _start_key(row, password), row["dklen"]
    if n <= 0:
        raise BadParameters("derived_key_len %r" % n)
    if row["argon"]:
        t, m, p = row["argon"]  # RustCrypto Params::new takes (m, t, p); m is KiB
        try:
            return hash_secret_raw(secret=start, salt=row["salt"], time_cost=t, memory_cost=m,
                                   parallelism=p, hash_len=n, type=Type.ID, version=ARGON2_VERSION)
        except Exception as e:
            raise BadParameters("argon2: %s" % e) from None
    if row["iters"] is None or row["iters"] <= 0:
        raise BadParameters("iterations %r" % row["iters"])
    return hashlib.pbkdf2_hmac("sha1", start, row["salt"], row["iters"], n)


def _decrypt_member(row, key, blob):
    """Still-compressed plaintext. The cipher selects the verifier (plan section 2)."""
    c = row["cipher"]
    if "gcm" in c:
        if len(row["iv"]) != 12:
            raise BadParameters("GCM IV length")
        if len(blob) <= 12 + 16:
            raise BadParameters("shorter than IV+tag")          # ciphercontext.cxx:296
        if blob[:12] != row["iv"]:
            raise BadParameters("inconsistent IV")              # ciphercontext.cxx:277
        try:
            return AESGCM(key).decrypt(row["iv"], blob[12:], None)
        except Exception:
            raise WrongPassword("GCM tag") from None
    if "cbc" in c:
        if len(row["iv"]) != 16:
            raise BadParameters("CBC IV length")
        if len(blob) == 0 or len(blob) % 16:
            raise BadParameters("not a block multiple")         # ciphercontext.cxx:311
        d = Cipher(algorithms.AES(key), modes.CBC(row["iv"])).decryptor()
        pt = d.update(blob) + d.finalize()
        pad = pt[-1]
        if not 1 <= pad <= 16:                                  # W3C / ISO 10126
            raise WrongPassword("W3C pad byte")
        pt = pt[:-pad]
    else:
        if len(row["iv"]) != 8:
            raise BadParameters("Blowfish IV length")
        # 64-bit-segment CFB, not CFB-8: sal BF_updateCFB / EVP_bf_cfb.
        d = Cipher(Blowfish(key), modes.CFB(row["iv"])).decryptor()
        pt = d.update(blob) + d.finalize()
    want = row["digest"]
    hasher = hashlib.sha256 if "sha256" in (row["dalg"] or "") else hashlib.sha1
    if want is not None and hasher(pt[:1024]).digest() != want:  # ZipFile.cxx:482-534
        raise WrongPassword("checksum")
    return pt


def _inflate(pt, row):
    """plan section 2: raw DEFLATE, then both post-conditions."""
    d = zlib.decompressobj(-15)                                  # InflateZlib(true)
    try:
        out = d.decompress(pt, INFLATE_CEILING)
    except zlib.error as e:
        raise Inflate(str(e)) from None
    if d.unconsumed_tail:
        raise Inflate("exceeds ceiling")
    if not d.eof:
        raise Inflate("deflate stream did not end")              # truncation past the digest window
    if len(out) != row["size"]:
        raise Inflate("inflated %d != manifest:size %d" % (len(out), row["size"]))
    return out


def _member_for(names, path):
    """plan section 6.5: an EntryEncryption path is a tree path, not a namelist key."""
    def collapse(n):
        out, prev = [], False
        for ch in n:
            if ch == "/":
                if not prev:
                    out.append(ch)
                prev = True
            else:
                out.append(ch)
                prev = False
        return "".join(out)
    for n in names:
        if n == path or collapse(n) == path:
            return n
    raise BadParameters("row path %r has no zip member" % path)


def _strip_manifest(xml):
    """plan section 3.3: drop encryption-data and manifest:size; keep everything else."""
    root = ET.fromstring(xml)
    for fe in root.findall(M + "file-entry"):
        for ed in fe.findall(M + "encryption-data"):
            fe.remove(ed)
        fe.attrib.pop(M + "size", None)
    return ET.tostring(root, encoding="UTF-8", xml_declaration=True)


def decrypt(data: bytes, password: str) -> bytes:
    """Plaintext ODF zip, or one of the exceptions above."""
    if not password:
        raise EmptyPassword()
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        raise BadParameters("not a zip: %s" % e) from None
    try:
        manifest = z.read("META-INF/manifest.xml")
    except KeyError:
        raise BadParameters("no manifest") from None
    rows = _rows(manifest)
    if not rows:
        raise NotEncrypted()
    if any("pgp" in r["kdf"].lower() or "rsa" in r["kdf"].lower() for r in rows):
        raise UnsupportedPgp()

    names = z.namelist()
    whole = [r for r in rows if r["path"] == "encrypted-package"]
    if whole and "encrypted-package" in names:
        # plan section 3: this row, never `common`; other rows are ignored here.
        r = whole[0]
        return _inflate(_decrypt_member(r, _derive(r, password), z.read("encrypted-package")), r)

    plain = {}
    for r in rows:  # every row, not only the latch
        member = _member_for(names, r["path"])
        plain[member] = _inflate(_decrypt_member(r, _derive(r, password), z.read(member)), r)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:  # plan section 3: raw namelist, original order
        for info in z.infolist():
            zi = zipfile.ZipInfo(info.filename, info.date_time)
            zi.external_attr, zi.create_system = info.external_attr, info.create_system
            if info.filename == "META-INF/manifest.xml":
                zi.compress_type = zipfile.ZIP_DEFLATED
                out.writestr(zi, _strip_manifest(manifest))
            elif info.filename in plain:
                zi.compress_type = zipfile.ZIP_DEFLATED
                out.writestr(zi, plain[info.filename])
            else:
                zi.compress_type = info.compress_type  # mimetype stays first and STORED
                out.writestr(zi, z.read(info.filename))
    return buf.getvalue()


# --- sweep ------------------------------------------------------------------

ENCRYPTED = [
    ("S2", "aoo-blowfish-pbkdf2.odt", PASSWORD),
    ("S2", "lo-odf11-nonascii-password.odt", NONASCII_PASSWORD),
    ("S3", "lo-legacy-aes-cbc.odt", PASSWORD),
    ("S4", "lo-wholesome-gcm-argon2.odt", PASSWORD),
    # Written by the crate's own `encrypt()`, not by LibreOffice (encrypt arc
    # #18/#23). This oracle never saw that code either, so decrypting it here
    # checks the write direction against an implementation that shares nothing
    # with it -- the read-direction goldens above cannot do that for `encrypt`.
    ("E1", "lo-opens-our-encrypt-output.odt", PASSWORD),
]


def _flip_checksum(xml):
    root = ET.fromstring(xml)
    for fe in root.findall(M + "file-entry"):
        ed = fe.find(M + "encryption-data")
        if ed is not None and ed.get(M + "checksum"):
            d = bytearray(base64.b64decode(ed.get(M + "checksum")))
            d[0] ^= 1
            ed.set(M + "checksum", base64.b64encode(bytes(d)).decode())
    return ET.tostring(root, encoding="UTF-8", xml_declaration=True)


def _mutate(name, member=None, fn=None, manifest_fn=None):
    src = zipfile.ZipFile(io.BytesIO((HERE / name).read_bytes()))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as out:
        for i in src.infolist():
            body = src.read(i.filename)
            if fn and i.filename == member:
                body = fn(body)
            if manifest_fn and i.filename == "META-INF/manifest.xml":
                body = manifest_fn(body)
            zi = zipfile.ZipInfo(i.filename, i.date_time)
            zi.compress_type = i.compress_type
            out.writestr(zi, body)
    return buf.getvalue()


def sweep():
    failures = []

    def check(label, cond, detail=""):
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}{' - ' + detail if detail else ''}")
        if not cond:
            failures.append(label)

    def expect(label, fn, exc):
        try:
            fn()
            check(label, False, "no error raised")
        except exc as e:
            check(label, True, f"{type(e).__name__}({e})")
        except Exception as e:  # noqa: BLE001
            check(label, False, f"got {type(e).__name__}({e})")

    print("S1  lo-unencrypted.odt")
    data = (HERE / "lo-unencrypted.odt").read_bytes()
    expect("plain -> NotEncrypted", lambda: decrypt(data, PASSWORD), NotEncrypted)
    expect("empty password -> EmptyPassword", lambda: decrypt(data, ""), EmptyPassword)

    for slice_, name, pw in ENCRYPTED:
        data = (HERE / name).read_bytes()
        src = zipfile.ZipFile(io.BytesIO(data))
        rows = _rows(src.read("META-INF/manifest.xml"))
        print(f"\n{slice_}  {name}  ({len(rows)} row(s))")
        got = decrypt(data, pw)
        z = zipfile.ZipFile(io.BytesIO(got))
        mf = z.read("META-INF/manifest.xml").decode()
        check("re-zips", True, f"{len(got)} B, {len(z.namelist())} members")
        check("no encryption-data left", "encryption-data" not in mf)
        check("no manifest:size left", "manifest:size" not in mf)
        first = z.infolist()[0]
        check("mimetype first and STORED",
              first.filename == "mimetype" and first.compress_type == 0, first.filename)
        check("no STORED+data-descriptor",
              not any(i.compress_type == 0 and i.flag_bits & 0x08 for i in z.infolist()))
        if rows[0]["path"] == "encrypted-package":
            check("inner package returned, outer not rewritten", z.namelist() != src.namelist())
        else:
            check("member set preserved (incl. directory entries)", z.namelist() == src.namelist())
            for r in rows:
                body = z.read(r["path"])
                ET.fromstring(body)  # raises if the plaintext is not well-formed XML
                check(f"{r['path']} == manifest:size {r['size']}, well-formed",
                      len(body) == r["size"])
        expect("wrong password -> WrongPassword", lambda d=data: decrypt(d, "wrong"), WrongPassword)

    print("\nS5  constructed negatives")
    BF, NA, CBC, GCM = (n for _, n, _ in ENCRYPTED[:4])
    cases = [
        ("blowfish: truncated past the 1K digest window", BF, "content.xml",
         lambda b: b[:-64], None, PASSWORD, Inflate),
        ("blowfish: checksum flipped", BF, None, None, _flip_checksum, PASSWORD, WrongPassword),
        ("blowfish: ciphertext head flipped", BF, "content.xml",
         lambda b: bytes([b[0] ^ 1]) + b[1:], None, PASSWORD, WrongPassword),
        ("odf11 non-ascii: wrong encoding of password", NA, None, None, None,
         NONASCII_PASSWORD.encode("cp1252").decode("latin-1") + "x", WrongPassword),
        ("cbc: checksum flipped", CBC, None, None, _flip_checksum, PASSWORD, WrongPassword),
        ("cbc: not a block multiple", CBC, "content.xml", lambda b: b[:-1], None,
         PASSWORD, BadParameters),
        ("cbc: pad byte mangled", CBC, "content.xml",
         lambda b: b[:-1] + bytes([b[-1] ^ 0xFF]), None, PASSWORD, WrongPassword),
        ("gcm: tag flipped", GCM, "encrypted-package",
         lambda b: b[:-1] + bytes([b[-1] ^ 1]), None, PASSWORD, WrongPassword),
        ("gcm: shorter than IV+tag", GCM, "encrypted-package", lambda b: b[:20], None,
         PASSWORD, BadParameters),
        ("gcm: IV prefix mangled", GCM, "encrypted-package",
         lambda b: bytes([b[0] ^ 1]) + b[1:], None, PASSWORD, BadParameters),
        ("gcm: ciphertext body flipped", GCM, "encrypted-package",
         lambda b: b[:40] + bytes([b[40] ^ 1]) + b[41:], None, PASSWORD, WrongPassword),
    ]
    for label, golden, member, fn, mfn, pw, exc in cases:
        blob = _mutate(golden, member, fn, mfn)
        expect(label, lambda b=blob, p=pw: decrypt(b, p), exc)

    print(f"\n{'all checks passed' if not failures else str(len(failures)) + ' FAILED'}")
    return 0 if not failures else 1


def main(argv):
    if not argv:
        return sweep()
    if len(argv) < 2:
        print(__doc__)
        return 2
    src = pathlib.Path(argv[0])
    out = decrypt(src.read_bytes(), argv[1])
    dest = pathlib.Path(argv[2]) if len(argv) > 2 else None
    if dest:
        dest.write_bytes(out)
        print(f"wrote {dest} ({len(out)} bytes)")
    else:
        print(f"{src.name}: decrypted to {len(out)} bytes; "
              f"members {zipfile.ZipFile(io.BytesIO(out)).namelist()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
