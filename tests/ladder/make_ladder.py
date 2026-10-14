"""Synthesize the SHA-1 ladder fixtures from `lo-odf11-nonascii-password.odt`.

    python tests/ladder/make_ladder.py

**These are not LibreOffice output**, which is why they live here and not in
`tests/goldens/`. Current LibreOffice writes only the correct UTF-8 SHA-1 start key
(decrypt plan OQ1, measured), so no LibreOffice that can be run today produces a file
needing any other rung. Their evidence is the other direction: `lo_accepts.py` shows
current LibreOffice *opens* each one, because it walks the same ladder on read.

Each fixture is the golden with every encrypted member re-encrypted under one start
key. Everything else is byte-for-byte the golden's: manifest, salts, IVs, iteration
count, checksums. The SHA1/1K checksum covers the compressed plaintext, which does not
change, so the manifest stays valid as written.

| fixture | start key | upstream |
| --- | --- | --- |
| ladder-staroffice-utf8.odt | StarOffice SHA-1(UTF-8) | `Bugs::WrongSHA1`, tdf#114939 |
| ladder-forced-sha256.odt | SHA-256(UTF-8) | rhbz#1013844 force |
| ladder-staroffice-ms1252.odt | StarOffice SHA-1(MS-1252) | `Bugs::WinEncodingWrongSHA1` |
| ladder-not-a-rung.odt | correct SHA-1(MS-1252) | none: the negative control |

Deterministic: same golden in, same bytes out, so rerunning is a check.
"""

from __future__ import annotations

import hashlib
import io
import pathlib
import sys
import warnings
import zipfile

warnings.filterwarnings("ignore")

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "goldens"))

from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, modes  # noqa: E402

import ref_decrypt  # noqa: E402
from sha1_star import GOLDEN, staroffice_sha1  # noqa: E402

PW = ref_decrypt.NONASCII_PASSWORD
U, W = PW.encode("utf-8"), PW.encode("cp1252")

FIXTURES = {
    "ladder-staroffice-utf8.odt": staroffice_sha1(U),
    "ladder-forced-sha256.odt": hashlib.sha256(U).digest(),
    "ladder-staroffice-ms1252.odt": staroffice_sha1(W),
    "ladder-not-a-rung.odt": hashlib.sha1(W).digest(),
}


def _key(row, start: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", start, row["salt"], row["iters"], row["dklen"])


def _cfb(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    c = Cipher(Blowfish(key), modes.CFB(iv))
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(data) + op.finalize()


def build(golden: bytes, start: bytes) -> bytes:
    z = zipfile.ZipFile(io.BytesIO(golden))
    rows = {r["path"]: r for r in ref_decrypt._rows(z.read("META-INF/manifest.xml"))}
    correct = hashlib.sha1(U).digest()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as w:
        for info in z.infolist():
            data = z.read(info)
            row = rows.get(info.filename)
            if row is not None:
                assert row["cipher"].endswith("blowfish") or "Blowfish" in row["cipher"], row["cipher"]
                plain = _cfb(_key(row, correct), row["iv"], data, encrypt=False)
                assert hashlib.sha1(plain[:1024]).digest() == row["digest"], info.filename
                data = _cfb(_key(row, start), row["iv"], plain, encrypt=True)
            w.writestr(info, data)
    return out.getvalue()


def main() -> int:
    golden = (HERE.parent / "goldens" / GOLDEN).read_bytes()
    keys = list(FIXTURES.values()) + [hashlib.sha1(U).digest()]
    assert len(set(keys)) == len(keys), "start keys are not all distinct"
    for name, start in FIXTURES.items():
        (HERE / name).write_bytes(build(golden, start))
        print(f"wrote {name}  start key {start.hex()[:16]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
