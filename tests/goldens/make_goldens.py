"""Create the S1/S6 goldens with a local LibreOffice (UNO).

Produces:
  lo-unencrypted.odt           — S1 real unencrypted ODT (no password)
  lo-wholesome-gcm-argon2.odt  — default / ODF latest extended
  lo-legacy-aes-cbc.odt        — ODF 1.2 per-entry AES-CBC
  aoo-blowfish-pbkdf2.odt      — ODF 1.1 Blowfish + PBKDF2 (classic path)
  lo-odf11-nonascii-password.odt — ODF 1.1, non-ASCII password (decrypt OQ1)
  lo-legacy-aes-cbc-image.odt  — ODF 1.2 per-entry AES-CBC with an embedded PNG,
                                 so the package has a Pictures/ member (#92)

Password: `password`, except lo-odf11-nonascii-password.odt (see NONASCII_PASSWORD).

Run with LibreOffice's bundled Python (the system one has no `uno`):

    "C:\\Program Files\\LibreOffice\\program\\python.exe" make_goldens.py

Name one or more goldens to write only those; with no arguments it writes all
four. Each save produces fresh salts, IVs and sizes, so regenerating a golden
means re-checking the `size` assertions in `classify_tests.rs` and the recorded
URIs in `URIS.md`. Prefer naming the one you actually need:

    ... make_goldens.py lo-unencrypted
"""

from __future__ import annotations

import os
import random
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from pathlib import Path

import uno
from com.sun.star.beans import PropertyValue
from com.sun.star.connection import NoConnectException

SOFFICE = Path(r"C:\Program Files\LibreOffice\program\soffice.exe")
PASSWORD = "password"

# Decrypt-plan OQ1 probe. Both properties are load-bearing:
#   * one non-ASCII char (U+00E4) -> UTF-8 and MS-1252 encodings differ,
#     separating PACKAGE_ENCRYPTIONDATA_SHA1UTF8 from ...SHA1MS1252;
#   * 52 chars -> 53 UTF-8 bytes and 52 MS-1252 bytes, both inside the
#     len%64 in {52,53,54,55} window where rtl_digest_SHA1 emits a spurious
#     block (tdf#114939, sal/rtl/digest.cxx:1053), separating the correct
#     SHA-1 from the StarOffice one on *both* encodings.
# All four SHA-1 start-key candidates are therefore distinct for this string.
NONASCII_PASSWORD = "\u00e4bcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP"

# officecfg Office.Common.Save.ODF.DefaultVersion
ODF_LATEST = 3
ODF_011 = 2
ODF_012 = 4


def _file_url(path: Path) -> str:
    return path.resolve().as_uri()


def _prop(name: str, value) -> PropertyValue:
    p = PropertyValue()
    p.Name = name
    p.Value = value
    return p


def _bootstrap(profile: Path):
    pipe = "odfgolden" + str(random.random())[2:10]
    connect = f"pipe,name={pipe};urp;"
    cmd = [
        str(SOFFICE),
        "--headless",
        "--nologo",
        "--nodefault",
        "--norestore",
        "--nolockcheck",
        "--nofirststartwizard",
        f"--accept={connect}",
        f"-env:UserInstallation={_file_url(profile)}",
    ]
    print("starting", " ".join(cmd), flush=True)
    proc = subprocess.Popen(cmd)
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local
    )
    url = f"uno:{connect}StarOffice.ComponentContext"
    last = None
    for i in range(90):  # cold profile creation can take ~40s
        try:
            ctx = resolver.resolve(url)
            print(f"connected after {i}s", flush=True)
            return ctx, proc
        except NoConnectException as err:
            last = err
            time.sleep(1)
    proc.terminate()
    raise RuntimeError(f"could not connect: {last}")


def _set_odf_version(ctx, version: int) -> None:
    config = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.configuration.ConfigurationProvider", ctx
    )
    access = config.createInstanceWithArguments(
        "com.sun.star.configuration.ConfigurationUpdateAccess",
        (_prop("nodepath", "/org.openoffice.Office.Common/Save/ODF"),),
    )
    access.setPropertyValue("DefaultVersion", version)
    access.commitChanges()


def _png(width: int = 8, height: int = 8) -> bytes:
    """A small opaque RGB PNG, built here so the golden needs no binary input."""

    def chunk(kind: bytes, body: bytes) -> bytes:
        crc = zlib.crc32(kind + body)
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", crc)

    # Each row: filter byte 0, then RGB per pixel.
    rows = b"".join(
        b"\x00" + b"".join(bytes((x * 31 % 256, y * 31 % 256, 128)) for x in range(width))
        for y in range(height)
    )
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    signature = b"\x89PNG\r\n\x1a\n"
    return (
        signature
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(rows))
        + chunk(b"IEND", b"")
    )


def _insert_image(ctx, doc) -> None:
    """Embed a PNG in `doc`, as a picture inserted from a file would be."""
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
        f.write(_png())
        png_path = Path(f.name)
    try:
        provider = ctx.ServiceManager.createInstanceWithContext(
            "com.sun.star.graphic.GraphicProvider", ctx
        )
        graphic = provider.queryGraphic((_prop("URL", _file_url(png_path)),))
        shape = doc.createInstance("com.sun.star.text.TextGraphicObject")
        shape.Graphic = graphic
        doc.Text.insertTextContent(doc.Text.getEnd(), shape, False)
    finally:
        png_path.unlink(missing_ok=True)


def _save(
    ctx, dest: Path, text: str, odf_version: int, password: str | None, image: bool = False
) -> None:
    print(f"set ODF version {odf_version}", flush=True)
    _set_odf_version(ctx, odf_version)
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx
    )
    print("loading writer", flush=True)
    doc = desktop.loadComponentFromURL(
        "private:factory/swriter",
        "_blank",
        0,
        (_prop("Hidden", True),),
    )
    cursor = doc.Text.createTextCursor()
    doc.Text.insertString(cursor, text, False)
    if image:
        _insert_image(ctx, doc)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()
    print(f"storing {dest.name}", flush=True)
    args = [_prop("FilterName", "writer8")]
    if password is not None:
        args.append(_prop("Password", password))
    doc.storeToURL(_file_url(dest), tuple(args))
    doc.close(True)
    print(f"  wrote {dest.stat().st_size} bytes", flush=True)


GOLDENS = {
    "lo-unencrypted": ("S1 real unencrypted ODT.", ODF_LATEST, None),
    "lo-wholesome-gcm-argon2": ("S6 wholesome GCM+Argon2 golden.", ODF_LATEST, PASSWORD),
    "lo-legacy-aes-cbc": ("S6 legacy per-entry AES-CBC golden.", ODF_012, PASSWORD),
    "aoo-blowfish-pbkdf2": ("S6 classic Blowfish+PBKDF2 golden.", ODF_011, PASSWORD),
    "lo-odf11-nonascii-password": (
        "Decrypt OQ1: ODF 1.1 start-key probe, non-ASCII password.",
        ODF_011,
        NONASCII_PASSWORD,
    ),
    "lo-legacy-aes-cbc-image": ("S6 per-entry AES-CBC golden with a picture.", ODF_012, PASSWORD),
}

# Goldens that also embed a picture (#92: a per-entry package with a Pictures/
# member, to show its rows are all encrypted).
WITH_IMAGE = {"lo-legacy-aes-cbc-image"}


def main(argv: list[str]) -> int:
    wanted = argv or list(GOLDENS)
    unknown = [n for n in wanted if n not in GOLDENS]
    if unknown:
        print(f"unknown golden(s): {', '.join(unknown)}", flush=True)
        print(f"choose from: {', '.join(GOLDENS)}", flush=True)
        return 2

    out_dir = Path(__file__).resolve().parent
    profile = Path(os.environ.get("TEMP", "/tmp")) / f"odf-crypto-goldens-lo-{os.getpid()}"
    profile.mkdir(parents=True, exist_ok=True)

    ctx, proc = _bootstrap(profile)
    try:
        for name in wanted:
            text, version, password = GOLDENS[name]
            _save(ctx, out_dir / f"{name}.odt", text, version, password, name in WITH_IMAGE)
    finally:
        try:
            desktop = ctx.ServiceManager.createInstanceWithContext(
                "com.sun.star.frame.Desktop", ctx
            )
            desktop.terminate()
        except Exception:
            pass
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
