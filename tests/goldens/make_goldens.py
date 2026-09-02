"""Create the S1/S6 goldens with a local LibreOffice (UNO).

Produces:
  lo-unencrypted.odt           — S1 real unencrypted ODT (no password)
  lo-wholesome-gcm-argon2.odt  — default / ODF latest extended
  lo-legacy-aes-cbc.odt        — ODF 1.2 per-entry AES-CBC
  aoo-blowfish-pbkdf2.odt      — ODF 1.1 Blowfish + PBKDF2 (classic path)
  lo-odf11-nonascii-password.odt — ODF 1.1, non-ASCII password (decrypt OQ1)

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
import subprocess
import sys
import time
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


def _save(ctx, dest: Path, text: str, odf_version: int, password: str | None) -> None:
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
}


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
            _save(ctx, out_dir / f"{name}.odt", text, version, password)
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
