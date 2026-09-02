"""Create the three S6 goldens with a local LibreOffice (UNO).

Produces:
  lo-wholesome-gcm-argon2.odt  — default / ODF latest extended
  lo-legacy-aes-cbc.odt        — ODF 1.2 per-entry AES-CBC
  aoo-blowfish-pbkdf2.odt      — ODF 1.1 Blowfish + PBKDF2 (classic path)

Password for every file: password
"""

from __future__ import annotations

import os
import random
import shutil
import subprocess
import time
from pathlib import Path

import uno
from com.sun.star.beans import PropertyValue
from com.sun.star.connection import NoConnectException

SOFFICE = Path(r"C:\Program Files\LibreOffice\program\soffice.exe")
PASSWORD = "password"

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
    for i in range(30):
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


def _save_encrypted(ctx, dest: Path, text: str, odf_version: int) -> None:
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
    doc.storeToURL(
        _file_url(dest),
        (
            _prop("FilterName", "writer8"),
            _prop("Password", PASSWORD),
        ),
    )
    doc.close(True)
    print(f"  wrote {dest.stat().st_size} bytes", flush=True)


def main() -> int:
    out_dir = Path(__file__).resolve().parent
    profile = Path(os.environ.get("TEMP", "/tmp")) / f"odf-decrypt-goldens-lo-{os.getpid()}"
    profile.mkdir(parents=True, exist_ok=True)

    ctx, proc = _bootstrap(profile)
    try:
        dest = out_dir / "lo-unencrypted.odt"
        print(f"set ODF version {ODF_LATEST} (unencrypted)", flush=True)
        _set_odf_version(ctx, ODF_LATEST)
        desktop = ctx.ServiceManager.createInstanceWithContext(
            "com.sun.star.frame.Desktop", ctx
        )
        doc = desktop.loadComponentFromURL(
            "private:factory/swriter",
            "_blank",
            0,
            (_prop("Hidden", True),),
        )
        cursor = doc.Text.createTextCursor()
        doc.Text.insertString(cursor, "S1 real unencrypted ODT.", False)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            dest.unlink()
        doc.storeToURL(_file_url(dest), (_prop("FilterName", "writer8"),))
        doc.close(True)
        print(f"  wrote {dest.stat().st_size} bytes", flush=True)

        jobs = [
            (
                out_dir / "lo-wholesome-gcm-argon2.odt",
                "S6 wholesome GCM+Argon2 golden.",
                ODF_LATEST,
            ),
            (
                out_dir / "lo-legacy-aes-cbc.odt",
                "S6 legacy per-entry AES-CBC golden.",
                ODF_012,
            ),
            (
                out_dir / "aoo-blowfish-pbkdf2.odt",
                "S6 classic Blowfish+PBKDF2 golden.",
                ODF_011,
            ),
        ]
        for dest, text, version in jobs:
            _save_encrypted(ctx, dest, text, version)
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
    raise SystemExit(main())
