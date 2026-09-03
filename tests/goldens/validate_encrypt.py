"""Validate that real LibreOffice opens what this crate's own `encrypt()` writes.

Counterpart to `make_goldens.py`'s UNO bootstrap, run in the opposite direction, per
docs/plans/odf-encryption-encrypt-2026-09-03.md S5 (issue #23): self-consistency
(`decrypt(encrypt(p, pw)?, pw)? == p`) proves *we* agree with ourselves, not that real
LibreOffice -- which has never seen a line of this crate -- accepts what `encrypt()`
writes. This script is the check that catches a shared framing mistake self-consistency
cannot see.

Steps:
  (a) Shell out to `cargo run --example encrypt_for_validation` to encrypt
      `lo-unencrypted.odt` with THIS CRATE's own `encrypt()` (not LibreOffice's),
      writing the result to the fixed, checked-in-worthy path
      `lo-opens-our-encrypt-output.odt`.
  (b) Bootstrap real LibreOffice over UNO (scaffolding copied from `make_goldens.py`'s
      `_bootstrap`/`_prop`/`_file_url` -- this file runs standalone under LO's bundled
      Python, which cannot import `make_goldens.py`'s module as a library because that
      module has import-time side effects of its own).
  (c) `loadComponentFromURL` the file from (a) with a `Password` property, and assert
      both that the load raises no exception and that the recovered text is exactly
      `lo-unencrypted.odt`'s known content (`make_goldens.py`'s
      `GOLDENS["lo-unencrypted"]`: "S1 real unencrypted ODT.").

Prints a PASS/FAIL line and exits non-zero on failure, same convention as
`ref_decrypt.py`'s sweep.

Run with LibreOffice's bundled Python (the system one has no `uno`), from the repo root:

    "C:\\Program Files\\LibreOffice\\program\\python.exe" tests\\goldens\\validate_encrypt.py
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
# make_goldens.py GOLDENS["lo-unencrypted"] -- the text lo-unencrypted.odt was saved with.
EXPECTED_TEXT = "S1 real unencrypted ODT."

HERE = Path(__file__).resolve().parent  # tests/goldens
REPO_ROOT = HERE.parent.parent
SOURCE_ODT = HERE / "lo-unencrypted.odt"
# Fixed, checked-in-worthy path (plan S5 step 2d): this file becomes the checked-in
# evidence that real LibreOffice accepted our encrypt() output.
OUTPUT_ODT = HERE / "lo-opens-our-encrypt-output.odt"


# --- copied from make_goldens.py (standalone script, cannot import across files) ------


def _file_url(path: Path) -> str:
    return path.resolve().as_uri()


def _prop(name: str, value) -> PropertyValue:
    p = PropertyValue()
    p.Name = name
    p.Value = value
    return p


def _bootstrap(profile: Path):
    pipe = "odfvalidate" + str(random.random())[2:10]
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


# --- new for this script ---------------------------------------------------------------


def _lo_version(ctx) -> str:
    """UNO-reported product version, for the checked-in evidence note (S5 step 4)."""
    try:
        config = ctx.ServiceManager.createInstanceWithContext(
            "com.sun.star.configuration.ConfigurationProvider", ctx
        )
        access = config.createInstanceWithArguments(
            "com.sun.star.configuration.ConfigurationAccess",
            (_prop("nodepath", "/org.openoffice.Setup/Product"),),
        )
        name = access.getPropertyValue("ooName")
        version = access.getPropertyValue("ooSetupVersionAboutBox")
        return f"{name} {version}"
    except Exception as e:  # noqa: BLE001 -- version string is evidence, not load-bearing
        return f"<UNO version query failed: {e}>"


def _encrypt_with_our_crate(src: Path, dest: Path) -> None:
    """Step (a): shell out to THIS CRATE's own `encrypt()`, not LibreOffice's, via the
    `encrypt_for_validation` example."""
    cmd = [
        "cargo",
        "run",
        "--quiet",
        "--example",
        "encrypt_for_validation",
        "--",
        str(src),
        PASSWORD,
        str(dest),
    ]
    print("running", " ".join(cmd), flush=True)
    result = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"encrypt_for_validation failed (exit {result.returncode})\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    print(result.stdout.strip(), flush=True)


def main() -> int:
    if not SOURCE_ODT.exists():
        print(f"FAIL: source golden missing: {SOURCE_ODT}", flush=True)
        return 1

    try:
        _encrypt_with_our_crate(SOURCE_ODT, OUTPUT_ODT)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: encrypt step: {e}", flush=True)
        return 1

    profile = Path(os.environ.get("TEMP", "/tmp")) / f"odf-crypto-validate-{os.getpid()}"
    profile.mkdir(parents=True, exist_ok=True)
    ctx, proc = _bootstrap(profile)
    try:
        version = _lo_version(ctx)
        print(f"LibreOffice version (UNO): {version}", flush=True)

        desktop = ctx.ServiceManager.createInstanceWithContext(
            "com.sun.star.frame.Desktop", ctx
        )
        print(f"loading {OUTPUT_ODT.name} with password", flush=True)
        try:
            doc = desktop.loadComponentFromURL(
                _file_url(OUTPUT_ODT),
                "_blank",
                0,
                (_prop("Hidden", True), _prop("Password", PASSWORD)),
            )
        except Exception as e:  # noqa: BLE001
            print(
                f"FAIL: LibreOffice could not open our encrypt() output: {e}",
                flush=True,
            )
            return 1

        try:
            got_text = doc.getText().getString()
        finally:
            doc.close(True)

        if got_text != EXPECTED_TEXT:
            print(
                f"FAIL: text mismatch: got {got_text!r}, want {EXPECTED_TEXT!r}",
                flush=True,
            )
            return 1

        print(
            f"PASS: LibreOffice ({version}) opened our encrypt() output "
            f"({OUTPUT_ODT.name}) and recovered the exact original text",
            flush=True,
        )
        return 0
    finally:
        try:
            desktop = ctx.ServiceManager.createInstanceWithContext(
                "com.sun.star.frame.Desktop", ctx
            )
            desktop.terminate()
        except Exception:  # noqa: BLE001
            pass
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
