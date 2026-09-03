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
  (b) Bootstrap real LibreOffice over UNO, reusing `make_goldens.py`'s own
      `_bootstrap`/`_prop`/`_file_url` by importing them -- that module defines only
      constants and functions at import time, and Python puts this script's own
      directory on `sys.path`, so there is nothing to copy.
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
import shutil
import subprocess
from pathlib import Path

# `make_goldens.py` sits beside this file, and Python puts a script's own
# directory on sys.path, so its UNO scaffolding is importable rather than
# copy-pasted. It defines only constants and functions at import time (its
# entry point is guarded by `if __name__ == "__main__"`), so importing it
# starts no LibreOffice of its own.
from make_goldens import _bootstrap, _file_url, _prop

PASSWORD = "password"
# make_goldens.py GOLDENS["lo-unencrypted"] -- the text lo-unencrypted.odt was saved with.
EXPECTED_TEXT = "S1 real unencrypted ODT."

HERE = Path(__file__).resolve().parent  # tests/goldens
REPO_ROOT = HERE.parent.parent
SOURCE_ODT = HERE / "lo-unencrypted.odt"
# Fixed, checked-in-worthy path (plan S5 step 2d): this file becomes the checked-in
# evidence that real LibreOffice accepted our encrypt() output.
OUTPUT_ODT = HERE / "lo-opens-our-encrypt-output.odt"


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
        if version.startswith("<"):
            # The version string is checked into URIS.md as evidence; a failed
            # query must not be interpolated into a PASS line as though it were
            # a product version.
            print(f"FAIL: could not determine the LibreOffice version: {version}", flush=True)
            return 1

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

        # UNO returns a NULL reference (None) rather than raising when LO
        # type-detects the package but cannot decrypt or parse it -- exactly the
        # failure this script exists to report. Without this check the next line
        # dies with an AttributeError and the FAIL line never prints.
        if doc is None:
            print(
                "FAIL: LibreOffice could not open our encrypt() output "
                f"({OUTPUT_ODT.name}): loadComponentFromURL returned no document",
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
            proc.wait(timeout=15)
        # make_goldens.py leaves its profile behind; each run here would
        # otherwise add another ~10 MB tree under TEMP.
        shutil.rmtree(profile, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
