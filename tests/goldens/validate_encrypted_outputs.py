"""LibreOffice gate for `encrypt_to` and `reencrypt_to`: does real LibreOffice
open what they write, with the password they were given, and refuse it with
any other?

Self-consistency proves only that this crate agrees with itself. This loads
each output in a real LibreOffice with its password, requires the recovered
text to be the source golden's, and then requires a wrong password to fail --
the negative control that shows a PASS is not a LibreOffice that opens
anything.

One soffice per load, on one reused profile: a second `loadComponentFromURL`
on one instance hangs, and a fresh profile often never answers the pipe (see
the UNO harness notes in the repository's memory).

    set ODF_CRYPTO_LO_GATE_DIR=<dir>
    cargo test --features crypto-ops --lib -- --ignored write_lo_gate_output
    "C:\Program Files\LibreOffice\program\python.exe" tests\goldens\validate_encrypted_outputs.py <dir>
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from make_goldens import GOLDENS, _bootstrap, _file_url, _prop

PASSWORD = "password"
NEW = "a new password"  # reencrypt_tests.rs NEW

# output file -> (its password, the golden whose text it must hold)
OUTPUTS = {
    "encrypt-to.odt": (PASSWORD, "lo-unencrypted"),
    "rekeyed-lo-wholesome-gcm-argon2.odt": (NEW, "lo-wholesome-gcm-argon2"),
    "rekeyed-lo-legacy-aes-cbc.odt": (NEW, "lo-legacy-aes-cbc"),
    "rekeyed-aoo-blowfish-pbkdf2.odt": (NEW, "aoo-blowfish-pbkdf2"),
}


def load_text(profile: Path, path: Path, password: str) -> str | None:
    """Open `path` with `password` in a fresh soffice; its text, or None."""
    ctx, proc = _bootstrap(profile)
    try:
        desktop = ctx.ServiceManager.createInstanceWithContext("com.sun.star.frame.Desktop", ctx)
        try:
            doc = desktop.loadComponentFromURL(
                _file_url(path), "_blank", 0, (_prop("Hidden", True), _prop("Password", password))
            )
        except Exception:  # noqa: BLE001 -- a refusal is an expected outcome here
            return None
        if doc is None:
            return None
        try:
            return doc.getText().getString()
        finally:
            doc.close(True)
    finally:
        try:
            ctx.ServiceManager.createInstanceWithContext("com.sun.star.frame.Desktop", ctx).terminate()
        except Exception:  # noqa: BLE001
            pass
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=15)


def main() -> int:
    gate = Path(sys.argv[1])
    profile = Path(os.environ.get("TEMP", "/tmp")) / f"odf-crypto-gate-{os.getpid()}"
    profile.mkdir(parents=True, exist_ok=True)
    failures = 0
    try:
        for name, (password, golden) in OUTPUTS.items():
            path = gate / name
            want = GOLDENS[golden][0]
            if not path.exists():
                print(f"FAIL {name}: missing", flush=True)
                failures += 1
                continue
            got = load_text(profile, path, password)
            refused = load_text(profile, path, "not the password") is None
            ok = got == want and refused
            failures += not ok
            print(
                f"{'PASS' if ok else 'FAIL'} {name}: text {'matches' if got == want else repr(got)}, "
                f"wrong password {'refused' if refused else 'ACCEPTED'}",
                flush=True,
            )
    finally:
        shutil.rmtree(profile, ignore_errors=True)
    print(f"{len(OUTPUTS) - failures}/{len(OUTPUTS)} passed", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
