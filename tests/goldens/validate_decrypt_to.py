r"""LibreOffice gate for `decrypt_to`: does real LibreOffice open what it writes?

`decrypt_to`'s per-entry output is a zip this crate frames itself -- deflated
members carry data descriptors, because the writer cannot seek -- so agreeing
with our own reader proves nothing about LibreOffice's. This converts each
streamed output to text with a headless LibreOffice, beside the whole-buffer
`decrypt` output for the same fixture as a control, and requires the two texts
to be identical and non-empty.

One soffice per file, one shared profile: see the UNO harness notes -- a
second load on one instance hangs, and a fresh profile often never answers.

    set ODF_CRYPTO_LO_GATE_DIR=<dir>
    cargo test --features crypto-ops --lib -- --ignored write_lo_gate_outputs
    python tests/goldens/validate_decrypt_to.py <dir> [path\to\soffice.exe]
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_SOFFICE = r"C:\Program Files\LibreOffice\program\soffice.exe"


def to_text(soffice: str, profile: Path, odt: Path, out: Path) -> str | None:
    out.mkdir(parents=True, exist_ok=True)
    cmd = [
        soffice,
        f"-env:UserInstallation={profile.as_uri()}",
        "--headless",
        "--norestore",
        "--convert-to",
        "txt:Text (encoded):UTF8",
        "--outdir",
        str(out),
        str(odt),
    ]
    subprocess.run(cmd, capture_output=True, timeout=120)
    txt = out / (odt.stem + ".txt")
    return txt.read_text(encoding="utf-8-sig") if txt.exists() else None


def main() -> int:
    gate = Path(sys.argv[1])
    soffice = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_SOFFICE
    streamed = sorted(gate.glob("*.streamed.odt"))
    if not streamed:
        print(f"FAIL: no *.streamed.odt under {gate}")
        return 1
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        profile = Path(tmp) / "profile"
        # Initialise the profile once, so later runs do not race its creation.
        to_text(soffice, profile, streamed[0], Path(tmp) / "warmup")
        for odt in streamed:
            control = odt.with_name(odt.name.replace(".streamed.", ".whole."))
            want = to_text(soffice, profile, control, Path(tmp) / "whole")
            got = to_text(soffice, profile, odt, Path(tmp) / "streamed")
            ok = bool(want) and got == want
            failures += not ok
            detail = f"{len(got or '')} chars" if ok else f"control={want!r:.60} streamed={got!r:.60}"
            print(f"{'PASS' if ok else 'FAIL'} {odt.name}: {detail}")
    print(f"{len(streamed) - failures}/{len(streamed)} opened in LibreOffice")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
