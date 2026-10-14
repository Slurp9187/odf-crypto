"""Does current LibreOffice open each ladder fixture with the password?

Run with LibreOffice's bundled Python (the system one has no `uno`):

    "C:\\Program Files\\LibreOffice\\program\\python.exe" tests/ladder/lo_accepts.py [--reverse]

This is the evidence the ladder fixtures carry. `make_ladder.py` wrote them, so their
bytes prove nothing on their own; that LibreOffice opens the three rungs and refuses
`ladder-not-a-rung.odt` is what makes them fixtures of LibreOffice's behavior rather
than of ours. The golden they were made from runs first as a positive control.

Three traps make a UNO harness return confident wrong answers, and each is handled:
a second load on one instance hangs, so every case gets a fresh soffice; a crashed
instance answers "refused" for everything, so after a refusal the bridge must still
answer a call; and a fresh profile often never accepts the pipe, so one profile is made
once and reused. Run it both ways (`--reverse`) before believing an asymmetric result.
"""

from __future__ import annotations

import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "goldens"))

import make_goldens as mg  # noqa: E402  (bootstrap, URL and property helpers)

EXPECTED_TEXT = "Decrypt OQ1: ODF 1.1 start-key probe, non-ASCII password."

CASES = [
    (HERE.parent / "goldens" / "lo-odf11-nonascii-password.odt", True),
    (HERE / "ladder-staroffice-utf8.odt", True),
    (HERE / "ladder-forced-sha256.odt", True),
    (HERE / "ladder-staroffice-ms1252.odt", True),
    (HERE / "ladder-not-a-rung.odt", False),
]


def probe(profile: pathlib.Path, path: pathlib.Path) -> str:
    ctx, proc = mg._bootstrap(profile)
    try:
        desktop = ctx.ServiceManager.createInstanceWithContext("com.sun.star.frame.Desktop", ctx)
        try:
            doc = desktop.loadComponentFromURL(
                mg._file_url(path), "_blank", 0,
                (mg._prop("Hidden", True), mg._prop("Password", mg.NONASCII_PASSWORD)),
            )
        except Exception as err:  # noqa: BLE001 - any refusal is data here
            desktop.getComponents()  # raises if the bridge is dead: a crash is not a refusal
            return f"REFUSED ({type(err).__name__})"
        if doc is None:
            desktop.getComponents()
            return "REFUSED (no document)"
        text = doc.Text.getString()
        doc.close(True)
        return "OPENED" if EXPECTED_TEXT in text else f"OPENED, WRONG TEXT {text[:40]!r}"
    finally:
        proc.terminate()
        proc.wait(timeout=60)


def main(argv: list[str]) -> int:
    cases = list(reversed(CASES)) if "--reverse" in argv else CASES
    ok = True
    with tempfile.TemporaryDirectory(prefix="odf-ladder-profile-", ignore_cleanup_errors=True) as tmp:
        profile = pathlib.Path(tmp)
        for path, should_open in cases:
            got = probe(profile, path)
            good = (got == "OPENED") == should_open and not got.startswith("OPENED, WRONG")
            ok &= good
            print(f"RESULT [{'PASS' if good else 'FAIL'}] {path.name}: {got} "
                  f"(expected {'OPENED' if should_open else 'REFUSED'})", flush=True)
    print("all cases as expected" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
