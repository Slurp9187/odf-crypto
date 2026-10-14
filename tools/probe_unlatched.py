"""What does LibreOffice do with an encrypted package that has no latch row?

    "C:\\Program Files\\LibreOffice\\program\\python.exe" tools/probe_unlatched.py <odf-crypto.exe> [--reverse]

The shape `EncryptError::PartiallyEncrypted` names, and that `classify` reports as
`Mode::PerEntry` with `package_encrypted == false`: complete `encryption-data` rows,
none of them on `content.xml` or `encrypted-package`. `ZipPackage.cxx:435-446` never
sets `HasEncryptedEntries`, so LibreOffice does not ask for a password. This measures
what it does instead.

Built from `tests/goldens/lo-legacy-aes-cbc.odt`: content.xml is swapped for its
plaintext (taken from `odf-crypto decrypt`) and its `encryption-data` dropped. Every
other stream stays encrypted. Each case gets a fresh soffice (a second load on one
instance hangs), and the plain golden runs as a positive control.
"""

from __future__ import annotations

import io
import pathlib
import re
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests" / "goldens"))

import make_goldens as mg  # noqa: E402
import unohelper  # noqa: E402
from com.sun.star.task import XInteractionAbort, XInteractionHandler  # noqa: E402


class Recorder(unohelper.Base, XInteractionHandler):
    """Records every request LibreOffice would put to a user, then aborts it."""

    def __init__(self):
        self.seen = []

    def handle(self, request):
        req = request.getRequest()
        name = getattr(req, "typeName", None) or type(req).__name__
        self.seen.append(f"{name}:{getattr(req, 'Mode', '')}{hex(req.ErrCode) if hasattr(req, 'ErrCode') else ''}")
        for c in request.getContinuations():
            if c.queryInterface(uno_type("com.sun.star.task.XInteractionAbort")):
                c.select()
                return


def uno_type(name):
    import uno
    return uno.getTypeByName(name)

GOLDEN = ROOT / "tests" / "goldens" / "lo-legacy-aes-cbc.odt"
EXPECTED_TEXT = "S6 legacy per-entry AES-CBC golden."


def build_unlatched(cli: str, out: pathlib.Path) -> None:
    plain = subprocess.run(
        [cli, "decrypt", str(GOLDEN), "-o", "-", "--password-stdin"],
        input=mg.PASSWORD.encode(), capture_output=True, check=True,
    ).stdout
    content = zipfile.ZipFile(io.BytesIO(plain)).read("content.xml")
    src = zipfile.ZipFile(GOLDEN)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as w:
        for info in src.infolist():
            data = src.read(info)
            if info.filename == "content.xml":
                info.compress_type = zipfile.ZIP_DEFLATED
                data = content
            elif info.filename == "META-INF/manifest.xml":
                xml = data.decode("utf-8")
                entry = re.compile(
                    r'(<manifest:file-entry manifest:full-path="content.xml"[^>]*?)'
                    r'( manifest:size="\d+")?>\s*<manifest:encryption-data.*?</manifest:encryption-data>\s*'
                    r'</manifest:file-entry>', re.S)
                xml, n = entry.subn(r"\1/>", xml)
                assert n == 1, "content.xml row not rewritten"
                data = xml.encode("utf-8")
            w.writestr(info, data)
    out.write_bytes(buf.getvalue())


def probe(profile: pathlib.Path, path: pathlib.Path, password: str | None, handler: bool = False) -> str:
    ctx, proc = mg._bootstrap(profile)
    try:
        desktop = ctx.ServiceManager.createInstanceWithContext("com.sun.star.frame.Desktop", ctx)
        args = [mg._prop("Hidden", True)]
        if password is not None:
            args.append(mg._prop("Password", password))
        rec = Recorder() if handler else None
        if rec is not None:
            args.append(mg._prop("InteractionHandler", rec))
        try:
            doc = desktop.loadComponentFromURL(mg._file_url(path), "_blank", 0, tuple(args))
        except Exception as err:  # noqa: BLE001
            desktop.getComponents()
            return f"REFUSED ({type(err).__name__}: {getattr(err, 'Message', '')[:120]}) asked={rec.seen if rec else '-'}"
        if doc is None:
            desktop.getComponents()
            return f"REFUSED (no document) asked={rec.seen if rec else '-'}"
        text = doc.Text.getString()
        styles = doc.StyleFamilies.getByName("ParagraphStyles").getCount()
        doc.close(True)
        return f"OPENED text_ok={EXPECTED_TEXT in text} paragraph_styles={styles} asked={rec.seen if rec else '-'}"
    finally:
        proc.terminate()
        proc.wait(timeout=60)


def main(argv: list[str]) -> int:
    cli = argv[0]
    with tempfile.TemporaryDirectory(prefix="odf-unlatched-", ignore_cleanup_errors=True) as tmp:
        tmp = pathlib.Path(tmp)
        unlatched = tmp / "unlatched.odt"
        build_unlatched(cli, unlatched)
        shape = subprocess.run([cli, "classify", "--json", str(unlatched)],
                               capture_output=True, text=True).stdout.strip()
        print(f"SHAPE {shape}", flush=True)
        plain = tmp / "plain.odt"
        plain.write_bytes(subprocess.run(
            [cli, "decrypt", str(GOLDEN), "-o", "-", "--password-stdin"],
            input=mg.PASSWORD.encode(), capture_output=True, check=True).stdout)
        cases = [
            ("plain control", plain, None),
            ("unlatched, no password", unlatched, None),
            ("unlatched, with password", unlatched, mg.PASSWORD),
            ("encrypted golden, handler, no password", GOLDEN, None, True),
            ("unlatched, handler, no password", unlatched, None, True),
        ]
        if "--reverse" in argv:
            cases.reverse()
        profile = tmp / "profile"
        for label, path, pw, *h in cases:
            print(f"RESULT {label}: {probe(profile, path, pw, bool(h))}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
