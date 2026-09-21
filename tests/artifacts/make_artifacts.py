#!/usr/bin/env python3
"""Generate the human-openable artifact set for rc.5 plan §7.

    python tests/artifacts/make_artifacts.py

Writes `tests/artifacts/*.odt` and `MANIFEST.md`, then stops. **The point of
this directory is a verdict a harness cannot give.**

`tests/goldens/validate_encrypt.py` drives LibreOffice over UNO, which is not
the path a double-click takes: no password dialog, no recovery prompt, no
"LibreOffice has detected a problem" bar. A file can pass UNO and still be one a
person cannot open. So these are produced once, committed, and opened by hand.

Not run in CI, like every other Python helper here, and deliberately: it shells
out to `cargo run`, needs no network, and its output is checked in.

**Regeneration changes every byte.** `encrypt` draws a fresh salt and IV per
call, so re-running this invalidates every sha256 in the manifest. That is
correct behaviour, not a bug -- but it means the committed files are the
artifacts, and this script is how they were made rather than a thing to re-run
casually. Re-run it only when the set itself should change, and re-open the
files afterwards: a new sha256 with an old "opened by hand" claim beside it is
exactly the stale-evidence shape this repo keeps tripping over.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PLAINTEXT = ROOT / "tests" / "goldens" / "lo-unencrypted.odt"
EXPECTED_TEXT = "S1 real unencrypted ODT."

PASSWORD = "password"
# Matches `test_support::NONASCII_PASSWORD` and `make_goldens.py`.
NONASCII = "äbcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP"

# (filename, argon2 tuple or None for the default, password, why this one is here)
CASES = [
    (
        "wholesome-default.odt",
        None,
        PASSWORD,
        "LibreOffice's own tuple, which is what a caller who expresses no opinion "
        "gets. If only one file is opened, open this one: everything else here "
        "is a deviation from it.",
    ),
    (
        "wholesome-nonascii-password.odt",
        None,
        NONASCII,
        "Default tuple, non-ASCII password. The start key is SHA-256 over UTF-8 "
        "bytes, so this fails if anything in the chain re-encodes the password -- "
        "a failure mode no ASCII password can surface.",
    ),
    (
        "argon2-floor-1-8-1.odt",
        (1, 8, 1),
        PASSWORD,
        "The weakest tuple argon2 will run at all: m = 8p is its own floor, not "
        "ours. Deliberately a bad choice, and accepted -- the cost is the "
        "caller's decision. Here to prove LibreOffice honours what is written "
        "rather than assuming its own default.",
    ),
    (
        "argon2-1-1024-1.odt",
        (1, 1024, 1),
        PASSWORD,
        "The tuple the encrypt arc already verified against LibreOffice 26.2.1.2. "
        "Re-open it to confirm that claim still holds on whatever version is "
        "installed now.",
    ),
    (
        "argon2-above-lo-default.odt",
        (4, 131072, 8),
        PASSWORD,
        "Above LibreOffice's default on every axis: 128 MiB and 8 lanes. Slow to "
        "open on purpose. Fails if LO caps what it will read, which nothing in "
        "its source suggests it does -- so this is the file that would prove it "
        "wrong.",
    ),
    (
        "argon2-lanes-only.odt",
        (3, 65536, 1),
        PASSWORD,
        "LibreOffice's tuple with p dropped from 4 to 1. Isolates parallelism: if "
        "this opens and the default does not, the problem is lanes and not the "
        "profile.",
    ),
]

GOLDEN_READ_SIDE = [
    ("lo-wholesome-gcm-argon2.odt", PASSWORD, "AES-256-GCM / Argon2id / SHA-256 — the profile `encrypt` writes"),
    ("lo-legacy-aes-cbc.odt", PASSWORD, "AES-CBC / PBKDF2 — read-only; `encrypt` cannot produce this (#59)"),
    ("aoo-blowfish-pbkdf2.odt", PASSWORD, "Blowfish-CFB / PBKDF2, ODF 1.1 — read-only (#59)"),
    ("lo-odf11-nonascii-password.odt", NONASCII, "ODF 1.1 with the `rtl_digest_SHA1` fallback ladder — read-only"),
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(path: Path, password: str) -> None:
    """Decrypt what we just wrote and check the text, through the shipped CLI.

    A generator that does not read back its own output will eventually commit a
    set of files nobody can open, and the failure would surface as a confusing
    LibreOffice session rather than as an error here. This is NOT a substitute
    for opening them by hand -- it exercises exactly the path the harness
    already covers -- it only rules out handing a person a file this crate
    itself cannot read.
    """
    out = path.with_suffix(".verify.tmp")
    env = dict(os.environ, ODF_ARTIFACT_PW=password)
    subprocess.run(
        ["cargo", "run", "--quiet", "--locked", "--no-default-features",
         "--features", "cli", "--bin", "odf-crypto", "--",
         "decrypt", str(path), "-o", str(out),
         "--password-env", "ODF_ARTIFACT_PW", "--force"],
        cwd=ROOT, env=env, check=True,
    )
    try:
        with zipfile.ZipFile(out) as z:
            body = z.read("content.xml").decode("utf-8", "replace")
        paragraphs = [re.sub(r"<[^>]+>", "", m) for m in
                      re.findall(r"<text:p[^>]*>(.*?)</text:p>", body, re.S)]
        if not any(EXPECTED_TEXT in p for p in paragraphs):
            raise SystemExit(f"{path.name}: decrypted, but the text is {paragraphs[:2]!r}")
    finally:
        out.unlink(missing_ok=True)


def generate(name: str, tuple_: tuple[int, int, int] | None, password: str) -> Path:
    out = HERE / name
    env = dict(os.environ, ODF_ENCRYPT_PASSWORD=password)
    if tuple_ is not None:
        t, m, p = tuple_
        env |= {"ODF_ARGON2_T": str(t), "ODF_ARGON2_M_KIB": str(m), "ODF_ARGON2_P": str(p)}
    else:
        # Belt and braces: a stale tuple inherited from the caller's shell would
        # silently produce a file whose manifest row says "default".
        for k in ("ODF_ARGON2_T", "ODF_ARGON2_M_KIB", "ODF_ARGON2_P"):
            env.pop(k, None)
    subprocess.run(
        ["cargo", "run", "--quiet", "--locked", "--no-default-features",
         "--features", "crypto-ops", "--example", "encrypt_for_validation",
         "--", str(PLAINTEXT), str(out)],
        cwd=ROOT, env=env, check=True,
    )
    return out


def main() -> int:
    if not PLAINTEXT.is_file():
        print(f"missing {PLAINTEXT}", file=sys.stderr)
        return 1

    rows = []
    for name, tuple_, password, why in CASES:
        out = generate(name, tuple_, password)
        verify(out, password)
        rows.append((name, tuple_, password, sha256(out), out.stat().st_size, why))

    lines = [
        "# Human-openable artifacts",
        "",
        "Generated by `make_artifacts.py`. **Open these in a real LibreOffice, by",
        "double-click, and type the password at the prompt.** That verdict outranks",
        "every automated check in this repository, because the automated ones drive",
        "UNO and a person does not.",
        "",
        "Nothing here ships in the published crate: `include` in `Cargo.toml` is an",
        "allowlist and no pattern names this directory. That is deliberate — these",
        "are evidence for a maintainer, not something a consumer compiles.",
        "",
        f"Every file decrypts to a document whose only paragraph reads **{EXPECTED_TEXT!r}**,",
        "and is `tests/goldens/lo-unencrypted.odt` sealed under the tuple in its row.",
        "",
        "Each was read back through this crate's own CLI at generation time and its",
        "text checked, so none of these is a file `odf-crypto` itself cannot open.",
        "**That is not the verdict this directory exists for.** It exercises the same",
        "path the automated suite already does; what is still owed is a person",
        "double-clicking these and typing the password. Record that below.",
        "",
        "## What a failure means",
        "",
        "| symptom | what it tells you |",
        "| --- | --- |",
        "| No password prompt at all | The package does not classify as encrypted to LibreOffice — a manifest problem, not a crypto one. The most serious failure here. |",
        "| Prompt, then \"wrong password\" | Key derivation disagrees: the start key, the salt, or the Argon2 tuple as written into the manifest. |",
        "| Prompt accepted, then a repair/recovery bar | The plaintext zip `decrypt` would return is malformed — an `encrypt` packaging bug, not a KDF one. |",
        "| Opens, but the text is wrong or empty | The cipher or the inflate is wrong while the checksum still passed. |",
        "| Opens correctly but takes minutes | Expected for `argon2-above-lo-default.odt`, and a finding for any other row. |",
        "",
        "## Write side — what `encrypt` produces",
        "",
        "One profile: single `encrypted-package` member, AES-256-GCM, Argon2id,",
        "SHA-256 start key, no checksum, `manifest:version=\"1.4\"`. Only the Argon2",
        "tuple varies below.",
        "",
        "| file | argon2 `(t, m_kib, p)` | password | bytes | sha256 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name, tuple_, password, digest, size, _ in rows:
        tup = "default `(3, 65536, 4)`" if tuple_ is None else f"`{tuple_}`"
        lines.append(f"| `{name}` | {tup} | `{password}` | {size} | `{digest}` |")

    lines += ["", "### Why each one is here", ""]
    for name, _, _, _, _, why in rows:
        lines += [f"**`{name}`** — {why}", ""]

    lines += [
        "## Read side — the profiles `encrypt` cannot write",
        "",
        "These are the existing goldens, listed here because the write set above",
        "covers one profile and the crate reads three. They are equally openable by",
        "hand and are the only evidence for the other two.",
        "",
        "| file (in `tests/goldens/`) | password | profile |",
        "| --- | --- | --- |",
    ]
    for name, password, profile in GOLDEN_READ_SIDE:
        g = ROOT / "tests" / "goldens" / name
        mark = "" if g.is_file() else " **(MISSING)**"
        lines.append(f"| `{name}`{mark} | `{password}` | {profile} |")

    lines += [
        "",
        "## Record the verdict here",
        "",
        "Add a line per session. An empty table below means **this set has not been",
        "opened by a human**, which is the state the plan gates the release on — not",
        "a formality, and not something a green CI run substitutes for.",
        "",
        "| date | LibreOffice version | OS | files opened | result |",
        "| --- | --- | --- | --- | --- |",
        "| | | | | |",
        "",
    ]

    (HERE / "MANIFEST.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {len(rows)} artifacts and MANIFEST.md in {HERE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
