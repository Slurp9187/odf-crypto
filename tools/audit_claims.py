#!/usr/bin/env python3
"""Read this project's prose back against the tree.

Lints check shape, not truth. Nothing here checks whether a sentence is *right* --
this checks the truths a machine can reach, which is a floor and not a substitute
for reading.

  A  relative links in Markdown resolve, AND resolve for a reader of the
     PUBLISHED crate, not merely for someone standing in a git checkout
  B  `file.rs:NNN` citations name a real source file with at least NNN lines
  C  backticked `module::item` paths name something findable in `src/`
  E  version and MSRV figures in the LIVE documents agree with `Cargo.toml`
  F  upstream `file.cxx:NNN` citations resolve against a local LibreOffice
     clone                                                       (local only)

Exit status is 1 if anything is flagged, 0 otherwise.

    python tools/audit_claims.py                  # A-C, E, plus F if the clone is there
    python tools/audit_claims.py --clone DIR      # point F elsewhere
    python tools/audit_claims.py --clone /nope    # skip F, as CI does

Adapted from msoffice-crypto's `tools/audit_claims.py`, same owner and the same
`MIT OR Apache-2.0` terms. **The check letters are deliberately kept**, including
the gaps, so the two files stay legible to someone who knows the other one -- the
same reason the two READMEs share a section order.

# The two checks that are deliberately absent

**D (a CLAUDE.md Layout block naming every `src/*.rs`) does not apply**: this
repository has no such block.

**G (CHANGELOG heading against Cargo.toml and the tags) is deliberately not
reimplemented.** The global `changelog-protocol` skill ships a checker that
already does it, and this repo's profile names it as the thing to run. A second
copy of a rule is free to drift from the first, which is the defect this whole
file exists to catch. Run that instead:

    python ~/.claude/skills/changelog-protocol/scripts/check_changelog.py

# What is deliberately NOT checked, and why

**Version figures in dated documents are exempt from E.** `CHANGELOG.md` and
everything under `docs/plans/`, `docs/audits/`, `docs/handoffs/` and
`docs/design/` are dated records; `docs/plans/` deliberately preserves decisions
that were later reversed, and a naive version check reports that as drift. They
are still checked for dead links and bad citations, because a dead link is dead
whenever it was written.

**E matches syntactic contexts, not every version-shaped string.** A blanket scan
flags six legitimate historical mentions in `src/limits.rs` alone -- "it was
`1 << 16` until `0.1.0-rc.6`" is a true sentence about the past. A check with
false positives on correct files is worse than no check, because it trains the
reader to skip the output.

# Proved by breaking what it guards

A check that passes on a clean tree has demonstrated nothing. Every arm was made
to fire before this shipped, and the tree restored:

    A  a link to a file that is not there            -> dead relative link
    A  a README link to `docs/LICENSING.md`          -> resolves on disk but is
                                                        not in the published crate
    B  `decrypt.rs:999999`                           -> past the end (file has 1158)
    B  `nosuch.rs:12`                                -> names no such source file
    C  `decrypt::no_such_fn_here`                    -> names nothing in src/
    E  `odf-crypto = "0.1.0-rc.3"` in README         -> disagrees with Cargo.toml
    E  "Requires Rust 1.99." in src/lib.rs           -> MSRV disagrees
    F  `ZipFile.cxx:9999999`                         -> past the end of every candidate
    F  `NoSuchThing.cxx:12`                          -> names no such file

The A case is not invented. A relative link into `docs/` was written into the
README during the rc.7 restructure and caught by reading, which is the only
reason this arm exists.

# The first run found eleven things and all eleven were wrong

Both causes are worth keeping, because each made the check SHARPER rather than
more permissive, and a naive reader would have taken either as a real defect:

  * One "dead link" was `file-plan-issues` quoting `[plan](docs/plans/x.md)` as
    an example of a link you must NOT write. Prose about markup quotes the
    markup -- hence `code_spans`.
  * Ten citations were into dependencies: `argon2-0.5.3/src/lib.rs:230`,
    `zip-2.4.2/src/result.rs:19`, `quick-xml-0.38.4/src/errors.rs:98`. Matching
    a basename and ignoring the path in front of it reported ten files as
    missing that were never ours -- hence `ours`.
"""

import argparse
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_CLONE = pathlib.Path("o:/projects-github-clones/LibreOffice/core")

# Documents whose factual claims are live and must track the tree.
LIVE_DOCS = ["README.md", "CLAUDE.md", "docs/LICENSING.md", "docs/plan-workflow.md"]
# Dated records: links and citations checked, version figures exempt. See the docstring.
DATED_DIRS = ["docs/plans", "docs/audits", "docs/handoffs", "docs/design"]
DATED_FILES = ["CHANGELOG.md"]

PRUNE = {".git", "target", "__pycache__"}


def read(p):
    return p.read_text(encoding="utf-8", errors="replace")


def line_of(txt, pos):
    return txt[:pos].count("\n") + 1


def code_spans(txt):
    """(start, end) of every inline code span and fenced block.

    Prose about markup quotes the markup. `file-plan-issues` shows
    ``[plan](docs/plans/x.md)`` as an example of a link you must NOT write, and a
    naive link check calls that file broken -- flagging a document for correctly
    describing the defect it is warning about.
    """
    return [(m.start(), m.end()) for m in
            re.finditer(r"```.*?```|``.*?``|`[^`\n]*`", txt, re.S)]


def in_code(pos, spans):
    return any(a <= pos < b for a, b in spans)


def ours(prefix):
    """Is a `file.rs:NNN` citation about THIS crate?

    A bare basename is, and so is `src/`-relative. A vendored path is not:
    `argon2-0.5.3/src/lib.rs:230` and `zip-2.4.2/src/result.rs:19` are citations
    into dependencies, and matching on the basename alone reports ten of them as
    missing files that were never ours to have.
    """
    return prefix in ("", "src/")


def live_docs():
    out = [ROOT / n for n in LIVE_DOCS]
    # The repo profiles are live: they state facts about this tree.
    out += sorted((ROOT / ".claude" / "skills").glob("*/SKILL.md"))
    return [p for p in out if p.exists()]


def dated_docs():
    out = [ROOT / n for n in DATED_FILES]
    for d in DATED_DIRS:
        out += sorted((ROOT / d).glob("**/*.md"))
    return [p for p in out if p.exists()]


def packaged():
    """Paths `cargo package` would ship, or None when cargo cannot answer.

    Read the LIST, never the `include` allowlist: cargo auto-includes `README.md`
    and the licence files without their appearing in `include`, so reading the
    allowlist reports shipping files as broken.
    """
    try:
        r = subprocess.run(
            ["cargo", "package", "--locked", "--allow-dirty", "--list", "--features", "cli"],
            cwd=ROOT, capture_output=True, text=True, timeout=300,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return {ln.strip().replace("\\", "/") for ln in r.stdout.splitlines() if ln.strip()}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--clone", type=pathlib.Path, default=DEFAULT_CLONE,
                    help="a LibreOffice core checkout for check F; a nonexistent path skips it")
    args = ap.parse_args()

    src = sorted(ROOT.glob("src/**/*.rs"))
    src_text = {p.name: read(p) for p in src}
    src_lines = {name: len(txt.splitlines()) for name, txt in src_text.items()}
    all_src = "\n".join(src_text.values())

    flags = []

    def flag(kind, msg):
        flags.append(f"{kind}: {msg}")

    LIVE, DATED = live_docs(), dated_docs()
    ALL = LIVE + DATED
    ship = packaged()

    # ---- A: relative links ---------------------------------------------------------
    # Two properties, and the second is the one that bites. A link can resolve on disk
    # and still be dead for every reader of the published crate, because `include` is an
    # allowlist and `docs/` is not in it. Not hypothetical: such a link was introduced
    # and caught by hand during the rc.7 README restructure.
    for p in ALL:
        txt, rel = read(p), p.relative_to(ROOT).as_posix()
        spans = code_spans(txt)
        for m in re.finditer(r"\]\((?!https?:|#|mailto:)([^)#]+)(?:#[^)]*)?\)", txt):
            if in_code(m.start(), spans):
                continue  # a link inside backticks is being displayed, not followed
            target = m.group(1).strip()
            resolved = (p.parent / target).resolve()
            where = f"{rel}:{line_of(txt, m.start())}"
            if not resolved.exists():
                flag("A dead relative link", f"{where} -> {target}")
                continue
            if ship is None or rel not in ship:
                continue
            try:
                inside = resolved.relative_to(ROOT).as_posix()
            except ValueError:
                flag("A link escapes the repository", f"{where} -> {target}")
                continue
            if inside not in ship:
                flag("A link resolves on disk but is not in the published crate",
                     f"{where} -> {target} (use an absolute URL)")

    # ---- B: this repository's own file:line citations --------------------------------
    own = re.compile(r"((?:[\w.+-]+/)*)([A-Za-z0-9_]+\.rs):(\d+)(?:-(\d+))?")
    for p in ALL:
        txt, rel = read(p), p.relative_to(ROOT).as_posix()
        for m in own.finditer(txt):
            if not ours(m.group(1)):
                continue
            name, lo, hi = m.group(2), int(m.group(3)), m.group(4)
            where = f"{rel}:{line_of(txt, m.start())}"
            if name not in src_lines:
                flag("B citation names no such source file", f"{where} -> {name}")
                continue
            top = int(hi) if hi else lo
            if top > src_lines[name]:
                flag("B citation past the end of the file",
                     f"{where} -> {name}:{top}, file has {src_lines[name]}")

    # ---- C: backticked module::item --------------------------------------------------
    # Conservative on purpose: only paths whose first segment is a real module here, and
    # only flagged when the item appears nowhere in `src/`. A broad version of this check
    # flags every `std::` and `argon2::` path and is worse than nothing.
    mods = {p.stem for p in src}
    for p in ALL:
        txt, rel = read(p), p.relative_to(ROOT).as_posix()
        for m in re.finditer(r"`([a-z][a-z0-9_]*)::([A-Za-z_][A-Za-z0-9_]*)`", txt):
            mod, item = m.group(1), m.group(2)
            if mod not in mods:
                continue
            if not re.search(rf"\b{re.escape(item)}\b", all_src):
                flag("C module::item names nothing in src/",
                     f"{rel}:{line_of(txt, m.start())} -> {mod}::{item}")

    # ---- E: versions and MSRV, live documents only -----------------------------------
    cargo = read(ROOT / "Cargo.toml")
    pkg = re.search(r'^version = "([^"]+)"', cargo, re.M).group(1)
    msrv = re.search(r'^rust-version = "([^"]+)"', cargo, re.M).group(1)
    # `src/lib.rs` carries the MSRV sentence that renders on docs.rs, so it is checked
    # here even though it is not Markdown and is not in LIVE_DOCS.
    PATS = [
        (r'odf-crypto = "([^"]+)"', "pkg", "package version"),
        (r'odf-crypto = \{ version = "([^"]+)"', "pkg", "package version"),
        (r"This is `([^`]+)`", "pkg", "package version"),
        (r"Rust \*?\*?(\d+\.\d+)", "msrv", "MSRV"),
        (r"MSRV (\d+\.\d+)", "msrv", "MSRV"),
    ]
    want = {"pkg": pkg, "msrv": msrv}
    for p in LIVE + [ROOT / "src/lib.rs"]:
        if not p.exists():
            continue
        txt, rel = read(p), p.relative_to(ROOT).as_posix()
        for pat, key, what in PATS:
            for m in re.finditer(pat, txt):
                if m.group(1) != want[key]:
                    flag(f"E {what} disagrees with Cargo.toml",
                         f"{rel}:{line_of(txt, m.start())} says {m.group(1)}, "
                         f"Cargo.toml says {want[key]}")

    # ---- F: upstream citations, only when the clone is here --------------------------
    # LibreOffice's behaviour IS this crate's specification, and CLAUDE.md, the plans and
    # the README cite it by line. Those numbers drift every time upstream moves, and in a
    # repository whose first rule is that a claim carries its proof, an unverifiable
    # citation is worse than none.
    clone = args.clone
    if clone is not None and clone.exists():
        index = {}
        for dirpath, dirnames, filenames in os.walk(clone):
            dirnames[:] = [d for d in dirnames if d not in PRUNE]
            for f in filenames:
                if f.endswith((".cxx", ".hxx", ".cpp", ".hpp", ".h", ".c")):
                    index.setdefault(f, []).append(pathlib.Path(dirpath) / f)
        up = re.compile(r"\b([A-Za-z0-9_]+\.(?:cxx|hxx|cpp|hpp|h)):(\d+)(?:-(\d+))?")
        checked = 0
        for p in ALL:
            txt, rel = read(p), p.relative_to(ROOT).as_posix()
            for m in up.finditer(txt):
                name, lo, hi = m.group(1), int(m.group(2)), m.group(3)
                where = f"{rel}:{line_of(txt, m.start())}"
                if name not in index:
                    flag("F upstream citation names no such file", f"{where} -> {name}")
                    continue
                top = int(hi) if hi else lo
                # A basename can be ambiguous upstream, so accept when ANY candidate is
                # long enough -- and say so, rather than implying the citation is pinned.
                if not any(len(read(c).splitlines()) >= top for c in index[name]):
                    flag("F upstream citation past the end of every candidate",
                         f"{where} -> {name}:{top}")
                    continue
                checked += 1
        print(f"check F: {checked} upstream citations verified against {clone}")
    else:
        print(f"check F: SKIPPED, no LibreOffice clone at {clone}")

    if ship is None:
        print("check A: packaging half SKIPPED, `cargo package --list` did not answer")

    for f in sorted(flags):
        print(f, file=sys.stderr)
    print(f"{len(ALL)} documents checked, {len(flags)} flagged")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
