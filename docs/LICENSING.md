# Licensing

Why `odf-crypto` ships as `MIT OR Apache-2.0`, and what it owes the two projects
it learned the format from.

> Engineering analysis, not legal advice. The reasoning and the evidence behind
> it are written out so a reader can check the conclusion rather than take it.

## Verdict

**Yes — `MIT OR Apache-2.0`, unconditionally.** Neither upstream imposes an
obligation on this crate, because nothing was copied from either. Both are
credited in the README anyway.

## 1. Can this crate be dual-licensed MIT OR Apache-2.0?

Yes. The dual license is the ordinary Rust convention and nothing here conflicts
with it.

The question is worth asking because the two directions differ. Apache-2.0
material sits comfortably under the Apache-2.0 half of a dual offer. It does
*not* sit under the MIT half: you cannot sublicense Apache-2.0 code as MIT alone,
because a downstream user choosing MIT would not receive the attribution and
patent terms that code carries. So if any Apache-2.0 expression had been copied
in, the MIT half would be over-granting.

None was. See §3.

## 2. LibreOffice — MPL-2.0

LibreOffice is the behavioural reference throughout. `classify` deliberately
mirrors LibreOffice's `package/` accept predicates rather than a spec-literal
reading of ODF, and the plan documents in `docs/plans/` cite specific upstream
source locations for individual decisions.

**MPL-2.0 copyleft is file-level.** It reaches files containing Covered Software,
not every project that studied it. Two things fall outside its reach:

- **The format.** OpenDocument is a published OASIS/ISO standard. Implementing
  it is not derivative of any particular implementation.
- **The behaviour.** Which accept predicate LibreOffice applies, which algorithm
  tuple it writes, that `rtl_digest_SHA1` emits a spurious block when
  `len(msg) % 64` falls in `{52, 53, 54, 55}` — these are facts about how a
  program behaves. Facts are not copyrightable; the code expressing them is.

Citing `ZipPackage.cxx` line numbers in a design document records *where a fact
was observed*. It is the opposite of concealment, and it is not itself copying.

**One quotation exists and is disclosed.** `tests/goldens/sha1_star.py` quotes a
three-line explanatory comment from LibreOffice's `sal/rtl/digest.cxx` (the
`tdf#114939` comment) while documenting the non-conforming SHA-1 that LibreOffice
retains for compatibility. It is short, attributed inline to its source file and
function, and explanatory rather than functional. That file is also excluded from
the published crate (see §5). Credited in the README regardless.

## 3. Horsmann/odfdecrypt — Apache-2.0

<https://github.com/Horsmann/odfdecrypt>, declared `license = "Apache-2.0"` in
its `pyproject.toml` with the full Apache text in `LICENSE`. Prior art solving
the same problem in Python, and useful confirmation that a reading of the format
was not idiosyncratic.

**Apache-2.0 §4(d) does not attach: the project carries no `NOTICE` file.** The
NOTICE-propagation obligation is conditional on the original having one.

**Nothing here derives from it.** Three independent lines of evidence:

1. **Naming.** Function-name overlap between odfdecrypt's modules and this
   repository's Python helpers is `decrypt` and `main` — both generic. The
   vocabularies are unrelated: odfdecrypt has `_decrypt_legacy_format`,
   `derive_key_argon`, `detect_origin`, `_parse_encryption_entry`; this
   repository has `_start_key`, `staroffice_sha`, `_flip_checksum`, `oq`,
   `sweep`. Ported code retains its donor's names.

2. **Contemporaneous documentation.** `tests/goldens/ref_decrypt.py` describes
   itself in its own docstring as *"an independent second implementation of the
   decrypt plan"*, written to pre-validate a slice before the Rust existed, with
   each step citing the plan section it implements.

3. **Deliberate divergence.** `src/lib.rs` states that `classify` follows
   LibreOffice's `package/` accept predicates, *not* Horsmann's origin detector.
   The two take different approaches to the central question.

Had anything been copied, the remedy would have been small — retain notices,
include the Apache license, state changes. It is not needed here.

## 4. Test fixtures

The six `.odt` files under `tests/goldens/` were generated for this project by
driving a local LibreOffice over UNO (`tests/goldens/make_goldens.py`). They are
program *output*, not program code, and carry no upstream licence. They contain
no third-party document content.

## 5. What ships

`Cargo.toml` uses an `include` allowlist. The published crate carries `src/**`,
the six `.odt` goldens, `examples/encrypt_for_validation.rs`, `README.md` and
both licence files — 29 files with cargo's own additions.

The Python helpers (`make_goldens.py`, `ref_decrypt.py`, `sha1_star.py`,
`validate_encrypt.py`) stay in git and on GitHub but leave the tarball. They are
UNO-driven developer tooling that no Rust code invokes. This is a packaging
decision, not a licensing one — but it does mean the one LibreOffice quotation
in §2 is not present in the crates.io artifact.

## 6. Dependencies

All runtime dependencies are permissively licensed (MIT / Apache-2.0 / dual), as
is typical for the RustCrypto stack this crate builds on. `secure-gate` is the
same author's crate. No copyleft dependency, so nothing constrains redistributing
this crate under MIT or Apache-2.0.

Verify with `cargo deny check licenses` or `cargo license` after any dependency
change — this section is a claim about the graph on the day it was written, and
a new transitive dependency could change it without anyone noticing.

## 7. Attribution given

Neither of the following is legally required on the analysis above. Both are in
the README because the work would have been substantially harder without them,
and because a reader deserves to know where the behaviour came from.

- **LibreOffice** (MPL-2.0) — the behavioural reference; source of the accept
  predicates, the algorithm defaults, and the `rtl_digest_SHA1` quirk.
- **Horsmann/odfdecrypt** (Apache-2.0) — prior art covering the same problem.

## 8. Standing actions

- [x] `license = "MIT OR Apache-2.0"` in `Cargo.toml`
- [x] `LICENSE-MIT` and `LICENSE-APACHE` present and shipped
- [x] Attribution section in `README.md`
- [x] LibreOffice quotation in `sha1_star.py` attributed at the point of use
- [ ] Re-check §6 whenever a dependency is added — the graph is not self-policing
- [ ] Revisit if code is ever *copied* from either upstream rather than written
      against observed behaviour. That changes the analysis, and the MIT half of
      the dual license is what would break first.
