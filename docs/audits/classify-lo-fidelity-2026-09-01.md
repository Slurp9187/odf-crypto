Status: Audit — applied and verified 2026-09-01 against `07047a02f94d` · A1–A10, B1–B7, C1–C7, D1–D7 landed · see §Verification pass

# Audit — `classify` vs LibreOffice `package/`

> **Scope.** Adversarial audit of the full arc [#1](https://github.com/Slurp9187/odf-crypto/issues/1)
> implementation — S1–S6, `src/` and `src/classify_tests.rs` — against LibreOffice
> `package/` at the plan's pin. Not a code review: the question is only _where does
> `classify` answer differently than LibreOffice_, on input that can be constructed.
>
> **Verdict.** The crate reproduces LO's **manifest semantics** closely and its
> **zip-acceptance semantics** hardly at all. The accept predicates, both latch sites,
> sticky `key_info`, order-dependent `derived_key_size` and the URI table all came back
> clean. Divergences cluster at two seams no slice owned: the integer and base64
> primitives underneath Stage A, and everything that decides whether LO opens the
> archive at all.

## Authority

Same trees and pin as the plan. Do not re-download.

| Tree             | Path                                         | Pin                                                |
| ---------------- | -------------------------------------------- | -------------------------------------------------- |
| LibreOffice core | `O:\projects-github-clones\LibreOffice\core` | `07047a02f94d`, verified checked out at audit time |
| odfdecrypt       | `O:\projects-github-clones\odfdecrypt`       | not consulted; this audit scores against LO only   |

Files cited beyond the plan's list: `package/source/manifest/ManifestReader.cxx`,
`package/source/zipapi/ZipFile.cxx`, `comphelper/source/misc/base64.cxx`,
`comphelper/source/misc/storagehelper.cxx`, `sal/rtl/strtmpl.hxx`,
`sax/source/expatwrap/sax_expat.cxx`, `package/inc/HashMaps.hxx`.

## Reading this file

Every finding has a stable id. Cite the id in an issue body; do not restate the
finding there.

| Group | Meaning                                                                                                        | Ids    |
| ----- | -------------------------------------------------------------------------------------------------------------- | ------ |
| **A** | `classify` returns a different `Mode` / `package_encrypted` / `common` / `odf_version` / `odf12_fatal` than LO | A1–A10 |
| **B** | LO refuses the archive outright; `classify` returns a confident `Classification`                               | B1–B7  |
| **C** | Verdict agrees; a reported field of `EntryEncryption` / `Classification` is wrong                              | C1–C7  |
| **D** | Implementation is correct, but the named behaviour survives mutation with the suite green                      | D1–D7  |

Findings marked **unrefuted** came from the completeness pass after verification
closed. They carry less evidence than the rest — treat them as the next thing to
check, not as settled.

`measured` means reproduced end to end through the public `classify()` in a scratch
copy of the crate, not reasoned from source.

## A. Divergences that change the answer

### A1 — `parse_i32` / `parse_i64` are not `OUString::toInt32` / `toInt64`

`src/manifest.rs:452-469` · `sal/rtl/strtmpl.hxx:638-651` (`HandleSignChar`), `:662-703` (`toInt`)

The highest-value fix in this file. One helper feeds `manifest:size`,
`iteration-count`, `key-size`, and all three Argon2 parameters, so its divergence
reaches the accept predicate rather than only a reported field.

LO consumes one optional leading `+` or `-`, then folds digits until the first
non-digit, returning 0 only on overflow. The crate's
`take_while(|c| c.is_ascii_digit() || *c == '-')` has no `+` in the set, so the digit
run is empty and `parse()` falls through to `unwrap_or(0)`.

```
manifest:argon2-iterations="+3" on an otherwise complete row
  LO    → t=3, m,p > 0 → Argon2Args written → PerEntry, encrypted
  crate → t=0 → ignore_encrypt_data, argon2_args None → Plain, not encrypted   (measured)

iteration-count="+100000" → 0 (LO 100000) · key-size="+32" → 0 (LO 32)
embedded '-' ("12-3")     → 0 (LO 12)
```

**Fix.** Port `toInt` directly: skip LO's `implIsWhitespace` set — _not_ Rust's
`trim`, which also strips U+00A0 — take at most one sign character, fold ASCII
digits, return 0 on overflow. A hand-written loop, not `take_while` + `str::parse`.

Found independently by three dimensions. `HandleSignChar` read in-source during
write-up.

### A2 — Level-2 elements are gated on the root frame's validity

`src/manifest.rs:122-125` · `ManifestImport.cxx:335-345` (case 2) vs `:346-351` (case 3)

LO's `switch (nLevel)` has **no** parent-validity test in `case 1` or `case 2`. The
`aIter->m_bValid` check first appears in `case 3` and repeats for 4, 5, 6. The
crate's blanket `if level > 1 && !self.parent_valid()` invents that gate one level
too high, so a root element that is not `manifest:manifest` invalidates level 1 and
then drops every `file-entry` and every `manifest:encrypted-key` beneath it.

```
<manifest:manifest-typo xmlns:manifest="urn:oasis:...manifest:1.0">
  <manifest:file-entry manifest:full-path="content.xml" ...complete encryption-data.../>

  LO    → 2 rows, content.xml complete → SetIsEncrypted → PerEntry, encrypted
  crate → 0 bags → Plain, odf_version None, media_type None                    (measured)
```

**Fix.** Apply the guard only for `level >= 3`, mirroring LO's per-case structure.

Found independently by three dimensions. Read in-source during write-up.

### A3 — A malformed `manifest.xml` hard-errors or keeps partial rows

`src/manifest.rs:490-530`, `src/classify.rs:43` · `ManifestReader.cxx:46-75`, `ZipPackage.cxx:453`

An entire LO layer is unmodelled. `ManifestReader::readManifestSequence` declares
its result sequence _before_ parsing, converts the accumulated vector only on
success, and catches `SAXParseException` / `SAXException` / `IOException` — so any
XML error discards every row already collected. `ZipPackage::parseManifest` then runs
a zero-iteration row loop and still sets `bManifestParsed = true`, so nothing
downstream throws and the package opens as a plain ODF document.

```
(a) truncated manifest, root never closed
      crate → Ok, PerEntry, package_encrypted = true, odf_version Some("1.3")
      LO    → 0 rows → Plain, root version empty                               (measured)

(b) one mangled end tag
      crate → Err(Manifest("ill-formed document ..."))
      LO    → 0 rows, opens as a plain ODF text document                       (measured)
```

**Fix.** On any reader error, and on `Eof` with a non-empty element stack, discard
`import.bags` and return `Ok(vec![])`. Reserve `DetectError::Manifest` for non-XML
failures. Note this also subsumes C6.

### A4 — `Mode::Wholesome` is keyed on a row's short name, not the root member's row

`src/classify.rs:118-125`

Plan §6 step 12 and issue [#4](https://github.com/Slurp9187/odf-crypto/issues/4)'s
first Do bullet both say Wholesome requires the zip's root `encrypted-package` member
**and that member's** bag to be complete. The implementation sets
`encrypted_package_complete` from `short_name(entry.path) == "encrypted-package"`, so
a complete `Object 1/encrypted-package` row satisfies it while the root member's own
row is incomplete.

The same short-name test captures `encrypted_package_media_type` from a nested row,
which then feeds the mimetype comparison at `classify.rs:158-163` and produces a
spurious `DetectError::Inconsistent` where LO (`ZipPackage.cxx:520-522`) reads the
root member's media-type and does not throw.

**Fix.** Gate on `bag.full_path == "encrypted-package"`; better, store media-type on
the resolved stream node and read it back from the tree.

### A5 — Folder rows never _clear_ media-type or version

`src/zip_tree.rs:120-146`, `src/classify.rs:114` · `ZipPackage.cxx:237`, `:289-290`

LO declares `sMediaType` and `sVersion` fresh inside the row loop and calls
`SetMediaType` / `SetVersion` unconditionally, so a later bare `/` row blanks the
root. The crate models both as `Option` and skips `None`, so the first row's values
stick permanently.

```
rows: / (media-type odt, version 1.2) → / (bare) → content.xml
zip also carries an unreferenced stray.txt

  LO    → root version "" → not ODF-1.2 → opens, not fatal
  crate → odf_version Some("1.2") → odf12_fatal = true                         (measured)
```

The mirror case: the stale root media-type turns the mimetype check into a false
`DetectError::Inconsistent` where LO takes the empty-media-type fallback and opens.

**Fix.** Have Stage A record `Some("")` for an absent attribute — LO's MediaType
property name is always set (`ManifestImport.cxx:77-78`), so `erase_if` never removes
it — and assign unconditionally in `set_folder_meta`.

### A6 — `zip_has_encrypted_package` requires a stream; LO's `hasByName` is kind-agnostic

`src/classify.rs:31`, `src/zip_tree.rs:51-53` · `ZipPackageFolder.cxx:221-224`, `ZipPackage.cxx:520`, `:535-536`

A zip carrying `encrypted-package/inner.bin` gives LO a root _folder_ of that name.
`hasByName` matches it, so LO runs the wholesome allow-list scan and takes the
folder's empty media-type into the mimetype comparison, throwing at
`ZipPackage.cxx:525`. The crate reports `zip_has_encrypted_package = false` and a
clean result. (measured)

**Fix.** Add a kind-agnostic `root_has_entry(name)` and use it for both the
`encrypted-package` and `mimetype` root lookups. See A7.

### A7 — `read_mimetype` consults the flat zip namelist, not the folder tree

`src/classify.rs:48-63` · `ZipPackage.cxx:474`

The one anti-pattern plan §1 names verbatim — _"Do not implement 'path exists in the
zip' as `zip.namelist().contains(path)`"_ — and one of the four state leaks arc #1
lists as its close condition. Three of the four are honoured; this is the leak.

LO uses `m_xRootFolder->hasByName(u"mimetype")`. A package whose only root node named
`mimetype` is a folder (member `mimetype/x`) makes LO read an empty media-type and
throw `ZipIOException("mimetype conflicts with manifest.xml, ...")`; the crate sees
no `mimetype` at all and returns a fully clean `Ok`. (measured)

The bare-directory-entry variant (`mimetype/`) is not a reliable trigger — LO's
`ZipFile.cxx:1488-1494` may skip it depending on the writing tool. Use `mimetype/x`.

### A8 — A leading-slash folder row resolves to the root in LO; the crate drops it

`src/zip_tree.rs:95-98` vs `:129-146` · `ZipPackage.cxx:1057-1081`, `:978-998`

`resolve`'s `Some(0)` arm returns `Folder` for a path with an empty first segment,
but `set_folder_meta` then walks that empty component and bails — so the row is
accepted and silently discarded. LO's walk breaks at the same point and hands back
the folder reached so far, which is the **root**.

```
row: full-path="/Pictures/" media-type="...text" version="1.2"
     (no Pictures member needed — LO never checks for one)

  LO    → root media-type and version set from this row, then the mimetype
          comparison throws ZipIOException
  crate → Ok, media_type None, odf_version None                                (measured)
```

**Fix.** Have `resolve` return the node it landed on and apply the row to that node,
instead of re-deriving the target from the path string in `set_folder_meta`.

### A9 — `insert_path` discards every component after an empty path segment

`src/zip_tree.rs:230-233` · `ZipPackage.cxx:654-686` (`getZipFileContents`)

```
member a//content.xml + a complete AES-CBC/PBKDF2 row for it
  LO    → stream a/content.xml exists, row resolves, getName()=="content.xml"
          → m_bHasEncryptedEntries → encrypted
  crate → member never inserted → row unresolvable → Plain                     (measured)

member META-INF//manifest.xml
  LO    → parses the manifest normally
  crate → Err(MissingManifest)                                                 (measured)
```

**Fix.** Walk folder segments up to the first empty segment without aborting, then
insert the stream named after the final `/` into the folder reached. Keep `resolve`
on the same truncated walk.

### A10 — LO's `m_aRecent` lookup cache is off by one level for folder paths — **implemented 2026-09-01**

`ZipPackage.cxx:996`, `:1079`, `:623-680`, `:1012-1090`

LO caches hierarchical-name lookups in `m_aRecent`, keyed on everything before the
last `/`, never cleared across rows. Stream lookups cache the containing folder
(correct). Folder-shaped paths on the **miss/walk** path store `pPrevious` (the
parent), one level too shallow. `getByHierarchicalName` still returns `pCurrent`
(the real folder), so folder meta applies correctly; the poison is the next cache
hit.

The naive `Pictures/` + `Pictures/photo.png` pair does **not** flip: insert already
seeded `["Pictures"]` correctly, and a later `Pictures/` is a hit (`getName()`
matches) that does not overwrite. The realistic flip is a nested member that
never seeds `"Pictures"`:

```
zip: content.xml + Pictures/album/photo.png
manifest: Pictures/ folder row, then Pictures/content.xml with a complete encryption bag

  LO    → Pictures/ miss caches ROOT; Pictures/content.xml hits ROOT.content.xml
          → package_encrypted, latch getName()=="content.xml"
  crate (before) → Pictures/content.xml does not resolve → Plain
```

`FolderTree` now carries a mutable `recent: HashMap<String, Vec<String>>` seeded
like `getZipFileContents` (containing folder on cache miss). `resolve` is
`hasByHierarchicalName` cache + walk: folder miss caches `pPrevious` (skipped when
previous is None), returns walked `pCurrent`. Stream cache hit is a child of the
cached folder. `set_folder_meta` / `mark_from_manifest` / `EntryEncryption.path`
use the **resolved tree path**, not `bag.full_path`. V2 empty-segment keys stay
insert-seeded (`a//content.xml` → `"a/"`); `/content.xml` still misses.

Regression tests: `folder_row_poisons_recent_one_level_too_shallow`,
`pictures_photo_insert_does_not_poison_folder_lookup`,
`pictures_folder_row_poisons_nested_content_xml_onto_root`,
`pictures_photo_insert_then_folder_row_does_not_poison`.

## B. LO refuses the archive; `classify` answers

Everything here is a whole-package refusal in LO — `ZipException` or `ZipIOException`
before any classification happens — where `classify` returns a `Classification` with
a confident `Mode` and a full algorithm tuple.

**Whether the crate should reproduce refusals at all is a design call the plan never
makes.** Right now it is unmade rather than decided, and the four state leaks arc #1
enumerates are all manifest-side. Decide it before fixing B1–B7 piecemeal.

### B1 — `checkZipEntriesWithDD` is not modelled anywhere — **unrefuted**

`ZipPackage.cxx:180-207`, called at `:456`

Not zip trivia: a direct cross-check of the manifest accept predicate against the
zip's physical shape. For every entry that is STORED with the data-descriptor flag
set, LO resolves it and throws `ZipIOException` unless it is a stream whose
`WasEncrypted` is true. **Every encrypted member of a real LO or AOO ODF is exactly
that shape** — it is live on all three goldens.

```
delete one <encryption-data> element from a real golden
  LO    → "Bad Zip File", package unopenable
  crate → clean PerEntry, encrypted
```

Any future change to which rows are accepted silently changes whether LO would open
the file, and nothing in the crate or its tests models that coupling.

### B2 — Zip entry names are never validated

`src/classify.rs:19-31` · `ZipFile.cxx:1407-1408`, `comphelper/source/misc/storagehelper.cxx:567-600`

```
member a/../content.xml with a complete row
  LO    → ZipException at readCEN, file unopenable
  crate → PerEntry, package_encrypted = true                                   (measured)

also rejected by LO, accepted here:
  /evil.bin · C:/evil.bin · Pictures\photo.png · control chars                 (measured)
```

The comment at `src/zip_tree.rs:215` is right that LO's `\`→`/` rewrite is
recovery-only; the missing piece is the _rejection_ at CEN time.

**Fix.** Port `IsValidZipEntryFileName(name, true)` over every member name in
`classify` before the tree is built.

### B3 — Duplicate central-directory entries let a crafted file choose its answer

`src/classify.rs:19-41` · `ZipFile.cxx:1496-1500`, `:1502-1517`

LO throws `ZipException("Duplicate CEN entry")`, and for ODF also arms the
case-insensitive variant (`m_nFormat` is `PACKAGE`, so `Checks::TryCheckInsensitive`).
The crate builds its name list with `by_index` but reads the manifest with `by_name`,
so two records named `META-INF/manifest.xml` resolve last-wins: order the plain
manifest first and the encrypted one second to pick the verdict. (measured — the
crate parsed the second manifest)

A related claim that the _folder tree_ keeps the first occurrence was **refuted**:
`ZipFile::aEntries` is an `unordered_map` (`package/inc/HashMaps.hxx:30-31`), so
first-wins was never LO's behaviour.

### B4 — Stream/folder collisions are dropped silently instead of rejecting the package

`src/zip_tree.rs:247-250` · `ZipPackage.cxx:670-677`, `:890-913`

When a path component names something already bound to a stream, LO throws at
tree-build time. `insert_path` is infallible: it returns, dropping the member and
every later component, and `classify` returns a clean `Ok`. Verification narrowed one
detail — LO does not iterate the zip in physical order, so _which_ member wins the
collision is not deterministic from file order — but the divergence holds.

### B5 — FAT directory entries LO skips are inserted and flagged inconsistent

`src/classify.rs:19-31` · `ZipFile.cxx:1488-1494`

LO skips a member whose uncompressed size is 0, whose version-made-by high byte is 0,
and whose external attributes carry `FILE_ATTRIBUTE_DIRECTORY`. The crate inserts it.

```
wholesome package + an empty DOS directory entry Pictures/
  LO    → skipped → consistent
  crate → Wholesome, has_unexpected_streams = true, odf12_fatal = true         (measured)
```

Only the no-trailing-slash form diverges unconditionally; a trailing-slash entry
diverges when it creates a root folder in a wholesome package or a subfolder under
META-INF. **Fix at the source** in `classify.rs` using the zip crate's per-entry
metadata, not in `zip_tree`.

### B6 — Entry names are CP437-decoded when GP bit 11 is clear

`src/classify.rs:19-28` · `ZipFile.cxx:1403-1405`

LO always decodes UTF-8. A member such as `Pictures/ä.png` written without the UTF-8
flag gets a different name in the tree than in its manifest row, so the row never
resolves and the stream reads as unlisted: `has_unexpected_streams` and `odf12_fatal`
both flip true on an ODF 1.2 package LO calls consistent.

**Fix.** Build the tree from `name_raw()` decoded UTF-8-lossy. `by_name` for
`META-INF/manifest.xml` is unaffected — that path is pure ASCII.

### B7 — Quadratic namespace resolution; a 730-byte zip occupies `classify` for 12–25 s

`src/manifest.rs:60-69`, `src/classify.rs:38` · `ManifestImport.cxx:604-615`

`convert_name` rescans the whole element stack on every event. LO's `ConvertName` has
the same O(depth) scan but feeds the SAX parser from the `XInputStream` rather than
materialising the manifest.

```
manifest of 60,000 nested <a> elements, deflated → 730 bytes
  classify → Ok(Plain) after 12.1 s measured (17-25 s on the reporting machine)
  894 bytes → 100 s · 1,553 bytes → 315 s
```

`read_to_end` is bounded by deflate's ~1032:1 ratio, so 1 MB of input buys ~1 GB.

**Fix.** Keep an incremental `(prefix, uri, frame_index)` binding stack so resolution
is O(1) amortised, and cap nesting depth — the code already invalidates everything
past level 6 at `src/manifest.rs:204`, so a cap costs nothing.

## C. Right verdict, wrong tuple

The accept predicate agrees with LO; a returned field does not. These matter
precisely because the crate exists to hand a typed description to a later crypto crate.

### C1 — `decode_b64` returns an empty vector where LO's decoder cannot fail

`src/manifest.rs:471-479` → `:302`, `:347`, `:366`, `:425` · `comphelper/source/misc/base64.cxx:142-208`

`Base64::decodeSomeChars` skips any character outside its table without resetting the
4-symbol accumulator and emits every complete quad. It has no failure mode. The crate
hands the string to the `STANDARD` engine, which requires canonical padding, and maps
`Err` to `Vec::new()` — so the row is still reported as encrypted, with an empty salt,
IV or checksum and no error anywhere.

```
"AQIDBA"         (unpadded)   → crate []   LO [1,2,3]
"CCCC*CCCCCCC…"  (stray *)    → crate []   LO 15 bytes
"QUJD="          (interior =) → crate []   LO [65,66,67]                       (measured)
```

Whitespace is already handled correctly by the filter at `:472`. The concrete harm is
a later decrypt crate receiving `Kdf::Pbkdf2 { salt: [] }` from a third-party writer's
unpadded base64.

**Fix.** Port `decodeSomeChars`: map through LO's table over `'+'..='z'` (note `'='`
maps to 0 and participates in the group), skip anything else, emit only complete
quads, drop a trailing partial group. It cannot fail, which removes the
`unwrap_or_default()` entirely.

### C2 — `derived_key_len: u8` silently clamps LO's `sal_Int32`

`src/classify.rs:258`, `:267`, `src/types.rs:68` · `ManifestImport.cxx:283-294`, `ZipPackage.cxx:418-419`, `:428`

LO reads `manifest:key-size` into a `sal_Int32` with no floor and no ceiling.
`key-size="256"` — a plausible bits-for-bytes mistake by a third-party writer —
reports 255; `"-8"` reports 0, which is also the legitimate value LO produces for
`key-size="0"`. The defaulting cascade itself is faithful; only the width is not.
(measured)

**This cannot be fixed as an implementation bug alone.** The public API matches plan
§5 exactly and §5 specifies `u8`. See "Plan amendments".

### C3 — `Event::GeneralRef` is dropped, deleting every entity reference in text

`src/manifest.rs:510-527`; false comment at `:513-515`

quick-xml 0.38 splits element text at `&…;` and delivers the reference as its own
event; the `_ => {}` arm deletes it. The comment at `src/manifest.rs:513-515` —
_"decode already unescapes entities when the reader is configured that way"_ — is
false: there is no `unescape()` on `BytesText` in 0.38 and `decode()` does charset
decoding only. Attribute values are fine (`decode_and_unescape_value`); only text
nodes are affected.

```
<loext:PGPKeyID>QUJ&#68;RUZH</loext:PGPKeyID>
events: Text("QUJ") · GeneralRef("#68") · Text("RUZH")
  crate → "QUJRUZH" → base64 error → key_id = []
  LO    → "QUJDRUZH" → 6 bytes                                                 (measured)
```

Unobservable in `Classification` today — `EncryptedKey` is `pub(crate)`, is not
re-exported, and only `key_info.is_some()` is read — but it is exactly the parse S5
will start typing. Delete the comment either way.

### C4 — No XML attribute-value whitespace normalization

`src/manifest.rs:498-501` · expat via `ManifestReader.cxx:49` → `sax_expat.cxx:431`

Expat applies XML §3.3.3 normalization: a literal tab, CR or LF inside an attribute
value becomes a space. `algorithm-name="Blowfish⏎CFB"` written with a real line break
is `"Blowfish CFB"` to LO — row accepted, package encrypted — and a rejected row here,
so `Plain`. (measured)

This flips the verdict, but only on a hand-written manifest. Verification corrected
the trigger: a character reference (`&#x0A;`) is _protected_ from normalization and
behaves identically in both, so the trigger needs a raw byte.

**Fix.** Map literal `\t`, `\n`, `\r` to a single space after unescaping, in the
attribute loop in `parse_manifest`. Do not collapse runs.

### C5 — A second `encryption-data` in one file-entry re-reads the checksum in LO

`src/manifest.rs:337-348` · `ManifestImport.cxx:158-177`

LO reads `manifest:checksum` whenever the _accumulated_ `DigestAlgorithm` already has
a value (`:171-177`); the crate reads it only when _this_ element's checksum-type
mapped. With a second element carrying `checksum-type="bogus"`, LO reports that
element's digest bytes and the crate keeps the first; if the second omits the
attribute entirely, LO reports an empty digest. (measured)

**Fix.** Set `digest_alg` from `checksum_alg_from_type` on a match as now, then write
`digest` independently whenever `bag.digest_alg.is_some()`.

### C6 — A non-UTF-8 `manifest.xml` aborts `classify`

`src/manifest.rs:483`; quick-xml's `encoding` feature is off (`default = []`)

Recorded with its correction attached, because the original finding got LO's
mechanism wrong. A declared legacy encoding (`ISO-8859-1` with a 0xE9 byte) parses in
LO and returns `DetectError::Manifest("cannot decode input using UTF-8 …")` here.
(measured)

But LO does **not** transcode UTF-16 either — `rtl_getTextEncodingFromMimeCharset("utf-16")`
normalizes to `"utf16"` and finds no entry in `sal/textenc/tencinfo.cxx` — so the
headline UTF-16 trigger is not a divergence. Folding this into A3's zero-rows contract
covers the surviving case.

### C7 — Two PGP key-collection divergences that only S5 will feel

`src/manifest.rs:231-242`, `:285-291`, `:300-330` · `ManifestImport.cxx:94-98`, `:111-151`, `:480-489`

A nested `encrypted-key` makes LO push a second, zero-length key for the outer
element; the crate pushes nothing, because `current_key` was already taken. And
`take_chars_decoded` clears the character buffer unconditionally where LO clears it
only on the three-slot branch, so LO's stale text can survive into a later value.

Both verdict-neutral today — `Classification` is identical, since only
`key_info.is_some()` is read — and both become wrong bytes the moment S5 types the
key material.

## D. Correct code, no test holding it

Each item was confirmed by mutation: the named behaviour was removed or inverted and
the suite stayed at 33/33. The implementation is right in every case.

### D1 — S2's marquee derived-key-size row pins only the 16 branch

`src/classify_tests.rs:418-437`; behaviour at `src/manifest.rs:360-364`

The row named _"KDF before algorithm, no `key-size`, `aes256-cbc` → `derived_key_len == 16`"_
is one-sided. Delete the cipher-implied `nDerivedKeySize` write in `do_algorithm`
entirely and all 33 tests still pass, because nothing asserts the normal-order case
where it must produce 32. This is plan open question 1 / F2 — the order-dependence the
plan says makes a row-independent `classify` wrong.

**Add.** Normal order, no `key-size`, `aes256-cbc` → 32; and an `aes192-gcm` row → 24.

### D2 — The `rManVector.empty()` version-copy gate has no fixture

`src/manifest.rs:220` · `ManifestImport.cxx:461-466`

Issue [#4](https://github.com/Slurp9187/odf-crypto/issues/4) sets this in bold:
_"The gate is `rManVector.empty()` — **not** '`/` is omitted'."_ The shipped code is
correct, but replacing the gate with `&& self.bag.full_path != "/"` leaves the suite
green. The effect is visible in `odf_version` and `odf12_fatal`.

**Add.** A first, versionless `/` row plus a package version and an extra root stream;
assert `odf_version == Some("1.2")` and `odf12_fatal`.

### D3 — "A malformed `encrypted-key` poisons exactly one file-entry" is untested

`src/manifest.rs:229` · `src/classify_tests.rs:898-931` · `ManifestImport.cxx:475`

Every S5 fixture is single-entry, so deleting the per-entry `ignore_encrypt_data`
reset passes the whole suite. Behaviour verified correct on the unmutated crate.

**Add.** A poisoned first entry followed by a complete password `content.xml` row;
assert `package_encrypted`, `common.path == "content.xml"`, and that the first entry
is absent from `encrypted_entries`.

### D4 — `s2_pictures_folder_resolves_without_zip_dir_entry` asserts nothing about resolution

`src/classify_tests.rs:494-525`

Its two assertions — `mode == PerEntry` and `odf_version == Some("1.2")` — are both
produced by the `content.xml` and `/` rows and survive the `Pictures/` row resolving
to `None`. It does discriminate one thing (an `Err(StreamAsFolder)` would fail the
`expect`), so it is not vacuous, just unable to separate "resolved as folder" from
"did not resolve". This is F11.

**Fix.** Drop the `Pictures/photo.png` manifest row so the nested stream is unlisted,
then assert `has_unexpected_streams`.

### D5 — "A real unencrypted ODF" is still a hand-built zip

`src/classify_tests.rs:190-199`, `:245-256`; `tests/goldens/`

The only literally unmet close condition in the arc — issue
[#2](https://github.com/Slurp9187/odf-crypto/issues/2) close-when 1, plan §7 S1.
All three goldens are encrypted, and `classify_unencrypted_odt_is_plain` runs on the
constructed fixture.

S6's arrival removed the excuse: `tests/goldens/make_goldens.py` already drives a
headless soffice through UNO and only ever calls `storeToURL` with a `Password`
property. Dropping that property yields a real `.odt` with `Thumbnails/` and
`Configurations2/` — the first realistic exercise of the non-wholesome scan, and the
answer `classify` gives most often in production.

### D6 — The _empty_-root-version arm of the ODF-1.2 gate is untested

`src/classify_tests.rs:698-712` uses root version `"1.1"`

Issue [#5](https://github.com/Slurp9187/odf-crypto/issues/5) close-when 2 asks for
_"extra root stream, **empty** / pre-1.2 root version"_; only the pre-1.2 arm exists.
The empty arm is the one plan §3 and F7 single out — the outcome of the
mimetype-fallback gate failing, and the only path on which a wholesome package with a
missing or non-`application/vnd.` mimetype stays non-fatal.

### D7 — Fields and error paths no test touches

`src/classify_tests.rs:152-156`, `:998-1049`

- `EntryEncryption::size` and `::iv` — asserted nowhere, on any fixture.
- The PGP path's unconditional SHA-256 start-key clamp — no fixture gives a PGP row an
  explicit `start-key-generation` to prove the clamp wins.
- No `DetectError` variant is exercised; `classify_pkg` always `expect`s.
- The three real goldens assert none of `odf_version`, `has_unexpected_streams`,
  `odf12_fatal`, `encrypted_entries.len()` — so `lo-wholesome-gcm-argon2.odt`, the only
  real exercise of the whole S3 version-fallback chain (package version 1.4 → first
  entry → root via the `application/vnd.` fallback), pins none of it. Measured today:
  `odf_version = Some("1.4")`.
- `nDerivedKeySize`'s per-`encryption-data` reset (plan §6 step 5) — every fixture has
  at most one encrypted row carrying a `key-size`.

## What holds

Negative results, recorded so nobody re-litigates them.

- **Plan §4's emit column survives contact with real files.** Checked against the
  goldens' raw manifest bytes rather than against `URIS.md`: `xmlenc11#aes256-gcm` +
  experimental Argon2 URN + `loext:argon2-*`; `xmlenc#aes256-cbc` + `xmldsig#sha256`
  (OFFICE-3708) + oasis `#sha256-1k`; `Blowfish CFB` with the start-key element omitted
  entirely. Issue #7's "if a written URI disagrees, amend the plan" clause did not fire,
  and `URIS.md` is accurate.
- **The public API matches plan §5 field for field** — three `Cipher` variants with no
  key length, `size: i64`, one `derived_key_len`, nine `Classification` fields, and
  nothing exported beyond those seven types plus `DetectError`.
- **Nothing from "Out of scope" or "Do not copy" is present.** `Cargo.toml` carries no
  crypto dependency at all, so key derivation is structurally impossible; the three
  odfdecrypt-only URLs exist only as `#[cfg(test)]` negative controls; no origin
  heuristics anywhere.
- **`ManifestImport.cxx` is fully mapped.** All 618 lines were re-walked handler by
  handler against `src/manifest.rs`; no decision point beyond A1–A3, C1, C3–C5, C7.
- **Three of the four state leaks are reproduced correctly** — sticky `key_info`,
  order-dependent `derived_key_size`, and the scan taking `zip_has_encrypted_package`
  rather than `mode == Wholesome`. Only "folder tree not namelist" leaks (A7).
- **Two findings were refuted.** A "duplicate names resolve first-wins in LO" claim
  collapsed on `HashMaps.hxx` (see B3). And the latch's short-name conjunct is correctly
  implemented and adequately covered by the goldens.

## Plan amendments

Amend `docs/plans/odf-encryption-detection-2026-09-01.md` in place, per its own rule.

| #   | Change                                                                                                                                                                                                                                                                                                                   |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | **§5 is wrong about `derived_key_len`.** LO carries `manifest:key-size` as a `sal_Int32` end to end (C2). The plan says `u8` and the implementation matches the plan exactly, so the type moves in both places or the fix reads as a spec violation. Issue #2's "`derived_key_len` as the one LO value" moves with it.   |
| 2   | **OQ4 is stale.** §10 and the §7 S6 row still read as though `tests/resources/` were empty; the three files issue #7 required are in-tree and passing.                                                                                                                                                                   |
| 3   | **OQ1's producer half now has evidence.** All three goldens write `<manifest:algorithm>` before `<manifest:key-derivation>`, with `<start-key-generation>` between them where present — direct evidence that no producer emits the reversed order, which is exactly what OQ1 asks. Record it rather than re-deriving it. |
| 4   | **§4 omits a real emit detail.** LO also writes `manifest:key-size` on `<start-key-generation>` (32 for SHA-256, 20 for SHA-1 — `ManifestExport.cxx:456-463`), and `doStartKeyAlg` (`ManifestImport.cxx:306-317`) ignores it on read. The crate ignoring it is correct; the table should say so.                         |
| 5   | **Zip-acceptance fidelity is undecided, not out of scope.** §2's "the path resolves in the folder tree" is manifest-side only. Group B needs either a scope line in the plan or a slice.                                                                                                                                 |

**Arc #1 cannot close as filed.** Its close condition is "every slice sub-issue is
closed" and all six are open. #6 and #7 are closeable today; #2 is blocked on D5;
#3, #4 and #5 each need one added assertion (D1, D2/A4, D6) before their close
conditions are honestly rather than nominally met. OQ3 (PGP + SHA512-1K) still has no
tracking issue and will vanish when #1 closes.

## Verification pass

The findings were implemented and then re-checked against LO source. Baseline
after the fixes below: `cargo test --offline` → **63 passed, 0 failed**; clippy
clean.

**Two regressions the implementation introduced, both found by probe and fixed.**

### V1 — the depth cap unbalanced the element stack

`src/manifest.rs`. B7's fix capped depth by pushing a frame that stored the _raw_
element name while `end_element` still compared against the _converted_ name, and
`convert_name` searched only the top 8 frames. For an element deeper than 8 whose
prefix was bound above that window, the two disagreed, so the frame never popped —
and with A3's new contract (`Eof` with a non-empty stack → zero rows) the entire
manifest was discarded.

```
a file-entry containing a 40-deep subtree under an aliased manifest namespace,
followed by a normal encrypted content.xml row
  before → Plain, package_encrypted false, encrypted_entries 0, odf_version None
  LO      → PerEntry, encrypted (levels past 6 are invalid, parsing continues)
```

Fixed by counting depth past `MAX_DEPTH` instead of pushing frames, so start/end
stay balanced with no name comparison at all, and dropping the `take(8)` window.
Levels past 6 are invalid in LO regardless, so counting them is faithful. B7's
win is kept: the 60,000-deep 854-byte input now classifies in **22.7 ms** (release),
against 12–25 s before B7 and a hang-length regression risk if the cap is removed.
Regression test: `deep_subtree_does_not_drop_later_entries`.

### V2 — a leading-slash stream row resolved where LO returns false

`src/zip_tree.rs`. A8/A9's fix made the walk, on breaking at an empty segment, look
up the name after the final `/` in the folder reached. That is right for
`a//content.xml` but wrong for `/content.xml`, which LO does **not** resolve.

LO's walk cannot resolve either: on the break it looks up `aName[nOldIndex..]` —
still carrying the empty segment — as one child name (`ZipPackage.cxx` 1083–1090).
`a//content.xml` resolves only through the `m_aRecent` cache, keyed on
`name[..name.rfind('/')]` exactly as `getZipFileContents` spelled it (`:678-680`,
read at `:1026-1044`). `/content.xml` has an empty dirname, which is never a key.

```
manifest row full-path="/content.xml", complete tuple, root content.xml member
  before → PerEntry, package_encrypted true
  LO      → row not applied → Plain
```

Fixed by recording the member dirname keys on `FolderTree` and requiring a hit
before the break path resolves a stream. Regression tests:
`leading_slash_stream_row_is_not_applied`, `leading_slash_stream_row_does_not_resolve`,
`double_slash_stream_needs_the_member_dirname_key`. Both fixes were mutation-checked:
reverting either makes the new tests fail at both the unit and `classify` layers.
V3 replaced the immutable `dir_keys` set with insert-time `recent` seeds; those
three tests still pass.

### V3 — `m_aRecent` folder miss stores `pPrevious` (A10)

`src/zip_tree.rs`, `src/classify.rs`. A10's cache is load-bearing in the same way
V2 was: `a//content.xml` only resolves because insert wrote `recent["a/"]`. The
folder-shaped miss path was the remaining hole.

`resolve` is now `&mut self` and matches `hasByHierarchicalName` then returns
`getByHierarchicalName`'s node. Insert seeds the containing folder. A `Pictures/`
walk caches `[]` (root). Folder meta still uses `pCurrent` (`Pictures/`). The
next `Pictures/content.xml` hit looks up `content.xml` on the cached folder —
root — and Stage B applies the row to that stream (`EntryEncryption.path` is the
resolved tree path, so latch sees `getName()=="content.xml"`). `pPrevious ==
nullptr` does not insert a cache entry.

The naive `Pictures/photo.png` then `Pictures/` pair is a cache hit and does not
overwrite. Tests cover both directions at zip_tree and classify layers.

**A10's LO claim is no longer unrefuted.** It was the one finding filed without a
repro, so it was verified in source before the port was judged:
`hasByHierarchicalName` really does end its folder branch with
`m_aRecent[sDirName] = pPrevious; return true;` (`:1077-1081`), the matching
`getByHierarchicalName` branch writes the same shallow pointer (`:994-998`), and
`parseManifest` applies the bag to whatever object comes back — `dynamic_cast`
picks folder vs stream (`:282-296`). The root folder is constructed at `:167`
without `setName`, so `getName()` is `""`, which is what makes the `Pictures/`
cache hit _fail_ its name check and fall through to the poisoning walk. All three
scenarios were then reproduced through the public `classify()` and match.

Two repairs on review:

- **The control was missing.** `Pictures/album/photo.png` + a `Pictures/` row +
  `Pictures/content.xml` proves the poison fires, and the `Pictures/photo.png`
  variant proves a correct cache hit does not — but neither pins that the _folder
  row_ is what writes the shallow entry. Seeding every ancestor prefix at insert
  time is a plausible bug that leaves both green. Added
  `nested_row_without_a_folder_row_does_not_latch` and
  `nested_member_alone_does_not_poison`: same zip, no folder row, must stay
  `Plain`. Mutation-checked — that seeding bug fails exactly these two and nothing
  else.
- **The null-`pPrevious` case is now documented rather than silent.** `previous`
  is None only when the walk broke on a leading empty segment (`/foo/`). LO stores
  a null pointer there and a later stream row on that key dereferences it —
  `hasByHierarchicalName` has no null guard where `getByHierarchicalName` does
  (`:958`). Storing nothing is the deliberate choice: we do not model a null
  deref, and the next lookup falls to the walk, which finds nothing.
  `leading_slash_folder_row_does_not_cache_a_null_parent` pins it.

### Confirmed correct on re-read

- **A1** — `HandleSignChar` (`strtmpl.hxx` 638–651) read in source; the port handles
  sign, overflow-to-zero, and LO's whitespace set (not `str::trim`).
- **A2** — `ManifestImport.cxx` 335–345 read in source: `case 2:` has no parent check,
  `case 3:` is the first that does. The guard is now `level >= 3`.
- **A9** — `IsValidZipEntryFileName` allows `//` (only `.`/`..` and a leading `/` are
  rejected), so the doubled-slash member really does reach the tree.
- **C1** — `decode_b64` is a faithful port of `decodeSomeChars`, including `'='`
  decrementing the output width only at positions 3 and 4.
- **C4** — `normalize_attr_value` expands references _before_ normalizing, so
  `&#x0A;` survives as a newline and a literal newline becomes a space. Correct per
  XML §3.3.3; the audit's own note said character references are protected.
- **A5 / mimetype fallback** — `ZipPackage.cxx` 496–507 read in source: the version
  copy is guarded by `GetVersion().isEmpty()`, which the adapted call preserves now
  that `set_folder_meta` assigns unconditionally.
- Plan amendments 1–4 landed; amendment 5 was missing and is now §6 Stage 0.

### Known, accepted, still open

- **A10 — closed 2026-09-01.** `m_aRecent` is now a mutable folder-path cache on
  `FolderTree`. Insert seeds the containing folder (`getZipFileContents` `:678-680`).
  A folder miss caches `pPrevious` (`:1079`); `Pictures/` after
  `Pictures/album/photo.png` poisons `["Pictures"]=ROOT`, so `Pictures/content.xml`
  latches root `content.xml`. Folder meta still applies to `pCurrent`. A
  `Pictures/photo.png` insert then `Pictures/` is a cache hit and does not poison.
  See V3.
- **D5 — closed 2026-09-01.** `tests/goldens/lo-unencrypted.odt` was generated with
  `make_goldens.py lo-unencrypted` (LibreOffice 26.2.1.2, `DefaultVersion=3`, no
  `Password`). `classify_real_unencrypted_odt_is_plain` now loads it through
  `load_golden`, so a missing file fails the suite instead of silently skipping,
  and asserts the full set the finding asked for: `Plain`, `!package_encrypted`,
  no `common`, no entries, `odf_version == Some("1.4")`, the root media-type, and
  `!has_unexpected_streams` / `!odf12_fatal`.

  The file is the only fixture whose member set a producer actually wrote, so it
  is the first real exercise of the non-wholesome scan: `mimetype` stored first,
  an explicit `Configurations2/` directory entry, an implicit `Thumbnails/` folder
  with no directory entry of its own, and every stream listed in the manifest.
  Recorded in `tests/goldens/URIS.md`.

  `make_goldens.py` now takes golden names, defaulting to all four. Each save
  produces fresh salts, IVs and sizes, so regenerating an S6 golden means
  re-checking the `size` assertions and `URIS.md`; naming one avoids churning the
  three already validated against LO. The three encrypted goldens were not
  regenerated.

- **Ordering nuance:** LO runs `checkZipEntriesWithDD` at `ZipPackage.cxx:456`,
  before the mimetype block; `classify` runs it after `stage_b`. A package that trips
  both reports the mimetype conflict where LO reports the data-descriptor error.
  Both are `Err`, so no Ok/Err flip — not worth restructuring `stage_b` for.
- **Unknown entities:** `expand_ref` drops an undefined general entity silently;
  expat treats it as a parse error, which under A3 would mean zero rows.

## Method

8 lens-specific finders → 1 adversarial refuter per finding → 2 completeness critics.
64 agents, 5.5M tokens, 101 minutes. 54 findings raised: **39 confirmed, 13 narrowed,
2 refuted.**

Each finder read the LibreOffice source before the Rust and was told a clean dimension
is a valid result. Each refuter defaulted to REFUTED, re-read the LO source rather than
trusting the cited line number, re-traced the path from `classify()`, and reproduced
the trigger in its own scratch copy of the crate with `cargo test` — every `measured`
figure above comes from those runs. The 13 narrowings are folded into the entries
rather than recorded separately. `ManifestImport.cxx:335-345` (A2) and
`strtmpl.hxx:638-651` (A1) were read in-source during write-up.

Baseline at audit time: `cargo test --offline` → 33 passed, 0 failed.

## Not covered

Settled in plan §6 Stage 0 (2026-09-02): these stay out of detection, they are not a
second classify arc.

- **`m_bForceRecovery` is modelled nowhere** — now specified as **normal load only**.
  Every LO throw the crate reproduces is unconditional, whereas roughly a dozen are
  suppressed under Repair (`ZipPackage.cxx:461-465`, `:469`, `:512`, `:540`; the
  `\`→`/` rewrite at `:636-640`). Every Group B finding assumes `m_bForceRecovery ==
  false`. Repair is a different product.
- **`m_bMediaTypeFallbackUsed`** (`ZipPackage.cxx:503-507`) and
  **`m_bHasNonEncryptedEntries`** (`:441`) are computed by LO in `parseManifest` and
  stay off `Classification`. `encrypted_entries` is the complete tuples.
- **The remaining `readCEN` structural checks** — overlapping entries (`ZipFile.cxx:1436-1481`),
  STORED with inconsistent size (`:1427-1430`), data-descriptor holes (`:1521+`),
  `Count != Total`, name length. Same family as Group B; noted, never audited; not a
  decrypt-arc blocker.
- **LO's out-of-bounds `aSequence[PKG_MNFST_*]` writes** when a crypto element appears
  with no enclosing file-entry (e.g. `loext:keyinfo` > `manifest:encryption-data`). That
  shape has no defined LO semantics to match, so the crate's safe behaviour there cannot
  be scored.
