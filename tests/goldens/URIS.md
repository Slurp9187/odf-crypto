# S6 golden written URIs

Produced 2026-09-01 with local LibreOffice UNO (`tests/goldens/make_goldens.py`). Password for every file: `password` — except `lo-odf11-nonascii-password.odt` (added 2026-09-02), which uses `NONASCII_PASSWORD`.

These strings are what LO *wrote*. They match plan §4 emit (no alias-table change).

## `lo-wholesome-gcm-argon2.odt`

Zip: `mimetype`, `encrypted-package`, `META-INF/manifest.xml`. No `/` file-entry.

| Field | Written |
|---|---|
| `manifest:manifest/@manifest:version` | `1.4` |
| algorithm-name | `http://www.w3.org/2009/xmlenc11#aes256-gcm` |
| start-key-generation-name | `http://www.w3.org/2001/04/xmlenc#sha256` |
| start-key `key-size` | `32` |
| key-derivation-name | `urn:org:documentfoundation:names:experimental:office:manifest:argon2id` |
| argon2 attrs | `loext:argon2-iterations="3"` `loext:argon2-memory="65536"` `loext:argon2-lanes="4"` |
| KDF `key-size` | `32` |
| checksum | omitted (GCM) |

## `lo-legacy-aes-cbc.odt`

Per-entry ODF 1.2. Latch member `content.xml`.

| Field | Written |
|---|---|
| `manifest:manifest/@manifest:version` | `1.2` |
| algorithm-name | `http://www.w3.org/2001/04/xmlenc#aes256-cbc` |
| start-key-generation-name | `http://www.w3.org/2000/09/xmldsig#sha256` (AES-CBC emit, OFFICE-3708) |
| start-key `key-size` | `32` |
| key-derivation-name | `PBKDF2` |
| iteration-count | `100000` |
| KDF `key-size` | `32` |
| checksum-type | `urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k` |

## `aoo-blowfish-pbkdf2.odt`

Classic path: current LO with ODF 1.1 (`DefaultVersion=2`), not Apache OpenOffice itself. Written tuple is AOO-style Blowfish+PBKDF2.

| Field | Written |
|---|---|
| `manifest:manifest/@manifest:version` | omitted |
| algorithm-name | `Blowfish CFB` |
| start-key-generation | omitted (detect defaults SHA-1) |
| key-derivation-name | `PBKDF2` |
| iteration-count | `100000` |
| checksum-type | `SHA1/1K` |

## `lo-unencrypted.odt`

S1, not S6: no encryption-data, so no URIs to record. Kept because it is the only
fixture whose member set a producer actually wrote — the non-wholesome
unexpected-stream scan runs over it for real.

Written 2026-09-01 by LibreOffice 26.2.1.2 at `DefaultVersion=3` with no
`Password` property.

| Field | Written |
|---|---|
| `manifest:manifest/@manifest:version` | `1.4` |
| root `/` row | `manifest:version="1.4"`, media-type `application/vnd.oasis.opendocument.text` |
| Zip members | `mimetype` (stored, first), `manifest.rdf`, `Configurations2/`, `styles.xml`, `settings.xml`, `meta.xml`, `Thumbnails/thumbnail.png`, `content.xml`, `META-INF/manifest.xml` |
| Shapes exercised | explicit `Configurations2/` directory entry; implicit `Thumbnails/` folder with no directory entry of its own; every stream listed in the manifest |

## `lo-odf11-nonascii-password.odt`

Added 2026-09-02 to close decrypt-plan OQ1. Same written tuple as `aoo-blowfish-pbkdf2.odt`
— the file differs only in its **password**, which is `NONASCII_PASSWORD` in
`make_goldens.py`: 52 characters, one of them U+00E4, giving 53 UTF-8 bytes and 52
MS-1252 bytes. Both lengths sit in the `len % 64 ∈ {52,53,54,55}` window where
`rtl_digest_SHA1` diverges from real SHA-1 (tdf#114939), so the four SHA-1 start-key
candidates LibreOffice keeps — correct/StarOffice × UTF-8/MS-1252 — are all distinct for
this string. Only **correct SHA-1 over UTF-8** decrypts the file — re-run that measurement with
`python sha1_star.py`.

| Field | Written |
|---|---|
| `manifest:manifest/@manifest:version` | omitted (ODF 1.1) |
| `/` file-entry | present, media-type only, no version |
| algorithm-name | `Blowfish CFB` |
| start-key-generation | omitted (→ SHA-1) |
| key-derivation-name | `PBKDF2` |
| iteration-count | `100000` |
| KDF `key-size` | omitted (→ `derived_key_len` 16) |
| checksum-type | `SHA1/1K` |
| encrypted members | `manifest.rdf`, `styles.xml`, `settings.xml`, `meta.xml`, `content.xml` |

Regenerating it changes salts, IVs and `manifest:size`; the OQ1 conclusion does not
depend on those, but the recorded sizes do.
