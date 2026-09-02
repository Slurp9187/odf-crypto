# S6 golden written URIs

Produced 2026-09-01 with local LibreOffice UNO (`tests/goldens/make_goldens.py`). Password for every file: `password`.

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
