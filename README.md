# odf-crypto

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

LibreOffice-faithful ODF package encryption: detect it, decrypt it, write it.

`odf-crypto` reads and writes the encryption LibreOffice actually produces for
OpenDocument packages (`.odt`, `.ods`, `.odp`, …) — not an approximation of the
ODF specification, but the behaviour of the implementation that made the files.
Where the spec is ambiguous and LibreOffice picked an interpretation, this crate
follows LibreOffice.

That fidelity is the whole point. `classify` mirrors LibreOffice's `package/`
accept predicates, so a package this crate calls encrypted is one LibreOffice
would prompt for, and a package it refuses is one LibreOffice would refuse to
open.

> **Pre-release.** This is `0.1.0-rc.1`. The API may change before `0.1.0`.

## Install

```toml
[dependencies]
# Detection only — no cryptographic dependency.
odf-crypto = "0.1.0-rc.1"

# Detection, reading and writing.
odf-crypto = { version = "0.1.0-rc.1", features = ["crypto-ops"] }
```

Pre-release versions are not matched by ordinary requirements — name the full
version as above; `"0.1"` will not resolve to it.

## Usage

### Classify

`classify` answers whether the bytes are an ODF package, whether it is
encrypted, in which zip shape, and with which algorithm tuple.

```rust
use odf_crypto::{classify, Mode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read("document.odt")?;
    let c = classify(&bytes)?;

    if c.odf12_fatal {
        // Unexpected ODF 1.2 streams. LibreOffice throws rather than opening
        // these, so decrypt and encrypt refuse them too.
        return Err("LibreOffice would not open this package".into());
    }

    match c.mode {
        Mode::Plain => println!("not encrypted"),
        Mode::PerEntry => println!("per-entry, {} entries", c.encrypted_entries.len()),
        Mode::Wholesome => println!("single encrypted-package member"),
    }
    Ok(())
}
```

`Classification` also carries `package_encrypted` (LibreOffice's
`HasEncryptedEntries` latch), `odf_version`, `media_type`, and any PGP
`encrypted-key` material found in the manifest.

### Decrypt

```rust
use odf_crypto::decrypt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sealed = std::fs::read("locked.odt")?;
    // The plaintext ODF zip LibreOffice would open after a correct password.
    let plain: Vec<u8> = decrypt(&sealed, "correct horse battery staple")?;
    std::fs::write("unlocked.odt", plain)?;
    Ok(())
}
```

`DecryptError` distinguishes the cases worth handling separately — `WrongPassword`,
`NotEncrypted`, `EmptyPassword`, `Odf12Fatal` and `UnsupportedPgp` among them —
so a caller can tell "bad password" from "we will not touch this package".

### Encrypt

```rust
use odf_crypto::encrypt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let plain = std::fs::read("document.odt")?;
    // What current LibreOffice writes for that input under that password.
    let sealed: Vec<u8> = encrypt(&plain, "correct horse battery staple")?;
    std::fs::write("locked.odt", sealed)?;
    Ok(())
}
```

Output is validated against a real LibreOffice: the repository carries a golden
(`tests/goldens/lo-opens-our-encrypt-output.odt`) and a UNO-driven checker
(`tests/goldens/validate_encrypt.py`) that bootstraps LibreOffice and confirms it
opens what this crate wrote.

## Supported algorithms

| Cipher (`Cipher`) | KDF (`Kdf`) | Start key (`StartKeyAlg`) | Typical producer |
| --- | --- | --- | --- |
| `AesGcmW3c` — AES-GCM | `Argon2id { t, m, p }` | `Sha256` | Current LibreOffice |
| `AesCbcW3c` — AES-CBC | `Pbkdf2 { iterations, salt }` | `Sha256` / `Sha1` | Legacy LibreOffice |
| `BlowfishCfb8` — Blowfish-CFB | `Pbkdf2 { iterations, salt }` | `Sha1` | Apache OpenOffice, older ODF |

Derived key length (128/192/256) is carried on `EntryEncryption::derived_key_len`.
Entry integrity is `Checksum::Sha1_1K` or `Checksum::Sha256_1K` over the first
1 KiB, matching LibreOffice.

The SHA-1 start-key path also handles LibreOffice's four-candidate fallback
ladder, including `rtl_digest_SHA1` — a deliberately non-conforming SHA-1 that
LibreOffice keeps for compatibility (`tdf#114939`). The repository carries the
analysis in `tests/goldens/sha1_star.py`; `tests/goldens/lo-odf11-nonascii-password.odt`
is the fixture that exercises it.

PGP-encrypted packages are detected and reported (`Classification::pgp_keys`) but
not decrypted — `DecryptError::UnsupportedPgp`.

## Features

There are two builds, and no feature flag turns anything off — the default is
simply the smaller one.

| Build | How | What you get |
| --- | --- | --- |
| **Detection-only** | `odf-crypto = "0.1.0-rc.1"` | `classify` alone. No cryptographic dependency. **27 crates.** |
| **Full** | `features = ["crypto-ops"]` | `classify`, `decrypt` and `encrypt`. **61 crates.** |

**Detection is the default because it is cheap.** `classify` parses
`META-INF/manifest.xml` and the zip central directory; it never derives a key or
touches a cipher. Enabling `crypto-ops` adds `aes`, `aes-gcm`, `argon2`,
`blowfish`, `pbkdf2`, `sha1`, `sha2`, `hmac` and their transitive graph, plus
`libc` and `getrandom`. Nobody should pay for that to ask whether a file is
encrypted.

The feature is named for what it gates, which is not only ciphers: `pbkdf2` and
`argon2` are KDFs, `sha1`/`sha2` are hashes, `hmac` is a MAC, and `miniz_oxide`
is compression.

Reading and writing were once separate features. They are not any more: both
pulled an identical dependency graph, so the split cost a build configuration
and bought nothing a linker does not already do for a consumer that never calls
`encrypt`.

## MSRV

Rust **1.85**.

## Attribution

This crate is an independent implementation. Its behaviour was derived from the
published OpenDocument format and from studying how existing implementations
behave; no code was copied from either project below. They are credited because
the work would have been substantially harder without them.

**[LibreOffice](https://www.libreoffice.org/)** — MPL-2.0. The behavioural
reference throughout. This crate follows LibreOffice's `package/` accept
predicates rather than a spec-literal reading, and the plan documents in `docs/`
cite specific upstream source locations for each decision so a disagreement
points at a paragraph rather than a guess. `tests/goldens/sha1_star.py` quotes a
short explanatory comment from LibreOffice's `sal/rtl/digest.cxx` when
documenting the `rtl_digest_SHA1` quirk.

**[Horsmann/odfdecrypt](https://github.com/Horsmann/odfdecrypt)** — Apache-2.0.
Prior art covering the same problem in Python, and useful for confirming that a
reading of the format was not idiosyncratic. This crate's classification
deliberately diverges from it: `classify` follows LibreOffice's accept predicates,
not odfdecrypt's origin detector.

The `.odt` fixtures under `tests/goldens/` were generated for this project.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual-licensed as above, without any additional terms or conditions.
