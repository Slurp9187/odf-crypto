# odf-crypto

[![crates.io](https://img.shields.io/crates/v/odf-crypto.svg?include_prereleases)](https://crates.io/crates/odf-crypto)
[![docs.rs](https://img.shields.io/docsrs/odf-crypto)](https://docs.rs/odf-crypto)
[![CI](https://github.com/Slurp9187/odf-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/Slurp9187/odf-crypto/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/crates/msrv/odf-crypto)](https://github.com/Slurp9187/odf-crypto#msrv)
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

> **Pre-release.** This is `0.1.0-rc.7`. The API may change before `0.1.0`.

## What it does

| What you have | Detect | Decrypt | Encrypt |
| --- | --- | --- | --- |
| AES-256-GCM + Argon2id — what current LibreOffice writes | ✅ | ✅ | ✅ |
| AES-CBC + PBKDF2 — older LibreOffice | ✅ | ✅ | ❌ |
| Blowfish-CFB + PBKDF2 — ODF 1.1 | ✅ | ✅ | ❌ |
| PGP-wrapped package | ✅ | ❌ | ❌ |
| Unencrypted package | ✅ | n/a | ✅ |
| **Needs** | the default build | `crypto-ops` | `crypto-ops` |

Detection is the entire default build and links no cryptography at all; the
cipher stack is opt-in. See [Features](#features).

**This crate reads three profiles and writes one.** The grid above is what
`decrypt` accepts; `encrypt` always writes the first row, whatever the input
was. That asymmetry is an effort gap rather than a judgement — wholesome
Argon2id/AES-GCM is what current LibreOffice saves by default, so it is what a
new file should be, and nothing has yet needed a writer for the older two. If
you need one, say so on the tracker; the primitives are already here, because
`decrypt` uses them.

PGP-encrypted packages are detected and reported (`Classification::pgp_keys`) but
not decrypted — `DecryptError::UnsupportedPgp`. **That one is not an effort
gap.** `decrypt(bytes, password)` has no surface a private key could arrive
through: PGP unwrapping needs a keyring, an agent socket or a smartcard PIN, not
a password string, and an OpenPGP stack would dwarf the 25-crate default this
crate is built around. `classify` hands you the wrapped key material so a caller
who already has an OpenPGP implementation can do the unwrap.

**Writing a profile is not the same as LibreOffice opening the result.** Those
are two claims, and the second is the one that matters to whoever has to read
the file afterwards. It is evidenced separately — see
[How it's verified](#how-its-verified).

## Install

```toml
[dependencies]
# Detection only — no cryptographic dependency.
odf-crypto = "0.1.0-rc.7"

# Detection, reading and writing.
odf-crypto = { version = "0.1.0-rc.7", features = ["crypto-ops"] }
```

Pre-release versions are not matched by ordinary requirements — name the full
version as above; `"0.1"` will not resolve to it.

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

## Usage

### Classify

`classify` answers whether the bytes are an ODF package, whether it is
encrypted, in which zip shape, and with which algorithm tuple.

```rust,no_run
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

```rust,no_run
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

```rust,no_run
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

#### Choosing the Argon2id cost

`encrypt` uses LibreOffice's `(t=3, m=65536, p=4)`. That `m` is **64 MiB of
working memory per call**, which some hardware cannot spend — and since the
parameters are stored in the file, a device that cannot afford 64 MiB to write
cannot afford it to read the document back either.

```rust,no_run
use odf_crypto::{encrypt_with_params, Argon2Params};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let plain = std::fs::read("document.odt")?;

    // 8 MiB instead of 64. Accepted, and weaker — both on purpose.
    let params = Argon2Params::new(2, 8192, 2)?;
    if params.is_weaker_than_libreoffice() {
        eprintln!("warning: this file will be cheaper to attack, forever");
    }

    let sealed = encrypt_with_params(&plain, "correct horse battery staple", params)?;
    std::fs::write("locked.odt", sealed)?;
    Ok(())
}
```

`Argon2Params::new` never refuses a tuple for being merely weak. Whose document
it is, and what its owner can afford to run, is not this crate's decision; it
reports the trade instead of overruling it.

When it does refuse, the error carries a typed `ParamsReason` naming **whose rule
was broken**, because those need different things from a caller:

| reason | means | what to tell a user |
| --- | --- | --- |
| `OutOfRange` | a policy bound of **this crate** | the OpenDocument format permits this value; the library is stricter than the format |
| `CipherRejects` | **`argon2`** cannot run it (`m < 8p`, or `p` above its `MAX_P_COST`) | not a setting any library could relax |

The distinction is not cosmetic, and the Argon2 attributes make it sharp: they
are defined by **LibreOffice's own extension schema**
(`OpenDocument-v1.4+libreoffice-manifest-schema.rng`) and appear in no OASIS
schema at all, typed there as unbounded `positiveInteger`; LibreOffice then
validates the triple only as `0 < t && 0 < m && 0 < p`. So the only authority
that defines them imposes no ceiling, and a tuple `OutOfRange` refuses may be
entirely legal and openable elsewhere. Reporting it as a format violation would
be false, and falsely authoritative.

Each reason carries an `Argon2Axis` (`T` / `MKib` / `P`) and the offending value
with its bounds — enums and integers, never interpolated text, so the payload
needs no sanitising before it reaches a user. Both types are `#[non_exhaustive]`;
match with a `_` arm.

The cost travels **with the file**, so it is not a local performance setting. A
document written cheaply stays cheap to attack for every future reader, on any
hardware.

LibreOffice honours whatever is written — checked in its source, not just
sampled. `ManifestImport.cxx:257` validates the three attributes for positivity
and nothing else, `ZipFile.cxx:184-186` passes the file's own values into
`argon2_context`, and `:192` says why there is no range check there either:
*"libargon2 validates all the arguments so don't need to do it here."* What this
crate will write is a strict subset of what libargon2 accepts.

## Command line

```sh
cargo install odf-crypto --features cli
```

`cli` is not a default feature: a library consumer should not pay for an
argument parser or a terminal crate to link `classify`.

```sh
odf-crypto classify report.odt              # what is it, and how is it encrypted
odf-crypto classify --json report.odt       # the same, as one JSON object
odf-crypto decrypt  locked.odt -o plain.odt
odf-crypto encrypt  plain.odt  -o locked.odt

# Argon2id cost, for hardware that cannot spend 64 MiB. Each axis defaults
# independently, so this keeps LibreOffice's t=3 and p=4.
odf-crypto encrypt plain.odt -o locked.odt --argon2-m 8192
```

A tuple weaker than LibreOffice's prints a warning on stderr and **still writes
the file** — the cost is the caller's decision. A tuple `argon2` cannot run
(`m < 8p`) is refused with exit 1, because that is a mistyped flag rather than a
damaged document.

```text
$ odf-crypto classify report.odt
package:     ODF
mode:        wholesome
encrypted:   yes
odf-version: 1.4
media-type:  application/vnd.oasis.opendocument.text
cipher:      AES-GCM (W3C)
kdf:         Argon2id t=3 m=65536KiB p=4
start-key:   SHA-256
checksum:    none
key-size:    32
```

### Passwords never come from the command line

There is deliberately **no `--password VALUE` flag**. `argv` is world-readable
in a process listing for the lifetime of the run — `ps aux`, or Task Manager's
command-line column. Four sources instead, exactly one per invocation:

| Flag | Source |
| --- | --- |
| `--password-env NAME` | that environment variable |
| `--password-file PATH` | first line of the file |
| `--password-stdin` | one line from stdin |
| *(none)* | non-echoing terminal prompt |

```sh
ODF_PW=... odf-crypto decrypt locked.odt --password-env ODF_PW
odf-crypto decrypt locked.odt --password-file ~/.secrets/odf
pass show odf | odf-crypto decrypt locked.odt --password-stdin
```

Giving two sources is an error rather than a silent precedence win. With none of
them and no terminal, the command fails telling you which flags exist instead of
blocking on a prompt nobody can see.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | usage error |
| 2 | I/O error |
| 3 | not an ODF package |
| 4 | wrong password |
| 5 | refused — not encrypted, already encrypted, PGP, or one LibreOffice would not open |
| 6 | malformed or hostile package |
| 7 | internal invariant violated |

4 and 5 are the distinction that earns the table: **4 means try again, 5 means
you had the wrong file.** An unencrypted package passed to `classify` is exit 0
with `encrypted: no` — an answer, not a failure.

### Output files

With no `-o`, output lands beside the input as `report.decrypted.odt` or
`report.encrypted.odt`. An existing file is never overwritten without `--force`,
and writes go to a temporary in the destination directory and are renamed over
the target, so an interrupted run cannot leave a half-written `.odt` that looks
complete. `-o -` writes to stdout.

## Features

There are two builds, and no feature flag turns anything off — the default is
simply the smaller one.

| Build | How | What you get |
| --- | --- | --- |
| **Detection-only** | `odf-crypto = "0.1.0-rc.7"` | `classify` alone. No cryptographic dependency. **25 crates.** |
| **Full** | `features = ["crypto-ops"]` | `classify`, `decrypt` and `encrypt`. **59 crates.** |
| **CLI** | `features = ["cli"]` | The `odf-crypto` binary. Implies `crypto-ops`; adds `rpassword` for the prompt. |

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

## How it's verified

Fidelity to LibreOffice is this crate's only substantive claim, so the evidence
for it ships with the crate rather than living in a CI log.

**Six goldens, every one real LibreOffice output.** `tests/goldens/*.odt` were
produced by a local LibreOffice — check `meta:generator`, all six read 26.2.1.2 —
and they ship *inside the published tarball*, so the crate can verify its own
fidelity claim from the artifact a consumer actually downloads. That includes
`aoo-blowfish-pbkdf2.odt`, whose `aoo-` prefix names the ODF 1.1 Blowfish format
family rather than its producer; there is no Apache OpenOffice-produced evidence
here, so the corpus proves fidelity to LibreOffice and to the format, not
agreement between two independent writers.

**A round trip through LibreOffice, not merely through us.**
`lo-opens-our-encrypt-output.odt` is what LibreOffice saved after being handed a
package this crate wrote. That is the difference between *we can read what we
write* and *the reference implementation can*.

**A human opened the artifacts by double-click.** The UNO harness that drives
LibreOffice is not the path a double-click takes — no password dialog, no
recovery prompt — so `tests/artifacts/` exists to be opened by hand, with a
manifest naming the password and expected text for each. Recorded verdict:
2026-09-20, LibreOffice 26.2.1.2 on Windows 11 build 26200, all six prompted for
a password, accepted it, rendered the expected text, and raised no recovery bar.
That verdict outranks the harness.

**226 tests, passing in every feature configuration** — 149 library, 20 CLI
unit, 35 CLI end-to-end, 22 doctests. All three builds run in CI, not just the
two that are cheap.

**The examples below are among those doctests.** Every ` ```rust ` block in this
file is compiled on each CI run, so an example naming an item that has since
moved fails the build instead of reaching you.

**A 54-finding audit against LibreOffice source** — 39 confirmed, 2 refuted, the
rest narrowed. [The record](https://github.com/Slurp9187/odf-crypto/blob/main/docs/audits/classify-lo-fidelity-2026-09-01.md)
carries the upstream citation and a reproduction for each, including the two it
could not substantiate.

## Security

**Key material zeroizes on drop.** The password digest and every derived key are
held in [`secure-gate`](https://crates.io/crates/secure-gate) wrappers, which is
this crate's only zeroizing primitive; no bare `Vec<u8>` holds a key between
derivation and use. Plaintext crosses the public API as a plain `Vec<u8>` on
purpose — a wrapper in the signature would conscript an exact dependency version
on every consumer, and the caller receives the bytes either way.

**The library does not abort your process.** No `panic!`, `unwrap` or `expect`
on any non-test path — and, the part that is easy to miss, an allocation sized
from an untrusted manifest field goes through `Vec::try_reserve_exact` and
returns `DecryptError::HostCannotAllocate` rather than reaching
`handle_alloc_error`. That is not tidiness: an abort skips unwinding, so `Drop`
never runs, so the keys above are **not** wiped. Two allocation sites remain
outside this, and both are named in the source together with the reason they
stay open.

**The file chooses what opening it costs.** `decrypt` has to derive the key
before it can tell whether the password was even right, so a manifest's Argon2
and PBKDF2 parameters are acted on before anything about the file is trusted.
Measured: a 7 KiB package rewritten to ask for 8 GiB of Argon2 memory took 29
minutes to report a wrong password. So `decrypt` applies default ceilings —
chosen to refuse nothing any real producer writes — and `decrypt_with_limits`
lets a caller who knows their input raise them, up to `DecryptLimits::PERMISSIVE`.

**Passwords never reach `argv`.** There is deliberately no `--password VALUE`
flag; a process listing is world-readable. See
[Passwords never come from the command line](#passwords-never-come-from-the-command-line).

**What this does not do.** It will not tell you a password is weak. It cannot
distinguish a wrong password from tampered ciphertext — both surface as
`WrongPassword`, and on the AES-CBC and Blowfish profiles the checksum covers
only the first 1 KiB, so damage past that appears as an inflate failure instead.
And it is not a hardened implementation of the ciphers themselves: those are the
RustCrypto crates, and inherit their properties rather than this crate's.

## MSRV

Rust **1.85**.

## Sibling crate

[**`msoffice-crypto`**](https://github.com/Slurp9187/msoffice-crypto) does for
Microsoft Office what this crate does for OpenDocument — same method, same
author, different format family. The two READMEs share a section order so that
knowing one file tells you where to look in the other.

## Acknowledgements

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
