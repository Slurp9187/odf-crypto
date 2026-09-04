Status: Planned

# `odf-crypto` CLI

A command-line front end over the published library, so the people who actually
hit encrypted ODF files — forensics, DLP triage, archival ingest, anyone with a
locked `.odt` and no Rust toolchain in the loop — can use it without writing a
program. Horsmann/odfdecrypt ships one; this crate does not, and that is the
single largest gap between the two for a non-Rust user.

## 1. Shape

One binary, `odf-crypto`, three subcommands:

```
odf-crypto classify <FILE>                 # what is it, is it encrypted, how
odf-crypto decrypt  <IN> [-o OUT]          # -> plaintext ODF zip
odf-crypto encrypt  <IN> [-o OUT]          # -> LibreOffice-shaped encrypted ODF
```

`classify` needs no password and no `crypto-ops`. `decrypt` and `encrypt` do.

### Why a `cli` feature, default off

A library consumer must not pay for an argument parser or a terminal crate. The
binary is gated:

```toml
cli = ["crypto-ops", "dep:rpassword", "dep:clap", "dep:serde_json"]

[[bin]]
name = "odf-crypto"
required-features = ["cli"]
```

`required-features` is what stops `cargo test` from trying to build the binary
in a library-only configuration — the same mechanism `examples/` already uses
(`Cargo.toml`, the `[[example]]` table). Without it the detection-only test job
fails on a binary that references `odf_crypto::decrypt`.

`cargo install odf-crypto --features cli` is the install line. It is not the
default because `cargo install` on a library is not the common path, and making
`cli` default would put `rpassword` in front of every library consumer.

### Argument parsing: `clap`, builder API

**Reversed during implementation.** This section originally said hand-rolled,
on two arguments that did not survive contact:

- It quoted "roughly fifteen crates" for `clap`. Measured, `derive` is **21** —
  but the **builder API with `suggestions` is 5**, and that option was never
  considered. The section argued against the expensive variant and missed the
  cheap one.
- It reasoned from "this crate advertises 27 crates for detection". That is an
  argument about *library consumers*, who are unaffected either way: `cli` is
  opt-in, and the default build still resolves 27 crates with no `clap`. It
  applied the library's standard to a binary.

The hand-rolled parser also shipped two real defects, both found by probing the
built binary: `--output=x.odt` was rejected outright — the GNU `--flag=value`
form — and a near-miss like `--password-en` got "unrecognised option" with no
suggestion.

So: `clap` 4, `default-features = false`, features `std`, `help`, `usage`,
`error-context`, `suggestions`. **No `derive`** (21 crates) and no `wrap_help`
(8, pulls `terminal_size` and `windows-sys`).

One thing the hand-rolled version did better, and which is preserved: a caller
typing `--password secret` gets *the reason it does not exist*, not "unexpected
argument". `--password` is registered as a hidden argument purely so that
explanation is reachable.

## 2. Passwords never come from `argv`

`argv` is world-readable in a process listing for the lifetime of the run —
`ps aux` on Linux, Task Manager's command-line column on Windows. There is
deliberately **no `--password VALUE` flag**, and adding one later is a
regression, not a feature.

Four sources, checked in this order:

| Flag | Source | For |
|---|---|---|
| `--password-env NAME` | that environment variable | scripts, CI |
| `--password-file PATH` | first line of the file, trailing newline stripped | secret managers, `--password-file /dev/stdin` |
| `--password-stdin` | one line from stdin | pipelines |
| *(none)* | non-echoing terminal prompt via `rpassword` | interactive use |

Exactly one may be given; two is a usage error rather than a silent precedence
win. With none of them and no terminal — stdin is not a TTY — the command fails
telling the user which flags exist, rather than blocking forever on a prompt
nobody can see.

`examples/encrypt_for_validation.rs` already made this call for the same reason
(`ODF_ENCRYPT_PASSWORD` rather than an argument). The CLI generalizes it.

## 3. Exit codes

A CLI that returns 1 for everything cannot be scripted. `decrypt` in particular
has to let a caller tell *wrong password* from *this was never encrypted*,
because those drive different next steps.

| Code | Meaning | Maps from |
|---|---|---|
| 0 | success | — |
| 1 | usage error | bad flags, missing operand, two password sources |
| 2 | I/O error | unreadable input, unwritable output |
| 3 | not an ODF package | `DetectError::NotZip`, `MissingManifest` |
| 4 | wrong password | `DecryptError::WrongPassword` |
| 5 | refused: this crate will not act on it | `NotEncrypted`, `AlreadyEncrypted`, `Odf12Fatal`, `UnsupportedPgp`, `Inconsistent` |
| 6 | malformed or hostile package | `BadParameters`, `Inflate`, `Zip`, `Mimetype`, `Deflate` |
| 7 | internal invariant violated | `DecryptError::Internal`, `EncryptError::Internal` |

Codes 4 and 5 are the distinction that earns the table: `WrongPassword` means
*try again*, `NotEncrypted` means *stop, you had the wrong file*.

## 4. `classify` output

Human-readable by default, one field per line, stable key names:

```
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

`--json` emits the same data as one object, built as a `serde_json::Value`.

**Also reversed.** This originally said hand-written, and the hand-written
version was correct — `json_escape` was tested over quotes, backslashes, the
named short escapes, sub-`0x20`, `0x7f` and non-ASCII, and every golden's output
parsed. It was replaced anyway, for a structural reason rather than a defect:
with escaping done by hand, a field added later without remembering to escape it
silently emits broken JSON. Handing the object to `serde_json` makes that class
of error impossible.

`serde_json` alone is 5 crates; the `serde` derive (11) is not needed, because
the object is built directly rather than derived from a struct.

An unencrypted package prints `encrypted: no` and exits 0 — that is an answer,
not a failure. Only a non-ODF input is exit 3.

## 5. Output paths

`-o/--output PATH` writes there. With no `-o`, write next to the input:
`report.odt` → `report.decrypted.odt` / `report.encrypted.odt`. Never overwrite
an existing file without `--force`; a decrypt that silently replaced the
encrypted original would be unrecoverable, and this crate's whole posture is
that the user's data outlives the tool.

Write to a temporary file in the destination directory and rename over the
target, so an interrupted run cannot leave a half-written `.odt` that looks
complete. `-o -` writes to stdout for pipelines, and suppresses the progress
line.

## 6. Slices

| Slice | Work | Done when |
|---|---|---|
| **S1** | `cli` feature and `[[bin]]` with `required-features`, arg parsing, `--help`/`-h`/`--version`, the exit-code table as an `ExitCode` mapping, and `classify` with human output. No password handling, no decrypt/encrypt. | `--help` and `--version` exit 0 and name all three subcommands. `classify` on `lo-wholesome-gcm-argon2.odt` prints mode `wholesome` and the AES-GCM/Argon2id tuple; on `lo-unencrypted.odt` prints `encrypted: no` and exits 0; on a non-zip exits 3. Unknown flag exits 1 with the flag named on stderr. `cargo test --no-default-features` still green — the binary must not build in that configuration. |
| **S2** | `--json` for `classify`. | `--json` output parses as one object for all six goldens, discovered at run time rather than hardcoded, and carries the same values the human form printed. A unit test round-trips the output back through `serde_json::from_str` for an encrypted and an unencrypted golden, so a malformed field fails rather than merely looking plausible. |
| **S3** | Password sourcing: `--password-env`, `--password-file`, `--password-stdin`, and the `rpassword` prompt fallback. Two sources is a usage error; none with no TTY is a usage error naming the flags. | Each of the three non-interactive sources decrypts `lo-wholesome-gcm-argon2.odt`. Two sources together exits 1. No source with stdin redirected from `/dev/null` exits 1 and does not hang. **No `--password` flag exists** — a test greps the binary's own `--help` for the string `--password ` and fails if it appears. |
| **S4** | `decrypt` and `encrypt` subcommands over S3's password sourcing: `-o`, the default derived output name, `--force`, atomic temp-then-rename, `-o -` to stdout. | `decrypt` of each encrypted golden round-trips to a package `classify` calls `Mode::Plain`. `encrypt` of `lo-unencrypted.odt` then `decrypt` is byte-identical to the input. Wrong password exits 4; decrypting `lo-unencrypted.odt` exits 5. Existing output without `--force` exits 1 and leaves the existing file byte-identical. An interrupted write leaves no partial file at the target path. |
| **S5** | README CLI section, install line, the exit-code table, and the "never in argv" rule stated where a user reads it. `cli` documented in the feature table. | README documents all three subcommands with a worked example each, and the exit-code table matches §3 exactly. `cargo package --features cli` includes `src/bin/`, verified by `cargo package --list`. |

S2, S3 and S4 block on S1. S4 blocks on S3 (it needs a password). S5 blocks on S4.

## 7. Out of scope

- **No batch or recursive mode.** `find … -exec` composes better than a flag,
  and a half-finished directory walk is a worse failure than a shell loop.
- **No password-guessing, wordlist or brute-force affordance.** The library
  cannot distinguish a wrong password from corrupted ciphertext anyway
  (`DecryptError::WrongPassword`'s own doc), so such a mode would be
  slow *and* unreliable — and it is not what this crate is for.
- **No PGP.** The library refuses those packages; the CLI reports the refusal
  and exits 5.
- **No config file.** Three subcommands and six flags.
- **No coloured output.** It would pull a terminal-styling crate to decorate
  ten lines of key-value text.

## 8. Borrow / do not copy

**Borrow:** the argv reasoning and `ExitCode` shape already in
`examples/encrypt_for_validation.rs`; the goldens as CLI fixtures, driven
through the built binary rather than re-read in-process, so the test exercises
argument handling and exit codes rather than the library a second time.

**Do not copy:** the example itself. It is a throwaway shim for
`validate_encrypt.py` with two positional arguments and one env var, and it
stays that way — the CLI does not replace it, and `validate_encrypt.py` keeps
calling the example so the LibreOffice validation path does not start depending
on the CLI's argument grammar.
