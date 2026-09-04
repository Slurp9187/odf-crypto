//! `odf-crypto` — classify, decrypt and encrypt ODF packages from a shell.
//!
//! Plan: `docs/plans/odf-crypto-cli-2026-09-04.md`.
//!
//! Argument parsing is hand-rolled rather than `clap`: three subcommands and six
//! flags do not justify roughly fifteen crates in a project that advertises 27
//! for detection. The bar that still has to be met is `--help` everywhere,
//! `--version`, an unknown flag that names itself, and a usage line on stderr.
//!
//! Passwords never come from `argv`. There is deliberately no `--password
//! VALUE` flag, because `argv` is world-readable in a process listing for the
//! lifetime of the run.

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use odf_crypto::{
    classify, decrypt, encrypt, Checksum, Cipher, Classification, DecryptError, DetectError,
    EncryptError, Kdf, Mode, StartKeyAlg,
};

// Plan §3. A CLI that returns 1 for everything cannot be scripted; 4 vs 5 is
// the distinction that earns the table -- "try again" against "wrong file".
const EX_OK: u8 = 0;
const EX_USAGE: u8 = 1;
const EX_IO: u8 = 2;
const EX_NOT_ODF: u8 = 3;
const EX_WRONG_PASSWORD: u8 = 4;
const EX_REFUSED: u8 = 5;
const EX_MALFORMED: u8 = 6;
const EX_INTERNAL: u8 = 7;

const USAGE: &str = "\
odf-crypto — LibreOffice-faithful ODF package encryption

USAGE:
    odf-crypto <COMMAND> [OPTIONS] <FILE>

COMMANDS:
    classify    Report whether a file is an ODF package and how it is encrypted
    decrypt     Decrypt an encrypted ODF package
    encrypt     Encrypt a plaintext ODF package

OPTIONS:
    -h, --help       Print help (use with a command for its own options)
    -V, --version    Print version

EXIT CODES:
    0 ok   1 usage   2 io   3 not-odf   4 wrong-password
    5 refused   6 malformed   7 internal

Run `odf-crypto <COMMAND> --help` for command options.";

const CLASSIFY_USAGE: &str = "\
odf-crypto classify — report what a file is, and how it is encrypted

USAGE:
    odf-crypto classify [OPTIONS] <FILE>

OPTIONS:
        --json    Emit one JSON object instead of key-value lines
    -h, --help    Print help

Needs no password. An unencrypted package prints `encrypted: no` and exits 0 —
that is an answer, not a failure. Only a non-ODF input exits 3.";

const PASSWORD_HELP: &str = "\
PASSWORD (exactly one, or none to be prompted):
        --password-env <NAME>    Read the password from this environment variable
        --password-file <PATH>   Read the first line of this file
        --password-stdin         Read one line from stdin

There is deliberately no `--password <VALUE>` flag: argv is world-readable in a
process listing for the lifetime of the run. With none of these and a terminal,
you are prompted without echo.";

fn decrypt_usage() -> String {
    format!(
        "\
odf-crypto decrypt — decrypt an encrypted ODF package

USAGE:
    odf-crypto decrypt [OPTIONS] <FILE>

OPTIONS:
    -o, --output <PATH>    Write here; `-` for stdout. Default: FILE.decrypted.odt
        --force            Overwrite an existing output file
    -h, --help             Print help

{PASSWORD_HELP}"
    )
}

fn encrypt_usage() -> String {
    format!(
        "\
odf-crypto encrypt — encrypt a plaintext ODF package

USAGE:
    odf-crypto encrypt [OPTIONS] <FILE>

OPTIONS:
    -o, --output <PATH>    Write here; `-` for stdout. Default: FILE.encrypted.odt
        --force            Overwrite an existing output file
    -h, --help             Print help

{PASSWORD_HELP}"
    )
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(run(&args))
}

fn run(args: &[String]) -> u8 {
    let Some(first) = args.first() else {
        eprintln!("{USAGE}");
        return EX_USAGE;
    };
    match first.as_str() {
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            EX_OK
        }
        "-V" | "--version" => {
            println!("odf-crypto {}", env!("CARGO_PKG_VERSION"));
            EX_OK
        }
        "classify" => cmd_classify(&args[1..]),
        "decrypt" => cmd_crypt(&args[1..], Direction::Decrypt),
        "encrypt" => cmd_crypt(&args[1..], Direction::Encrypt),
        other => {
            eprintln!("odf-crypto: unknown command `{other}`\n\n{USAGE}");
            EX_USAGE
        }
    }
}

// --- classify -------------------------------------------------------------

fn cmd_classify(args: &[String]) -> u8 {
    let mut json = false;
    let mut file: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{CLASSIFY_USAGE}");
                return EX_OK;
            }
            "--json" => json = true,
            "--" => {
                if let Some(f) = it.next() {
                    file = Some(f.clone());
                }
            }
            other if other.starts_with('-') && other != "-" => {
                return usage_err(&format!("unrecognised option `{other}` for `classify`"));
            }
            other => {
                if file.is_some() {
                    return usage_err("classify takes exactly one FILE");
                }
                file = Some(other.to_string());
            }
        }
    }
    let Some(file) = file else {
        return usage_err("classify needs a FILE");
    };

    let bytes = match std::fs::read(&file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("odf-crypto: cannot read {file}: {e}");
            return EX_IO;
        }
    };
    match classify(&bytes) {
        Ok(c) => {
            if json {
                println!("{}", classification_json(&c));
            } else {
                print!("{}", classification_human(&c));
            }
            EX_OK
        }
        Err(e) => {
            eprintln!("odf-crypto: {e}");
            detect_exit(&e)
        }
    }
}

fn mode_str(m: Mode) -> &'static str {
    match m {
        Mode::Plain => "plain",
        Mode::PerEntry => "per-entry",
        Mode::Wholesome => "wholesome",
    }
}

fn cipher_str(c: Cipher) -> &'static str {
    match c {
        Cipher::BlowfishCfb8 => "Blowfish-CFB",
        Cipher::AesCbcW3c => "AES-CBC (W3C)",
        Cipher::AesGcmW3c => "AES-GCM (W3C)",
    }
}

fn start_key_str(s: StartKeyAlg) -> &'static str {
    match s {
        StartKeyAlg::Sha1 => "SHA-1",
        StartKeyAlg::Sha256 => "SHA-256",
    }
}

fn kdf_str(k: &Kdf) -> String {
    match k {
        Kdf::Pbkdf2 { iterations, .. } => format!("PBKDF2 iterations={iterations}"),
        Kdf::Argon2id { t, m, p, .. } => format!("Argon2id t={t} m={m}KiB p={p}"),
        Kdf::PgpRsaOaepMgf1p => "PGP RSA-OAEP-MGF1P".to_string(),
    }
}

fn checksum_str(c: &Checksum) -> &'static str {
    match c {
        Checksum::None => "none",
        Checksum::Sha1_1K(_) => "SHA-1/1K",
        Checksum::Sha256_1K(_) => "SHA-256/1K",
    }
}

fn classification_human(c: &Classification) -> String {
    let mut out = String::new();
    let line = |out: &mut String, k: &str, v: &str| {
        out.push_str(&format!("{k:<13}{v}\n"));
    };
    line(&mut out, "package:", "ODF");
    line(&mut out, "mode:", mode_str(c.mode));
    line(
        &mut out,
        "encrypted:",
        if c.package_encrypted { "yes" } else { "no" },
    );
    line(
        &mut out,
        "odf-version:",
        c.odf_version.as_deref().unwrap_or("(none)"),
    );
    line(
        &mut out,
        "media-type:",
        c.media_type.as_deref().unwrap_or("(none)"),
    );
    if c.odf12_fatal {
        line(&mut out, "refused:", "unexpected ODF 1.2 streams");
    }
    if !c.pgp_keys.is_empty() {
        line(
            &mut out,
            "pgp-keys:",
            &format!("{} (not decryptable by this tool)", c.pgp_keys.len()),
        );
    }
    if let Some(row) = c.common.as_ref() {
        line(&mut out, "cipher:", cipher_str(row.cipher));
        line(&mut out, "kdf:", &kdf_str(&row.kdf));
        line(&mut out, "start-key:", start_key_str(row.start_key));
        line(&mut out, "checksum:", checksum_str(&row.checksum));
        line(&mut out, "key-size:", &row.derived_key_len.to_string());
    }
    if c.encrypted_entries.len() > 1 {
        line(&mut out, "entries:", &c.encrypted_entries.len().to_string());
    }
    out
}

/// Hand-written rather than `serde_json`: the field set is fixed and small, and
/// ten scalars do not justify that graph in a crate whose manifest argues about
/// single dependencies. Quoting is the one real risk, so it goes through
/// [`json_escape`], which is tested.
fn classification_json(c: &Classification) -> String {
    let mut f: Vec<String> = Vec::new();
    f.push(format!("\"package\":\"{}\"", json_escape("ODF")));
    f.push(format!("\"mode\":\"{}\"", mode_str(c.mode)));
    f.push(format!("\"encrypted\":{}", c.package_encrypted));
    f.push(match c.odf_version.as_deref() {
        Some(v) => format!("\"odf_version\":\"{}\"", json_escape(v)),
        None => "\"odf_version\":null".to_string(),
    });
    f.push(match c.media_type.as_deref() {
        Some(v) => format!("\"media_type\":\"{}\"", json_escape(v)),
        None => "\"media_type\":null".to_string(),
    });
    f.push(format!("\"odf12_fatal\":{}", c.odf12_fatal));
    f.push(format!(
        "\"has_unexpected_streams\":{}",
        c.has_unexpected_streams
    ));
    f.push(format!("\"pgp_keys\":{}", c.pgp_keys.len()));
    f.push(format!(
        "\"encrypted_entries\":{}",
        c.encrypted_entries.len()
    ));
    match c.common.as_ref() {
        Some(row) => {
            f.push(format!(
                "\"cipher\":\"{}\"",
                json_escape(cipher_str(row.cipher))
            ));
            f.push(format!("\"kdf\":\"{}\"", json_escape(&kdf_str(&row.kdf))));
            f.push(format!(
                "\"start_key\":\"{}\"",
                json_escape(start_key_str(row.start_key))
            ));
            f.push(format!(
                "\"checksum\":\"{}\"",
                json_escape(checksum_str(&row.checksum))
            ));
            f.push(format!("\"key_size\":{}", row.derived_key_len));
        }
        None => {
            for k in ["cipher", "kdf", "start_key", "checksum", "key_size"] {
                f.push(format!("\"{k}\":null"));
            }
        }
    }
    format!("{{{}}}", f.join(","))
}

/// RFC 8259 §7: `"` and `\` must be escaped, every scalar below `0x20` must be,
/// and anything else may be emitted literally. Non-ASCII passes through as UTF-8
/// rather than `\u`-escaping, which the spec allows and which keeps a media type
/// readable.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// --- decrypt / encrypt ----------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Decrypt,
    Encrypt,
}

impl Direction {
    fn suffix(self) -> &'static str {
        match self {
            Direction::Decrypt => "decrypted",
            Direction::Encrypt => "encrypted",
        }
    }
    fn usage(self) -> String {
        match self {
            Direction::Decrypt => decrypt_usage(),
            Direction::Encrypt => encrypt_usage(),
        }
    }
}

/// Exactly one may be selected. Two is a usage error rather than a silent
/// precedence win, because a script that sets both is wrong and should be told.
enum PasswordSource {
    Env(String),
    File(PathBuf),
    Stdin,
    Prompt,
}

fn cmd_crypt(args: &[String], dir: Direction) -> u8 {
    let mut file: Option<String> = None;
    let mut output: Option<String> = None;
    let mut force = false;
    let mut sources: Vec<PasswordSource> = Vec::new();

    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{}", dir.usage());
                return EX_OK;
            }
            "--force" => force = true,
            "--password-stdin" => sources.push(PasswordSource::Stdin),
            "-o" | "--output" => match it.next() {
                Some(v) => output = Some(v.clone()),
                None => return usage_err("`--output` needs a PATH"),
            },
            "--password-env" => match it.next() {
                Some(v) => sources.push(PasswordSource::Env(v.clone())),
                None => return usage_err("`--password-env` needs a NAME"),
            },
            "--password-file" => match it.next() {
                Some(v) => sources.push(PasswordSource::File(PathBuf::from(v))),
                None => return usage_err("`--password-file` needs a PATH"),
            },
            "--password" => {
                return usage_err(
                    "there is no `--password` flag: argv is world-readable in a process \
                     listing. Use --password-env, --password-file or --password-stdin",
                );
            }
            other if other.starts_with('-') && other != "-" => {
                return usage_err(&format!(
                    "unrecognised option `{other}` for `{}`",
                    match dir {
                        Direction::Decrypt => "decrypt",
                        Direction::Encrypt => "encrypt",
                    }
                ));
            }
            other => {
                if file.is_some() {
                    return usage_err("takes exactly one FILE");
                }
                file = Some(other.to_string());
            }
        }
    }

    let Some(file) = file else {
        return usage_err("needs a FILE");
    };
    if sources.len() > 1 {
        return usage_err(
            "give exactly one of --password-env, --password-file or --password-stdin",
        );
    }
    let source = sources.pop().unwrap_or(PasswordSource::Prompt);

    let bytes = match std::fs::read(&file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("odf-crypto: cannot read {file}: {e}");
            return EX_IO;
        }
    };

    let password = match read_password(source, dir) {
        Ok(p) => p,
        Err(code) => return code,
    };

    let produced = match dir {
        Direction::Decrypt => match decrypt(&bytes, &password) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("odf-crypto: {e}");
                return decrypt_exit(&e);
            }
        },
        Direction::Encrypt => match encrypt(&bytes, &password) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("odf-crypto: {e}");
                return encrypt_exit(&e);
            }
        },
    };

    match output.as_deref() {
        Some("-") => {
            let mut stdout = std::io::stdout().lock();
            if let Err(e) = stdout.write_all(&produced).and_then(|()| stdout.flush()) {
                eprintln!("odf-crypto: cannot write to stdout: {e}");
                return EX_IO;
            }
            EX_OK
        }
        _ => {
            let target = match output {
                Some(o) => PathBuf::from(o),
                None => derived_output(Path::new(&file), dir.suffix()),
            };
            if target.exists() && !force {
                eprintln!(
                    "odf-crypto: {} already exists; pass --force to overwrite",
                    target.display()
                );
                return EX_USAGE;
            }
            match write_atomically(&target, &produced) {
                Ok(()) => {
                    eprintln!("odf-crypto: wrote {}", target.display());
                    EX_OK
                }
                Err(e) => {
                    eprintln!("odf-crypto: cannot write {}: {e}", target.display());
                    EX_IO
                }
            }
        }
    }
}

/// `report.odt` -> `report.decrypted.odt`. A file with no extension gets the
/// suffix appended, so `report` -> `report.decrypted`.
fn derived_output(input: &Path, suffix: &str) -> PathBuf {
    let stem = input.file_stem().unwrap_or_default().to_string_lossy();
    let name = match input.extension() {
        Some(ext) => format!("{stem}.{suffix}.{}", ext.to_string_lossy()),
        None => format!("{stem}.{suffix}"),
    };
    input.with_file_name(name)
}

/// Write to a temporary file in the destination directory, then rename over the
/// target. An interrupted run leaves the temporary behind rather than a
/// half-written `.odt` at the target path that looks complete — and a decrypt
/// that silently truncated the encrypted original would be unrecoverable.
///
/// Same directory, because a rename across filesystems is not atomic and would
/// degrade to a copy.
fn write_atomically(target: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = target.parent().unwrap_or(Path::new("."));
    let file_name = target.file_name().unwrap_or_default().to_string_lossy();
    let tmp = dir.join(format!(".{file_name}.odf-crypto.tmp"));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    match std::fs::rename(&tmp, target) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn read_password(source: PasswordSource, dir: Direction) -> Result<String, u8> {
    match source {
        PasswordSource::Env(name) => std::env::var(&name).map_err(|_| {
            eprintln!("odf-crypto: environment variable `{name}` is not set");
            EX_USAGE
        }),
        PasswordSource::File(path) => match std::fs::read_to_string(&path) {
            Ok(s) => Ok(first_line(&s)),
            Err(e) => {
                eprintln!("odf-crypto: cannot read {}: {e}", path.display());
                Err(EX_IO)
            }
        },
        PasswordSource::Stdin => {
            let mut s = String::new();
            match std::io::stdin().read_to_string(&mut s) {
                Ok(_) => Ok(first_line(&s)),
                Err(e) => {
                    eprintln!("odf-crypto: cannot read stdin: {e}");
                    Err(EX_IO)
                }
            }
        }
        PasswordSource::Prompt => {
            // Refuse rather than block on a prompt nobody can see.
            if !std::io::stdin().is_terminal() {
                eprintln!(
                    "odf-crypto: no password source and stdin is not a terminal.\n\
                     Use --password-env NAME, --password-file PATH or --password-stdin."
                );
                return Err(EX_USAGE);
            }
            let verb = match dir {
                Direction::Decrypt => "Password",
                Direction::Encrypt => "New password",
            };
            rpassword::prompt_password(format!("{verb}: ")).map_err(|e| {
                eprintln!("odf-crypto: cannot read password: {e}");
                EX_IO
            })
        }
    }
}

/// A password file written by an editor ends with a newline that is not part of
/// the password. Strips one trailing CR-LF or LF, and nothing else — trailing
/// spaces are kept, because they can be deliberate.
fn first_line(s: &str) -> String {
    let line = s.split('\n').next().unwrap_or("");
    line.strip_suffix('\r').unwrap_or(line).to_string()
}

// --- error -> exit code ---------------------------------------------------

fn usage_err(msg: &str) -> u8 {
    eprintln!("odf-crypto: {msg}");
    EX_USAGE
}

fn detect_exit(e: &DetectError) -> u8 {
    match e {
        DetectError::NotZip | DetectError::MissingManifest => EX_NOT_ODF,
        DetectError::Inconsistent(_) => EX_REFUSED,
        DetectError::Zip(_) => EX_MALFORMED,
        _ => EX_MALFORMED,
    }
}

fn decrypt_exit(e: &DecryptError) -> u8 {
    match e {
        DecryptError::Classify(d) => detect_exit(d),
        DecryptError::WrongPassword => EX_WRONG_PASSWORD,
        DecryptError::NotEncrypted
        | DecryptError::Odf12Fatal
        | DecryptError::UnsupportedPgp
        | DecryptError::EmptyPassword => EX_REFUSED,
        DecryptError::BadParameters(_) | DecryptError::Inflate(_) | DecryptError::Zip(_) => {
            EX_MALFORMED
        }
        DecryptError::Internal(_) => EX_INTERNAL,
        _ => EX_MALFORMED,
    }
}

fn encrypt_exit(e: &EncryptError) -> u8 {
    match e {
        EncryptError::Classify(d) => detect_exit(d),
        EncryptError::AlreadyEncrypted | EncryptError::Odf12Fatal | EncryptError::EmptyPassword => {
            EX_REFUSED
        }
        EncryptError::Mimetype(_) | EncryptError::Deflate(_) | EncryptError::Zip(_) => EX_MALFORMED,
        EncryptError::Random(_) | EncryptError::Internal(_) => EX_INTERNAL,
        _ => EX_MALFORMED,
    }
}

#[cfg(test)]
#[path = "odf-crypto_tests.rs"]
mod tests;
