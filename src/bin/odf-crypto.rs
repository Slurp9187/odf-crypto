//! `odf-crypto` — classify, decrypt and encrypt ODF packages from a shell.
//!
//! Plan: `docs/plans/odf-crypto-cli-2026-09-04.md`.
//!
//! Passwords never come from `argv`. There is deliberately no `--password
//! VALUE` argument, because `argv` is world-readable in a process listing for
//! the lifetime of the run. `--password` is registered anyway, hidden, purely so
//! that reaching for it produces an explanation rather than "unexpected
//! argument".

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};
use odf_crypto::{
    classify, decrypt, encrypt, Checksum, Cipher, Classification, DecryptError, DetectError,
    EncryptError, Kdf, Mode, StartKeyAlg,
};

// Plan §3. A CLI that returns 1 for everything cannot be scripted; 4 against 5
// is the distinction that earns the table -- "try again" against "wrong file".
const EX_OK: u8 = 0;
const EX_USAGE: u8 = 1;
const EX_IO: u8 = 2;
const EX_NOT_ODF: u8 = 3;
const EX_WRONG_PASSWORD: u8 = 4;
const EX_REFUSED: u8 = 5;
const EX_MALFORMED: u8 = 6;
const EX_INTERNAL: u8 = 7;

const AFTER_HELP: &str = "\
EXIT CODES:
  0 ok        1 usage      2 io          3 not-odf
  4 wrong-password         5 refused     6 malformed   7 internal

4 and 5 differ on purpose: 4 means try again, 5 means you had the wrong file.";

const PASSWORD_AFTER_HELP: &str = "\
PASSWORDS:
  argv is world-readable in a process listing, so there is no `--password
  VALUE` argument. Give exactly one source, or none to be prompted without echo.

EXIT CODES:
  0 ok        1 usage      2 io          3 not-odf
  4 wrong-password         5 refused     6 malformed   7 internal";

/// Registered but hidden, so `--password secret` is met with the reason it does
/// not exist rather than clap's generic "unexpected argument". Removing it would
/// make the tool *less* clear about a decision the plan calls load-bearing.
const PASSWORD_TRAP: &str = "password";

fn password_args() -> [Arg; 4] {
    [
        Arg::new("password-env")
            .long("password-env")
            .value_name("NAME")
            .help("Read the password from this environment variable"),
        Arg::new("password-file")
            .long("password-file")
            .value_name("PATH")
            .help("Read the password from the first line of this file"),
        Arg::new("password-stdin")
            .long("password-stdin")
            .action(ArgAction::SetTrue)
            .help("Read the password as one line from stdin"),
        Arg::new(PASSWORD_TRAP)
            .long("password")
            .value_name("VALUE")
            .hide(true),
    ]
}

fn crypt_command(name: &'static str, about: &'static str, default_suffix: &'static str) -> Command {
    let output_help: &'static str = Box::leak(
        format!("Write here; `-` for stdout. Default: FILE.{default_suffix}.odt").into_boxed_str(),
    );
    Command::new(name)
        .about(about)
        .arg(
            Arg::new("file")
                .value_name("FILE")
                .required(true)
                .help("The ODF package to read"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("PATH")
                .help(output_help),
        )
        .arg(
            Arg::new("force")
                .long("force")
                .action(ArgAction::SetTrue)
                .help("Overwrite an existing output file"),
        )
        .args(password_args())
        // Exactly one password source, so two is an error rather than a silent
        // precedence win. Not `required`: none of them means "prompt".
        .group(
            ArgGroup::new("password-source")
                .args(["password-env", "password-file", "password-stdin"])
                .multiple(false),
        )
        .after_help(PASSWORD_AFTER_HELP)
}

fn cli() -> Command {
    Command::new("odf-crypto")
        .version(env!("CARGO_PKG_VERSION"))
        .about("LibreOffice-faithful ODF package encryption")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .after_help(AFTER_HELP)
        .subcommand(
            Command::new("classify")
                .about("Report whether a file is an ODF package, and how it is encrypted")
                .arg(
                    Arg::new("file")
                        .value_name("FILE")
                        .required(true)
                        .help("The file to inspect"),
                )
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Emit one JSON object instead of key-value lines"),
                )
                .after_help(
                    "An unencrypted package prints `encrypted: no` and exits 0 — that is an \
                     answer, not a failure. Only a non-ODF input exits 3.",
                ),
        )
        .subcommand(crypt_command(
            "decrypt",
            "Decrypt an encrypted ODF package",
            "decrypted",
        ))
        .subcommand(crypt_command(
            "encrypt",
            "Encrypt a plaintext ODF package",
            "encrypted",
        ))
}

fn main() -> ExitCode {
    // Parsed by hand rather than `get_matches()` so a clap usage error becomes
    // exit 1 from the table above, not clap's own exit 2 -- which would collide
    // with the I/O code.
    let m = match cli().try_get_matches() {
        Ok(m) => m,
        Err(e) => {
            let ok = matches!(
                e.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            );
            let _ = e.print();
            return ExitCode::from(if ok { EX_OK } else { EX_USAGE });
        }
    };
    ExitCode::from(dispatch(&m))
}

fn dispatch(m: &ArgMatches) -> u8 {
    match m.subcommand() {
        Some(("classify", sub)) => cmd_classify(sub),
        Some(("decrypt", sub)) => cmd_crypt(sub, Direction::Decrypt),
        Some(("encrypt", sub)) => cmd_crypt(sub, Direction::Encrypt),
        _ => EX_USAGE,
    }
}

// --- classify -------------------------------------------------------------

fn cmd_classify(m: &ArgMatches) -> u8 {
    let file = m.get_one::<String>("file").expect("required by clap");
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("odf-crypto: cannot read {file}: {e}");
            return EX_IO;
        }
    };
    match classify(&bytes) {
        Ok(c) => {
            if m.get_flag("json") {
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
    let mut line = |k: &str, v: &str| out.push_str(&format!("{k:<13}{v}\n"));
    line("package:", "ODF");
    line("mode:", mode_str(c.mode));
    line("encrypted:", if c.package_encrypted { "yes" } else { "no" });
    line("odf-version:", c.odf_version.as_deref().unwrap_or("(none)"));
    line("media-type:", c.media_type.as_deref().unwrap_or("(none)"));
    if c.odf12_fatal {
        line("refused:", "unexpected ODF 1.2 streams");
    }
    if !c.pgp_keys.is_empty() {
        line(
            "pgp-keys:",
            &format!("{} (not decryptable by this tool)", c.pgp_keys.len()),
        );
    }
    if let Some(row) = c.common.as_ref() {
        line("cipher:", cipher_str(row.cipher));
        line("kdf:", &kdf_str(&row.kdf));
        line("start-key:", start_key_str(row.start_key));
        line("checksum:", checksum_str(&row.checksum));
        line("key-size:", &row.derived_key_len.to_string());
    }
    if c.encrypted_entries.len() > 1 {
        line("entries:", &c.encrypted_entries.len().to_string());
    }
    out
}

/// Built as a `serde_json::Value` rather than by string concatenation.
///
/// The hand-written version this replaced was correct and tested, so this buys
/// nothing today. What it removes is a class of future error: a field added
/// without remembering to escape it can no longer emit broken JSON, because
/// escaping is no longer something this function does.
fn classification_json(c: &Classification) -> String {
    use serde_json::{json, Map, Value};

    let mut o = Map::new();
    o.insert("package".into(), json!("ODF"));
    o.insert("mode".into(), json!(mode_str(c.mode)));
    o.insert("encrypted".into(), json!(c.package_encrypted));
    o.insert("odf_version".into(), json!(c.odf_version));
    o.insert("media_type".into(), json!(c.media_type));
    o.insert("odf12_fatal".into(), json!(c.odf12_fatal));
    o.insert(
        "has_unexpected_streams".into(),
        json!(c.has_unexpected_streams),
    );
    o.insert("pgp_keys".into(), json!(c.pgp_keys.len()));
    o.insert("encrypted_entries".into(), json!(c.encrypted_entries.len()));
    match c.common.as_ref() {
        Some(row) => {
            o.insert("cipher".into(), json!(cipher_str(row.cipher)));
            o.insert("kdf".into(), json!(kdf_str(&row.kdf)));
            o.insert("start_key".into(), json!(start_key_str(row.start_key)));
            o.insert("checksum".into(), json!(checksum_str(&row.checksum)));
            o.insert("key_size".into(), json!(row.derived_key_len));
        }
        None => {
            for k in ["cipher", "kdf", "start_key", "checksum", "key_size"] {
                o.insert(k.into(), Value::Null);
            }
        }
    }
    Value::Object(o).to_string()
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
}

enum PasswordSource {
    Env(String),
    File(PathBuf),
    Stdin,
    Prompt,
}

fn cmd_crypt(m: &ArgMatches, dir: Direction) -> u8 {
    // The hidden trap arg. Registered so this explains itself rather than
    // clap saying "unexpected argument", which would not tell a caller why.
    if m.get_one::<String>(PASSWORD_TRAP).is_some() {
        eprintln!(
            "odf-crypto: there is no `--password` argument: argv is world-readable in a \
             process listing.\nUse --password-env NAME, --password-file PATH or --password-stdin."
        );
        return EX_USAGE;
    }

    // The ArgGroup already rejects two sources, so at most one is present.
    let source = if let Some(name) = m.get_one::<String>("password-env") {
        PasswordSource::Env(name.clone())
    } else if let Some(path) = m.get_one::<String>("password-file") {
        PasswordSource::File(PathBuf::from(path))
    } else if m.get_flag("password-stdin") {
        PasswordSource::Stdin
    } else {
        PasswordSource::Prompt
    };

    let file = m.get_one::<String>("file").expect("required by clap");
    let bytes = match std::fs::read(file) {
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

    match m.get_one::<String>("output").map(String::as_str) {
        Some("-") => {
            let mut stdout = std::io::stdout().lock();
            if let Err(e) = stdout.write_all(&produced).and_then(|()| stdout.flush()) {
                eprintln!("odf-crypto: cannot write to stdout: {e}");
                return EX_IO;
            }
            EX_OK
        }
        other => {
            let target = match other {
                Some(o) => PathBuf::from(o),
                None => derived_output(Path::new(file), dir.suffix()),
            };
            if target.exists() && !m.get_flag("force") {
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
