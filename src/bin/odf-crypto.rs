//! `odf-crypto` — classify, decrypt and encrypt ODF packages from a shell.
//!
//! Plan: `docs/plans/odf-crypto-cli-2026-09-04.md`.
//!
//! Passwords never come from `argv`. There is deliberately no `--password
//! VALUE` argument, because `argv` is world-readable in a process listing for
//! the lifetime of the run. `--password` is registered anyway, hidden, purely so
//! that reaching for it produces an explanation rather than "unexpected
//! argument".

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use clap::{Arg, ArgAction, ArgGroup, ArgMatches, Command};
use odf_crypto::{
    classify_reader, decrypt_to, encrypt_with_params_to, reencrypt_to, Argon2Params, Checksum,
    Cipher, Classification, DecryptError, DecryptLimits, DetectError, EncryptError, Kdf, Mode,
    ReencryptError, StartKeyAlg,
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
/// This machine could not supply the memory the work needed. Not the file's
/// fault and not the flags' -- the same input may succeed on a larger host, or
/// at a lower `--argon2-m`. It earns a code of its own for the reason 4 and 5
/// do: it is the one failure here whose remedy is "change the machine or the
/// cost", and a script that cannot separate it from 6 would tell a user their
/// document is damaged when it is not.
const EX_HOST_CAPACITY: u8 = 8;
/// Cancelled with Ctrl-C: 128 + SIGINT, the shell convention. Not a verdict on
/// the file; any temporary output has been deleted.
const EX_CANCELLED: u8 = 130;

const AFTER_HELP: &str = "\
EXIT CODES:
  0 ok        1 usage      2 io          3 not-odf
  4 wrong-password         5 refused     6 malformed   7 internal
  8 host-capacity          130 cancelled (Ctrl-C)

4 and 5 differ on purpose: 4 means try again, 5 means you had the wrong file.
8 means neither: this machine could not supply the memory, and the same file
may work on a larger one or at a lower --argon2-m.";

const PASSWORD_AFTER_HELP: &str = "\
PASSWORDS:
  argv is world-readable in a process listing, so there is no `--password
  VALUE` argument. Give exactly one source, or none to be prompted without echo.

EXIT CODES:
  0 ok        1 usage      2 io          3 not-odf
  4 wrong-password         5 refused     6 malformed   7 internal
  8 host-capacity          130 cancelled (Ctrl-C)";

/// Registered but hidden, so `--password secret` is met with the reason it does
/// not exist rather than clap's generic "unexpected argument". Removing it would
/// make the tool *less* clear about a decision the plan calls load-bearing.
const PASSWORD_TRAP: &str = "password";

/// `encrypt` gets its own after-help: the Argon2 flags need the trade spelled
/// out where somebody about to use them will read it, and `PASSWORD_AFTER_HELP`
/// is shared with `decrypt`, which has no such flags.
const ENCRYPT_AFTER_HELP: &str = "ARGON2 COST:
  Defaults are what LibreOffice writes: --argon2-t 3 --argon2-m 65536 --argon2-p 4.
  Lower values exist for hardware that cannot afford 64 MiB. They are accepted,
  not blocked -- but the cost is stored IN THE FILE and applies to every future
  reader on every device, so a cheap file stays cheap to attack forever.
  A tuple weaker than LibreOffice's prints a warning on stderr and still writes.

PASSWORDS:
  argv is world-readable in a process listing, so there is no `--password
  VALUE` argument. Give exactly one source, or none to be prompted without echo.

EXIT CODES:
  0 ok        1 usage      2 io          3 not-odf
  4 wrong-password         5 refused     6 malformed   7 internal
  8 host-capacity          130 cancelled (Ctrl-C)";

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

/// The Argon2id cost flags, shared by `encrypt` and `rekey`.
fn argon2_args() -> [Arg; 3] {
    [
        Arg::new("argon2-t")
            .long("argon2-t")
            .value_name("N")
            .value_parser(clap::value_parser!(i32))
            .help("Argon2id time cost (default 3)"),
        Arg::new("argon2-m")
            .long("argon2-m")
            .value_name("KIB")
            .value_parser(clap::value_parser!(i32))
            .help("Argon2id memory cost in KiB (default 65536, i.e. 64 MiB)"),
        Arg::new("argon2-p")
            .long("argon2-p")
            .value_name("N")
            .value_parser(clap::value_parser!(i32))
            .help("Argon2id parallelism (default 4)"),
    ]
}

/// `rekey`'s after-help: what it refuses, and where the second password comes
/// from.
const REKEY_AFTER_HELP: &str = "REKEY:
  Decrypts with the old password and encrypts with the new one in a single
  stream: no plaintext is written anywhere. The result is what `encrypt`
  writes -- AES-256-GCM with Argon2id -- whatever the source used.

  An older per-entry file is refused (exit 5) if any listed part of it is not
  encrypted, or if it holds parts its manifest does not list: re-keying would
  seal that unencrypted content under the new password's authentication.
  `decrypt` still opens such a file.

PASSWORDS:
  The old password comes from --password-env, --password-file,
  --password-stdin or a prompt; the new one from --new-password-env,
  --new-password-file or a prompt. argv is world-readable in a process
  listing, so neither has a VALUE argument.

EXIT CODES:
  0 ok        1 usage      2 io          3 not-odf
  4 wrong-password         5 refused     6 malformed   7 internal
  8 host-capacity          130 cancelled (Ctrl-C)";

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
        .subcommand(
            crypt_command("encrypt", "Encrypt a plaintext ODF package", "encrypted")
                .args(argon2_args())
                .after_help(ENCRYPT_AFTER_HELP),
        )
        .subcommand(
            crypt_command(
                "rekey",
                "Change an encrypted ODF package's password",
                "rekeyed",
            )
            .args(argon2_args())
            .arg(
                Arg::new("new-password-env")
                    .long("new-password-env")
                    .value_name("NAME")
                    .help("Read the new password from this environment variable"),
            )
            .arg(
                Arg::new("new-password-file")
                    .long("new-password-file")
                    .value_name("PATH")
                    .help("Read the new password from the first line of this file"),
            )
            .group(
                ArgGroup::new("new-password-source")
                    .args(["new-password-env", "new-password-file"])
                    .multiple(false),
            )
            .after_help(REKEY_AFTER_HELP),
        )
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
        Some(("rekey", sub)) => cmd_crypt(sub, Direction::Rekey),
        _ => EX_USAGE,
    }
}

// --- classify -------------------------------------------------------------

fn cmd_classify(m: &ArgMatches) -> u8 {
    let file = m.get_one::<String>("file").expect("required by clap");
    let input = match File::open(file) {
        Ok(f) => BufReader::with_capacity(64 * 1024, f),
        Err(e) => {
            eprintln!("odf-crypto: cannot read {file}: {e}");
            return EX_IO;
        }
    };
    match classify_reader(input) {
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
    // The payload row for a wholesome package, the latch row otherwise. Not
    // `common` alone: on a crafted two-row wholesome manifest that reports the
    // cipher of a row `decrypt` will not touch -- see
    // `Classification::wholesome_row`.
    if let Some(row) = c.wholesome_row().or(c.common.as_ref()) {
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
    o.insert(
        "has_non_encrypted_entries".into(),
        json!(c.has_non_encrypted_entries),
    );
    o.insert("odf_version".into(), json!(c.odf_version));
    o.insert("media_type".into(), json!(c.media_type));
    o.insert("odf12_fatal".into(), json!(c.odf12_fatal));
    o.insert(
        "has_unexpected_streams".into(),
        json!(c.has_unexpected_streams),
    );
    o.insert("pgp_keys".into(), json!(c.pgp_keys.len()));
    o.insert("encrypted_entries".into(), json!(c.encrypted_entries.len()));
    // Same as the human output above: the row decrypt acts on, not the latch.
    match c.wholesome_row().or(c.common.as_ref()) {
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

// --- decrypt / encrypt / rekey ---------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Decrypt,
    Encrypt,
    Rekey,
}

impl Direction {
    fn suffix(self) -> &'static str {
        match self {
            Direction::Decrypt => "decrypted",
            Direction::Encrypt => "encrypted",
            Direction::Rekey => "rekeyed",
        }
    }

    /// The prompt for the first password the run asks for.
    fn first_verb(self) -> &'static str {
        match self {
            Direction::Decrypt => "Password",
            Direction::Encrypt => "New password",
            Direction::Rekey => "Old password",
        }
    }
}

enum PasswordSource {
    Env(String),
    File(PathBuf),
    Stdin,
    Prompt,
}

/// Build [`Argon2Params`] from the flags, defaulting each axis independently
/// so `--argon2-m 8192` alone keeps LibreOffice's `t` and `p`.
fn argon2_params(m: &ArgMatches) -> Result<Argon2Params, EncryptError> {
    let d = Argon2Params::LIBREOFFICE_DEFAULT;
    Argon2Params::new(
        *m.get_one::<i32>("argon2-t").unwrap_or(&d.t()),
        *m.get_one::<i32>("argon2-m").unwrap_or(&d.m_kib()),
        *m.get_one::<i32>("argon2-p").unwrap_or(&d.p()),
    )
}

/// A password source from the flags; the ArgGroup already rejects two.
fn password_source(m: &ArgMatches, env: &str, file: &str, stdin: Option<&str>) -> PasswordSource {
    if let Some(name) = m.get_one::<String>(env) {
        PasswordSource::Env(name.clone())
    } else if let Some(path) = m.get_one::<String>(file) {
        PasswordSource::File(PathBuf::from(path))
    } else if stdin.is_some_and(|flag| m.get_flag(flag)) {
        PasswordSource::Stdin
    } else {
        PasswordSource::Prompt
    }
}

// --- cancellation and temporary output -------------------------------------
//
// Ctrl-C does not kill the run outright: the handler sets a flag the input
// reader checks on every read, so the library stops through its own
// reader-driven cancel and the temporary output is deleted on the way out. Key
// derivation cannot be interrupted, so a second Ctrl-C deletes the temporary
// file itself and exits at once. A hard kill skips both; the README's "The
// CLI" section records that limit. Neither static holds a secret: a flag and
// a path.

static CANCELLED: AtomicBool = AtomicBool::new(false);
static TEMP_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

fn install_ctrl_c() {
    let _ = ctrlc::set_handler(|| {
        if CANCELLED.swap(true, Ordering::SeqCst) {
            if let Ok(slot) = TEMP_PATH.lock() {
                if let Some(path) = slot.as_ref() {
                    let _ = std::fs::remove_file(path);
                }
            }
            std::process::exit(i32::from(EX_CANCELLED));
        }
        eprintln!("odf-crypto: cancelling; press Ctrl-C again to stop at once");
    });
}

/// The input, read through a check of the cancel flag.
struct Cancellable<R>(R);

impl<R: Read> Read for Cancellable<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if CANCELLED.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("cancelled by Ctrl-C"));
        }
        self.0.read(buf)
    }
}

impl<R: Seek> Seek for Cancellable<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(pos)
    }
}

/// A temporary output file, deleted unless [`TempOutput::commit`] renames it
/// into place -- on every error, every refusal and a Ctrl-C alike, because a
/// partial file beside the target is at best a broken document and, for
/// `decrypt`, plaintext.
///
/// Given the target's permissions when the target exists, before a byte is
/// written, so a decrypted file is never briefly more readable than the file
/// it replaces. In the target's directory, because a rename across
/// filesystems is not atomic and would degrade to a copy.
struct TempOutput {
    path: PathBuf,
    file: Option<File>,
}

impl TempOutput {
    fn beside(target: &Path) -> std::io::Result<Self> {
        let dir = target.parent().unwrap_or(Path::new("."));
        let name = target.file_name().unwrap_or_default().to_string_lossy();
        Self::at(dir.join(format!(".{name}.odf-crypto.tmp")), Some(target))
    }

    /// For output only this process reads back: `encrypt` and `rekey` to
    /// stdout, which must seek while writing. It holds ciphertext only.
    fn scratch() -> std::io::Result<Self> {
        let name = format!("odf-crypto-{}.tmp", std::process::id());
        Self::at(std::env::temp_dir().join(name), None)
    }

    fn at(path: PathBuf, like: Option<&Path>) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        let guard = TempOutput {
            path,
            file: Some(file),
        };
        if let Ok(mut slot) = TEMP_PATH.lock() {
            *slot = Some(guard.path.clone());
        }
        if let Some(meta) = like.and_then(|t| std::fs::metadata(t).ok()) {
            std::fs::set_permissions(&guard.path, meta.permissions())?;
        }
        Ok(guard)
    }

    fn file(&mut self) -> std::io::Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| std::io::Error::other("temporary file already closed"))
    }

    /// Flush to disk and rename over `target`.
    fn commit(mut self, target: &Path) -> std::io::Result<()> {
        if let Some(file) = self.file.take() {
            file.sync_all()?;
        }
        std::fs::rename(&self.path, target)?;
        self.forget();
        Ok(())
    }

    /// Copy the whole file to `out`; it is deleted when `self` drops.
    fn copy_to(mut self, out: &mut dyn Write) -> std::io::Result<()> {
        let file = self.file()?;
        file.seek(SeekFrom::Start(0))?;
        std::io::copy(file, out)?;
        out.flush()
    }

    fn forget(&mut self) {
        if let Ok(mut slot) = TEMP_PATH.lock() {
            *slot = None;
        }
        self.path = PathBuf::new();
    }
}

impl Drop for TempOutput {
    fn drop(&mut self) {
        self.file = None;
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
            self.forget();
        }
    }
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

    let source = password_source(m, "password-env", "password-file", Some("password-stdin"));
    let file = m.get_one::<String>("file").expect("required by clap");
    let input = match File::open(file) {
        Ok(f) => Cancellable(BufReader::with_capacity(64 * 1024, f)),
        Err(e) => {
            eprintln!("odf-crypto: cannot read {file}: {e}");
            return EX_IO;
        }
    };

    let password = match read_password(source, dir.first_verb()) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let new_password = if dir == Direction::Rekey {
        let source = password_source(m, "new-password-env", "new-password-file", None);
        match read_password(source, "New password") {
            Ok(p) => p,
            Err(code) => return code,
        }
    } else {
        String::new()
    };
    let params = if dir == Direction::Decrypt {
        Argon2Params::LIBREOFFICE_DEFAULT
    } else {
        match argon2_params(m) {
            Ok(p) => p,
            Err(e) => return report(&e, encrypt_exit(&e)),
        }
    };
    // Warn, never block -- the cost is the caller's decision and the crate
    // does not overrule it. stderr so it cannot corrupt `-o -`.
    if dir != Direction::Decrypt && params.is_weaker_than_libreoffice() {
        eprintln!(
            "odf-crypto: warning: Argon2id t={} m={} KiB p={} is weaker than LibreOffice's t=3 m=65536 p=4.
odf-crypto: the cost is stored in the file and applies to every future reader, on any hardware.",
            params.t(),
            params.m_kib(),
            params.p()
        );
    }

    let to_stdout = m.get_one::<String>("output").map(String::as_str) == Some("-");
    let target = match m.get_one::<String>("output") {
        Some(o) if o != "-" => PathBuf::from(o),
        _ => derived_output(Path::new(file), dir.suffix()),
    };
    if !to_stdout && target.exists() && !m.get_flag("force") {
        eprintln!(
            "odf-crypto: {} already exists; pass --force to overwrite",
            target.display()
        );
        return EX_USAGE;
    }
    install_ctrl_c();

    // `decrypt` to stdout needs no seek, so it writes straight through.
    if to_stdout && dir == Direction::Decrypt {
        let mut out = std::io::stdout().lock();
        let r = decrypt_to(input, &mut out, &password)
            .map(|_| ())
            .map_err(|e| report(&e, decrypt_exit(&e)))
            .and_then(|()| out.flush().map_err(|e| report(&e, EX_IO)));
        return finish(r);
    }

    let made = if to_stdout {
        TempOutput::scratch()
    } else {
        TempOutput::beside(&target)
    };
    let mut temp = match made {
        Ok(t) => t,
        Err(e) => return report(&format!("cannot create a temporary file: {e}"), EX_IO),
    };
    let ran = temp.file().map_err(|e| report(&e, EX_IO)).and_then(|f| {
        let mut out = BufWriter::with_capacity(64 * 1024, f);
        let r = match dir {
            Direction::Decrypt => decrypt_to(input, &mut out, &password)
                .map(|_| ())
                .map_err(|e| report(&e, decrypt_exit(&e))),
            Direction::Encrypt => encrypt_with_params_to(input, &mut out, &password, params)
                .map_err(|e| report(&e, encrypt_exit(&e))),
            Direction::Rekey => reencrypt_to(
                input,
                &mut out,
                &password,
                &new_password,
                DecryptLimits::default(),
                params,
            )
            .map(|_| ())
            .map_err(|e| report(&e, reencrypt_exit(&e))),
        };
        r.and_then(|()| out.flush().map_err(|e| report(&e, EX_IO)))
    });
    if let Err(code) = ran {
        return finish(Err(code));
    }
    let done = if to_stdout {
        temp.copy_to(&mut std::io::stdout().lock())
            .map_err(|e| report(&format!("cannot write to stdout: {e}"), EX_IO))
    } else {
        temp.commit(&target)
            .map(|()| eprintln!("odf-crypto: wrote {}", target.display()))
            .map_err(|e| report(&format!("cannot write {}: {e}", target.display()), EX_IO))
    };
    finish(done)
}

/// Print `e` and hand back its exit code.
fn report(e: &dyn std::fmt::Display, code: u8) -> u8 {
    eprintln!("odf-crypto: {e}");
    code
}

/// The exit code for a finished run. A cancel wins over whatever the step it
/// interrupted reported, which is the cancel's own I/O error.
fn finish(r: Result<(), u8>) -> u8 {
    if CANCELLED.load(Ordering::SeqCst) {
        return EX_CANCELLED;
    }
    match r {
        Ok(()) => EX_OK,
        Err(code) => code,
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

fn read_password(source: PasswordSource, verb: &str) -> Result<String, u8> {
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
        // The reader failed, not the file: the same code as failing to open it.
        DetectError::Io(_) => EX_IO,
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
        DecryptError::HostCannotAllocate { .. } => EX_HOST_CAPACITY,
        // A policy refusal: the file asks for more than the caller allows.
        DecryptError::OutputLimit { .. } => EX_REFUSED,
        DecryptError::Io(_) => EX_IO,
        _ => EX_MALFORMED,
    }
}

fn encrypt_exit(e: &EncryptError) -> u8 {
    match e {
        EncryptError::Classify(d) => detect_exit(d),
        EncryptError::AlreadyEncrypted
        | EncryptError::PartiallyEncrypted
        | EncryptError::Odf12Fatal
        | EncryptError::EmptyPassword => EX_REFUSED,
        EncryptError::Mimetype(_) | EncryptError::Deflate(_) | EncryptError::Zip(_) => EX_MALFORMED,
        // The caller typed a bad --argon2-* value; the document is fine. This
        // variant reached the `_` arm below when it was added, which is the
        // silent fall-through #40 exists to catch.
        EncryptError::Params(_) => EX_USAGE,
        EncryptError::Random(_) | EncryptError::Internal(_) => EX_INTERNAL,
        EncryptError::HostCannotAllocate { .. } => EX_HOST_CAPACITY,
        EncryptError::Io(_) => EX_IO,
        _ => EX_MALFORMED,
    }
}

fn reencrypt_exit(e: &ReencryptError) -> u8 {
    match e {
        // Each side keeps its own table: a wrong old password is still 4.
        ReencryptError::Decrypt(d) => decrypt_exit(d),
        ReencryptError::Encrypt(e) => encrypt_exit(e),
        // The source had plaintext a re-key would launder: the wrong file.
        ReencryptError::PartiallyEncrypted | ReencryptError::UnexpectedStreams => EX_REFUSED,
        ReencryptError::Io(_) => EX_IO,
        _ => EX_MALFORMED,
    }
}

#[cfg(test)]
#[path = "odf-crypto_tests.rs"]
mod tests;
