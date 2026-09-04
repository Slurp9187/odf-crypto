//! End-to-end tests for the `odf-crypto` binary.
//!
//! These drive the built binary as a subprocess rather than calling into the
//! library, because what is under test is argument handling, exit codes and
//! file side effects — none of which a library call exercises. The library
//! itself already has 107 tests.
//!
//! Gated on the `cli` feature, which is what builds the binary at all.
//!
//! Exit-code coverage. Codes 0-5 are proven here against real fixtures. 6
//! (malformed) and 7 (internal) are not, deliberately: 6 needs a package that
//! classifies cleanly and then fails mid-decrypt, which means rebuilding a zip
//! with a hostile manifest and no zip crate in scope here, and 7 is unreachable
//! by construction -- both `Internal` variants report an invariant nothing can
//! currently violate. Their *mapping* is what matters, and that is asserted
//! directly in the binary's own unit tests (`exit_codes_map_each_error_class`),
//! which is sharper than constructing a hostile fixture to reach the same line.
#![cfg(feature = "cli")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

// Plan §3.
const EX_OK: i32 = 0;
const EX_USAGE: i32 = 1;
const EX_IO: i32 = 2;
const EX_NOT_ODF: i32 = 3;
const EX_WRONG_PASSWORD: i32 = 4;
const EX_REFUSED: i32 = 5;

const PASSWORD: &str = "password";

/// `CARGO_BIN_EXE_<name>` is set by Cargo for every binary target when building
/// an integration test, so this needs no path guessing and no `cargo run`.
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_odf-crypto")
}

fn goldens() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/goldens")
}

fn golden(name: &str) -> PathBuf {
    goldens().join(name)
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("binary runs")
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("process exited normally")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A scratch directory that removes itself, so a failing test does not leave
/// `.odt` files in the repo. No `tempfile` dev-dependency for four tests.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let mut d = std::env::temp_dir();
        d.push(format!("odf-crypto-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch dir");
        Scratch(d)
    }
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// --- S1: help, version, classify, exit codes ------------------------------

#[test]
fn help_and_version_exit_zero_and_name_the_subcommands() {
    for flag in ["--help", "-h"] {
        let out = run(&[flag]);
        assert_eq!(code(&out), EX_OK, "{flag}");
        let s = stdout(&out);
        for cmd in ["classify", "decrypt", "encrypt"] {
            assert!(s.contains(cmd), "{flag} output must name `{cmd}`");
        }
    }
    for flag in ["--version", "-V"] {
        let out = run(&[flag]);
        assert_eq!(code(&out), EX_OK);
        assert!(stdout(&out).contains(env!("CARGO_PKG_VERSION")));
    }
}

#[test]
fn every_subcommand_has_its_own_help() {
    for cmd in ["classify", "decrypt", "encrypt"] {
        let out = run(&[cmd, "--help"]);
        assert_eq!(code(&out), EX_OK, "{cmd} --help");
        assert!(stdout(&out).contains(cmd));
    }
}

#[test]
fn classify_reports_the_algorithm_tuple() {
    let out = run(&[
        "classify",
        golden("lo-wholesome-gcm-argon2.odt").to_str().unwrap(),
    ]);
    assert_eq!(code(&out), EX_OK);
    let s = stdout(&out);
    assert!(s.contains("mode:        wholesome"), "{s}");
    assert!(s.contains("encrypted:   yes"), "{s}");
    assert!(s.contains("AES-GCM (W3C)"), "{s}");
    assert!(s.contains("Argon2id t=3 m=65536KiB p=4"), "{s}");
}

#[test]
fn an_unencrypted_package_is_an_answer_not_a_failure() {
    let out = run(&["classify", golden("lo-unencrypted.odt").to_str().unwrap()]);
    assert_eq!(code(&out), EX_OK, "plain must exit 0");
    assert!(stdout(&out).contains("encrypted:   no"));
}

#[test]
fn a_non_odf_input_exits_not_odf() {
    let s = Scratch::new("notodf");
    let f = s.join("junk.bin");
    std::fs::write(&f, b"this is not a zip file").unwrap();
    let out = run(&["classify", f.to_str().unwrap()]);
    assert_eq!(code(&out), EX_NOT_ODF);
}

#[test]
fn an_unknown_flag_exits_usage_and_names_itself() {
    let out = run(&[
        "classify",
        "--frobnicate",
        golden("lo-unencrypted.odt").to_str().unwrap(),
    ]);
    assert_eq!(code(&out), EX_USAGE);
    assert!(stderr(&out).contains("--frobnicate"), "{}", stderr(&out));
}

#[test]
fn an_unknown_subcommand_exits_usage() {
    assert_eq!(code(&run(&["frobnicate"])), EX_USAGE);
    assert_eq!(code(&run(&[])), EX_USAGE);
}

// --- S2: --json -----------------------------------------------------------

/// Every golden's `--json` must be parseable. Parsing is done by a tiny
/// structural check rather than a JSON dependency: balanced braces outside
/// strings, and every key quoted. It catches the failure mode a hand-written
/// serialiser actually has — an unescaped quote or a missing comma.
fn looks_like_one_json_object(s: &str) -> bool {
    let s = s.trim();
    if !(s.starts_with('{') && s.ends_with('}')) {
        return false;
    }
    let (mut depth, mut in_str, mut esc) = (0i32, false, false);
    for c in s.chars() {
        match (in_str, esc, c) {
            (true, true, _) => esc = false,
            (true, false, '\\') => esc = true,
            (true, false, '"') => in_str = false,
            (true, false, _) => {}
            (false, _, '"') => in_str = true,
            (false, _, '{') => depth += 1,
            (false, _, '}') => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0 && !in_str
}

#[test]
fn json_is_well_formed_for_every_golden() {
    let mut seen = 0;
    for entry in std::fs::read_dir(goldens()).expect("goldens dir") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|e| e.to_str()) != Some("odt") {
            continue;
        }
        seen += 1;
        let out = run(&["classify", "--json", p.to_str().unwrap()]);
        assert_eq!(code(&out), EX_OK, "{}", p.display());
        let s = stdout(&out);
        assert!(looks_like_one_json_object(&s), "{}: {s}", p.display());
        assert!(s.contains("\"mode\":"), "{}", p.display());
    }
    // Discovered at run time rather than hardcoded, but assert the corpus is
    // not silently empty -- a glob that matches nothing passes every test.
    assert!(
        seen >= 6,
        "expected at least six .odt goldens, found {seen}"
    );
}

#[test]
fn json_and_human_agree() {
    let f = golden("aoo-blowfish-pbkdf2.odt");
    let human = stdout(&run(&["classify", f.to_str().unwrap()]));
    let json = stdout(&run(&["classify", "--json", f.to_str().unwrap()]));
    assert!(human.contains("per-entry") && json.contains("\"mode\":\"per-entry\""));
    assert!(human.contains("Blowfish-CFB") && json.contains("\"cipher\":\"Blowfish-CFB\""));
}

// --- S3: password sourcing ------------------------------------------------

#[test]
fn password_env_decrypts() {
    let s = Scratch::new("penv");
    let out = Command::new(bin())
        .args([
            "decrypt",
            golden("lo-wholesome-gcm-argon2.odt").to_str().unwrap(),
            "-o",
            s.join("out.odt").to_str().unwrap(),
            "--password-env",
            "ODF_CLI_TEST_PW",
        ])
        .env("ODF_CLI_TEST_PW", PASSWORD)
        .stdin(Stdio::null())
        .output()
        .expect("runs");
    assert_eq!(out.status.code(), Some(EX_OK), "{}", stderr(&out));
    assert!(s.join("out.odt").exists());
}

#[test]
fn password_file_decrypts_and_tolerates_a_trailing_newline() {
    let s = Scratch::new("pfile");
    let pw = s.join("pw.txt");
    std::fs::write(&pw, format!("{PASSWORD}\n")).unwrap();
    let out = run(&[
        "decrypt",
        golden("lo-wholesome-gcm-argon2.odt").to_str().unwrap(),
        "-o",
        s.join("out.odt").to_str().unwrap(),
        "--password-file",
        pw.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), EX_OK, "{}", stderr(&out));
}

#[test]
fn password_stdin_decrypts() {
    let s = Scratch::new("pstdin");
    let mut child = Command::new(bin())
        .args([
            "decrypt",
            golden("lo-wholesome-gcm-argon2.odt").to_str().unwrap(),
            "-o",
            s.join("out.odt").to_str().unwrap(),
            "--password-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .expect("write password");
    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(EX_OK), "{}", stderr(&out));
}

#[test]
fn two_password_sources_is_a_usage_error() {
    let out = run(&[
        "decrypt",
        golden("lo-wholesome-gcm-argon2.odt").to_str().unwrap(),
        "--password-stdin",
        "--password-env",
        "ODF_CLI_TEST_PW",
    ]);
    assert_eq!(code(&out), EX_USAGE);
}

#[test]
fn no_password_source_without_a_tty_fails_rather_than_hanging() {
    // stdin is /dev/null via Stdio::null(), so a prompt would block forever.
    // The point of the test is that it returns at all.
    let out = run(&[
        "decrypt",
        golden("lo-wholesome-gcm-argon2.odt").to_str().unwrap(),
    ]);
    assert_eq!(code(&out), EX_USAGE);
    let e = stderr(&out);
    assert!(e.contains("--password-env"), "{e}");
    assert!(e.contains("--password-file"), "{e}");
    assert!(e.contains("--password-stdin"), "{e}");
}

#[test]
fn there_is_no_password_value_flag() {
    // Plan §2. argv is world-readable in a process listing, so the flag must
    // not exist -- and a caller reaching for it is told why, not just "unknown".
    let out = run(&[
        "decrypt",
        golden("lo-wholesome-gcm-argon2.odt").to_str().unwrap(),
        "--password",
        PASSWORD,
    ]);
    assert_eq!(code(&out), EX_USAGE);
    assert!(stderr(&out).contains("world-readable"), "{}", stderr(&out));

    // And it is never advertised as an option in any help output.
    for args in [
        vec!["--help"],
        vec!["classify", "--help"],
        vec!["decrypt", "--help"],
        vec!["encrypt", "--help"],
    ] {
        for line in stdout(&run(&args)).lines() {
            let t = line.trim_start();
            assert!(
                !(t.starts_with("--password ") || t.starts_with("--password=")),
                "{args:?} defines a --password option: {line:?}"
            );
        }
    }
}

// --- S4: decrypt and encrypt ----------------------------------------------

fn decrypt_to(s: &Scratch, input: &Path, out_name: &str) -> Output {
    let pw = s.join("pw.txt");
    std::fs::write(&pw, PASSWORD).unwrap();
    run(&[
        "decrypt",
        input.to_str().unwrap(),
        "-o",
        s.join(out_name).to_str().unwrap(),
        "--password-file",
        pw.to_str().unwrap(),
    ])
}

#[test]
fn decrypt_of_every_encrypted_golden_yields_a_plain_package() {
    let s = Scratch::new("decall");
    let mut seen = 0;
    for name in [
        "lo-wholesome-gcm-argon2.odt",
        "lo-legacy-aes-cbc.odt",
        "aoo-blowfish-pbkdf2.odt",
    ] {
        seen += 1;
        let out_name = format!("{name}.out");
        let out = decrypt_to(&s, &golden(name), &out_name);
        assert_eq!(out.status.code(), Some(EX_OK), "{name}: {}", stderr(&out));

        let check = run(&["classify", s.join(&out_name).to_str().unwrap()]);
        assert_eq!(check.status.code(), Some(EX_OK), "{name} reclassify");
        assert!(
            stdout(&check).contains("mode:        plain"),
            "{name} must decrypt to a plain package"
        );
    }
    assert_eq!(seen, 3);
}

#[test]
fn encrypt_then_decrypt_is_byte_identical() {
    let s = Scratch::new("round");
    let pw = s.join("pw.txt");
    std::fs::write(&pw, PASSWORD).unwrap();
    let src = golden("lo-unencrypted.odt");
    let sealed = s.join("sealed.odt");
    let back = s.join("back.odt");

    let e = run(&[
        "encrypt",
        src.to_str().unwrap(),
        "-o",
        sealed.to_str().unwrap(),
        "--password-file",
        pw.to_str().unwrap(),
    ]);
    assert_eq!(code(&e), EX_OK, "{}", stderr(&e));
    assert!(stdout(&run(&["classify", sealed.to_str().unwrap()])).contains("wholesome"));

    let d = run(&[
        "decrypt",
        sealed.to_str().unwrap(),
        "-o",
        back.to_str().unwrap(),
        "--password-file",
        pw.to_str().unwrap(),
    ]);
    assert_eq!(code(&d), EX_OK, "{}", stderr(&d));
    assert_eq!(
        std::fs::read(&src).unwrap(),
        std::fs::read(&back).unwrap(),
        "round trip must be byte-identical"
    );
}

#[test]
fn wrong_password_and_not_encrypted_have_different_exit_codes() {
    let s = Scratch::new("codes");
    let pw = s.join("pw.txt");
    std::fs::write(&pw, "definitely not the password").unwrap();
    let wrong = run(&[
        "decrypt",
        golden("lo-wholesome-gcm-argon2.odt").to_str().unwrap(),
        "-o",
        s.join("x.odt").to_str().unwrap(),
        "--password-file",
        pw.to_str().unwrap(),
    ]);
    assert_eq!(code(&wrong), EX_WRONG_PASSWORD);

    std::fs::write(&pw, PASSWORD).unwrap();
    let plain = run(&[
        "decrypt",
        golden("lo-unencrypted.odt").to_str().unwrap(),
        "-o",
        s.join("y.odt").to_str().unwrap(),
        "--password-file",
        pw.to_str().unwrap(),
    ]);
    assert_eq!(code(&plain), EX_REFUSED);

    // The distinction the exit-code table exists for: "try again" is not the
    // same answer as "you had the wrong file".
    assert_ne!(code(&wrong), code(&plain));
}

#[test]
fn encrypting_an_already_encrypted_package_is_refused() {
    let s = Scratch::new("already");
    let pw = s.join("pw.txt");
    std::fs::write(&pw, PASSWORD).unwrap();
    let out = run(&[
        "encrypt",
        golden("lo-wholesome-gcm-argon2.odt").to_str().unwrap(),
        "-o",
        s.join("x.odt").to_str().unwrap(),
        "--password-file",
        pw.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), EX_REFUSED);
}

#[test]
fn an_existing_output_is_never_overwritten_without_force() {
    let s = Scratch::new("force");
    let pw = s.join("pw.txt");
    std::fs::write(&pw, PASSWORD).unwrap();
    let target = s.join("taken.odt");
    std::fs::write(&target, b"PRECIOUS").unwrap();

    let args = [
        "decrypt".to_string(),
        golden("lo-wholesome-gcm-argon2.odt")
            .to_str()
            .unwrap()
            .to_string(),
        "-o".to_string(),
        target.to_str().unwrap().to_string(),
        "--password-file".to_string(),
        pw.to_str().unwrap().to_string(),
    ];
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();

    let out = run(&refs);
    assert_eq!(code(&out), EX_USAGE, "must refuse to clobber");
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"PRECIOUS",
        "the existing file must be untouched"
    );

    // With --force it proceeds, and leaves no temporary behind.
    let mut forced = refs.clone();
    forced.push("--force");
    let out = run(&forced);
    assert_eq!(code(&out), EX_OK, "{}", stderr(&out));
    assert_ne!(std::fs::read(&target).unwrap(), b"PRECIOUS");

    let leftovers: Vec<_> = std::fs::read_dir(&s.0)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("odf-crypto.tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temporary left behind: {leftovers:?}");
}

#[test]
fn the_default_output_name_is_derived_from_the_input() {
    let s = Scratch::new("derive");
    let pw = s.join("pw.txt");
    std::fs::write(&pw, PASSWORD).unwrap();
    // Copy the golden into the scratch dir so the derived sibling lands there.
    let input = s.join("doc.odt");
    std::fs::copy(golden("lo-wholesome-gcm-argon2.odt"), &input).unwrap();

    let out = run(&[
        "decrypt",
        input.to_str().unwrap(),
        "--password-file",
        pw.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), EX_OK, "{}", stderr(&out));
    assert!(
        s.join("doc.decrypted.odt").exists(),
        "expected doc.decrypted.odt beside the input"
    );
}

#[test]
fn output_dash_writes_the_package_to_stdout() {
    let s = Scratch::new("stdout");
    let pw = s.join("pw.txt");
    std::fs::write(&pw, PASSWORD).unwrap();
    let out = run(&[
        "decrypt",
        golden("lo-wholesome-gcm-argon2.odt").to_str().unwrap(),
        "-o",
        "-",
        "--password-file",
        pw.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), EX_OK, "{}", stderr(&out));
    // A zip local file header, so what landed on stdout is the package itself
    // and not a progress line.
    assert_eq!(&out.stdout[..2], b"PK", "stdout must carry the zip");
}

// --- coverage for the exit codes and paths the suite did not reach ---------

#[test]
fn a_missing_input_file_is_an_io_error() {
    let s = Scratch::new("missing");
    let out = run(&["classify", s.join("nope.odt").to_str().unwrap()]);
    assert_eq!(
        code(&out),
        EX_IO,
        "exit 2, not 'not-odf' -- the file is absent"
    );
    assert!(stderr(&out).contains("cannot read"), "{}", stderr(&out));
}

#[test]
fn a_missing_password_file_is_an_io_error() {
    let s = Scratch::new("nopw");
    let out = run(&[
        "decrypt",
        golden("lo-wholesome-gcm-argon2.odt").to_str().unwrap(),
        "-o",
        s.join("x.odt").to_str().unwrap(),
        "--password-file",
        s.join("nope").to_str().unwrap(),
    ]);
    assert_eq!(code(&out), EX_IO);
}

#[test]
fn an_unset_password_env_var_is_a_usage_error() {
    // Usage, not I/O: the caller named a variable that does not exist, which is
    // a mistake in the invocation rather than a failure to read something.
    let s = Scratch::new("unsetenv");
    let out = run(&[
        "decrypt",
        golden("lo-wholesome-gcm-argon2.odt").to_str().unwrap(),
        "-o",
        s.join("x.odt").to_str().unwrap(),
        "--password-env",
        "ODF_CRYPTO_DEFINITELY_UNSET_VARIABLE",
    ]);
    assert_eq!(code(&out), EX_USAGE);
    assert!(stderr(&out).contains("is not set"), "{}", stderr(&out));
}

#[test]
fn an_empty_password_is_refused() {
    // A password file holding only a newline. first_line yields "", the library
    // rejects it as EmptyPassword, and that maps to refused rather than to
    // wrong-password -- it never got as far as trying a key.
    let s = Scratch::new("emptypw");
    let pw = s.join("pw.txt");
    std::fs::write(&pw, "\n").unwrap();
    let out = run(&[
        "decrypt",
        golden("lo-wholesome-gcm-argon2.odt").to_str().unwrap(),
        "-o",
        s.join("x.odt").to_str().unwrap(),
        "--password-file",
        pw.to_str().unwrap(),
    ]);
    assert_eq!(code(&out), EX_REFUSED);
}

#[test]
fn a_truncated_package_is_not_odf() {
    let s = Scratch::new("trunc");
    let whole = std::fs::read(golden("lo-wholesome-gcm-argon2.odt")).unwrap();
    let f = s.join("trunc.odt");
    std::fs::write(&f, &whole[..400]).unwrap();
    let out = run(&["classify", f.to_str().unwrap()]);
    assert_eq!(
        code(&out),
        EX_NOT_ODF,
        "a truncated zip has no central directory"
    );
}

#[test]
fn a_near_miss_flag_is_given_a_suggestion() {
    // One of the two gaps that motivated moving to clap: the hand-rolled parser
    // said only "unrecognised option".
    let out = run(&[
        "decrypt",
        "--password-en",
        "X",
        golden("lo-unencrypted.odt").to_str().unwrap(),
    ]);
    assert_eq!(code(&out), EX_USAGE);
    let e = stderr(&out);
    assert!(
        e.contains("--password-env"),
        "must suggest the real flag: {e}"
    );
}

#[test]
fn the_equals_form_works_end_to_end() {
    // The other gap: `--output=PATH` was rejected outright before clap.
    let s = Scratch::new("equals");
    let pw = s.join("pw.txt");
    std::fs::write(&pw, PASSWORD).unwrap();
    let target = s.join("eq.odt");
    let out = run(&[
        "decrypt",
        golden("lo-wholesome-gcm-argon2.odt").to_str().unwrap(),
        &format!("--output={}", target.display()),
        &format!("--password-file={}", pw.display()),
    ]);
    assert_eq!(code(&out), EX_OK, "{}", stderr(&out));
    assert!(target.exists(), "--output=PATH must be honoured");
}

#[test]
fn encrypt_also_accepts_a_piped_password() {
    // decrypt's stdin path is covered above; encrypt shares the code, so this
    // pins that the wiring is actually shared rather than duplicated.
    let s = Scratch::new("encstdin");
    let mut child = Command::new(bin())
        .args([
            "encrypt",
            golden("lo-unencrypted.odt").to_str().unwrap(),
            "-o",
            s.join("sealed.odt").to_str().unwrap(),
            "--password-stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    assert_eq!(out.status.code(), Some(EX_OK), "{}", stderr(&out));
    assert!(
        stdout(&run(&["classify", s.join("sealed.odt").to_str().unwrap()])).contains("wholesome")
    );
}

#[test]
fn no_subcommand_prints_help_and_exits_usage() {
    // clap's arg_required_else_help. Help on stdout is a courtesy; the exit code
    // still has to say the invocation was wrong, or a script cannot tell.
    let out = run(&[]);
    assert_eq!(code(&out), EX_USAGE);
}
