//! Unit tests for the CLI's own logic — the parts that are not the library and
//! not clap.
//!
//! End-to-end behaviour (exit codes, argv handling, atomic writes) is exercised
//! by `tests/cli.rs`, which drives the built binary. What is tested here is the
//! pure helpers and the command definition, where a unit test is sharper than a
//! subprocess.

use super::*;

#[test]
fn the_command_definition_is_internally_consistent() {
    // clap's own audit: catches a duplicate id, a group naming an argument that
    // does not exist, a short flag used twice. Cheap, and it covers every
    // subcommand rather than only the paths a test happens to take.
    cli().debug_assert();
}

#[test]
fn derived_output_inserts_before_the_extension() {
    assert_eq!(
        derived_output(Path::new("report.odt"), "decrypted"),
        PathBuf::from("report.decrypted.odt")
    );
    assert_eq!(
        derived_output(Path::new("/tmp/a/report.ods"), "encrypted"),
        PathBuf::from("/tmp/a/report.encrypted.ods")
    );
}

#[test]
fn derived_output_appends_when_there_is_no_extension() {
    assert_eq!(
        derived_output(Path::new("report"), "decrypted"),
        PathBuf::from("report.decrypted")
    );
}

#[test]
fn derived_output_keeps_a_dotted_stem() {
    // `a.b.odt` has stem `a.b`; the suffix goes before the real extension only.
    assert_eq!(
        derived_output(Path::new("a.b.odt"), "decrypted"),
        PathBuf::from("a.b.decrypted.odt")
    );
}

#[test]
fn first_line_strips_one_trailing_newline_and_no_more() {
    assert_eq!(first_line("hunter2\n"), "hunter2");
    assert_eq!(first_line("hunter2\r\n"), "hunter2");
    assert_eq!(first_line("hunter2"), "hunter2");
    // Only the first line: a file with more in it is not a multi-line password.
    assert_eq!(first_line("hunter2\nignored\n"), "hunter2");
    // Trailing spaces can be deliberate, so they survive.
    assert_eq!(first_line("hunter2  \n"), "hunter2  ");
    assert_eq!(first_line(""), "");
}

#[test]
fn exit_codes_separate_try_again_from_wrong_file() {
    // The distinction the whole table exists for.
    assert_eq!(
        decrypt_exit(&DecryptError::WrongPassword),
        EX_WRONG_PASSWORD
    );
    assert_eq!(decrypt_exit(&DecryptError::NotEncrypted), EX_REFUSED);
    assert_ne!(EX_WRONG_PASSWORD, EX_REFUSED);
}

#[test]
fn exit_codes_map_each_error_class() {
    assert_eq!(detect_exit(&DetectError::NotZip), EX_NOT_ODF);
    assert_eq!(detect_exit(&DetectError::MissingManifest), EX_NOT_ODF);
    assert_eq!(
        detect_exit(&DetectError::Inconsistent(String::new())),
        EX_REFUSED
    );
    assert_eq!(detect_exit(&DetectError::Zip(String::new())), EX_MALFORMED);

    // A wrapped classify failure keeps the classify code rather than collapsing
    // to a generic decrypt failure.
    assert_eq!(
        decrypt_exit(&DecryptError::Classify(DetectError::NotZip)),
        EX_NOT_ODF
    );
    assert_eq!(decrypt_exit(&DecryptError::UnsupportedPgp), EX_REFUSED);
    assert_eq!(
        decrypt_exit(&DecryptError::Inflate(String::new())),
        EX_MALFORMED
    );
    assert_eq!(
        decrypt_exit(&DecryptError::Internal(String::new())),
        EX_INTERNAL
    );

    assert_eq!(encrypt_exit(&EncryptError::AlreadyEncrypted), EX_REFUSED);
    assert_eq!(
        encrypt_exit(&EncryptError::Classify(DetectError::MissingManifest)),
        EX_NOT_ODF
    );
    assert_eq!(
        encrypt_exit(&EncryptError::Internal(String::new())),
        EX_INTERNAL
    );
    assert_eq!(
        encrypt_exit(&EncryptError::Random(String::new())),
        EX_INTERNAL
    );
}

#[test]
fn exactly_one_password_source_is_accepted() {
    // clap's ArgGroup enforces it, so this pins the wiring rather than the rule.
    let two = cli().try_get_matches_from([
        "odf-crypto",
        "decrypt",
        "f.odt",
        "--password-stdin",
        "--password-env",
        "PW",
    ]);
    assert!(two.is_err(), "two password sources must be rejected");

    for one in [
        vec!["odf-crypto", "decrypt", "f.odt", "--password-stdin"],
        vec!["odf-crypto", "decrypt", "f.odt", "--password-env", "PW"],
        vec!["odf-crypto", "decrypt", "f.odt", "--password-file", "p"],
        // None is legal: it means "prompt".
        vec!["odf-crypto", "decrypt", "f.odt"],
    ] {
        assert!(
            cli().try_get_matches_from(&one).is_ok(),
            "{one:?} must parse"
        );
    }
}

#[test]
fn the_equals_form_parses() {
    // The gap that motivated moving to clap: `--output=x.odt` was rejected
    // outright by the hand-rolled parser this replaced.
    let m = cli()
        .try_get_matches_from(["odf-crypto", "decrypt", "f.odt", "--output=x.odt"])
        .expect("--flag=value must parse");
    let sub = m.subcommand_matches("decrypt").expect("decrypt");
    assert_eq!(
        sub.get_one::<String>("output").map(String::as_str),
        Some("x.odt")
    );
}

#[test]
fn the_password_argument_is_hidden_but_recognised() {
    // Plan §2. It parses -- so `cmd_crypt` can explain *why* it does not exist,
    // rather than clap reporting a generic unexpected argument -- and it never
    // appears in help, so it is not offered.
    let m = cli()
        .try_get_matches_from(["odf-crypto", "decrypt", "f.odt", "--password", "secret"])
        .expect("the trap argument must parse");
    let sub = m.subcommand_matches("decrypt").expect("decrypt");
    assert_eq!(
        sub.get_one::<String>(PASSWORD_TRAP).map(String::as_str),
        Some("secret")
    );
    // And it is refused with an explanation, not acted on.
    assert_eq!(cmd_crypt(sub, Direction::Decrypt), EX_USAGE);
}

#[test]
fn no_help_output_ever_offers_a_password_value_argument() {
    // The predicate is "no line DEFINES the option", not "the string never
    // appears": the after-help text mentions `--password VALUE` precisely to say
    // it does not exist, and a substring check would fail on that prose.
    let mut cmd = cli();
    let mut texts = vec![cmd.render_long_help().to_string()];
    for name in ["classify", "decrypt", "encrypt"] {
        texts.push(
            cmd.find_subcommand_mut(name)
                .expect("subcommand")
                .render_long_help()
                .to_string(),
        );
    }
    for text in texts {
        for line in text.lines() {
            let t = line.trim_start();
            assert!(
                !(t.starts_with("--password ") || t.starts_with("--password=")),
                "a `--password <VALUE>` option must never be defined in help: {line:?}"
            );
        }
    }
}

#[test]
fn help_advertises_the_three_real_password_sources() {
    let mut cmd = cli();
    for name in ["decrypt", "encrypt"] {
        let text = cmd
            .find_subcommand_mut(name)
            .expect("subcommand")
            .render_long_help()
            .to_string();
        for flag in ["--password-env", "--password-file", "--password-stdin"] {
            assert!(text.contains(flag), "{name} help must offer {flag}");
        }
    }
}

#[test]
fn classification_json_is_valid_json_for_a_real_golden() {
    let bytes = include_bytes!("../../tests/goldens/lo-wholesome-gcm-argon2.odt");
    let c = classify(bytes).expect("golden classifies");
    let v: serde_json::Value =
        serde_json::from_str(&classification_json(&c)).expect("must be valid JSON");

    assert_eq!(v["mode"], "wholesome");
    assert_eq!(v["encrypted"], true);
    assert_eq!(v["cipher"], "AES-GCM (W3C)");
    assert_eq!(v["kdf"], "Argon2id t=3 m=65536KiB p=4");
    assert_eq!(v["key_size"], 32);
    assert_eq!(v["odf_version"], "1.4");
}

#[test]
fn classification_json_nulls_the_row_fields_when_plain() {
    let bytes = include_bytes!("../../tests/goldens/lo-unencrypted.odt");
    let c = classify(bytes).expect("golden classifies");
    let v: serde_json::Value =
        serde_json::from_str(&classification_json(&c)).expect("must be valid JSON");
    assert_eq!(v["encrypted"], false);
    assert!(v["cipher"].is_null());
    assert!(v["key_size"].is_null());
}

#[test]
fn human_output_reports_plain_as_an_answer_not_a_failure() {
    let bytes = include_bytes!("../../tests/goldens/lo-unencrypted.odt");
    let c = classify(bytes).expect("golden classifies");
    let text = classification_human(&c);
    assert!(text.contains("mode:        plain"));
    assert!(text.contains("encrypted:   no"));
    // No cipher block for a package that has none.
    assert!(!text.contains("cipher:"));
}

#[test]
fn human_output_names_the_algorithm_tuple() {
    let bytes = include_bytes!("../../tests/goldens/aoo-blowfish-pbkdf2.odt");
    let c = classify(bytes).expect("golden classifies");
    let text = classification_human(&c);
    assert!(text.contains("mode:        per-entry"));
    assert!(text.contains("Blowfish-CFB"));
    assert!(text.contains("PBKDF2 iterations="));
}
