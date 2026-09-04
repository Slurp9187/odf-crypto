//! Unit tests for the CLI's own logic — the parts that are not the library.
//!
//! End-to-end behaviour (exit codes, argv handling, atomic writes) is exercised
//! by `tests/cli.rs`, which drives the built binary. What is tested here is the
//! pure helpers, where a unit test is sharper than a subprocess.

use super::*;

#[test]
fn json_escape_covers_the_four_classes() {
    // Quote and backslash: RFC 8259 requires both.
    assert_eq!(json_escape(r#"a"b"#), r#"a\"b"#);
    assert_eq!(json_escape(r"a\b"), r"a\\b");
    // Named short escapes.
    assert_eq!(json_escape("a\nb"), r"a\nb");
    assert_eq!(json_escape("a\tb"), r"a\tb");
    assert_eq!(json_escape("a\rb"), r"a\rb");
    assert_eq!(json_escape("a\u{08}b"), r"a\bb");
    assert_eq!(json_escape("a\u{0c}b"), r"a\fb");
    // Any other scalar below 0x20 must be \u-escaped, not emitted raw.
    assert_eq!(json_escape("a\u{01}b"), "a\\u0001b");
    assert_eq!(json_escape("a\u{1f}b"), "a\\u001fb");
    // Non-ASCII passes through as UTF-8; the spec allows it and it keeps a
    // media type readable.
    assert_eq!(json_escape("äöü→"), "äöü→");
    // 0x7f is not a control character by the spec's definition.
    assert_eq!(json_escape("a\u{7f}b"), "a\u{7f}b");
}

#[test]
fn json_escape_leaves_ordinary_text_alone() {
    let s = "application/vnd.oasis.opendocument.text";
    assert_eq!(json_escape(s), s);
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
fn help_and_version_are_not_errors() {
    assert_eq!(run(&["--help".to_string()]), EX_OK);
    assert_eq!(run(&["-h".to_string()]), EX_OK);
    assert_eq!(run(&["--version".to_string()]), EX_OK);
    assert_eq!(run(&["-V".to_string()]), EX_OK);
}

#[test]
fn no_arguments_and_unknown_commands_are_usage_errors() {
    assert_eq!(run(&[]), EX_USAGE);
    assert_eq!(run(&["frobnicate".to_string()]), EX_USAGE);
}

#[test]
fn the_password_flag_is_refused_by_name() {
    // Not "unrecognised option" -- a caller reaching for --password gets told
    // why it does not exist and what to use instead.
    let args = [
        "decrypt".to_string(),
        "--password".to_string(),
        "x".to_string(),
    ];
    assert_eq!(cmd_crypt(&args[1..], Direction::Decrypt), EX_USAGE);
}

#[test]
fn two_password_sources_is_a_usage_error() {
    let args = [
        "f.odt".to_string(),
        "--password-stdin".to_string(),
        "--password-env".to_string(),
        "PW".to_string(),
    ];
    assert_eq!(cmd_crypt(&args, Direction::Decrypt), EX_USAGE);
}

#[test]
fn usage_strings_never_offer_a_password_value_flag() {
    // Pins the plan's §2 decision: reintroducing the flag has to defeat this.
    for text in [USAGE, CLASSIFY_USAGE, &decrypt_usage(), &encrypt_usage()] {
        // The predicate is "no line DEFINES the option", not "the string never
        // appears": the help text mentions `--password <VALUE>` precisely to
        // say it does not exist, and a substring check fails on that prose.
        // An option definition is an indented line whose first token is it.
        for line in text.lines() {
            let t = line.trim_start();
            assert!(
                !(t.starts_with("--password ") || t.starts_with("--password=")),
                "a `--password <VALUE>` option must never be defined in help output, found: {line:?}"
            );
        }
    }
    // The three real sources are all advertised.
    for text in [&decrypt_usage(), &encrypt_usage()] {
        assert!(text.contains("--password-env"));
        assert!(text.contains("--password-file"));
        assert!(text.contains("--password-stdin"));
    }
}

#[test]
fn classification_json_is_well_formed_for_a_real_golden() {
    let bytes = include_bytes!("../../tests/goldens/lo-wholesome-gcm-argon2.odt");
    let c = classify(bytes).expect("golden classifies");
    let json = classification_json(&c);

    assert!(json.starts_with('{') && json.ends_with('}'));
    assert!(json.contains("\"mode\":\"wholesome\""));
    assert!(json.contains("\"encrypted\":true"));
    assert!(json.contains("\"cipher\":\"AES-GCM (W3C)\""));
    assert!(json.contains("\"kdf\":\"Argon2id t=3 m=65536KiB p=4\""));
    assert!(json.contains("\"key_size\":32"));
    // Balanced braces and quotes: a hand-written serialiser's failure mode.
    assert_eq!(json.matches('{').count(), json.matches('}').count());
    assert_eq!(json.matches('"').count() % 2, 0);
}

#[test]
fn classification_json_nulls_the_row_fields_when_plain() {
    let bytes = include_bytes!("../../tests/goldens/lo-unencrypted.odt");
    let c = classify(bytes).expect("golden classifies");
    let json = classification_json(&c);
    assert!(json.contains("\"encrypted\":false"));
    assert!(json.contains("\"cipher\":null"));
    assert!(json.contains("\"key_size\":null"));
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
