//! Throwaway CLI shim for `tests/goldens/validate_encrypt.py` (issue #23,
//! plan `docs/plans/odf-encryption-encrypt-2026-09-03.md` S5) to shell out to.
//!
//! Not a public-facing tool: takes two positional args -- input `.odt` path
//! and output `.odt` path -- reads the password from `ODF_ENCRYPT_PASSWORD`,
//! calls this crate's own [`odf_crypto::encrypt`], and writes the result. Any
//! failure prints to stderr and exits non-zero so the calling script's
//! subprocess check fails loudly rather than leaving a stale/partial output
//! file.
//!
//! The password is an environment variable rather than an argument because
//! argv is world-readable in a process listing for the lifetime of the run.
//!
//! ```text
//! ODF_ENCRYPT_PASSWORD=... cargo run --quiet --example encrypt_for_validation -- <in.odt> <out.odt>
//! ```

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let [_, input_path, output_path] = args.as_slice() else {
        eprintln!(
            "usage: ODF_ENCRYPT_PASSWORD=... encrypt_for_validation <input.odt> <output.odt>"
        );
        return ExitCode::FAILURE;
    };

    // Read from the environment rather than argv: a password in argv is
    // visible in any process listing for as long as `cargo run` lasts. This is
    // throwaway validation plumbing, not the library API -- but it is the only
    // executable in the repo that takes a password at all, so it may as well
    // not model the bad habit.
    let Ok(password) = env::var("ODF_ENCRYPT_PASSWORD") else {
        eprintln!("ODF_ENCRYPT_PASSWORD must be set");
        return ExitCode::FAILURE;
    };
    let password = password.as_str();

    let plaintext = match std::fs::read(input_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {input_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let encrypted = match odf_crypto::encrypt(&plaintext, password) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("encrypt: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = std::fs::write(output_path, &encrypted) {
        eprintln!("write {output_path}: {e}");
        return ExitCode::FAILURE;
    }

    println!("wrote {output_path} ({} bytes)", encrypted.len());
    ExitCode::SUCCESS
}
