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
//!
//! `ODF_ARGON2_T`, `ODF_ARGON2_M_KIB` and `ODF_ARGON2_P` are optional. Set all
//! three to call [`odf_crypto::encrypt_with_params`] instead of
//! [`odf_crypto::encrypt`]; set none to get LibreOffice's default tuple. Setting
//! some but not all is an error rather than a silent partial default, because a
//! tuple half-applied is the one outcome nobody wants from a generator whose
//! whole job is producing files at a KNOWN cost
//! (`tests/artifacts/make_artifacts.py`, plan §7).

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

    let axes = ["ODF_ARGON2_T", "ODF_ARGON2_M_KIB", "ODF_ARGON2_P"];
    let set: Vec<Option<String>> = axes.iter().map(|k| env::var(k).ok()).collect();
    let params = match set.iter().filter(|v| v.is_some()).count() {
        0 => None,
        3 => {
            let mut parsed = [0i32; 3];
            for (i, v) in set.iter().enumerate() {
                match v.as_deref().unwrap_or("").parse::<i32>() {
                    Ok(n) => parsed[i] = n,
                    Err(e) => {
                        eprintln!("{}: {e}", axes[i]);
                        return ExitCode::FAILURE;
                    }
                }
            }
            match odf_crypto::Argon2Params::new(parsed[0], parsed[1], parsed[2]) {
                Ok(p) => Some(p),
                Err(e) => {
                    eprintln!("argon2 params: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        n => {
            eprintln!("set all three of {axes:?} or none; {n} were set");
            return ExitCode::FAILURE;
        }
    };

    let result = match params {
        Some(p) => odf_crypto::encrypt_with_params(&plaintext, password, p),
        None => odf_crypto::encrypt(&plaintext, password),
    };
    let encrypted = match result {
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
