//! Throwaway CLI shim for `tests/goldens/validate_encrypt.py` (issue #23,
//! plan `docs/plans/odf-encryption-encrypt-2026-09-03.md` S5) to shell out to.
//!
//! Not a public-facing tool: takes exactly three positional args -- input
//! `.odt` path, password, output `.odt` path -- calls this crate's own
//! [`odf_crypto::encrypt`], and writes the result. Any failure prints to
//! stderr and exits non-zero so the calling script's subprocess check fails
//! loudly rather than leaving a stale/partial output file.
//!
//! ```text
//! cargo run --quiet --example encrypt_for_validation -- <in.odt> <password> <out.odt>
//! ```

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let [_, input_path, password, output_path] = args.as_slice() else {
        eprintln!("usage: encrypt_for_validation <input.odt> <password> <output.odt>");
        return ExitCode::FAILURE;
    };

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
