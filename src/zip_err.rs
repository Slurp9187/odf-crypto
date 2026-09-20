//! Reproduces `zip::result::ZipError`'s `Display` wording without ever
//! calling `ZipError::to_string`.
//!
//! `ZipError` is `#[non_exhaustive]` (`zip-2.4.2/src/result.rs:19`) — semver
//! protects the shape of the variants already enumerated, not that the
//! enumeration stays complete. Calling `.to_string()` on it directly would
//! flow whatever a future variant's `Display` writes straight into a public
//! `Zip(String)` payload on a plain `cargo update`, with nothing at compile
//! time to catch it. This is not hypothetical: `zip` 6.0.0 widened
//! `InvalidArchive(&'static str)` to `InvalidArchive(Cow<'static, str>)` and
//! began interpolating an archive entry name into it
//! (`"Duplicate filename: {}"`, `zip-6.0.0/src/write.rs:1061`, still present
//! at `zip-8.6.0/src/write.rs:1382`).
//!
//! [`message`] matches every variant `zip` 2.4.2 declares and reproduces its
//! `displaydoc` string byte for byte — pinned by a test in this module that
//! asserts `message(&e) == e.to_string()` for each one. That test is the
//! guard: it is the one that fires the day a `zip` minor release changes its
//! wording. The `InvalidArchive` and `UnsupportedArchive` arms bind their
//! payload as `&'static str` explicitly (`let s: &'static str = s;`, relying
//! on the annotation to force the type rather than leaving it inferred), so a
//! future widening to `Cow<'static, str>` — the exact move `zip` 6.0.0
//! already made once — is a compile error here rather than a silent quote of
//! package-controlled text: `Cow`'s own `Deref` would still coerce, but only
//! to a reference borrowed for the match, not one that can satisfy
//! `'static`. The wildcard arm, present only because `#[non_exhaustive]`
//! requires one, contributes no text of its own.
//!
//! That second guard was checked rather than reasoned about, because a guard
//! that only looks protective is worse than none. Both shapes were compiled
//! standalone: `enum Narrow { InvalidArchive(&'static str) }` with this exact
//! binding compiles, and `enum Wide { InvalidArchive(Cow<'static, str>) }`
//! with the same binding fails — `error: lifetime may not live long enough`.
//! So the annotation is load-bearing, not decoration.

use zip::result::ZipError;

/// Formats `err` the way `zip` 2.4.2's `Display` impl does.
///
/// Every call site in this crate that turns a `ZipError` into one of the
/// three `Zip(String)` payloads (`DetectError`, `DecryptError`,
/// `EncryptError`) goes through this function instead of `ZipError`'s own
/// `Display`. See the module doc for why.
pub(crate) fn message(err: &ZipError) -> String {
    match err {
        ZipError::Io(io_err) => format!("i/o error: {io_err}"),
        ZipError::InvalidArchive(s) => {
            let s: &'static str = s;
            format!("invalid Zip archive: {s}")
        }
        ZipError::UnsupportedArchive(s) => {
            let s: &'static str = s;
            format!("unsupported Zip archive: {s}")
        }
        ZipError::FileNotFound => "specified file not found in archive".to_string(),
        ZipError::InvalidPassword => "The password provided is incorrect".to_string(),
        _ => "zip error (unrecognized variant)".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::message;
    use std::io;
    use zip::result::ZipError;

    /// Methods whose `Result` carries a [`ZipError`] in `zip` 2.4.2.
    const ZIP_RETURNING: [&str; 5] = [
        "ZipArchive::new",
        ".by_index(",
        ".by_name(",
        ".start_file(",
        ".finish()",
    ];

    /// `include_str!` resolves against this file at compile time, so these do
    /// not depend on the directory the tests are run from, and they are plain
    /// text -- the gated modules are readable here even in a detection-only
    /// build, so this guard runs in every feature configuration.
    const SOURCES: [(&str, &str); 3] = [
        ("classify.rs", include_str!("classify.rs")),
        ("decrypt.rs", include_str!("decrypt.rs")),
        ("encrypt.rs", include_str!("encrypt.rs")),
    ];

    /// The invariant the module exists for: no `ZipError` reaches a
    /// `Zip(String)` payload through its own `Display`.
    ///
    /// Fidelity is pinned by
    /// [`message_matches_display_for_every_known_variant`], but fidelity is not
    /// routing: before this test, reverting any of the call sites to
    /// `e.to_string()` left the whole suite green, clippy clean in all three
    /// configurations, and the headline claim silently false. A misrouted site
    /// cannot be caught by the compiler either, because `ZipError` and
    /// `io::Error` both implement `Display`.
    ///
    /// Scanning source text is blunt, and deliberately so: the property is
    /// syntactic. Broken on purpose to prove it fires -- restoring one
    /// `decrypt.rs` site to `DecryptError::Zip(e.to_string())` failed this test
    /// and nothing else in the suite.
    #[test]
    fn every_ziperror_site_routes_through_message() {
        for (name, src) in SOURCES {
            let lines: Vec<&str> = src.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if !ZIP_RETURNING.iter().any(|m| line.contains(m)) {
                    continue;
                }
                // Check ONLY this call's own `map_err`, which is on its line or
                // the next one or two. A fixed multi-line window is wrong here
                // and was caught failing on a clean tree: in `rebuild_zip` a
                // routed `start_file` is followed immediately by a `write_all`
                // that correctly keeps `to_string()`, so a window wide enough
                // to reach the next statement reads the neighbour's io::Error
                // conversion as this one's. The alternating trap catches the
                // guard as readily as the edit.
                let Some(conv) = lines[i..(i + 3).min(lines.len())]
                    .iter()
                    .find(|l| l.contains(".map_err("))
                else {
                    continue; // the error is discarded, not stringified
                };
                assert!(
                    !(conv.contains("::Zip(") && conv.contains(".to_string()")),
                    "{name}:{} converts a ZipError with its own Display; route it \
                     through zip_err::message instead:\n  {}",
                    i + 1,
                    line.trim()
                );
            }
        }
    }

    /// The wildcard arm is the whole point of the module and the one arm no
    /// test can reach: `#[non_exhaustive]` means an unknown variant cannot be
    /// constructed here to exercise it. So the guard is on the source instead
    /// -- it must not interpolate the error it was given.
    #[test]
    fn wildcard_arm_contributes_no_text_of_its_own() {
        let src = include_str!("zip_err.rs");
        let arm = src
            .lines()
            .find(|l| l.trim_start().starts_with("_ =>"))
            .expect("message() must keep a wildcard arm; #[non_exhaustive] requires one");
        // Testing for the substring "err" was the obvious check and was wrong:
        // the arm's own literal says "zip error", so it matched itself and the
        // guard passed only by accident. The property is that the arm does not
        // *interpolate* — `_` binds nothing, so quoting an unknown variant
        // takes a named binding and a format, and both need `format!`/`{`.
        assert!(
            !arm.contains("format!") && !arm.contains('{'),
            "the wildcard arm must not quote an unknown variant's Display: {}",
            arm.trim()
        );
    }

    /// Pins `message` to `ZipError`'s own `Display` for every variant `zip`
    /// 2.4.2 declares. Broken on purpose once to prove it fires (CLAUDE.md:
    /// "test the guard by breaking the thing it guards") — deleting the
    /// `FileNotFound` arm's string made this fail, as expected, and it was
    /// restored.
    #[test]
    fn message_matches_display_for_every_known_variant() {
        let cases = [
            ZipError::Io(io::Error::other("disk exploded")),
            ZipError::InvalidArchive("bad local file header"),
            ZipError::UnsupportedArchive("zip64 not supported"),
            ZipError::FileNotFound,
            ZipError::InvalidPassword,
        ];
        for case in cases {
            assert_eq!(message(&case), case.to_string());
        }
    }
}
