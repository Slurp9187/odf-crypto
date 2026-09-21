//! Troubleshooting, organised by symptom.
//!
//! The typed errors elsewhere in this crate tell a caller *which* case they
//! hit. They do not say what to do about it. This page does, and it is indexed
//! by **how a stuck developer actually arrives** rather than by API — arriving
//! by API only works if you already know what is wrong.
//!
//! It is documentation and nothing else: no items, no runtime cost. The
//! examples compile as doctests, so the advice cannot rot into describing
//! behaviour the code no longer has.
//!
//! **Deliberately no `file:line` citations.** They drift, and this repository
//! has repaired the same citation table three times. Functions and types are
//! named instead; `grep` finds them.
//!
//! - [`decrypt` returned `BadParameters`](#decrypt-returned-badparameters)
//! - [`WrongPassword`, but the password is right](#wrongpassword-but-the-password-is-right)
//! - [LibreOffice will not open what `encrypt` wrote](#libreoffice-will-not-open-what-encrypt-wrote)
//! - [Which Argon2 cost should I pick?](#which-argon2-cost-should-i-pick)
//! - [The error contains text I did not write](#the-error-contains-text-i-did-not-write)
//! - [`encrypt` refused a file LibreOffice opens without prompting](#encrypt-refused-a-file-libreoffice-opens-without-prompting)
//!
//! # `decrypt` returned `BadParameters`
//!
//! **Whose fault is it?** Four different answers wear this one name, and the
//! string does not distinguish them — its own doc says do not match on its
//! content. What decides the answer is *which bound* the manifest field
//! failed, and `src/limits.rs` labels every one of them.
//!
//! | case | means | where the label is |
//! | --- | --- | --- |
//! | 1. the format forbids it | OASIS or LibreOffice says no | bounds labelled `spec` / `LibreOffice` |
//! | 2. the cipher or KDF cannot run it | a block size, an IV length, `argon2`'s own `m >= 8p` | bounds labelled `hard` |
//! | 3. **this host** cannot afford it | not this variant at all | [`crate::DecryptError::HostCannotAllocate`] |
//! | 4. spec-legal, runnable, **and this crate declined** | a policy cap of ours | bounds labelled `policy` — and see below |
//!
//! **Case 4 is the one worth knowing about**, because reporting a policy cap as
//! case 1 tells a user their file is invalid when it is not. These are ours,
//! and the format permits more: `PBKDF2_MAX_ITER`, `ARGON2_MAX_T_COST`,
//! `MAX_ENCRYPTED_ENTRIES`, and the payload ceilings. A file refused by one of
//! them may open perfectly in LibreOffice.
//!
//! **Case 4 is the one you can do something about.** Since `0.1.0-rc.6` the
//! policy caps that apply to a package's own cost parameters are values on
//! [`crate::DecryptLimits`], not constants you cannot reach:
//!
//! ```
//! # #[cfg(feature = "crypto-ops")] {
//! use odf_crypto::{decrypt_with_limits, DecryptLimits};
//!
//! # fn demo(bytes: &[u8], pw: &str) -> Result<(), odf_crypto::DecryptError> {
//! // Raise one ceiling, having decided this file is worth it.
//! let plain = decrypt_with_limits(bytes, pw, DecryptLimits::default().with_argon2_max_t(64))?;
//! # let _ = plain;
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! The defaults refuse nothing LibreOffice writes — `t = 3`, `m = 64 MiB`,
//! `p = 4`, at most 600,000 PBKDF2 iterations, all comfortably inside them — so
//! a file that trips one came from somewhere else. `DecryptLimits::PERMISSIVE`
//! accepts everything the format can express, and is a decision to spend
//! whatever an unknown file asks for: a single Argon2 row at the format's
//! widths extrapolates to about **33 hours**, and `decrypt` cannot be
//! interrupted.
//!
//! Argon2 memory split in two in `0.1.0-rc.6` and is on the list only for the
//! direction you are reading about here. A manifest's `m` is still capped at
//! 1 GiB by policy, because `decrypt` must run the KDF before it can check a
//! password, so the file chooses the cost of the attempt. A cost **you** pass to
//! `encrypt_with_params` is not capped by us at all — at 1 GiB that refused RFC
//! 9106's own first recommended tuple — and an unaffordable one there is case 3
//! rather than case 4.
//!
//! **Case 3 is a separate variant on purpose.** It blames neither the package
//! nor this crate — the manifest may be entirely legal and the same bytes may
//! decrypt on a machine with more free memory. So retrying, or retrying
//! elsewhere, is meaningful; re-downloading the file is not. Its
//! [`AllocationSite`](crate::AllocationSite) names which buffer could not be
//! obtained.
//!
//! ```
//! use odf_crypto::{decrypt, DecryptError};
//!
//! fn explain(bytes: &[u8], password: &str) -> String {
//!     match decrypt(bytes, password) {
//!         Ok(_) => "decrypted".into(),
//!         // The string is a diagnostic. Which of cases 1, 2 and 4 this is
//!         // cannot be recovered from it -- look up the bound it names in
//!         // `limits.rs` and read its label.
//!         Err(DecryptError::BadParameters(msg)) => {
//!             format!("this crate will not act on a manifest field: {msg}")
//!         }
//!         // Case 3. Say "try again, or try on a bigger machine" -- never
//!         // "your file is damaged", which is what exit 6 used to imply.
//!         Err(DecryptError::HostCannotAllocate { site, requested_bytes }) => {
//!             format!("this machine could not spare {requested_bytes} bytes for {site}")
//!         }
//!         Err(other) => other.to_string(),
//!     }
//! }
//! # let _ = explain(&[], "");
//! ```
//!
//! # `WrongPassword`, but the password is right
//!
//! [`crate::DecryptError::WrongPassword`] **cannot distinguish a wrong password from
//! damaged or tampered ciphertext**, and how much it covers depends on the
//! cipher — which is the part that surprises people.
//!
//! **AES-GCM**: the verdict is the AEAD tag, over the *whole* ciphertext. Any
//! altered byte anywhere fails it. `manifest:checksum` is not consulted at all.
//! So here `WrongPassword` is a strong statement about the entire stream.
//!
//! **AES-CBC and Blowfish-CFB**: the key is never authenticated. The verdict is
//! a checksum over the **first `CHECKSUM_WINDOW` bytes** of the *compressed*
//! plaintext — 1024, which is LibreOffice's `n_ConstDigestLength`. A wrong key
//! almost always corrupts that first kilobyte too, so the error still fires
//! reliably. But **damage past that window, with the correct password, does not
//! surface here**: it surfaces as [`crate::DecryptError::Inflate`], when the corrupted
//! DEFLATE stream fails to decode or does not inflate to `manifest:size`.
//!
//! So a caller seeing `Inflate` after a *successful* password should not treat
//! it as a password problem, and a caller seeing `WrongPassword` should not
//! promise the user it is one.
//!
//! **Write the user-facing copy so it survives being wrong.** Not *"incorrect
//! password"* but something closer to: *"This file could not be opened with that
//! password. Either the password is wrong or the file has been damaged — try
//! the password once more, and if it still fails, get a fresh copy."* That
//! sentence is true in both worlds, and the shorter one is false in one of them.
//!
//! # LibreOffice will not open what `encrypt` wrote
//!
//! **`encrypt` writes one profile, whatever the input was.** One
//! `encrypted-package` member, AES-256-GCM, Argon2id, a SHA-256 start key, no
//! checksum, `manifest:version="1.4"`. It does not read a cipher off the input,
//! because a `Mode::Plain` input does not have one.
//!
//! The consequence catches people: **`decrypt` then `encrypt` is not
//! format-preserving.** Feed it an ODF 1.1 Blowfish document and you get the
//! modern profile back. The crate reads three profiles and writes one — that
//! asymmetry is an effort gap rather than a judgement, and it is tracked.
//!
//! **What is actually verified, stated precisely because the gap matters:** the
//! `tests/goldens/*.odt` corpus is real LibreOffice output, and one golden is
//! write-side evidence. It was produced by a script driving LibreOffice over
//! UNO with the password handed across as a property — **which is not what a
//! double-click does.** No password dialog, no wrong-password retry, no recovery
//! bar. A file can satisfy that harness and still be one a person cannot open,
//! which is why `tests/artifacts/` exists and why its verdict is recorded by
//! hand.
//!
//! If `encrypt` refused *before* writing anything, see
//! [`crate::EncryptError::Odf12Fatal`]: the **plaintext input** has streams its
//! manifest does not account for and declares ODF `>= 1.2`, which is the shape
//! LibreOffice itself refuses to open. Refusing early beats sealing a document
//! nothing can read.
//!
//! # Which Argon2 cost should I pick?
//!
//! **If you have no opinion, express none** — call [`encrypt`](crate::encrypt),
//! which uses LibreOffice's own tuple.
//!
//! The one sentence that matters: **the cost is written into the file and binds
//! every future reader on every device.** It is not a local performance knob.
//! Lowering it to suit today's hardware weakens that document permanently, and
//! it cannot be raised again without decrypting and re-encrypting.
//!
//! **A weak tuple is accepted, not refused.** The cost is the caller's decision
//! and this crate does not overrule it. It also does not *warn* on its own —
//! [`crate::Argon2Params::is_weaker_than_libreoffice`] is a predicate you must ask.
//! The CLI asks it and prints to stderr; a library has no terminal, so nothing
//! happens unless your code makes it happen.
//!
//! What *is* refused is a different axis entirely, and
//! [`ParamsReason`](crate::ParamsReason) names whose rule it was:
//! `OutOfRange` is **our** policy bound, `CipherRejects` is `argon2`'s own
//! requirement. Neither means "too weak". A third axis,
//! [`crate::EncryptError::HostCannotAllocate`], means the tuple was fine and this
//! machine was not.
//!
//! ```
//! use odf_crypto::{encrypt, encrypt_with_params, Argon2Params};
//!
//! # fn demo(plain: &[u8], pw: &str) -> Result<(), odf_crypto::EncryptError> {
//! // GOOD -- expresses no opinion, gets LibreOffice's profile.
//! let sealed = encrypt(plain, pw)?;
//!
//! // GOOD -- a constrained device, traded knowingly and recorded.
//! let p = Argon2Params::new(2, 8192, 2)?;          // ~8 MiB instead of 64
//! if p.is_weaker_than_libreoffice() {
//!     eprintln!("sealing at a reduced cost: {} {} {}", p.t(), p.m_kib(), p.p());
//! }
//! let sealed_cheaply = encrypt_with_params(plain, pw, p)?;
//!
//! // POOR -- legal, runnable, and about as cheap to attack as the format
//! // allows. Nothing refuses it. The document is weak for every future
//! // reader, on hardware that could have afforded more.
//! let weak = Argon2Params::new(1, 8, 1)?;
//! assert!(weak.is_weaker_than_libreoffice());
//! # let _ = (sealed, sealed_cheaply);
//! # Ok(())
//! # }
//! # let _ = demo;
//! ```
//!
//! # The error contains text I did not write
//!
//! Some payloads quote bytes the package chose. Rendering one as though it were
//! this library's own words hands an attacker your log line or your dialog.
//!
//! **Ask what was interpolated, not what the type is.** That is the trap: the
//! variants are `thiserror` enums with fixed format strings, which looks
//! reassuring and tells you nothing — the hazard is in the `{0}`.
//!
//! | payload | carries package text? |
//! | --- | --- |
//! | [`DetectError::Inconsistent`](crate::DetectError::Inconsistent) | **yes**, bounded to `DIAGNOSTIC_ELISION` (96 bytes) |
//! | the zip half of any `Zip` variant | no — rendered from `&'static str` this crate chose, never the zip crate's `Display` |
//! | the quick-xml half of [`crate::DecryptError::Zip`] | **yes**, and un-elided — see its own docs for why that is safe |
//! | [`crate::DecryptError::BadParameters`] | **yes** — it quotes manifest field values |
//! | `Internal` on either error | no — our own text about our own invariant |
//!
//! **Elision bounds volume, not trust.** 96 bytes of attacker-chosen text is
//! still attacker-chosen: nothing distinguishes a hostile media type from a
//! real one by shape. So the rule is not "short enough to print" — it is *do
//! not interpolate these into a sentence that reads as yours*. Show them quoted,
//! attributed to the file, and truncated for display.
//!
//! # `encrypt` refused a file LibreOffice opens without prompting
//!
//! That is [`crate::EncryptError::PartiallyEncrypted`], and the surprise is real rather
//! than a bug in your reasoning.
//!
//! [`Mode::PerEntry`](crate::Mode::PerEntry) means *complete `encryption-data`
//! rows exist*. [`Classification::package_encrypted`](crate::Classification::package_encrypted)
//! means something narrower — it is LibreOffice's `HasEncryptedEntries` latch,
//! and only a row resolving to `content.xml` or `encrypted-package` sets it.
//! **A package can be `PerEntry` with the latch false**, and LibreOffice opens
//! that without prompting, because the prompt is gated on the latch.
//!
//! So the old single `AlreadyEncrypted` was telling a caller something the
//! specifying implementation contradicts. It is still refused, for a reason
//! worth stating: `encrypt` deflates the **whole input** and wraps it in one new
//! member. Wrapping a package whose members are already ciphertext buries them
//! a layer deeper, readable by nobody.
//!
//! **Do not test `!package_encrypted` to decide whether a package is
//! plaintext.** That is exactly the confusion the split exists to stop. The
//! plaintext test is `mode == Mode::Plain`.
//!
//! ```
//! use odf_crypto::{classify, Mode};
//!
//! # fn is_sealable(bytes: &[u8]) -> Result<bool, odf_crypto::DetectError> {
//! let class = classify(bytes)?;
//! // Right. `package_encrypted` is a narrower question than this one.
//! Ok(class.mode == Mode::Plain)
//! # }
//! # let _ = is_sealable;
//! ```
//!
//! One limitation to know, because a caller may be trying to reproduce
//! LibreOffice's behaviour and cannot: `Classification` does not expose
//! LibreOffice's mirror-image flag, `HasNonEncryptedEntries`. With **both**
//! flags set on ODF `>= 1.2`, LibreOffice raises
//! `ERRCODE_SFX_INCOMPLETE_ENCRYPTION` and disables macro execution. Half of
//! that predicate is visible here and half is not, so that verdict cannot be
//! reconstructed from a `Classification`.

// No items. This module is a page.
