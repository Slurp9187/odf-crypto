//! LibreOffice-faithful ODF package encryption detection, decryption and encryption.
//!
//! [`classify`] answers whether a file is an ODF package, whether it is encrypted,
//! in which zip-shape [`Mode`], and with which algorithm tuple. It follows
//! LibreOffice `package/` accept predicates, not the origin-detection approach of
//! [Horsmann/odfdecrypt](https://github.com/Horsmann/odfdecrypt).
//!
//! ```
//! use odf_crypto::{classify, Mode};
//!
//! let bytes = include_bytes!("../tests/goldens/lo-unencrypted.odt");
//! let class = classify(bytes)?;
//! assert_eq!(class.mode, Mode::Plain);
//! # Ok::<(), odf_crypto::DetectError>(())
//! ```
//!
//! Detection is the default build: [`classify`] needs no cryptographic
//! dependency. Everything past it is behind the `crypto-ops` feature.
//!
//! With `crypto-ops` enabled, [`decrypt`] turns an LO-encrypted package into the
//! plaintext ODF zip LibreOffice would open after a correct password. Packages
//! `classify` reports as `odf12_fatal` are refused: LO would not open them, so
//! neither does this crate.
//!
//! [`encrypt`] is the reverse: it turns a plaintext ([`Mode::Plain`]) ODF package
//! into what current LibreOffice writes for that input under a password.
//!
//! # Scope
//!
//! [`encrypt`] writes one profile: a single `encrypted-package` member, Argon2id
//! `t=3, m=65536, p=4`, AES-256-GCM, a SHA-256 start key, no checksum, and
//! `manifest:version="1.4"`. Per-entry writing and PGP wrapping are out of scope.
//!
//! [`decrypt`] reads all three algorithm families LibreOffice and Apache
//! OpenOffice produce — AES-GCM + Argon2id, AES-CBC + PBKDF2, and Blowfish-CFB +
//! PBKDF2. PGP-wrapped packages are classified, and their wrapped material is
//! reported in [`Classification::pgp_keys`], but decryption refuses them.
//!
//! # Untrusted input
//!
//! Every bound a hostile package could push on is capped before any allocation
//! or key derivation: the manifest is read at most 8 MiB, inflate, ciphertext
//! and deflate at most 1 GiB each, at most 4096 complete `encryption-data` rows
//! get a KDF run, and `iteration-count`, Argon2 `t`/`m`/`p` and `key-size` each
//! carry a floor and a ceiling.
//!
//! At the API boundary: `password` is a `&str` and [`decrypt`] returns plaintext
//! as a plain `Vec<u8>`. Key material derived inside the crate is zeroized on
//! drop; the password you pass and the plaintext you receive are yours to wipe.
//!
//! # Stability
//!
//! Pre-1.0 — the API may change between releases. Requires Rust 1.85.

// Scoped to the one config where `decrypt`/`encrypt` genuinely are not compiled.
#![cfg_attr(not(feature = "crypto-ops"), allow(rustdoc::broken_intra_doc_links))]
// Inert on stable; on docs.rs it badges the feature-gated items.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

mod classify;
mod limits;
mod manifest;
mod types;
mod uris;
mod zip_tree;

#[cfg(test)]
mod test_support;

#[cfg(feature = "crypto-ops")]
mod decrypt;
#[cfg(feature = "crypto-ops")]
mod encrypt;
#[cfg(feature = "crypto-ops")]
mod kdf;
#[cfg(feature = "crypto-ops")]
mod sensitive;

pub use classify::classify;
pub use types::{
    Checksum, Cipher, Classification, DetectError, EncryptedKey, EntryEncryption, Kdf, Mode,
    StartKeyAlg,
};

#[cfg(feature = "crypto-ops")]
pub use decrypt::{decrypt, DecryptError};
#[cfg(feature = "crypto-ops")]
pub use encrypt::{encrypt, EncryptError};
