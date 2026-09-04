//! LibreOffice-faithful ODF package encryption detection and decryption.
//!
//! [`classify`] answers whether a file is an ODF package, whether it is encrypted,
//! in which zip-shape [`Mode`], and with which algorithm tuple. It follows
//! LibreOffice `package/` accept predicates, not Horsmann's origin detector.
//!
//! Detection is the default build: [`classify`] needs no cipher, KDF or inflate
//! dependency. Everything past it is behind the `crypto-ops` feature.
//!
//! With `crypto-ops` enabled, `decrypt` turns an LO-encrypted package into the
//! plaintext ODF zip LibreOffice would open after a correct password. Packages
//! `classify` reports as `odf12_fatal` are refused: LO would not open them, so
//! neither does this crate.
//!
//! `encrypt` is the reverse: it turns a plaintext (`Mode::Plain`) ODF package
//! into what current LibreOffice writes for that input under a password.
//!
//! (Those two are named in code spans rather than doc links because a
//! `--no-default-features` build compiles neither, and an intra-doc link to a
//! feature-gated item is a `broken_intra_doc_links` warning there.)

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
