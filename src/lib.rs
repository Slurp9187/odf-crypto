//! LibreOffice-faithful ODF package encryption detection and decryption.
//!
//! [`classify`] answers whether a file is an ODF package, whether it is encrypted,
//! in which zip-shape [`Mode`], and with which algorithm tuple. It follows
//! LibreOffice `package/` accept predicates, not Horsmann's origin detector.
//!
//! With the default `decrypt` feature enabled, [`decrypt`] turns an LO-encrypted
//! package into the plaintext ODF zip LibreOffice would open after a correct password.

mod classify;
mod manifest;
mod types;
mod uris;
mod zip_tree;

#[cfg(feature = "decrypt")]
mod decrypt;
#[cfg(feature = "decrypt")]
mod sensitive;

pub use classify::classify;
pub use types::{
    Checksum, Cipher, Classification, DetectError, EncryptedKey, EntryEncryption, Kdf, Mode,
    StartKeyAlg,
};

#[cfg(feature = "decrypt")]
pub use decrypt::{decrypt, DecryptError};
