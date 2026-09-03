//! LibreOffice-faithful ODF package encryption detection and decryption.
//!
//! [`classify`] answers whether a file is an ODF package, whether it is encrypted,
//! in which zip-shape [`Mode`], and with which algorithm tuple. It follows
//! LibreOffice `package/` accept predicates, not Horsmann's origin detector.
//!
//! With the `decrypt` feature enabled, [`decrypt`] turns an LO-encrypted
//! package into the plaintext ODF zip LibreOffice would open after a correct password.
//!
//! With the default `encrypt` feature enabled (it implies `decrypt`), [`encrypt`]
//! is the reverse: it turns a plaintext (`Mode::Plain`) ODF package into what
//! current LibreOffice writes for that input under a password.

mod classify;
mod manifest;
mod types;
mod uris;
mod zip_tree;

#[cfg(feature = "decrypt")]
mod kdf;
#[cfg(feature = "decrypt")]
mod decrypt;
#[cfg(feature = "encrypt")]
mod encrypt;

pub use classify::classify;
pub use types::{
    Checksum, Cipher, Classification, DetectError, EncryptedKey, EntryEncryption, Kdf, Mode,
    StartKeyAlg,
};

#[cfg(feature = "decrypt")]
pub use decrypt::{decrypt, DecryptError};
#[cfg(feature = "encrypt")]
pub use encrypt::{encrypt, EncryptError};
