//! LibreOffice-faithful ODF package encryption detection.
//!
//! `classify` answers whether a file is an ODF package, whether it is encrypted,
//! in which zip-shape [`Mode`], and with which algorithm tuple. It follows
//! LibreOffice `package/` accept predicates, not Horsmann's origin detector.
//!
//! This crate does not derive keys and does not decrypt.

mod classify;
mod manifest;
mod types;
mod uris;
mod zip_tree;

pub use classify::classify;
pub use types::{
    Checksum, Cipher, Classification, DetectError, EntryEncryption, Kdf, Mode, StartKeyAlg,
};
