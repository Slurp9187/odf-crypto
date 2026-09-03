//! Sensitive key material wrapped with `secure-gate`.
//!
//! Internal only: the public [`crate::decrypt`] API still takes `password: &str`
//! and returns a plain `Vec<u8>`. `DerivedKey` covers the one value that crosses
//! a function boundary while it's still key material — `derive_key`'s output, on
//! its way to a cipher constructor in `decrypt_member`. The password digest
//! (`start_key`'s output) never leaves `derive_key`, so it stays a plain
//! `zeroize::Zeroizing<Vec<u8>>` there — no boundary, no wrapper needed.
//!
//! Expect this module to grow when the encrypt arc
//! (`docs/plans/odf-encryption-encrypt-2026-09-03.md`) lands and introduces
//! writer-side keys, salts and IVs.

use secure_gate::dynamic_alias;

dynamic_alias!(
    pub(crate) DerivedKey,
    Vec<u8>,
    "PBKDF2/Argon2id-derived cipher key. Length (16/24/32 bytes) follows \
     `EntryEncryption::derived_key_len`, so this wraps `Vec<u8>`, not a fixed-size array."
);
