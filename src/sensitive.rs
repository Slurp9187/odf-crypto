//! Sensitive material wrapped with `secure-gate`.
//!
//! Internal only: the public [`crate::decrypt`] API still takes `password: &str`
//! and returns a plain `Vec<u8>`. Everything that used to be zeroized by hand
//! via `zeroize::Zeroizing` is wrapped here instead — `secure-gate` is this
//! crate's only zeroizing primitive now, not an addition alongside `zeroize` —
//! and so is every decrypted intermediate between a cipher and the output zip.
//!
//! Expect this module to grow when the encrypt arc
//! (`docs/plans/odf-encryption-encrypt-2026-09-03.md`) lands and introduces
//! writer-side keys, salts and IVs.

use secure_gate::dynamic_alias;

dynamic_alias!(
    pub(crate) PasswordDigest,
    Vec<u8>,
    "SHA-1 or SHA-256 digest of the user's password (`start_key`'s output), \
     before KDF stretching. Length depends on the digest algorithm (20 or 32 \
     bytes), so this wraps `Vec<u8>`, not a fixed-size array."
);

dynamic_alias!(
    pub(crate) DerivedKey,
    Vec<u8>,
    "PBKDF2/Argon2id-derived cipher key. Length (16/24/32 bytes) follows \
     `EntryEncryption::derived_key_len`, so this wraps `Vec<u8>`, not a fixed-size array."
);

dynamic_alias!(
    pub(crate) DeflatedPlaintext,
    Vec<u8>,
    "A decrypted package member exactly as the cipher emits it: still raw-DEFLATE \
     compressed, not yet inflated. Lives from the cipher call to `raw_inflate`."
);

dynamic_alias!(
    pub(crate) MemberPlaintext,
    Vec<u8>,
    "An inflated package member, held only until it is written into the rebuilt \
     plaintext zip. That zip is the public return value and stays a plain `Vec<u8>`."
);
