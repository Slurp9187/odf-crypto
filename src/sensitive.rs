//! Sensitive material wrapped with `secure-gate`.
//!
//! Internal only: the public [`crate::decrypt`] and [`crate::encrypt`] APIs
//! still take `password: &str` and return a plain `Vec<u8>`. Everything that
//! used to be zeroized by hand via `zeroize::Zeroizing` is wrapped here
//! instead — `secure-gate` is this crate's only zeroizing primitive now, not
//! an addition alongside `zeroize` — and so is every package plaintext
//! between a cipher and a zip, in either direction.
//!
//! The encrypt arc (`docs/plans/odf-encryption-encrypt-2026-09-03.md`) landed
//! without needing an alias of its own: key derivation is shared with decrypt
//! (`crate::kdf`), so the writer side reuses [`PasswordDigest`] and
//! [`DerivedKey`] verbatim, and its deflated-then-sealed buffer is the same
//! material as [`DeflatedPlaintext`] travelling the other way. Its salt and
//! IV are *not* wrapped: both are written to the manifest in the clear, so
//! they are public by construction, exactly like the KDF parameters they sit
//! beside. The plaintext the caller hands `encrypt()` stays plain for the
//! same reason `password: &str` does — the caller already owns it.

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
    "PBKDF2/Argon2id-derived cipher key. On the read side its length (16/24/32 bytes) \
     follows `EntryEncryption::derived_key_len`, so this wraps `Vec<u8>`, not a \
     fixed-size array; `encrypt` reuses it at its own fixed 32, since both directions \
     fill it through the same `crate::kdf` helpers."
);

dynamic_alias!(
    pub(crate) DeflatedPlaintext,
    Vec<u8>,
    "Package plaintext in its raw-DEFLATE form, on either side of a cipher. Decrypting, \
     it is what the cipher emits and lives until `raw_inflate`; encrypting, it is the \
     deflated input, wrapped before the cipher runs and sealed in place, so the crate's \
     own copy of the caller's document is zeroized on drop rather than left in a plain \
     buffer."
);

dynamic_alias!(
    pub(crate) MemberPlaintext,
    Vec<u8>,
    "An inflated package member, held only until it is written into the rebuilt \
     plaintext zip. That zip is the public return value and stays a plain `Vec<u8>`."
);
