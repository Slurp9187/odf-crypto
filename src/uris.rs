//! URI and name aliases from LibreOffice `ManifestDefines.hxx` — the strings
//! `ManifestImport` accepts on the read side, and the ones the manifest writer
//! emits on the write side.
//!
//! odfdecrypt-only URLs are not mapped — LO would set `bIgnoreEncryptData` for
//! those.

/// `http://openoffice.org/2001/manifest`
pub const MANIFEST_NS_OOO: &str = "http://openoffice.org/2001/manifest";
/// `urn:oasis:names:tc:opendocument:xmlns:manifest:1.0`
pub const MANIFEST_NS_OASIS: &str = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
/// `urn:org:documentfoundation:names:experimental:office:xmlns:loext:1.0`.
/// Not rewritten to `manifest:` — `ManifestImport` leaves `loext:` as-is.
/// Read-side, LOEXT elements are matched by their hardcoded `loext:`-prefixed
/// name constants below, not through this URI -- so the only real consumer is
/// `encrypt.rs`'s manifest writer (`xmlns:loext`).
///
/// `test` is in the gate because the negative assertion in this module's own
/// tests compiles in every configuration.
#[cfg(any(feature = "crypto-ops", test))]
pub const MANIFEST_NS_LOEXT: &str =
    "urn:org:documentfoundation:names:experimental:office:xmlns:loext:1.0";

pub const MANIFEST_PREFIX: &str = "manifest:";

pub const ELEMENT_MANIFEST: &str = "manifest:manifest";
pub const ELEMENT_FILE_ENTRY: &str = "manifest:file-entry";
pub const ELEMENT_ENCRYPTION_DATA: &str = "manifest:encryption-data";
pub const ELEMENT_ALGORITHM: &str = "manifest:algorithm";
pub const ELEMENT_START_KEY_GENERATION: &str = "manifest:start-key-generation";
pub const ELEMENT_KEY_DERIVATION: &str = "manifest:key-derivation";

pub const ELEMENT_LOEXT_KEYINFO: &str = "loext:keyinfo";
pub const ELEMENT_LOEXT_ENCRYPTED_KEY: &str = "loext:encrypted-key";
pub const ELEMENT_LOEXT_ENCRYPTION_METHOD: &str = "loext:encryption-method";
pub const ELEMENT_LOEXT_KEYINFO_DSIG: &str = "loext:KeyInfo";
pub const ELEMENT_LOEXT_PGP_DATA: &str = "loext:PGPData";
pub const ELEMENT_LOEXT_PGP_KEY_ID: &str = "loext:PGPKeyID";
pub const ELEMENT_LOEXT_PGP_KEY_PACKET: &str = "loext:PGPKeyPacket";
pub const ELEMENT_LOEXT_CIPHER_DATA: &str = "loext:CipherData";
pub const ELEMENT_LOEXT_CIPHER_VALUE: &str = "loext:CipherValue";

pub const ELEMENT_MANIFEST_KEYINFO: &str = "manifest:keyinfo";
pub const ELEMENT_MANIFEST_ENCRYPTED_KEY: &str = "manifest:encrypted-key";
pub const ELEMENT_MANIFEST_ENCRYPTION_METHOD: &str = "manifest:encryption-method";
pub const ELEMENT_MANIFEST_PGP_DATA: &str = "manifest:PGPData";
pub const ELEMENT_MANIFEST_PGP_KEY_ID: &str = "manifest:PGPKeyID";
pub const ELEMENT_MANIFEST_PGP_KEY_PACKET: &str = "manifest:PGPKeyPacket";
pub const ELEMENT_MANIFEST_CIPHER_DATA: &str = "manifest:CipherData";
pub const ELEMENT_MANIFEST_CIPHER_VALUE: &str = "manifest:CipherValue";

pub const ATTR_FULL_PATH: &str = "manifest:full-path";
pub const ATTR_VERSION: &str = "manifest:version";
pub const ATTR_MEDIA_TYPE: &str = "manifest:media-type";
pub const ATTR_SIZE: &str = "manifest:size";
pub const ATTR_CHECKSUM_TYPE: &str = "manifest:checksum-type";
pub const ATTR_CHECKSUM: &str = "manifest:checksum";
pub const ATTR_ALGORITHM_NAME: &str = "manifest:algorithm-name";
pub const ATTR_IV: &str = "manifest:initialisation-vector";
pub const ATTR_START_KEY_NAME: &str = "manifest:start-key-generation-name";
pub const ATTR_KEY_SIZE: &str = "manifest:key-size";
pub const ATTR_KEY_DERIVATION_NAME: &str = "manifest:key-derivation-name";
pub const ATTR_SALT: &str = "manifest:salt";
pub const ATTR_ITERATION_COUNT: &str = "manifest:iteration-count";
pub const ATTR_ARGON2_T: &str = "manifest:argon2-iterations";
pub const ATTR_ARGON2_M: &str = "manifest:argon2-memory";
pub const ATTR_ARGON2_P: &str = "manifest:argon2-lanes";
pub const ATTR_ARGON2_T_LO: &str = "loext:argon2-iterations";
pub const ATTR_ARGON2_M_LO: &str = "loext:argon2-memory";
pub const ATTR_ARGON2_P_LO: &str = "loext:argon2-lanes";
pub const ATTR_PGP_ALGORITHM_LO: &str = "loext:PGPAlgorithm";
pub const ATTR_PGP_ALGORITHM: &str = "manifest:PGPAlgorithm";

pub const SHA256_URL: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
/// OFFICE-3708: wrong URL cited in ODF 1.2 and used since OOo 3.4 beta.
pub const SHA256_URL_ODF12: &str = "http://www.w3.org/2000/09/xmldsig#sha256";
pub const SHA1_NAME: &str = "SHA1";
pub const SHA1_URL: &str = "http://www.w3.org/2000/09/xmldsig#sha1";

pub const SHA1_1K_NAME: &str = "SHA1/1K";
pub const SHA1_1K_URL: &str = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha1-1k";
pub const SHA256_1K_URL: &str = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k";

pub const BLOWFISH_NAME: &str = "Blowfish CFB";
pub const BLOWFISH_URL: &str = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#blowfish";
pub const AES128_URL: &str = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
pub const AES192_URL: &str = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
pub const AES256_URL: &str = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
pub const AESGCM128_URL: &str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
pub const AESGCM192_URL: &str = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
pub const AESGCM256_URL: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

pub const PBKDF2_NAME: &str = "PBKDF2";
pub const PGP_NAME: &str = "PGP";
pub const PBKDF2_URL: &str = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#pbkdf2";
pub const ARGON2ID_URL: &str = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.5#argon2id";
pub const ARGON2ID_URL_LO: &str =
    "urn:org:documentfoundation:names:experimental:office:manifest:argon2id";

pub const PGP_WRAP_URI: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

/// odfdecrypt-only; LO drops the row.
#[cfg(test)]
pub const BLOWFISH_CFB8_PYTHON: &str =
    "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#blowfish-cfb8";
/// odfdecrypt-only; LO does not accept this as PBKDF2.
#[cfg(test)]
pub const PBKDF2_XMLENC: &str = "http://www.w3.org/2001/04/xmlenc#pbkdf2";
/// odfdecrypt-only; LO does not accept this as SHA-1.
#[cfg(test)]
pub const SHA1_XMLENC: &str = "http://www.w3.org/2001/04/xmlenc#sha1";

use crate::types::{ChecksumAlg, Cipher, KdfId, StartKeyAlg};

/// Map an `algorithm-name` to LO's three `CipherID`s plus the cipher-URI default key length.
///
/// Blowfish does not write `nDerivedKeySize`. AES URIs do.
pub fn cipher_from_algorithm_name(name: &str) -> Result<(Cipher, Option<u8>), ()> {
    if name == BLOWFISH_NAME || name == BLOWFISH_URL {
        Ok((Cipher::BlowfishCfb8, None))
    } else if name == AESGCM256_URL {
        Ok((Cipher::AesGcmW3c, Some(32)))
    } else if name == AESGCM192_URL {
        Ok((Cipher::AesGcmW3c, Some(24)))
    } else if name == AESGCM128_URL {
        Ok((Cipher::AesGcmW3c, Some(16)))
    } else if name == AES256_URL {
        Ok((Cipher::AesCbcW3c, Some(32)))
    } else if name == AES192_URL {
        Ok((Cipher::AesCbcW3c, Some(24)))
    } else if name == AES128_URL {
        Ok((Cipher::AesCbcW3c, Some(16)))
    } else {
        Err(())
    }
}

/// `GetDefaultDerivedKeySize` (`ZipPackage.cxx` 137–148). PGP ignores `manifest:key-size`.
pub fn default_derived_key_size(cipher: Cipher) -> i32 {
    match cipher {
        Cipher::BlowfishCfb8 => 16,
        Cipher::AesCbcW3c | Cipher::AesGcmW3c => 32,
    }
}

pub fn start_key_from_name(name: &str) -> Result<StartKeyAlg, ()> {
    if name == SHA256_URL || name == SHA256_URL_ODF12 {
        Ok(StartKeyAlg::Sha256)
    } else if name == SHA1_NAME || name == SHA1_URL {
        Ok(StartKeyAlg::Sha1)
    } else {
        Err(())
    }
}

pub fn checksum_alg_from_type(name: &str) -> Option<ChecksumAlg> {
    if name == SHA1_1K_NAME || name == SHA1_1K_URL {
        Some(ChecksumAlg::Sha1_1K)
    } else if name == SHA256_1K_URL {
        Some(ChecksumAlg::Sha256_1K)
    } else {
        None
    }
}

/// Password-path KDF name. `"PGP"` is handled separately (needs `bPgpEncryption`).
pub fn password_kdf_from_name(name: &str) -> Option<KdfId> {
    if name == PBKDF2_NAME || name == PBKDF2_URL {
        Some(KdfId::Pbkdf2)
    } else if name == ARGON2ID_URL || name == ARGON2ID_URL_LO {
        Some(KdfId::Argon2id)
    } else {
        None
    }
}

pub fn is_manifest_namespace(uri: &str) -> bool {
    uri == MANIFEST_NS_OOO || uri == MANIFEST_NS_OASIS
}

pub fn is_pgp_wrap_uri(uri: &str) -> bool {
    uri == PGP_WRAP_URI
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_lo_cipher_aliases() {
        assert_eq!(
            cipher_from_algorithm_name(BLOWFISH_NAME).unwrap(),
            (Cipher::BlowfishCfb8, None)
        );
        assert_eq!(
            cipher_from_algorithm_name(BLOWFISH_URL).unwrap(),
            (Cipher::BlowfishCfb8, None)
        );
        assert_eq!(
            cipher_from_algorithm_name(AES256_URL).unwrap(),
            (Cipher::AesCbcW3c, Some(32))
        );
        assert_eq!(
            cipher_from_algorithm_name(AES128_URL).unwrap(),
            (Cipher::AesCbcW3c, Some(16))
        );
        assert_eq!(
            cipher_from_algorithm_name(AESGCM256_URL).unwrap(),
            (Cipher::AesGcmW3c, Some(32))
        );
    }

    #[test]
    fn rejects_odfdecrypt_only_urls() {
        assert!(cipher_from_algorithm_name(BLOWFISH_CFB8_PYTHON).is_err());
        assert!(password_kdf_from_name(PBKDF2_XMLENC).is_none());
        assert!(start_key_from_name(SHA1_XMLENC).is_err());
    }

    #[test]
    fn start_key_accepts_both_sha256_urls() {
        assert_eq!(
            start_key_from_name(SHA256_URL).unwrap(),
            StartKeyAlg::Sha256
        );
        assert_eq!(
            start_key_from_name(SHA256_URL_ODF12).unwrap(),
            StartKeyAlg::Sha256
        );
        assert_eq!(start_key_from_name(SHA1_NAME).unwrap(), StartKeyAlg::Sha1);
    }

    #[test]
    fn loext_namespace_is_not_a_manifest_rewrite() {
        assert!(!is_manifest_namespace(MANIFEST_NS_LOEXT));
        assert!(is_manifest_namespace(MANIFEST_NS_OASIS));
        assert!(is_manifest_namespace(MANIFEST_NS_OOO));
    }

    #[test]
    fn argon2_accepts_oasis_and_experimental() {
        assert_eq!(password_kdf_from_name(ARGON2ID_URL), Some(KdfId::Argon2id));
        assert_eq!(
            password_kdf_from_name(ARGON2ID_URL_LO),
            Some(KdfId::Argon2id)
        );
        assert_eq!(password_kdf_from_name(PBKDF2_NAME), Some(KdfId::Pbkdf2));
        assert_eq!(password_kdf_from_name(PBKDF2_URL), Some(KdfId::Pbkdf2));
    }
}
