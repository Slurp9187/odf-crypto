//! Stage B (`ZipPackage::parseManifest`) plus zip-shape `classify`.

use std::collections::HashSet;
use std::io::{Cursor, Read};

use zip::read::HasZipMetadata;
use zip::CompressionMethod;
use zip::ZipArchive;

use crate::manifest::parse_manifest;
use crate::types::{
    Checksum, ChecksumAlg, Classification, EntryEncryption, Kdf, KdfId, PropertyBag, StartKeyAlg,
};
use crate::uris;
use crate::zip_tree::{FolderTree, ResolvedKind, StreamAsFolder};
use crate::{Cipher, DetectError, Mode};

const MANIFEST_READ_CAP: usize = 8 * 1024 * 1024;

struct ZipMember {
    name: String,
    index: usize,
    stored: bool,
    data_descriptor: bool,
}

/// Classify an ODF package's encryption. Does not derive keys or decrypt.
pub fn classify(bytes: &[u8]) -> Result<Classification, DetectError> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(|_| DetectError::NotZip)?;
    let members = collect_members(&mut archive)?;
    let mut tree = FolderTree::from_zip_names(members.iter().map(|m| m.name.as_str()))
        .map_err(|_| DetectError::Zip("Bad Zip File, stream as folder".into()))?;
    let zip_has_encrypted_package = tree.root_has_entry("encrypted-package");

    let manifest_xml = read_named_member(&mut archive, &members, "META-INF/manifest.xml")?
        .ok_or(DetectError::MissingManifest)?;
    let bags = parse_manifest(&manifest_xml)?;
    let mimetype = read_mimetype(&mut archive, &members, &tree)?;
    let class = stage_b(bags, &mut tree, zip_has_encrypted_package, mimetype)?;
    check_stored_data_descriptors(&members, &class)?;
    Ok(class)
}

fn collect_members(archive: &mut ZipArchive<Cursor<&[u8]>>) -> Result<Vec<ZipMember>, DetectError> {
    let mut members = Vec::new();
    let mut seen = HashSet::new();
    let mut seen_lower = HashSet::new();
    for i in 0..archive.len() {
        let file = archive
            .by_index(i)
            .map_err(|err| DetectError::Zip(err.to_string()))?;
        let meta = file.get_metadata();
        if meta.uncompressed_size == 0
            && format!("{:?}", meta.system) == "Dos"
            && meta.external_attributes & 0x10 != 0
        {
            continue;
        }
        let name = String::from_utf8_lossy(file.name_raw()).into_owned();
        if !is_valid_zip_entry_file_name(&name) {
            return Err(DetectError::Zip("Zip entry has an invalid name.".into()));
        }
        if !seen.insert(name.clone()) {
            return Err(DetectError::Zip("Duplicate CEN entry".into()));
        }
        if !seen_lower.insert(name.to_ascii_lowercase()) {
            return Err(DetectError::Zip(
                "Duplicate CEN entry (case insensitive)".into(),
            ));
        }
        members.push(ZipMember {
            name,
            index: i,
            stored: file.compression() == CompressionMethod::Stored,
            data_descriptor: meta.using_data_descriptor,
        });
    }
    Ok(members)
}

/// `OStorageHelper::IsValidZipEntryFileName` with slashes allowed.
fn is_valid_zip_entry_file_name(name: &str) -> bool {
    let mut dots: i32 = 0;
    for (i, c) in name.chars().enumerate() {
        match c {
            '.' => {
                if dots != -1 {
                    dots += 1;
                }
            }
            '\\' | '?' | '<' | '>' | '"' | '|' | ':' => return false,
            '/' => {
                if dots == 1 || dots == 2 || i == 0 {
                    return false;
                }
                dots = 0;
            }
            _ => {
                dots = -1;
                let u = c as u32;
                if u < 32 || (0xD800..=0xDFFF).contains(&u) {
                    return false;
                }
            }
        }
    }
    dots != 1 && dots != 2
}

fn read_named_member(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    members: &[ZipMember],
    want: &str,
) -> Result<Option<Vec<u8>>, DetectError> {
    let Some(member) = members.iter().find(|m| member_matches_path(&m.name, want)) else {
        return Ok(None);
    };
    let mut file = archive
        .by_index(member.index)
        .map_err(|err| DetectError::Zip(err.to_string()))?;
    let mut buf = Vec::new();
    file.by_ref()
        .take(MANIFEST_READ_CAP as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|err| DetectError::Zip(err.to_string()))?;
    if buf.len() > MANIFEST_READ_CAP {
        return Err(DetectError::Zip("zip entry too large".into()));
    }
    Ok(Some(buf))
}

fn member_matches_path(zip_name: &str, want: &str) -> bool {
    if zip_name == want {
        return true;
    }
    // `META-INF//manifest.xml` inserts as `META-INF/manifest.xml`.
    let collapsed: String = collapse_slashes(zip_name);
    collapsed == want
}

fn collapse_slashes(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_slash = false;
    for c in name.chars() {
        if c == '/' {
            if !prev_slash {
                out.push(c);
            }
            prev_slash = true;
        } else {
            prev_slash = false;
            out.push(c);
        }
    }
    out
}

fn read_mimetype(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    members: &[ZipMember],
    tree: &FolderTree,
) -> Result<Option<String>, DetectError> {
    if !tree.root_has_entry("mimetype") {
        return Ok(None);
    }
    if !tree.root_has_stream("mimetype") {
        // Root folder named `mimetype`: LO reads an empty media-type.
        return Ok(Some(String::new()));
    }
    let Some(member) = members.iter().find(|m| m.name == "mimetype") else {
        return Ok(Some(String::new()));
    };
    let mut file = archive
        .by_index(member.index)
        .map_err(|err| DetectError::Zip(err.to_string()))?;
    let mut buf = [0u8; 1024];
    let n = file
        .read(&mut buf)
        .map_err(|err| DetectError::Zip(err.to_string()))?;
    Ok(Some(String::from_utf8_lossy(&buf[..n]).into_owned()))
}

fn nonempty(value: Option<&String>) -> bool {
    value.map(|s| !s.is_empty()).unwrap_or(false)
}

fn version_ge_12(version: Option<&str>) -> bool {
    version.map(|v| v >= "1.2").unwrap_or(false)
}

fn stage_b(
    bags: Vec<PropertyBag>,
    tree: &mut FolderTree,
    zip_has_encrypted_package: bool,
    mimetype: Option<String>,
) -> Result<Classification, DetectError> {
    let mut key_info = false;
    let mut o_first_version = None;
    let mut package_encrypted = false;
    let mut common = None;
    let mut encrypted_entries = Vec::new();
    let mut encrypted_package_complete = false;

    for bag in bags {
        if o_first_version.is_none() {
            if let Some(v) = bag.version.as_ref().filter(|s| !s.is_empty()) {
                o_first_version = Some(v.clone());
            }
        }
        if bag.key_info.is_some() {
            key_info = true;
        }
        if bag.full_path.is_empty() {
            continue;
        }
        let resolved = match tree.resolve(&bag.full_path) {
            Ok(r) => r,
            Err(StreamAsFolder) => {
                return Err(DetectError::Inconsistent(
                    "stream used as folder in manifest path".into(),
                ));
            }
        };
        let Some(resolved) = resolved else {
            continue;
        };

        match resolved.kind {
            ResolvedKind::Folder => {
                tree.set_folder_meta(
                    &resolved.tree_path,
                    bag.media_type.clone(),
                    bag.version.clone(),
                );
            }
            ResolvedKind::Stream => {
                tree.mark_from_manifest(&resolved.tree_path, bag.media_type.clone());
                if let Some(entry) = accept_row(&bag, key_info, resolved.tree_path.clone()) {
                    // Wholesome complete-check is the resolved root member,
                    // not the bag's `full-path`.
                    if resolved.tree_path == "encrypted-package" {
                        encrypted_package_complete = true;
                    }
                    let short = short_name(&entry.path);
                    if !package_encrypted
                        && (short == "content.xml" || short == "encrypted-package")
                    {
                        package_encrypted = true;
                        common = Some(entry.clone());
                    }
                    encrypted_entries.push(entry);
                }
            }
        }
    }

    let mode = if zip_has_encrypted_package && encrypted_package_complete {
        Mode::Wholesome
    } else if !encrypted_entries.is_empty() {
        Mode::PerEntry
    } else {
        Mode::Plain
    };

    let root_had_media = nonempty(tree.root_meta().media_type.as_ref());
    if let Some(ref mt) = mimetype {
        if !root_had_media {
            if mt.starts_with("application/vnd.") {
                let version = if !nonempty(tree.root_meta().version.as_ref()) {
                    o_first_version.clone()
                } else {
                    tree.root_meta().version.clone()
                };
                tree.set_folder_meta("/", Some(mt.clone()), version);
            }
        } else {
            let xml_mt = if zip_has_encrypted_package {
                tree.root_entry_media_type("encrypted-package")
                    .unwrap_or("")
            } else {
                tree.root_meta().media_type.as_deref().unwrap_or("")
            };
            if xml_mt != mt.as_str() {
                return Err(DetectError::Inconsistent(format!(
                    "mimetype conflicts with manifest.xml, \"{xml_mt}\" vs. \"{mt}\""
                )));
            }
        }
    }

    let root = tree.root_meta();
    let has_unexpected_streams = tree.has_unexpected_odf12_streams(zip_has_encrypted_package);
    let odf12_fatal = has_unexpected_streams && version_ge_12(root.version.as_deref());

    Ok(Classification {
        mode,
        package_encrypted,
        odf_version: root.version.clone(),
        zip_has_encrypted_package,
        media_type: root.media_type.clone(),
        common,
        encrypted_entries,
        has_unexpected_streams,
        odf12_fatal,
    })
}

fn check_stored_data_descriptors(
    members: &[ZipMember],
    class: &Classification,
) -> Result<(), DetectError> {
    let encrypted: HashSet<&str> = class
        .encrypted_entries
        .iter()
        .map(|e| e.path.as_str())
        .collect();
    for member in members {
        if member.stored && member.data_descriptor {
            let collapsed = collapse_slashes(&member.name);
            if !encrypted.contains(member.name.as_str()) && !encrypted.contains(collapsed.as_str())
            {
                return Err(DetectError::Zip(
                    "entry STORED with data descriptor but not encrypted".into(),
                ));
            }
        }
    }
    Ok(())
}

fn short_name(path: &str) -> &str {
    path.rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
}

fn accept_row(bag: &PropertyBag, key_info: bool, path: String) -> Option<EntryEncryption> {
    if key_info && pgp_complete(bag) {
        return Some(pgp_entry(bag, path));
    }
    if password_complete(bag) {
        return Some(password_entry(bag, path));
    }
    None
}

fn pgp_complete(bag: &PropertyBag) -> bool {
    bag.iv.is_some()
        && bag.size.is_some()
        && bag.enc_alg.is_some()
        && bag.kdf == Some(KdfId::PgpRsaOaepMgf1p)
        && (bag.enc_alg == Some(Cipher::AesGcmW3c)
            || (bag.digest.is_some() && bag.digest_alg.is_some()))
}

fn password_complete(bag: &PropertyBag) -> bool {
    bag.salt.is_some()
        && bag.iv.is_some()
        && bag.size.is_some()
        && bag.enc_alg.is_some()
        && match bag.kdf {
            Some(KdfId::Pbkdf2) => true,
            Some(KdfId::Argon2id) => bag.argon2_args.is_some(),
            _ => false,
        }
        && (bag.enc_alg == Some(Cipher::AesGcmW3c)
            || (bag.digest.is_some() && bag.digest_alg.is_some()))
}

fn pgp_entry(bag: &PropertyBag, path: String) -> EntryEncryption {
    let cipher = bag.enc_alg.expect("pgp_complete");
    EntryEncryption {
        path,
        cipher,
        kdf: Kdf::PgpRsaOaepMgf1p,
        start_key: StartKeyAlg::Sha256,
        checksum: checksum_of(bag),
        size: bag.size.expect("pgp_complete"),
        iv: bag.iv.clone().unwrap_or_default(),
        derived_key_len: uris::default_derived_key_size(cipher),
    }
}

fn password_entry(bag: &PropertyBag, path: String) -> EntryEncryption {
    let cipher = bag.enc_alg.expect("password_complete");
    let salt = bag.salt.clone().unwrap_or_default();
    let kdf = match bag.kdf {
        Some(KdfId::Pbkdf2) => Kdf::Pbkdf2 {
            iterations: bag.iteration_count.unwrap_or(0),
            salt,
        },
        Some(KdfId::Argon2id) => {
            let (t, m, p) = bag.argon2_args.expect("password_complete");
            Kdf::Argon2id { t, m, p, salt }
        }
        _ => unreachable!("password_complete"),
    };
    EntryEncryption {
        path,
        cipher,
        kdf,
        start_key: bag.start_key_alg.unwrap_or(StartKeyAlg::Sha1),
        checksum: checksum_of(bag),
        size: bag.size.expect("password_complete"),
        iv: bag.iv.clone().unwrap_or_default(),
        derived_key_len: bag.derived_key_size.unwrap_or(16),
    }
}

fn checksum_of(bag: &PropertyBag) -> Checksum {
    match (bag.digest_alg, bag.digest.as_ref()) {
        (Some(ChecksumAlg::Sha1_1K), Some(d)) => Checksum::Sha1_1K(d.clone()),
        (Some(ChecksumAlg::Sha256_1K), Some(d)) => Checksum::Sha256_1K(d.clone()),
        _ => Checksum::None,
    }
}

#[cfg(test)]
#[path = "classify_tests.rs"]
mod tests;
