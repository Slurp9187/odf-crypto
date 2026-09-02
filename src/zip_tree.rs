//! Folder tree matching `ZipPackage::getZipFileContents` / `hasByHierarchicalName`.
//!
//! Path existence is not `zip.namelist().contains(path)`. Implicit folders are
//! synthesized from member paths, and `"/"` always resolves.

use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub(crate) struct FolderMeta {
    pub media_type: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum TreeNode {
    Folder(FolderNode),
    Stream {
        from_manifest: bool,
        media_type: Option<String>,
    },
}

#[derive(Debug, Clone, Default)]
pub(crate) struct FolderNode {
    pub meta: FolderMeta,
    pub children: BTreeMap<String, TreeNode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolvedKind {
    Folder,
    Stream,
}

#[derive(Debug, Clone)]
pub(crate) struct FolderTree {
    root: FolderNode,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamAsFolder;

impl FolderTree {
    pub(crate) fn from_zip_names<I, S>(names: I) -> Result<Self, StreamAsFolder>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut root = FolderNode::default();
        for name in names {
            insert_path(&mut root, name.as_ref())?;
        }
        Ok(Self { root })
    }

    pub(crate) fn root_has_entry(&self, name: &str) -> bool {
        self.root.children.contains_key(name)
    }

    pub(crate) fn root_has_stream(&self, name: &str) -> bool {
        matches!(self.root.children.get(name), Some(TreeNode::Stream { .. }))
    }

    pub(crate) fn root_entry_media_type(&self, name: &str) -> Option<&str> {
        match self.root.children.get(name) {
            Some(TreeNode::Stream { media_type, .. }) => media_type.as_deref(),
            Some(TreeNode::Folder(f)) => f.meta.media_type.as_deref(),
            None => None,
        }
    }

    pub(crate) fn root_meta(&self) -> &FolderMeta {
        &self.root.meta
    }

    /// `hasByHierarchicalName`. `"/"` is unconditionally true.
    ///
    /// A leading empty segment (`/Pictures/`) stops the walk on the node
    /// reached so far — the root. Stream-as-folder is `Err`.
    pub(crate) fn resolve(&self, path: &str) -> Result<Option<ResolvedKind>, StreamAsFolder> {
        resolve_kind(&self.root, path)
    }

    pub(crate) fn set_folder_meta(
        &mut self,
        path: &str,
        media_type: Option<String>,
        version: Option<String>,
    ) {
        if let Ok(Some(ResolvedKind::Folder)) = resolve_kind(&self.root, path) {
            if let Some(node) = folder_mut(&mut self.root, path) {
                node.meta.media_type = media_type;
                node.meta.version = version;
            }
        }
    }

    pub(crate) fn mark_from_manifest(&mut self, path: &str, media_type: Option<String>) {
        if let Some(stream) = stream_mut(&mut self.root, path) {
            *stream.0 = true;
            *stream.1 = media_type;
        }
    }

    /// `LookForUnexpectedODF12Streams`. `is_wholesome` is the bare zip check.
    pub(crate) fn has_unexpected_odf12_streams(&self, is_wholesome: bool) -> bool {
        look_unexpected(&self.root, "", is_wholesome)
    }
}

fn resolve_kind(root: &FolderNode, path: &str) -> Result<Option<ResolvedKind>, StreamAsFolder> {
    if path == "/" {
        return Ok(Some(ResolvedKind::Folder));
    }
    if path.is_empty() {
        return Ok(None);
    }
    let folder_path = path.ends_with('/');
    let stream_name = path.rsplit('/').next().filter(|s| !s.is_empty());
    let mut node = root;
    let mut rest = path;
    loop {
        if rest.is_empty() {
            return Ok(Some(ResolvedKind::Folder));
        }
        match rest.find('/') {
            None => {
                return match node.children.get(rest) {
                    Some(TreeNode::Folder(_)) => Ok(Some(ResolvedKind::Folder)),
                    Some(TreeNode::Stream { .. }) => {
                        if folder_path {
                            Err(StreamAsFolder)
                        } else {
                            Ok(Some(ResolvedKind::Stream))
                        }
                    }
                    None => Ok(None),
                };
            }
            Some(0) => {
                // `nIndex == nOldIndex` → LO breaks; the row applies to the
                // folder reached. A stream path looks up the name after the
                // final `/` there (`a//content.xml` → `a/content.xml`).
                if folder_path {
                    return Ok(Some(ResolvedKind::Folder));
                }
                return match stream_name.and_then(|n| node.children.get(n)) {
                    Some(TreeNode::Stream { .. }) => Ok(Some(ResolvedKind::Stream)),
                    Some(TreeNode::Folder(_)) => Ok(Some(ResolvedKind::Folder)),
                    None => Ok(None),
                };
            }
            Some(i) => {
                let part = &rest[..i];
                match node.children.get(part) {
                    Some(TreeNode::Folder(f)) => {
                        node = f;
                        rest = &rest[i + 1..];
                    }
                    Some(TreeNode::Stream { .. }) => return Err(StreamAsFolder),
                    None => return Ok(None),
                }
            }
        }
    }
}

fn folder_mut<'a>(root: &'a mut FolderNode, path: &str) -> Option<&'a mut FolderNode> {
    if path == "/" || path.is_empty() {
        return Some(root);
    }
    let mut node = root;
    let mut rest = path;
    loop {
        if rest.is_empty() {
            return Some(node);
        }
        match rest.find('/') {
            None => {
                return match node.children.get_mut(rest) {
                    Some(TreeNode::Folder(f)) => Some(f),
                    _ => None,
                };
            }
            Some(0) => return Some(node),
            Some(i) => {
                let part = &rest[..i];
                match node.children.get_mut(part) {
                    Some(TreeNode::Folder(f)) => {
                        node = f;
                        rest = &rest[i + 1..];
                    }
                    _ => return None,
                }
            }
        }
    }
}

fn stream_mut<'a>(
    root: &'a mut FolderNode,
    path: &str,
) -> Option<(&'a mut bool, &'a mut Option<String>)> {
    if path.is_empty() || path == "/" {
        return None;
    }
    let stream_name = path.rsplit('/').next().filter(|s| !s.is_empty())?;
    let mut node = root;
    let mut rest = path;
    loop {
        match rest.find('/') {
            None => {
                return match node.children.get_mut(rest) {
                    Some(TreeNode::Stream {
                        from_manifest,
                        media_type,
                    }) => Some((from_manifest, media_type)),
                    _ => None,
                };
            }
            Some(0) => {
                return match node.children.get_mut(stream_name) {
                    Some(TreeNode::Stream {
                        from_manifest,
                        media_type,
                    }) => Some((from_manifest, media_type)),
                    _ => None,
                };
            }
            Some(i) => {
                let part = &rest[..i];
                match node.children.get_mut(part) {
                    Some(TreeNode::Folder(f)) => {
                        node = f;
                        rest = &rest[i + 1..];
                    }
                    _ => return None,
                }
            }
        }
    }
}

fn look_unexpected(folder: &FolderNode, path: &str, is_wholesome: bool) -> bool {
    for (short, node) in &folder.children {
        match node {
            TreeNode::Folder(child) => {
                if path == "META-INF/" {
                    return true;
                }
                if is_wholesome && short != "META-INF" {
                    return true;
                }
                let own = format!("{path}{short}/");
                if look_unexpected(child, &own, is_wholesome) {
                    return true;
                }
            }
            TreeNode::Stream { from_manifest, .. } => {
                if path == "META-INF/" {
                    if short != "manifest.xml" && !short.contains("signatures") {
                        return true;
                    }
                } else if (is_wholesome && short != "mimetype" && short != "encrypted-package")
                    || (!*from_manifest && (!path.is_empty() || short != "mimetype"))
                {
                    return true;
                }
            }
        }
    }
    false
}

fn insert_path(root: &mut FolderNode, name: &str) -> Result<(), StreamAsFolder> {
    let is_dir = name.ends_with('/');
    let (folder_part, stream) = if is_dir {
        (name.trim_end_matches('/'), None)
    } else if let Some(i) = name.rfind('/') {
        (&name[..i], Some(&name[i + 1..]))
    } else {
        ("", Some(name))
    };

    let mut current = root;
    for part in folder_part.split('/') {
        if part.is_empty() {
            break;
        }
        let child = current
            .children
            .entry(part.to_string())
            .or_insert_with(|| TreeNode::Folder(FolderNode::default()));
        match child {
            TreeNode::Folder(folder) => current = folder,
            TreeNode::Stream { .. } => return Err(StreamAsFolder),
        }
    }
    if let Some(stream_name) = stream {
        if stream_name.is_empty() {
            return Ok(());
        }
        match current.children.get(stream_name) {
            Some(TreeNode::Folder(_)) => return Err(StreamAsFolder),
            Some(TreeNode::Stream { .. }) => {}
            None => {
                current.children.insert(
                    stream_name.to_string(),
                    TreeNode::Stream {
                        from_manifest: false,
                        media_type: None,
                    },
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_always_resolves() {
        let tree = FolderTree::from_zip_names(["content.xml"]).unwrap();
        assert_eq!(tree.resolve("/").unwrap(), Some(ResolvedKind::Folder));
    }

    #[test]
    fn implicit_folder_from_member_path() {
        let tree = FolderTree::from_zip_names(["Pictures/photo.png"]).unwrap();
        assert_eq!(
            tree.resolve("Pictures/").unwrap(),
            Some(ResolvedKind::Folder)
        );
        assert_eq!(
            tree.resolve("Pictures").unwrap(),
            Some(ResolvedKind::Folder)
        );
        assert_eq!(
            tree.resolve("Pictures/photo.png").unwrap(),
            Some(ResolvedKind::Stream)
        );
        assert_eq!(tree.resolve("Pictures/missing.png").unwrap(), None);
    }

    #[test]
    fn namelist_does_not_see_implicit_folder() {
        let names = ["Pictures/photo.png", "content.xml"];
        assert!(!names.iter().any(|n| *n == "Pictures/" || *n == "Pictures"));
        let tree = FolderTree::from_zip_names(names).unwrap();
        assert_eq!(
            tree.resolve("Pictures/").unwrap(),
            Some(ResolvedKind::Folder)
        );
    }

    #[test]
    fn root_encrypted_package_is_a_root_stream() {
        let tree = FolderTree::from_zip_names(["encrypted-package", "META-INF/manifest.xml"]).unwrap();
        assert!(tree.root_has_stream("encrypted-package"));
        assert!(tree.root_has_entry("encrypted-package"));
        assert!(!tree.root_has_stream("META-INF/manifest.xml"));
        assert_eq!(
            tree.resolve("META-INF/manifest.xml").unwrap(),
            Some(ResolvedKind::Stream)
        );
    }

    #[test]
    fn encrypted_package_folder_is_kind_agnostic() {
        let tree = FolderTree::from_zip_names(["encrypted-package/inner.bin"]).unwrap();
        assert!(tree.root_has_entry("encrypted-package"));
        assert!(!tree.root_has_stream("encrypted-package"));
    }

    #[test]
    fn empty_segment_inserts_stream_after_last_slash() {
        let tree = FolderTree::from_zip_names(["a//content.xml"]).unwrap();
        assert_eq!(
            tree.resolve("a/content.xml").unwrap(),
            Some(ResolvedKind::Stream)
        );
        assert_eq!(
            tree.resolve("a//content.xml").unwrap(),
            Some(ResolvedKind::Stream)
        );
    }

    #[test]
    fn leading_slash_folder_row_lands_on_root() {
        let mut tree = FolderTree::from_zip_names(["content.xml"]).unwrap();
        assert_eq!(
            tree.resolve("/Pictures/").unwrap(),
            Some(ResolvedKind::Folder)
        );
        tree.set_folder_meta(
            "/Pictures/",
            Some("application/vnd.oasis.opendocument.text".into()),
            Some("1.2".into()),
        );
        assert_eq!(
            tree.root_meta().media_type.as_deref(),
            Some("application/vnd.oasis.opendocument.text")
        );
        assert_eq!(tree.root_meta().version.as_deref(), Some("1.2"));
    }

    #[test]
    fn wholesome_allow_list_flags_extra_root_stream() {
        let mut tree = FolderTree::from_zip_names([
            "mimetype",
            "encrypted-package",
            "META-INF/manifest.xml",
            "extra.bin",
        ])
        .unwrap();
        tree.mark_from_manifest("encrypted-package", None);
        tree.mark_from_manifest("extra.bin", None);
        assert!(tree.has_unexpected_odf12_streams(true));
        assert!(!tree.has_unexpected_odf12_streams(false));
    }

    #[test]
    fn nested_mimetype_is_not_exempt() {
        let tree = FolderTree::from_zip_names(["foo/mimetype", "META-INF/manifest.xml"]).unwrap();
        assert!(tree.has_unexpected_odf12_streams(false));
    }

    #[test]
    fn stream_as_folder_is_rejected() {
        let err = FolderTree::from_zip_names(["content.xml", "content.xml/extra"]);
        assert!(err.is_err());
    }
}
