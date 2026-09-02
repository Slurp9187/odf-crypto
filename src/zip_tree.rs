//! Folder tree matching `ZipPackage::getZipFileContents` / `hasByHierarchicalName`.
//!
//! Path existence is not `zip.namelist().contains(path)`. Implicit folders are
//! synthesized from member paths, and `"/"` always resolves.
//!
//! `recent` is LO's `m_aRecent`: a mutable pointer cache keyed on everything
//! before the last `/`. Insert seeds the containing folder (correct). A folder
//! miss on the walk stores `pPrevious` (one level too shallow).

use std::collections::{BTreeMap, HashMap};

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

/// One `hasByHierarchicalName` / `getByHierarchicalName` result.
///
/// `tree_path` is the node actually returned (`pCurrent` for a folder, the
/// resolved stream for a stream) — not the cache key and not the bag path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Resolved {
    pub kind: ResolvedKind,
    pub tree_path: String,
}

#[derive(Debug, Clone)]
pub(crate) struct FolderTree {
    root: FolderNode,
    /// `m_aRecent`: folder path from root (`[]` = root, `getName` `""`).
    /// Insert seeds the containing folder. Folder miss/walk stores `pPrevious`.
    recent: HashMap<String, Vec<String>>,
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
        let mut recent = HashMap::new();
        for name in names {
            let name = name.as_ref();
            insert_path(&mut root, name)?;
            // `getZipFileContents` (`ZipPackage.cxx` 641–680): on cache miss
            // the walk starts at root, then `m_aRecent[sDirName] = pCurrent`.
            if let Some(i) = name.rfind('/') {
                let s_dir_name = &name[..i];
                if !s_dir_name.is_empty() && !recent.contains_key(s_dir_name) {
                    recent.insert(s_dir_name.to_string(), walk_containing_folder(name));
                }
            }
        }
        Ok(Self { root, recent })
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

    #[cfg(test)]
    pub(crate) fn folder_meta(&self, tree_path: &str) -> Option<&FolderMeta> {
        folder_at(&self.root, tree_path).map(|f| &f.meta)
    }

    /// `hasByHierarchicalName` cache + walk, returning `getByHierarchicalName`'s
    /// node. `"/"` is unconditionally true. Empty path is not found.
    ///
    /// A leading empty segment (`/Pictures/`) stops the walk on the node
    /// reached so far — the root. Stream-as-folder is `Err`.
    pub(crate) fn resolve(&mut self, path: &str) -> Result<Option<Resolved>, StreamAsFolder> {
        if path == "/" {
            return Ok(Some(Resolved {
                kind: ResolvedKind::Folder,
                tree_path: "/".into(),
            }));
        }
        if path.is_empty() {
            return Ok(None);
        }

        let n_stream_index = path.rfind('/');
        let b_folder = n_stream_index == Some(path.len() - 1);

        if let Some(n_stream_index) = n_stream_index {
            let s_dir_name = &path[..n_stream_index];
            if let Some(cached) = self.recent.get(s_dir_name).cloned() {
                if b_folder {
                    // `lastIndexOf('/', nStreamIndex)` searches length
                    // `nStreamIndex`, so the trailing slash is excluded.
                    let n_dir_index = path[..n_stream_index].rfind('/');
                    let s_temp = match n_dir_index {
                        None => &path[..n_stream_index],
                        Some(d) => &path[d + 1..n_stream_index],
                    };
                    if s_temp == get_name(&cached) {
                        return Ok(Some(Resolved {
                            kind: ResolvedKind::Folder,
                            tree_path: folder_tree_path(&cached),
                        }));
                    }
                    self.recent.remove(s_dir_name);
                } else {
                    let s_temp = &path[n_stream_index + 1..];
                    if let Some(kind) = child_kind(&self.root, &cached, s_temp) {
                        return Ok(Some(Resolved {
                            kind,
                            tree_path: match kind {
                                ResolvedKind::Stream => stream_tree_path(&cached, s_temp),
                                ResolvedKind::Folder => {
                                    let mut parts = cached;
                                    parts.push(s_temp.to_string());
                                    folder_tree_path(&parts)
                                }
                            },
                        }));
                    }
                    self.recent.remove(s_dir_name);
                }
            }
        } else {
            return Ok(match self.root.children.get(path) {
                Some(TreeNode::Folder(_)) => Some(Resolved {
                    kind: ResolvedKind::Folder,
                    tree_path: folder_tree_path(&[path.to_string()]),
                }),
                Some(TreeNode::Stream { .. }) => Some(Resolved {
                    kind: ResolvedKind::Stream,
                    tree_path: path.to_string(),
                }),
                None => None,
            });
        }

        self.walk_resolve(path, b_folder, n_stream_index)
    }

    fn walk_resolve(
        &mut self,
        path: &str,
        b_folder: bool,
        n_stream_index: Option<usize>,
    ) -> Result<Option<Resolved>, StreamAsFolder> {
        let mut current: Vec<String> = Vec::new();
        let mut previous: Option<Vec<String>> = None;
        let mut n_old = 0;
        loop {
            let rest = &path[n_old..];
            match rest.find('/') {
                None => break,
                Some(0) => break,
                Some(i) => {
                    let s_temp = &rest[..i];
                    match child_kind(&self.root, &current, s_temp) {
                        Some(ResolvedKind::Folder) => {
                            previous = Some(current.clone());
                            current.push(s_temp.to_string());
                            n_old += i + 1;
                        }
                        Some(ResolvedKind::Stream) => return Err(StreamAsFolder),
                        None => return Ok(None),
                    }
                }
            }
        }

        if b_folder {
            // Folder miss: cache `pPrevious` — one level too shallow, which is
            // the A10 poison (`ZipPackage.cxx` 1079 / 996). Still return
            // `pCurrent`, so folder meta lands on the walked folder.
            //
            // `previous` is None only when the walk broke on a leading empty
            // segment (`/foo/`). LO stores a null `pPrevious` there, and a later
            // stream row on the same key dereferences it
            // (`hasByHierarchicalName` has no null guard where
            // `getByHierarchicalName` does). We decline to model a null deref:
            // storing nothing leaves the next lookup to the walk, which finds
            // nothing — the same answer LO would give if it survived the read.
            if let Some(n_stream_index) = n_stream_index {
                if let Some(prev) = previous {
                    self.recent.insert(path[..n_stream_index].to_string(), prev);
                }
            }
            return Ok(Some(Resolved {
                kind: ResolvedKind::Folder,
                tree_path: folder_tree_path(&current),
            }));
        }

        let s_temp = &path[n_old..];
        match child_kind(&self.root, &current, s_temp) {
            Some(kind) => {
                if let Some(n_stream_index) = n_stream_index {
                    self.recent
                        .insert(path[..n_stream_index].to_string(), current.clone());
                }
                let tree_path = match kind {
                    ResolvedKind::Stream => stream_tree_path(&current, s_temp),
                    ResolvedKind::Folder => {
                        let mut parts = current;
                        parts.push(s_temp.to_string());
                        folder_tree_path(&parts)
                    }
                };
                Ok(Some(Resolved { kind, tree_path }))
            }
            None => Ok(None),
        }
    }

    /// Apply folder meta at a **resolved** tree path. Does not touch `recent`.
    pub(crate) fn set_folder_meta(
        &mut self,
        tree_path: &str,
        media_type: Option<String>,
        version: Option<String>,
    ) {
        if let Some(node) = folder_at_mut(&mut self.root, tree_path) {
            node.meta.media_type = media_type;
            node.meta.version = version;
        }
    }

    /// Mark a stream at a **resolved** tree path. Does not touch `recent`.
    pub(crate) fn mark_from_manifest(&mut self, tree_path: &str, media_type: Option<String>) {
        if let Some(stream) = stream_at_mut(&mut self.root, tree_path) {
            *stream.0 = true;
            *stream.1 = media_type;
        }
    }

    /// `LookForUnexpectedODF12Streams`. `is_wholesome` is the bare zip check.
    pub(crate) fn has_unexpected_odf12_streams(&self, is_wholesome: bool) -> bool {
        look_unexpected(&self.root, "", is_wholesome)
    }
}

/// `getName()`: last component, or `""` for the root.
fn get_name(folder: &[String]) -> &str {
    folder.last().map(String::as_str).unwrap_or("")
}

fn folder_tree_path(parts: &[String]) -> String {
    if parts.is_empty() {
        "/".into()
    } else {
        format!("{}/", parts.join("/"))
    }
}

fn stream_tree_path(folder: &[String], name: &str) -> String {
    if folder.is_empty() {
        name.to_string()
    } else {
        format!("{}/{}", folder.join("/"), name)
    }
}

/// Folder reached by `getZipFileContents`' walk (`ZipPackage.cxx` 654–678).
fn walk_containing_folder(name: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut n_old = 0;
    while let Some(rel) = name[n_old..].find('/') {
        if rel == 0 {
            break;
        }
        parts.push(name[n_old..n_old + rel].to_string());
        n_old += rel + 1;
    }
    parts
}

fn node_at<'a>(root: &'a FolderNode, parts: &[String]) -> Option<&'a FolderNode> {
    let mut node = root;
    for part in parts {
        match node.children.get(part) {
            Some(TreeNode::Folder(f)) => node = f,
            _ => return None,
        }
    }
    Some(node)
}

fn child_kind(root: &FolderNode, folder: &[String], name: &str) -> Option<ResolvedKind> {
    let node = node_at(root, folder)?;
    match node.children.get(name) {
        Some(TreeNode::Folder(_)) => Some(ResolvedKind::Folder),
        Some(TreeNode::Stream { .. }) => Some(ResolvedKind::Stream),
        None => None,
    }
}

#[cfg(test)]
fn folder_at<'a>(root: &'a FolderNode, tree_path: &str) -> Option<&'a FolderNode> {
    if tree_path == "/" || tree_path.is_empty() {
        return Some(root);
    }
    let mut node = root;
    for part in tree_path.split('/') {
        if part.is_empty() {
            continue;
        }
        match node.children.get(part) {
            Some(TreeNode::Folder(f)) => node = f,
            _ => return None,
        }
    }
    Some(node)
}

fn folder_at_mut<'a>(root: &'a mut FolderNode, tree_path: &str) -> Option<&'a mut FolderNode> {
    if tree_path == "/" || tree_path.is_empty() {
        return Some(root);
    }
    let mut node = root;
    for part in tree_path.split('/') {
        if part.is_empty() {
            continue;
        }
        match node.children.get_mut(part) {
            Some(TreeNode::Folder(f)) => node = f,
            _ => return None,
        }
    }
    Some(node)
}

fn stream_at_mut<'a>(
    root: &'a mut FolderNode,
    tree_path: &str,
) -> Option<(&'a mut bool, &'a mut Option<String>)> {
    if tree_path.is_empty() || tree_path == "/" {
        return None;
    }
    let mut parts: Vec<&str> = tree_path.split('/').filter(|s| !s.is_empty()).collect();
    let name = parts.pop()?;
    let mut node = root;
    for part in parts {
        match node.children.get_mut(part) {
            Some(TreeNode::Folder(f)) => node = f,
            _ => return None,
        }
    }
    match node.children.get_mut(name) {
        Some(TreeNode::Stream {
            from_manifest,
            media_type,
        }) => Some((from_manifest, media_type)),
        _ => None,
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

    fn kind_of(tree: &mut FolderTree, path: &str) -> Option<ResolvedKind> {
        tree.resolve(path).unwrap().map(|r| r.kind)
    }

    #[test]
    fn slash_always_resolves() {
        let mut tree = FolderTree::from_zip_names(["content.xml"]).unwrap();
        assert_eq!(kind_of(&mut tree, "/"), Some(ResolvedKind::Folder));
    }

    #[test]
    fn implicit_folder_from_member_path() {
        let mut tree = FolderTree::from_zip_names(["Pictures/photo.png"]).unwrap();
        assert_eq!(kind_of(&mut tree, "Pictures/"), Some(ResolvedKind::Folder));
        assert_eq!(kind_of(&mut tree, "Pictures"), Some(ResolvedKind::Folder));
        assert_eq!(
            kind_of(&mut tree, "Pictures/photo.png"),
            Some(ResolvedKind::Stream)
        );
        assert_eq!(kind_of(&mut tree, "Pictures/missing.png"), None);
    }

    #[test]
    fn namelist_does_not_see_implicit_folder() {
        let names = ["Pictures/photo.png", "content.xml"];
        assert!(!names.iter().any(|n| *n == "Pictures/" || *n == "Pictures"));
        let mut tree = FolderTree::from_zip_names(names).unwrap();
        assert_eq!(kind_of(&mut tree, "Pictures/"), Some(ResolvedKind::Folder));
    }

    #[test]
    fn root_encrypted_package_is_a_root_stream() {
        let mut tree =
            FolderTree::from_zip_names(["encrypted-package", "META-INF/manifest.xml"]).unwrap();
        assert!(tree.root_has_stream("encrypted-package"));
        assert!(tree.root_has_entry("encrypted-package"));
        assert!(!tree.root_has_stream("META-INF/manifest.xml"));
        assert_eq!(
            kind_of(&mut tree, "META-INF/manifest.xml"),
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
        let mut tree = FolderTree::from_zip_names(["a//content.xml"]).unwrap();
        assert_eq!(
            kind_of(&mut tree, "a/content.xml"),
            Some(ResolvedKind::Stream)
        );
        assert_eq!(
            kind_of(&mut tree, "a//content.xml"),
            Some(ResolvedKind::Stream)
        );
    }

    #[test]
    fn leading_slash_folder_row_lands_on_root() {
        let mut tree = FolderTree::from_zip_names(["content.xml"]).unwrap();
        let resolved = tree.resolve("/Pictures/").unwrap().unwrap();
        assert_eq!(resolved.kind, ResolvedKind::Folder);
        assert_eq!(resolved.tree_path, "/");
        tree.set_folder_meta(
            &resolved.tree_path,
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

    #[test]
    fn leading_slash_stream_row_does_not_resolve() {
        // LO's walk breaks at the empty first segment and then looks up
        // "/content.xml" as one child name, which never matches; the dirname is
        // empty so `m_aRecent` has no key for it either. Not found.
        let mut tree =
            FolderTree::from_zip_names(["content.xml", "META-INF/manifest.xml"]).unwrap();
        assert_eq!(kind_of(&mut tree, "/content.xml"), None);
        // The folder form still lands on the root (`getByHierarchicalName`
        // returns `pCurrent` after the break).
        let folder = tree.resolve("/Pictures/").unwrap().unwrap();
        assert_eq!(folder.kind, ResolvedKind::Folder);
        assert_eq!(folder.tree_path, "/");
    }

    #[test]
    fn double_slash_stream_needs_the_member_dirname_key() {
        // `a//content.xml` resolves only because `getZipFileContents` wrote
        // `m_aRecent["a/"]` for that member spelling.
        let mut with_member = FolderTree::from_zip_names(["a//content.xml"]).unwrap();
        assert_eq!(
            kind_of(&mut with_member, "a//content.xml"),
            Some(ResolvedKind::Stream)
        );
        // Same tree shape, but the member was spelled `a/content.xml`, so the
        // key is "a" and the doubled-slash row finds no cache entry.
        let mut single = FolderTree::from_zip_names(["a/content.xml"]).unwrap();
        assert_eq!(kind_of(&mut single, "a//content.xml"), None);
        assert_eq!(
            kind_of(&mut single, "a/content.xml"),
            Some(ResolvedKind::Stream)
        );
    }

    #[test]
    fn folder_row_poisons_recent_one_level_too_shallow() {
        // Nested member seeds `"Pictures/album"`, not `"Pictures"`. A later
        // `Pictures/` miss caches `pPrevious` (root). `Pictures/content.xml`
        // then hits that entry and resolves as root `content.xml`.
        let mut tree =
            FolderTree::from_zip_names(["content.xml", "Pictures/album/photo.png"]).unwrap();
        let folder = tree.resolve("Pictures/").unwrap().unwrap();
        assert_eq!(folder.kind, ResolvedKind::Folder);
        assert_eq!(folder.tree_path, "Pictures/");
        tree.set_folder_meta(&folder.tree_path, Some("image/".into()), Some("1.2".into()));
        assert!(tree.root_meta().media_type.is_none());
        assert!(tree.root_meta().version.is_none());
        let pictures = tree.folder_meta("Pictures/").expect("Pictures folder");
        assert_eq!(pictures.media_type.as_deref(), Some("image/"));
        assert_eq!(pictures.version.as_deref(), Some("1.2"));

        let stream = tree.resolve("Pictures/content.xml").unwrap().unwrap();
        assert_eq!(stream.kind, ResolvedKind::Stream);
        assert_eq!(stream.tree_path, "content.xml");
    }

    #[test]
    fn pictures_photo_insert_does_not_poison_folder_lookup() {
        // `Pictures/photo.png` seeds `["Pictures"]` correctly. `Pictures/` is a
        // cache hit (`getName() == "Pictures"`) and must not overwrite.
        let mut tree = FolderTree::from_zip_names(["content.xml", "Pictures/photo.png"]).unwrap();
        let folder = tree.resolve("Pictures/").unwrap().unwrap();
        assert_eq!(folder.kind, ResolvedKind::Folder);
        assert_eq!(folder.tree_path, "Pictures/");
        assert_eq!(kind_of(&mut tree, "Pictures/content.xml"), None);
        assert_eq!(
            kind_of(&mut tree, "Pictures/photo.png"),
            Some(ResolvedKind::Stream)
        );
        let photo = tree.resolve("Pictures/photo.png").unwrap().unwrap();
        assert_eq!(photo.tree_path, "Pictures/photo.png");
    }

    #[test]
    fn nested_member_alone_does_not_poison() {
        // The control for `folder_row_poisons_recent_one_level_too_shallow`:
        // seeding `"Pictures/album"` is not itself enough. Without the
        // `Pictures/` folder row there is no entry under `"Pictures"`, so the
        // walk runs and finds no `content.xml` inside the Pictures folder.
        let mut tree =
            FolderTree::from_zip_names(["content.xml", "Pictures/album/photo.png"]).unwrap();
        assert_eq!(kind_of(&mut tree, "Pictures/content.xml"), None);
    }

    #[test]
    fn leading_slash_folder_row_does_not_cache_a_null_parent() {
        // The walk breaks before descending, so LO caches a null `pPrevious`.
        // We store nothing rather than model the deref that follows; either way
        // the row itself still lands on the root, and a later stream row on the
        // same key does not resolve.
        let mut tree = FolderTree::from_zip_names(["content.xml"]).unwrap();
        let folder = tree.resolve("/Pictures/").unwrap().unwrap();
        assert_eq!(folder.kind, ResolvedKind::Folder);
        assert_eq!(folder.tree_path, "/");
        assert_eq!(kind_of(&mut tree, "/Pictures/content.xml"), None);
    }
}
