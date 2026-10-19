//! Path access to a system or evidence view.
//!
//! A system view is one detected operating system with its volumes mounted
//! in one tree (Linux mounts from `/etc/fstab`, Windows drive letters as
//! top-level `C:` directories). An evidence view shows every volume of the
//! evidence as a top-level directory named by its volume key (`part:1`).
//! Paths are `/`-separated and relative to the view (`etc/passwd`); `..`
//! is refused. `stat` and `open` follow symbolic links, `list` does not.

use std::sync::Arc;

use crate::{
    file::FileRef,
    protocol::{
        method, FileInfo, FindPage, MountInfo, NodeInfo, NodePage, SystemInfo, Timestamps,
        ViewFind, ViewInfo, ViewList, ViewPath, MAX_LIST_PAGE,
    },
    record::SourceRef,
    text, Context, Error, Result,
};

/// Most paths one `View::find` returns.
pub const MAX_FIND_RESULTS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeKind {
    File,
    Dir,
    Link,
    Other,
}

/// A directory entry or path lookup result.
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub name: String,
    pub kind: NodeKind,
    pub size: u64,
    pub deleted: bool,
    pub link_target: Option<String>,
    pub timestamps: Timestamps,
}

impl Node {
    fn from_info(info: NodeInfo) -> Self {
        Self {
            kind: match info.kind.as_str() {
                "file" => NodeKind::File,
                "dir" => NodeKind::Dir,
                "link" => NodeKind::Link,
                _ => NodeKind::Other,
            },
            name: info.name,
            size: info.size,
            deleted: info.deleted,
            link_target: info.link_target,
            timestamps: info.timestamps,
        }
    }

    pub fn is_file(&self) -> bool {
        self.kind == NodeKind::File
    }

    pub fn is_dir(&self) -> bool {
        self.kind == NodeKind::Dir
    }
}

/// A view issued for one run.
#[derive(Clone)]
pub struct View {
    context: Context,
    info: Arc<ViewInfo>,
}

impl View {
    pub(crate) fn new(context: Context, info: ViewInfo) -> Self {
        Self {
            context,
            info: Arc::new(info),
        }
    }

    pub fn id(&self) -> &str {
        &self.info.view_id
    }

    pub fn label(&self) -> &str {
        &self.info.label
    }

    /// The operating system of a system view.
    pub fn system(&self) -> Option<&SystemInfo> {
        self.info.system.as_ref()
    }

    pub fn mounts(&self) -> &[MountInfo] {
        &self.info.mounts
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    /// The evidence address of a view path: the volume its longest mount
    /// prefix shows and the path inside that volume. Use it as a record
    /// source when the record names a file the analyzer did not open.
    pub fn source(&self, path: &str) -> SourceRef {
        let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        let best = self
            .info
            .mounts
            .iter()
            .filter_map(|mount| {
                let prefix: Vec<&str> = mount
                    .path
                    .split('/')
                    .filter(|part| !part.is_empty())
                    .collect();
                (parts.len() >= prefix.len()
                    && prefix
                        .iter()
                        .zip(&parts)
                        .all(|(left, right)| left.eq_ignore_ascii_case(right)))
                .then_some((prefix.len(), mount))
            })
            .max_by_key(|(depth, _)| *depth);
        match best {
            Some((depth, mount)) => SourceRef::path(mount.root.clone(), parts[depth..].join("/")),
            None => SourceRef {
                path: Some(parts.join("/")),
                ..SourceRef::default()
            },
        }
    }

    /// The node at `path`, or `None` when it does not exist.
    pub fn stat(&self, path: &str) -> Result<Option<Node>> {
        let node: Option<NodeInfo> = self.context.call_typed(
            method::VIEW_STAT,
            &ViewPath {
                view_id: self.info.view_id.clone(),
                path: path.to_owned(),
            },
        )?;
        Ok(node.map(Node::from_info))
    }

    pub fn exists(&self, path: &str) -> Result<bool> {
        Ok(self.stat(path)?.is_some())
    }

    pub fn is_file(&self, path: &str) -> Result<bool> {
        Ok(self.stat(path)?.is_some_and(|node| node.is_file()))
    }

    pub fn is_dir(&self, path: &str) -> Result<bool> {
        Ok(self.stat(path)?.is_some_and(|node| node.is_dir()))
    }

    /// Entries of the directory at `path` (`""` = the view root). Fails
    /// with `VIEW_PATH_NOT_FOUND` when the directory does not exist.
    pub fn list(&self, path: &str) -> Result<Vec<Node>> {
        let mut nodes = Vec::new();
        let mut expected_total = None;
        loop {
            self.context.check_cancelled()?;
            let page: NodePage = self.context.call_typed(
                method::VIEW_LIST,
                &ViewList {
                    view_id: self.info.view_id.clone(),
                    path: path.to_owned(),
                    skip: nodes.len() as u64,
                    limit: MAX_LIST_PAGE,
                },
            )?;
            let consistent = expected_total.is_none_or(|total| total == page.total)
                && (page.nodes.len() as u64) <= MAX_LIST_PAGE
                && (nodes.len() + page.nodes.len()) as u64 <= page.total
                && (!page.nodes.is_empty() || nodes.len() as u64 == page.total);
            if !consistent {
                return Err(Error::new(
                    "PROTOCOL_ERROR",
                    "view.list returned an inconsistent page or a changing total",
                ));
            }
            expected_total = Some(page.total);
            nodes.extend(page.nodes.into_iter().map(Node::from_info));
            if nodes.len() as u64 == page.total {
                return Ok(nodes);
            }
        }
    }

    /// [`View::list`], with a missing directory listing as empty.
    pub fn list_or_empty(&self, path: &str) -> Result<Vec<Node>> {
        match self.list(path) {
            Ok(nodes) => Ok(nodes),
            Err(error) if error.code == "VIEW_PATH_NOT_FOUND" => Ok(Vec::new()),
            Err(error) => Err(error),
        }
    }

    /// A handle to the file at `path`, or `None` when it does not exist.
    /// Fails with `VIEW_NOT_A_FILE` for directories.
    pub fn open(&self, path: &str) -> Result<Option<FileRef>> {
        let info: Option<FileInfo> = self.context.call_typed(
            method::VIEW_OPEN,
            &ViewPath {
                view_id: self.info.view_id.clone(),
                path: path.to_owned(),
            },
        )?;
        Ok(info.map(|info| FileRef::new(self.context.clone(), info)))
    }

    /// The whole file at `path` (see [`FileRef::read_all`]), or `None`.
    pub fn read(&self, path: &str, cap: u64) -> Result<Option<Vec<u8>>> {
        self.open(path)?.map(|file| file.read_all(cap)).transpose()
    }

    /// The first `cap` bytes of `path` as text, or `None`.
    pub fn read_text(&self, path: &str, cap: u64) -> Result<Option<String>> {
        self.open(path)?.map(|file| file.read_text(cap)).transpose()
    }

    /// [`View::read_text`] split into lines.
    pub fn read_lines(&self, path: &str, cap: u64) -> Result<Option<Vec<String>>> {
        Ok(self.read_text(path, cap)?.map(|text| {
            text::split_lines(&text)
                .into_iter()
                .map(str::to_owned)
                .collect()
        }))
    }

    /// Every file path matching one of `patterns` (see [`crate::glob`]),
    /// sorted. The host walks the view in bounded batches; deleted entries
    /// and links are skipped, and more than [`MAX_FIND_RESULTS`] matches
    /// fail with `RESOURCE_LIMIT` rather than returning a partial list.
    pub fn find(&self, patterns: &[&str]) -> Result<Vec<String>> {
        for pattern in patterns {
            crate::glob::Glob::new(pattern).map_err(Error::invalid_params)?;
        }
        let mut paths = Vec::new();
        let mut cursor: Option<String> = None;
        let mut visited = 0;
        loop {
            self.context.check_cancelled()?;
            let page: FindPage = self.context.call_typed(
                method::VIEW_FIND,
                &ViewFind {
                    view_id: self.info.view_id.clone(),
                    patterns: patterns
                        .iter()
                        .map(|pattern| (*pattern).to_owned())
                        .collect(),
                    cursor: cursor.take(),
                },
            )?;
            if page.visited < visited {
                return Err(Error::new("PROTOCOL_ERROR", "view.find went backwards"));
            }
            visited = page.visited;
            paths.extend(page.paths);
            if paths.len() > MAX_FIND_RESULTS {
                return Err(Error::new(
                    "RESOURCE_LIMIT",
                    format!("more than {MAX_FIND_RESULTS} paths match"),
                ));
            }
            match page.cursor {
                Some(next) => cursor = Some(next),
                None => {
                    paths.sort();
                    paths.dedup();
                    return Ok(paths);
                }
            }
        }
    }
}

impl std::fmt::Debug for View {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("View")
            .field("view_id", &self.info.view_id)
            .field("label", &self.info.label)
            .finish()
    }
}
