//! Filesystem parsers: `fs.probe` / `fs.open` and the browsing calls of an
//! opened session.

use rmpv::Value;

use crate::{value, Error, Result, Source};

/// A parser for one filesystem family (`[[capabilities]] type =
/// "filesystem"`).
///
/// The host probes every Unknown partition with all filesystem plugins and
/// opens it with the most confident one. Implementations must be
/// thread-safe: calls for different sources can arrive concurrently.
pub trait FileSystemParser: Send + Sync {
    /// Filesystem name; must match a `filesystem` capability in plugin.toml.
    fn filesystem(&self) -> &str;

    /// Confidence (0.0 – 1.0) that `source` holds this filesystem. Probing
    /// should read only a few blocks.
    fn probe(&self, source: &Source) -> Result<Probe>;

    /// Opens `source` as a browsable session. `options` is the host's
    /// `fs.open` options map (currently empty).
    fn open(&self, source: Source, options: &Value) -> Result<Box<dyn Volume>>;
}

/// An opened filesystem session. Node ids are opaque strings chosen by the
/// plugin; the host never interprets them.
///
/// Calls can arrive concurrently from several host threads, so internal
/// state needs its own locking. The host bounds each call with a deadline
/// (15 s for `stat`, 60 s for listings, 120 s for reads).
pub trait Volume: Send + Sync {
    fn root_node(&self) -> &str;

    fn children(&self, node_id: &str) -> Result<Vec<FsNode>>;

    /// One page of `children`. The default pages over [`Volume::children`]
    /// with an offset cursor; large directories should override it.
    fn children_page(&self, node_id: &str, limit: usize, cursor: Option<&str>) -> Result<NodePage> {
        let mut items = self.children(node_id)?;
        let total = items.len();
        let start = match cursor {
            None => 0,
            Some(cursor) => cursor
                .parse::<usize>()
                .map_err(|_| Error::invalid_params("invalid children_page cursor"))?,
        }
        .min(total);
        let end = start.saturating_add(limit.max(1)).min(total);
        items.truncate(end);
        let items = items.split_off(start);
        Ok(NodePage {
            items,
            next_cursor: (end < total).then(|| end.to_string()),
            total: Some(total),
        })
    }

    fn stat(&self, node_id: &str) -> Result<FsStat>;

    /// Reads up to `length` bytes of a file node at `offset` (at most 4 MiB
    /// per call); returns fewer bytes at the end of the file.
    fn read(&self, node_id: &str, offset: u64, length: usize) -> Result<Vec<u8>>;

    /// Called when the host closes the session.
    fn close(&self) {}
}

#[derive(Clone, Debug, PartialEq)]
pub struct Probe {
    pub confidence: f64,
    pub label: Option<String>,
}

impl Probe {
    pub fn no_match() -> Self {
        Self {
            confidence: 0.0,
            label: None,
        }
    }

    pub fn matched(confidence: f64, label: Option<&str>) -> Self {
        Self {
            confidence,
            label: label.map(str::to_owned),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeKind {
    Dir,
    File,
    Symlink,
    Unallocated,
}

impl NodeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Dir => "dir",
            Self::File => "file",
            Self::Symlink => "symlink",
            Self::Unallocated => "unallocated",
        }
    }
}

/// RFC 3339 timestamps of a node; every field is optional.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Timestamps {
    pub modified: Option<String>,
    pub accessed: Option<String>,
    pub created: Option<String>,
    pub mft_changed: Option<String>,
    pub birth: Option<String>,
}

impl Timestamps {
    pub(crate) fn to_value(&self) -> Value {
        value::map([
            ("modified", value::optional_string(self.modified.as_deref())),
            ("accessed", value::optional_string(self.accessed.as_deref())),
            ("created", value::optional_string(self.created.as_deref())),
            (
                "mft_changed",
                value::optional_string(self.mft_changed.as_deref()),
            ),
            ("birth", value::optional_string(self.birth.as_deref())),
        ])
    }
}

/// A directory entry (`FsNode` of the filesystem methods).
#[derive(Clone, Debug, PartialEq)]
pub struct FsNode {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub kind: NodeKind,
    pub size: u64,
    pub deleted: bool,
    pub inode: Option<u64>,
    pub timestamps: Timestamps,
    pub link_target: Option<String>,
    /// Namespaced extension attributes (at most 64).
    pub attributes: Attributes,
}

impl FsNode {
    pub fn new(id: impl Into<String>, name: impl Into<String>, kind: NodeKind) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            parent_id: None,
            kind,
            size: 0,
            deleted: false,
            inode: None,
            timestamps: Timestamps::default(),
            link_target: None,
            attributes: Attributes::new(),
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        value::map([
            ("id", Value::from(self.id.as_str())),
            ("name", Value::from(self.name.as_str())),
            (
                "parent_id",
                value::optional_string(self.parent_id.as_deref()),
            ),
            ("kind", Value::from(self.kind.as_str())),
            ("size", Value::from(self.size)),
            ("deleted", Value::from(self.deleted)),
            ("inode", value::optional_u64(self.inode)),
            ("timestamps", self.timestamps.to_value()),
            (
                "link_target",
                value::optional_string(self.link_target.as_deref()),
            ),
            ("attributes", self.attributes.to_value()),
        ])
    }
}

/// File metadata (LPP v1 `FsStat`).
#[derive(Clone, Debug, PartialEq)]
pub struct FsStat {
    pub node_id: Option<String>,
    pub size: u64,
    pub inode: Option<u64>,
    pub mode: Option<u16>,
    pub mime: String,
    pub magic_hex: Option<String>,
    pub entropy: Option<f64>,
    pub attributes: Attributes,
}

impl FsStat {
    pub fn new(size: u64) -> Self {
        Self {
            node_id: None,
            size,
            inode: None,
            mode: None,
            mime: "application/octet-stream".to_owned(),
            magic_hex: None,
            entropy: None,
            attributes: Attributes::new(),
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        value::map([
            ("node_id", value::optional_string(self.node_id.as_deref())),
            ("size", Value::from(self.size)),
            ("inode", value::optional_u64(self.inode)),
            ("mode", self.mode.map(Value::from).unwrap_or(Value::Nil)),
            ("mime", Value::from(self.mime.as_str())),
            (
                "magic_hex",
                value::optional_string(self.magic_hex.as_deref()),
            ),
            (
                "entropy",
                self.entropy.map(Value::from).unwrap_or(Value::Nil),
            ),
            ("attributes", self.attributes.to_value()),
        ])
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodePage {
    pub items: Vec<FsNode>,
    /// Opaque cursor of the next page; `None` on the last page.
    pub next_cursor: Option<String>,
    pub total: Option<usize>,
}

impl NodePage {
    pub(crate) fn to_value(&self) -> Value {
        value::map([
            (
                "items",
                Value::Array(self.items.iter().map(FsNode::to_value).collect()),
            ),
            (
                "next_cursor",
                value::optional_string(self.next_cursor.as_deref()),
            ),
            (
                "total",
                value::optional_u64(self.total.map(|total| total as u64)),
            ),
        ])
    }
}

/// Ordered attribute map with dictionary semantics: inserting an existing
/// key replaces its value in place. Keys are namespaced (`vendorfs.flags`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Attributes {
    entries: Vec<(String, Value)>,
}

impl Attributes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) {
        let key = key.into();
        let value = value.into();
        match self
            .entries
            .iter_mut()
            .find(|(existing, _)| *existing == key)
        {
            Some(entry) => entry.1 = value,
            None => self.entries.push((key, value)),
        }
    }

    /// Inserts `Some` values and `nil` for `None`.
    pub fn insert_optional(&mut self, key: impl Into<String>, value: Option<impl Into<Value>>) {
        self.insert(key, value.map(Into::into).unwrap_or(Value::Nil));
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find_map(|(existing, value)| (existing == key).then_some(value))
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Inserts every entry of `other`, replacing existing keys.
    pub fn update(&mut self, other: &Attributes) {
        for (key, value) in &other.entries {
            self.insert(key.clone(), value.clone());
        }
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&str, &Value) -> bool) {
        self.entries.retain(|(key, value)| keep(key, value));
    }

    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let index = self
            .entries
            .iter()
            .position(|(existing, _)| existing == key)?;
        Some(self.entries.remove(index).1)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries
            .iter()
            .map(|(key, value)| (key.as_str(), value))
    }

    pub fn to_value(&self) -> Value {
        Value::Map(
            self.entries
                .iter()
                .map(|(key, value)| (Value::from(key.as_str()), value.clone()))
                .collect(),
        )
    }
}

impl<K: Into<String>, V: Into<Value>> FromIterator<(K, V)> for Attributes {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(entries: I) -> Self {
        let mut attributes = Self::new();
        for (key, value) in entries {
            attributes.insert(key, value);
        }
        attributes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ListVolume(usize);

    impl Volume for ListVolume {
        fn root_node(&self) -> &str {
            "root"
        }

        fn children(&self, _node_id: &str) -> Result<Vec<FsNode>> {
            Ok((0..self.0)
                .map(|index| FsNode::new(format!("n{index}"), format!("{index}"), NodeKind::File))
                .collect())
        }

        fn stat(&self, _node_id: &str) -> Result<FsStat> {
            Ok(FsStat::new(0))
        }

        fn read(&self, _node_id: &str, _offset: u64, _length: usize) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn default_children_page_walks_an_offset_cursor() {
        let volume = ListVolume(5);
        let first = volume.children_page("root", 2, None).expect("first page");
        assert_eq!(first.items.len(), 2);
        assert_eq!(first.next_cursor.as_deref(), Some("2"));
        let last = volume
            .children_page("root", 2, Some("4"))
            .expect("last page");
        assert_eq!(
            last.items
                .iter()
                .map(|node| node.id.as_str())
                .collect::<Vec<_>>(),
            vec!["n4"]
        );
        assert_eq!(last.next_cursor, None);
        assert_eq!(last.total, Some(5));
    }
}
