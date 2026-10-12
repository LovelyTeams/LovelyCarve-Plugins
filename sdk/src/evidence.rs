//! Evidence analyzers: `analyzer.analyze_evidence` with path access to every
//! browsable volume of one evidence item.

use std::sync::{Mutex, PoisonError};

use rmpv::Value;

use crate::{
    filesystem::Timestamps, text, value, AnalysisResult, Context, Error, Result, MAX_HOST_READ,
};

/// An analyzer of a whole evidence item (`[[capabilities]] type =
/// "evidence_analyzer"`), such as the Linux base-information collector.
///
/// `analyze_evidence` runs on a host worker thread for up to thirty minutes.
/// Host reads through `evidence` fail with `CANCELLED` once the task is
/// cancelled; CPU-only loops should poll `evidence.context()`.
pub trait EvidenceAnalyzer: Send + Sync {
    /// Analyzer id; must match an `analyzer` capability in plugin.toml.
    fn analyzer(&self) -> &str;

    fn analyze_evidence(&self, evidence: &Evidence) -> Result<AnalysisResult>;
}

/// A browsable root (volume) of an evidence item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRoot {
    /// Volume key such as `part:0`, `lvm:1:0` or `root`.
    pub root_id: String,
    pub fs_prefix: String,
    pub kind: String,
    pub size: u64,
}

/// A path-resolved node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceNode {
    pub node_id: String,
    pub name: String,
    /// `file`, `dir`, `link` or `unallocated`.
    pub kind: String,
    pub size: u64,
    pub deleted: bool,
    pub link_target: Option<String>,
    pub timestamps: Timestamps,
}

impl EvidenceNode {
    pub fn is_file(&self) -> bool {
        self.kind == "file"
    }

    pub fn is_dir(&self) -> bool {
        self.kind == "dir"
    }

    fn from_value(node: &Value) -> Result<Self> {
        Ok(Self {
            node_id: value::optional_str(node, "node_id")
                .unwrap_or_default()
                .to_owned(),
            name: value::required_str(node, "name")?.to_owned(),
            kind: value::required_str(node, "kind")?.to_owned(),
            size: value::get(node, "size")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            deleted: value::get(node, "deleted")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            link_target: value::optional_str(node, "link_target").map(str::to_owned),
            timestamps: Timestamps::from_value(value::get(node, "timestamps")),
        })
    }
}

/// The whole-evidence read-only view issued for one analysis task.
pub struct Evidence {
    context: Context,
    evidence_id: String,
    image_id: String,
    params: Value,
    roots: Mutex<Option<Vec<EvidenceRoot>>>,
}

impl Evidence {
    pub(crate) fn from_params(context: Context, handle: &Value) -> Result<Self> {
        Ok(Self {
            evidence_id: value::required_str(handle, "evidence_id")?.to_owned(),
            image_id: value::optional_str(handle, "image_id")
                .unwrap_or_default()
                .to_owned(),
            params: value::get(handle, "params").cloned().unwrap_or(Value::Nil),
            roots: Mutex::new(None),
            context,
        })
    }

    pub fn id(&self) -> &str {
        &self.evidence_id
    }

    pub fn image_id(&self) -> &str {
        &self.image_id
    }

    /// The task parameters, forwarded verbatim (`platform`, `subItems`, …).
    pub fn params(&self) -> &Value {
        &self.params
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    /// Browsable roots in host order, fetched once per analysis.
    pub fn roots(&self) -> Result<Vec<EvidenceRoot>> {
        if let Some(roots) = self
            .roots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            return Ok(roots.clone());
        }
        let result = self.context.call_host(
            "evidence.roots",
            &value::map([("evidence_id", Value::from(self.evidence_id.as_str()))]),
        )?;
        let roots = match result {
            Value::Array(items) => items
                .iter()
                .map(|root| {
                    Ok(EvidenceRoot {
                        root_id: value::required_str(root, "root_id")?.to_owned(),
                        fs_prefix: value::optional_str(root, "fs_prefix")
                            .unwrap_or_default()
                            .to_owned(),
                        kind: value::optional_str(root, "kind")
                            .unwrap_or_default()
                            .to_owned(),
                        size: value::get(root, "size")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            _ => {
                return Err(Error::new(
                    "PROTOCOL_ERROR",
                    "evidence.roots result must be an array",
                ))
            }
        };
        *self.roots.lock().unwrap_or_else(PoisonError::into_inner) = Some(roots.clone());
        Ok(roots)
    }

    pub fn volume(&self, root_id: &str) -> EvidenceVolume {
        EvidenceVolume {
            context: self.context.clone(),
            evidence_id: self.evidence_id.clone(),
            root_id: root_id.to_owned(),
        }
    }

    /// The first root where every `required` path exists and, when
    /// `any_of` is not empty, at least one of `any_of` exists (the reference
    /// "@rootfs" search). Roots whose filesystem cannot be read are skipped.
    pub fn find_root(&self, required: &[&str], any_of: &[&str]) -> Result<Option<EvidenceVolume>> {
        for root in self.roots()? {
            let volume = self.volume(&root.root_id);
            let mut matches = true;
            for marker in required {
                if !volume.exists_or_unreadable(marker)? {
                    matches = false;
                    break;
                }
            }
            if !matches {
                continue;
            }
            if !any_of.is_empty() {
                let mut found = false;
                for marker in any_of {
                    if volume.exists_or_unreadable(marker)? {
                        found = true;
                        break;
                    }
                }
                if !found {
                    continue;
                }
            }
            return Ok(Some(volume));
        }
        Ok(None)
    }

    pub fn progress(&self, current: u64, total: Option<u64>, message: Option<&str>) -> Result<()> {
        self.context.progress(current, total, message)
    }

    /// Selected quick-analysis sub-items (`params.subItems`); empty means all.
    pub fn sub_items(&self) -> Vec<String> {
        match value::get(&self.params, "subItems") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| match item.as_str() {
                    Some(text) => text.to_owned(),
                    None => item.to_string(),
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    pub fn wants(&self, sub_item: &str) -> bool {
        let items = self.sub_items();
        items.is_empty() || items.iter().any(|item| item == sub_item)
    }
}

/// A path-scoped, read-only view of one browsable root. Paths are POSIX
/// style relative to the root (`etc/passwd`); symbolic links are followed by
/// `stat` and reads but not by `list`.
#[derive(Clone)]
pub struct EvidenceVolume {
    context: Context,
    evidence_id: String,
    root_id: String,
}

impl EvidenceVolume {
    pub fn root_id(&self) -> &str {
        &self.root_id
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    /// The node at `path`, or `None` when it does not exist.
    pub fn stat(&self, path: &str) -> Result<Option<EvidenceNode>> {
        match self
            .context
            .call_host("evidence.stat", &self.path_params(path))?
        {
            Value::Nil => Ok(None),
            node => EvidenceNode::from_value(&node).map(Some),
        }
    }

    pub fn exists(&self, path: &str) -> Result<bool> {
        Ok(self.stat(path)?.is_some())
    }

    pub fn is_dir(&self, path: &str) -> Result<bool> {
        Ok(self.stat(path)?.is_some_and(|node| node.is_dir()))
    }

    /// Children of the directory at `path` (empty = the root). Fails with
    /// `EVIDENCE_PATH_NOT_FOUND` when the directory does not exist.
    pub fn list(&self, path: &str) -> Result<Vec<EvidenceNode>> {
        let mut nodes = Vec::new();
        let mut expected_total = None;
        loop {
            let mut params = self.path_params(path);
            if let Value::Map(entries) = &mut params {
                entries.push(("skip".into(), (nodes.len() as u64).into()));
                entries.push(("limit".into(), 512_u64.into()));
            }
            let reply = match self.context.call_host("evidence.list_page", &params) {
                Ok(reply) => reply,
                Err(error) if nodes.is_empty() && error.code == "METHOD_NOT_FOUND" => {
                    return match self
                        .context
                        .call_host("evidence.list", &self.path_params(path))?
                    {
                        Value::Array(items) => items.iter().map(EvidenceNode::from_value).collect(),
                        _ => Err(Error::new(
                            "PROTOCOL_ERROR",
                            "evidence.list result must be an array",
                        )),
                    };
                }
                Err(error) => return Err(error),
            };
            let (page, total) = directory_page(&reply, nodes.len(), expected_total)?;
            expected_total = Some(total);
            nodes.extend(page);
            if nodes.len() == total {
                return Ok(nodes);
            }
        }
    }

    pub fn size(&self, path: &str) -> Result<Option<u64>> {
        Ok(self.stat(path)?.map(|node| node.size))
    }

    /// Complete, literal ASCII-case-insensitive name/prefix/suffix candidate scan.
    /// The host traverses regular directories in batches by native node ID, without
    /// following deleted entries or links. Errors/limits never return a partial list.
    /// Old hosts return METHOD_NOT_FOUND so callers can explicitly use a fallback.
    pub fn find_files_by_name(
        &self,
        names: &[&str],
        prefixes: &[&str],
        suffixes: &[&str],
    ) -> Result<Vec<String>> {
        let mut paths = Vec::new();
        let mut cursor: Option<String> = None;
        let mut previous = 0_u64;
        let mut seen = std::collections::BTreeSet::new();
        let mut bytes = 0;
        loop {
            self.context.check_cancelled()?;
            let params = value::map([
                ("evidence_id", Value::from(self.evidence_id.as_str())),
                ("root", Value::from(self.root_id.as_str())),
                (
                    "cursor",
                    cursor.as_deref().map(Value::from).unwrap_or(Value::Nil),
                ),
                (
                    "names",
                    Value::Array(names.iter().map(|name| Value::from(*name)).collect()),
                ),
                (
                    "prefixes",
                    Value::Array(prefixes.iter().map(|name| Value::from(*name)).collect()),
                ),
                (
                    "suffixes",
                    Value::Array(suffixes.iter().map(|name| Value::from(*name)).collect()),
                ),
            ]);
            let reply = self
                .context
                .call_host("evidence.find_names_page", &params)?;
            let invalid = || Error::new("PROTOCOL_ERROR", "invalid file-name scan reply");
            let visited = value::get(&reply, "visited")
                .and_then(Value::as_u64)
                .filter(|visited| *visited >= previous && *visited <= 4_000_000)
                .ok_or_else(invalid)?;
            previous = visited;
            let page = value::get(&reply, "paths")
                .and_then(Value::as_array)
                .ok_or_else(invalid)?;
            for path in page {
                let path = path
                    .as_str()
                    .filter(|path| !path.is_empty() && path.len() <= 4096)
                    .ok_or_else(invalid)?;
                bytes += path.len();
                paths.push(path.to_owned());
                if bytes > 2 * 1024 * 1024 || paths.len() > 4096 {
                    return Err(Error::new(
                        "RESOURCE_LIMIT",
                        "file-name scan exceeds 4096 matches / 2 MiB",
                    ));
                }
            }
            match value::get(&reply, "cursor") {
                Some(Value::Nil) => {
                    paths.sort();
                    return Ok(paths);
                }
                Some(Value::String(next)) => {
                    let next = next
                        .as_str()
                        .filter(|next| !next.is_empty() && next.len() <= 128)
                        .ok_or_else(invalid)?;
                    if !seen.insert(next.to_owned()) || seen.len() > 4097 {
                        return Err(invalid());
                    }
                    cursor = Some(next.to_owned());
                }
                _ => return Err(invalid()),
            }
        }
    }

    /// Reads `length` bytes (the rest of the file for `None`) at `offset`,
    /// clamped at the end of file. Fails with `EVIDENCE_PATH_NOT_FOUND` when
    /// `path` does not exist.
    pub fn read(&self, path: &str, offset: u64, length: Option<u64>) -> Result<Vec<u8>> {
        let Some(size) = self.size(path)? else {
            return Err(path_not_found(path));
        };
        self.read_sized(path, size, offset, length)
    }

    /// Reads several ranges of one file in one host call (at most 64
    /// ranges, 16 MiB).
    pub fn readv(&self, path: &str, ranges: &[(u64, usize)]) -> Result<Vec<Vec<u8>>> {
        let mut params = self.path_params(path);
        if let Value::Map(entries) = &mut params {
            entries.push((Value::from("ranges"), value::ranges(ranges)));
        }
        let result = self.context.call_host("evidence.readv", &params)?;
        value::into_byte_list(result, "evidence.readv")
    }

    /// The first `cap` bytes of `path` as lossy UTF-8, or `None` when the
    /// path does not exist.
    pub fn read_text(&self, path: &str, cap: u64) -> Result<Option<String>> {
        let Some(node) = self.stat(path)? else {
            return Ok(None);
        };
        let bytes = self.read_sized(path, node.size, 0, Some(cap))?;
        Ok(Some(text::decode_lossy(&bytes)))
    }

    /// [`EvidenceVolume::read_text`] split into lines.
    pub fn read_lines(&self, path: &str, cap: u64) -> Result<Option<Vec<String>>> {
        Ok(self.read_text(path, cap)?.map(|text| {
            text::split_lines(&text)
                .into_iter()
                .map(str::to_owned)
                .collect()
        }))
    }

    fn read_sized(
        &self,
        path: &str,
        size: u64,
        offset: u64,
        length: Option<u64>,
    ) -> Result<Vec<u8>> {
        let length = length.unwrap_or(size.saturating_sub(offset));
        if length == 0 || offset >= size {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(length).min(size);
        let mut output = Vec::with_capacity(usize::try_from(end - offset).unwrap_or(0));
        let mut position = offset;
        while position < end {
            let mut params = self.path_params(path);
            if let Value::Map(entries) = &mut params {
                entries.push((Value::from("offset"), Value::from(position)));
                entries.push((
                    Value::from("length"),
                    Value::from((end - position).min(MAX_HOST_READ as u64)),
                ));
            }
            let chunk = value::into_bytes(
                self.context.call_host("evidence.read", &params)?,
                "evidence.read",
            )?;
            if chunk.is_empty() {
                break;
            }
            position += chunk.len() as u64;
            output.extend_from_slice(&chunk);
        }
        Ok(output)
    }

    /// `exists`, treating a root whose filesystem cannot be read as not
    /// matching; cancellation still propagates.
    fn exists_or_unreadable(&self, path: &str) -> Result<bool> {
        match self.exists(path) {
            Ok(exists) => Ok(exists),
            Err(error) if error.is_cancelled() => Err(error),
            Err(_) => Ok(false),
        }
    }

    fn path_params(&self, path: &str) -> Value {
        value::map([
            ("evidence_id", Value::from(self.evidence_id.as_str())),
            ("root", Value::from(self.root_id.as_str())),
            ("path", Value::from(path)),
        ])
    }
}

fn path_not_found(path: &str) -> Error {
    Error::new("EVIDENCE_PATH_NOT_FOUND", format!("{path} does not exist"))
}

fn directory_page(
    reply: &Value,
    skip: usize,
    expected_total: Option<usize>,
) -> Result<(Vec<EvidenceNode>, usize)> {
    let invalid = || {
        Error::new(
            "PROTOCOL_ERROR",
            "invalid evidence.list_page reply or changing directory total",
        )
    };
    let total = value::get(reply, "total")
        .and_then(Value::as_u64)
        .and_then(|total| usize::try_from(total).ok())
        .ok_or_else(invalid)?;
    let Some(Value::Array(items)) = value::get(reply, "nodes") else {
        return Err(invalid());
    };
    if total > 1_000_000 {
        return Err(Error::new(
            "RESOURCE_LIMIT",
            "directory has more than 1000000 entries",
        ));
    }
    if expected_total.is_some_and(|expected| expected != total)
        || skip > total
        || items.len() != (total - skip).min(512)
    {
        return Err(invalid());
    }
    Ok((
        items
            .iter()
            .map(EvidenceNode::from_value)
            .collect::<Result<_>>()?,
        total,
    ))
}

#[cfg(test)]
mod page_tests {
    use super::*;
    #[test]
    fn changing_counts_empty_partial_pages_and_excessive_totals_fail() {
        let reply =
            |total: u64| value::map([("total", total.into()), ("nodes", Value::Array(Vec::new()))]);
        assert!(directory_page(&reply(1), 0, None).is_err());
        assert!(directory_page(&reply(0), 0, Some(1)).is_err());
        assert!(directory_page(&reply(0), 1, None).is_err());
        assert!(directory_page(&reply(1_000_001), 0, None).is_err());
        assert_eq!(directory_page(&reply(0), 0, None).unwrap(), (Vec::new(), 0));
    }
}
