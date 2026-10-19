//! Bounded reads of complete evidence files for the Linux analyzer.

use lovelycarve_plugin::{Result, View};

/// Missing paths and non-files have no content; oversized and short reads
/// fail (`RESOURCE_LIMIT`, `SHORT_READ`).
pub fn read(view: &View, path: &str, cap: u64) -> Result<Option<Vec<u8>>> {
    match view.stat(path)? {
        Some(node) if node.is_file() => view.read(path, cap),
        Some(_) | None => Ok(None),
    }
}

pub fn text(view: &View, path: &str, cap: u64) -> Result<Option<String>> {
    Ok(read(view, path, cap)?.map(|bytes| lovelycarve_plugin::text::decode_lossy(&bytes)))
}
