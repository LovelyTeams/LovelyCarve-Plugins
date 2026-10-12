//! Bounded reads of complete evidence files for the Linux analyzer.

use lovelycarve_plugin::{Error, EvidenceVolume, Result};

/// Missing paths and non-files have no content; oversized and short reads fail.
pub fn read(volume: &EvidenceVolume, path: &str, cap: u64) -> Result<Option<Vec<u8>>> {
    let Some(node) = volume.stat(path)? else {
        return Ok(None);
    };
    if !node.is_file() {
        return Ok(None);
    }
    if node.size > cap {
        return Err(Error::new(
            "RESOURCE_LIMIT",
            format!("{path} 超过读取上限 {cap} 字节"),
        ));
    }
    let bytes = volume.read(path, 0, Some(node.size))?;
    if bytes.len() as u64 != node.size {
        return Err(Error::new("SHORT_READ", format!("{path} 读取不完整")));
    }
    Ok(Some(bytes))
}

pub fn text(volume: &EvidenceVolume, path: &str, cap: u64) -> Result<Option<String>> {
    Ok(read(volume, path, cap)?.map(|bytes| lovelycarve_plugin::text::decode_lossy(&bytes)))
}
