//! File analyzers: `analyzer.analyze` over one opaque logical file.

use std::path::{Path, PathBuf};

use rmpv::Value;

use crate::{host::LogLevel, value, AnalysisResult, Context, Result, MAX_HOST_READ};

/// An analyzer of single logical files (`[[capabilities]] type =
/// "file_analyzer"`), scheduled from the file list's「插件分析任务」.
///
/// `analyze` runs on a host worker thread and may block for up to ten
/// minutes. The file is only valid during the call.
pub trait FileAnalyzer: Send + Sync {
    /// Analyzer id; must match an `analyzer` capability in plugin.toml.
    fn analyzer(&self) -> &str;

    fn analyze(&self, file: &File) -> Result<AnalysisResult>;
}

/// An opaque, owner-scoped, read-only logical file. It never exposes the
/// evidence path.
pub struct File {
    context: Context,
    file_id: String,
    name: String,
    size: u64,
    mime: String,
}

impl File {
    pub(crate) fn from_params(context: Context, handle: &Value) -> Result<Self> {
        Ok(Self {
            file_id: value::required_str(handle, "file_id")?.to_owned(),
            name: value::optional_str(handle, "name")
                .unwrap_or_default()
                .to_owned(),
            size: value::required_u64(handle, "size")?,
            mime: value::optional_str(handle, "mime")
                .unwrap_or("application/octet-stream")
                .to_owned(),
            context,
        })
    }

    pub fn id(&self) -> &str {
        &self.file_id
    }

    /// Display name; not a host path.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn mime(&self) -> &str {
        &self.mime
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    /// Reads up to `length` bytes at `offset`, clamped at the end of file.
    pub fn read(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
        if length == 0 || offset >= self.size {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(length as u64).min(self.size);
        let mut output = Vec::with_capacity((end - offset) as usize);
        let mut position = offset;
        while position < end {
            let chunk = value::into_bytes(
                self.context.call_host(
                    "file.read",
                    &value::map([
                        ("file_id", Value::from(self.file_id.as_str())),
                        ("offset", Value::from(position)),
                        (
                            "length",
                            Value::from((end - position).min(MAX_HOST_READ as u64)),
                        ),
                    ]),
                )?,
                "file.read",
            )?;
            if chunk.is_empty() {
                break;
            }
            position += chunk.len() as u64;
            output.extend_from_slice(&chunk);
        }
        Ok(output)
    }

    /// Reads several ranges in one host call (at most 64 ranges, 16 MiB).
    pub fn readv(&self, ranges: &[(u64, usize)]) -> Result<Vec<Vec<u8>>> {
        let result = self.context.call_host(
            "file.readv",
            &value::map([
                ("file_id", Value::from(self.file_id.as_str())),
                ("ranges", value::ranges(ranges)),
            ]),
        )?;
        value::into_byte_list(result, "file.readv")
    }

    /// Copies the file into a host-owned temporary path for native
    /// libraries that need one. Requires the `file_materialize` permission;
    /// the lease is released when the returned value is dropped.
    pub fn materialize(&self) -> Result<MaterializedFile> {
        let lease = self.context.call_host(
            "file.materialize",
            &value::map([("file_id", Value::from(self.file_id.as_str()))]),
        )?;
        Ok(MaterializedFile {
            context: self.context.clone(),
            lease_id: value::required_str(&lease, "lease_id")?.to_owned(),
            path: PathBuf::from(value::required_str(&lease, "path")?),
            size: value::required_u64(&lease, "size")?,
            released: false,
        })
    }
}

/// A host-owned temporary copy of a logical file.
pub struct MaterializedFile {
    context: Context,
    lease_id: String,
    path: PathBuf,
    size: u64,
    released: bool,
}

impl MaterializedFile {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// Releases the lease now instead of on drop.
    pub fn release(mut self) -> Result<()> {
        self.release_lease()
    }

    fn release_lease(&mut self) -> Result<()> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        // Release even when the request was cancelled; the host also drops
        // every lease after the analysis ends.
        self.context
            .host()
            .call(
                "file.release",
                &value::map([("lease_id", Value::from(self.lease_id.as_str()))]),
            )
            .map(drop)
    }
}

impl Drop for MaterializedFile {
    fn drop(&mut self) {
        if let Err(error) = self.release_lease() {
            self.context.log(
                LogLevel::Debug,
                &format!("materialized file lease release failed: {error}"),
            );
        }
    }
}
