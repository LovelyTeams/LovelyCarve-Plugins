//! Read-only file handles issued by the host for one run.

use std::{
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Arc,
};

use rmpv::Value;

use crate::{
    host::LogLevel,
    protocol::{self, method, FileHandleId, FileInfo, FileRead, FileReadv, Lease, LeaseId},
    record::SourceRef,
    text, value, Context, Error, Result,
};

/// Bytes the [`FileReader`] buffers per host read.
const READER_BUFFER: usize = 1024 * 1024;

/// An opaque, read-only logical file: an input of the run or a file opened
/// through its view. It never exposes the evidence path.
#[derive(Clone)]
pub struct FileRef {
    context: Context,
    info: Arc<FileInfo>,
}

impl FileRef {
    pub(crate) fn new(context: Context, info: FileInfo) -> Self {
        Self {
            context,
            info: Arc::new(info),
        }
    }

    pub fn id(&self) -> &str {
        &self.info.file_id
    }

    /// Display name; not a host path.
    pub fn name(&self) -> &str {
        &self.info.name
    }

    pub fn size(&self) -> u64 {
        self.info.size
    }

    pub fn mime(&self) -> Option<&str> {
        self.info.mime.as_deref()
    }

    /// Path inside the run's view.
    pub fn view_path(&self) -> Option<&str> {
        self.info.view_path.as_deref()
    }

    /// Volume key the file lives on (`part:1`).
    pub fn root(&self) -> Option<&str> {
        self.info.root.as_deref()
    }

    /// Path inside that volume.
    pub fn root_path(&self) -> Option<&str> {
        self.info.root_path.as_deref()
    }

    pub fn deleted(&self) -> bool {
        self.info.deleted
    }

    pub fn info(&self) -> &FileInfo {
        &self.info
    }

    pub fn context(&self) -> &Context {
        &self.context
    }

    /// Provenance of the whole file.
    pub fn source(&self) -> SourceRef {
        SourceRef {
            root: self.info.root.clone(),
            path: self
                .info
                .root_path
                .clone()
                .or_else(|| self.info.view_path.clone()),
            node_id: self.info.node_id.clone(),
            ..SourceRef::default()
        }
    }

    /// Provenance of `length` bytes at `offset`.
    pub fn source_at(&self, offset: u64, length: u64) -> SourceRef {
        self.source().at(offset, length)
    }

    /// Reads up to `length` bytes at `offset`, clamped at the end of file.
    pub fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
        if length == 0 || offset >= self.size() {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(length as u64).min(self.size());
        let mut output = Vec::with_capacity(usize::try_from(end - offset).unwrap_or(0));
        let mut position = offset;
        while position < end {
            let chunk = value::into_bytes(
                self.context.call_host(
                    method::FILE_READ,
                    &protocol::to_value(&FileRead {
                        file_id: self.info.file_id.clone(),
                        offset: position,
                        length: (end - position).min(protocol::MAX_READ),
                    })?,
                )?,
                method::FILE_READ,
            )?;
            if chunk.is_empty() {
                break;
            }
            position += chunk.len() as u64;
            output.extend_from_slice(&chunk);
        }
        Ok(output)
    }

    /// The whole file. Fails with `RESOURCE_LIMIT` when it is larger than
    /// `cap` and with `SHORT_READ` when the host returns fewer bytes than
    /// the file's size: a truncated read is never treated as complete.
    pub fn read_all(&self, cap: u64) -> Result<Vec<u8>> {
        if self.size() > cap {
            return Err(Error::new(
                "RESOURCE_LIMIT",
                format!(
                    "{} is {} bytes; the limit is {cap}",
                    self.name(),
                    self.size()
                ),
            ));
        }
        let bytes = self.read_at(0, usize::try_from(self.size()).unwrap_or(usize::MAX))?;
        if bytes.len() as u64 != self.size() {
            return Err(Error::new(
                "SHORT_READ",
                format!(
                    "{}: read {} of {} bytes",
                    self.name(),
                    bytes.len(),
                    self.size()
                ),
            ));
        }
        Ok(bytes)
    }

    /// The first `cap` bytes as text (UTF-8, invalid bytes replaced).
    pub fn read_text(&self, cap: u64) -> Result<String> {
        let length = self.size().min(cap);
        let bytes = self.read_at(0, usize::try_from(length).unwrap_or(usize::MAX))?;
        Ok(text::decode_lossy(&bytes))
    }

    /// [`FileRef::read_text`] split into lines.
    pub fn read_lines(&self, cap: u64) -> Result<Vec<String>> {
        Ok(text::split_lines(&self.read_text(cap)?)
            .into_iter()
            .map(str::to_owned)
            .collect())
    }

    /// Several ranges in one host call (at most 64 ranges, 8 MiB).
    pub fn readv(&self, ranges: &[(u64, usize)]) -> Result<Vec<Vec<u8>>> {
        let result = self.context.call_host(
            method::FILE_READV,
            &protocol::to_value(&FileReadv {
                file_id: self.info.file_id.clone(),
                ranges: ranges
                    .iter()
                    .map(|(offset, length)| (*offset, *length as u64))
                    .collect(),
            })?,
        )?;
        value::into_byte_list(result, method::FILE_READV)
    }

    /// A buffered `Read + Seek` view of the file.
    pub fn reader(&self) -> FileReader {
        FileReader {
            file: self.clone(),
            position: 0,
            buffer: Vec::new(),
            buffer_start: 0,
        }
    }

    /// Copies the file to a host-owned temporary path for native libraries
    /// that need one. Requires the `file_materialize` permission; the copy
    /// is removed when the returned value is dropped.
    pub fn materialize(&self) -> Result<MaterializedFile> {
        let lease: Lease = self.context.call_typed(
            method::FILE_MATERIALIZE,
            &FileHandleId {
                file_id: self.info.file_id.clone(),
            },
        )?;
        Ok(MaterializedFile {
            context: self.context.clone(),
            lease_id: lease.lease_id,
            path: PathBuf::from(lease.path),
            size: lease.size,
            released: false,
        })
    }
}

impl std::fmt::Debug for FileRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileRef")
            .field("file_id", &self.info.file_id)
            .field("name", &self.info.name)
            .field("size", &self.info.size)
            .finish()
    }
}

/// A buffered reader over a [`FileRef`].
pub struct FileReader {
    file: FileRef,
    position: u64,
    buffer: Vec<u8>,
    buffer_start: u64,
}

impl Read for FileReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position >= self.file.size() {
            return Ok(0);
        }
        let buffer_end = self.buffer_start + self.buffer.len() as u64;
        if self.position < self.buffer_start || self.position >= buffer_end {
            self.buffer = self
                .file
                .read_at(self.position, READER_BUFFER)
                .map_err(io::Error::other)?;
            self.buffer_start = self.position;
            if self.buffer.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("{}: the host returned no bytes", self.file.name()),
                ));
            }
        }
        let start = (self.position - self.buffer_start) as usize;
        let count = output.len().min(self.buffer.len() - start);
        output[..count].copy_from_slice(&self.buffer[start..start + count]);
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for FileReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let target = match position {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::End(delta) => self.file.size().checked_add_signed(delta),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
        };
        let target = target.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of the file",
            )
        })?;
        self.position = target;
        Ok(target)
    }
}

/// A host-owned temporary copy of a file.
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

    /// Releases the copy now instead of on drop.
    pub fn release(mut self) -> Result<()> {
        self.release_lease()
    }

    fn release_lease(&mut self) -> Result<()> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        // Release even when the run was cancelled; the host also drops every
        // lease when the run ends.
        self.context
            .host()
            .call_typed::<_, Value>(
                method::FILE_RELEASE,
                &LeaseId {
                    lease_id: self.lease_id.clone(),
                },
            )
            .map(drop)
    }
}

impl Drop for MaterializedFile {
    fn drop(&mut self) {
        if let Err(error) = self.release_lease() {
            self.context.log(
                LogLevel::Debug,
                &format!("materialized file release failed: {error}"),
            );
        }
    }
}
