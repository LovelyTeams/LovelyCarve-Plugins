//! Logical block sources handed to filesystem parsers.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, PoisonError},
};

use rmpv::Value;

use crate::{host::HostConnection, value, Error, Result};

/// Largest byte count the host returns for one `*.read` call.
pub const MAX_HOST_READ: usize = 4 * 1024 * 1024;
const BLOCK_SIZE: usize = 64 * 1024;
const CACHE_BLOCKS: usize = 64;

/// A read-only logical block device: a raw image, partition slice,
/// decrypted view or other host-managed source. Small reads go through a
/// 64-block LRU cache of 64 KiB blocks to save host round trips.
#[derive(Clone)]
pub struct Source {
    inner: Arc<SourceInner>,
}

struct SourceInner {
    host: HostConnection,
    source_id: String,
    size: u64,
    sector_size: u32,
    cache: Mutex<VecDeque<(u64, Arc<Vec<u8>>)>>,
}

impl Source {
    pub(crate) fn open(host: HostConnection, source_id: &str) -> Result<Self> {
        let info = host.call(
            "source.info",
            &value::map([("source_id", Value::from(source_id))]),
        )?;
        let sector_size = value::get(&info, "sector_size")
            .and_then(Value::as_u64)
            .and_then(|size| u32::try_from(size).ok())
            .unwrap_or(512);
        Ok(Self {
            inner: Arc::new(SourceInner {
                host,
                source_id: source_id.to_owned(),
                size: value::required_u64(&info, "size")?,
                sector_size,
                cache: Mutex::new(VecDeque::with_capacity(CACHE_BLOCKS)),
            }),
        })
    }

    pub fn id(&self) -> &str {
        &self.inner.source_id
    }

    pub fn size(&self) -> u64 {
        self.inner.size
    }

    pub fn sector_size(&self) -> u32 {
        self.inner.sector_size
    }

    /// Reads up to `length` bytes at `offset`, clamped at the end of the
    /// source.
    pub fn read(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
        if length == 0 || offset >= self.size() {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(length as u64).min(self.size());
        let mut output = Vec::with_capacity((end - offset) as usize);
        let mut position = offset;
        if end - offset > BLOCK_SIZE as u64 {
            while position < end {
                let chunk = self.read_host(position, (end - position).min(MAX_HOST_READ as u64))?;
                if chunk.is_empty() {
                    break;
                }
                position += chunk.len() as u64;
                output.extend_from_slice(&chunk);
            }
            return Ok(output);
        }
        while position < end {
            let block_offset = position - position % BLOCK_SIZE as u64;
            let block = self.cached_block(block_offset)?;
            let start = (position - block_offset) as usize;
            let take = ((end - position) as usize).min(block.len().saturating_sub(start));
            if take == 0 {
                break;
            }
            output.extend_from_slice(&block[start..start + take]);
            position += take as u64;
        }
        Ok(output)
    }

    /// Reads several ranges in one host call (at most 128 ranges, 8 MiB).
    pub fn readv(&self, ranges: &[(u64, usize)]) -> Result<Vec<Vec<u8>>> {
        let result = self.inner.host.call(
            "source.readv",
            &value::map([
                ("source_id", Value::from(self.id())),
                ("ranges", value::ranges(ranges)),
            ]),
        )?;
        value::into_byte_list(result, "source.readv")
    }

    fn read_host(&self, offset: u64, length: u64) -> Result<Vec<u8>> {
        let result = self.inner.host.call(
            "source.read",
            &value::map([
                ("source_id", Value::from(self.id())),
                ("offset", Value::from(offset)),
                ("length", Value::from(length)),
            ]),
        )?;
        let bytes = value::into_bytes(result, "source.read")?;
        if bytes.len() as u64 > length {
            return Err(Error::new(
                "PROTOCOL_ERROR",
                "source.read returned more bytes than requested",
            ));
        }
        Ok(bytes)
    }

    fn cached_block(&self, block_offset: u64) -> Result<Arc<Vec<u8>>> {
        {
            let mut cache = self
                .inner
                .cache
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(index) = cache.iter().position(|(offset, _)| *offset == block_offset) {
                if let Some(entry) = cache.remove(index) {
                    let block = Arc::clone(&entry.1);
                    cache.push_back(entry);
                    return Ok(block);
                }
            }
        }
        let length = (self.size() - block_offset).min(BLOCK_SIZE as u64);
        let block = Arc::new(self.read_host(block_offset, length)?);
        let mut cache = self
            .inner
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        cache.retain(|(offset, _)| *offset != block_offset);
        cache.push_back((block_offset, Arc::clone(&block)));
        while cache.len() > CACHE_BLOCKS {
            cache.pop_front();
        }
        Ok(block)
    }
}
