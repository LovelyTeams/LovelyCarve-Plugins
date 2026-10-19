//! LPP v2 method names and payloads, shared by the SDK, `lc-plugin-host`
//! and LovelyCarve. Payloads are MessagePack maps with these field names
//! (`rmp_serde::to_vec_named`); unknown fields are ignored, so a later
//! minor revision can add optional fields without breaking either side.
//!
//! Host → plugin: `run.start`, `plugin.shutdown`, and the frozen `fs.*`
//! filesystem methods. Plugin → host: `run.*` (records, warnings,
//! progress), `file.*` (read-only file handles), `view.*` (path access to a
//! system or evidence view) and the frozen `source.*` methods.

use std::collections::BTreeMap;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::record::{Severity, SourceRef};
use crate::schema::RecordSchema;

pub use crate::wire::PROTOCOL_VERSION;

/// Method names.
pub mod method {
    pub const HELLO: &str = "plugin.hello";
    pub const SHUTDOWN: &str = "plugin.shutdown";
    pub const RUN_START: &str = "run.start";
    pub const RUN_EMIT: &str = "run.emit";
    pub const RUN_WARN: &str = "run.warn";
    pub const RUN_PROGRESS: &str = "run.progress";
    pub const FILE_READ: &str = "file.read";
    pub const FILE_READV: &str = "file.readv";
    pub const FILE_MATERIALIZE: &str = "file.materialize";
    pub const FILE_RELEASE: &str = "file.release";
    pub const VIEW_STAT: &str = "view.stat";
    pub const VIEW_LIST: &str = "view.list";
    pub const VIEW_OPEN: &str = "view.open";
    pub const VIEW_FIND: &str = "view.find";
}

/// Largest byte count one `file.read` returns.
pub const MAX_READ: u64 = 4 * 1024 * 1024;
/// Most ranges of one `file.readv`.
pub const MAX_READV_RANGES: usize = 64;
/// Most bytes of one `file.readv` (leaves room for framing in 8 MiB).
pub const MAX_READV_BYTES: u64 = 8 * 1024 * 1024 - 4096;
/// Most nodes of one `view.list` page.
pub const MAX_LIST_PAGE: u64 = 512;
/// Most records of one `run.emit` batch.
pub const MAX_BATCH_RECORDS: usize = 4096;

/// `plugin.hello`: what the library implements, from its own code.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Hello {
    pub protocol: u16,
    /// Plugin id; must equal the manifest's.
    pub plugin: String,
    /// SDK version the library was built with.
    pub sdk: String,
    #[serde(default)]
    pub analyzers: Vec<String>,
    #[serde(default)]
    pub filesystems: Vec<String>,
    #[serde(default)]
    pub records: Vec<RecordSchema>,
    /// [`crate::schema::schema_hash`] of `records`.
    pub schema_hash: String,
}

/// The host's answer to `plugin.hello`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct HostHello {
    pub protocol: u16,
    pub host: String,
    pub version: String,
}

/// `run.start`: run one analyzer to completion. The reply is [`RunFinish`].
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RunStart {
    pub run_id: String,
    pub analyzer: String,
    pub target: Target,
    /// Files the host resolved for the run: the selected file of a `file`
    /// run, or the matches of the analyzer's declared inputs.
    #[serde(default)]
    pub inputs: Vec<FileInfo>,
    #[serde(default)]
    pub options: BTreeMap<String, Value>,
    /// Evidence profile facts known before the run (`timezone`, …).
    #[serde(default)]
    pub profile: BTreeMap<String, Value>,
    /// UI locale (`zh-CN`, `en`) for text the analyzer writes itself.
    #[serde(default)]
    pub locale: String,
}

/// What a run looks at.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    /// The run's inputs are the files to analyze.
    Files,
    /// One detected operating system, its volumes mounted in one tree.
    System { view: ViewInfo },
    /// Every volume of the evidence, each a top-level directory named by
    /// its volume key.
    Evidence { view: ViewInfo },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ViewInfo {
    pub view_id: String,
    pub label: String,
    #[serde(default)]
    pub system: Option<SystemInfo>,
    /// How the view's top-level paths map to volumes.
    #[serde(default)]
    pub mounts: Vec<MountInfo>,
}

/// A detected operating-system installation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SystemInfo {
    /// Stable id inside the evidence (`linux@part:2`).
    pub id: String,
    /// `linux`, `windows`, `macos`, `esxi`, `mikrotik`, `openwrt`, `dingtalk`.
    pub family: String,
    pub product: String,
    #[serde(default)]
    pub version: Option<String>,
    /// Volume key of the root (system) volume.
    pub root: String,
}

/// One mount of a view: `path` (`""` for the root, `home`, `C:`) shows
/// volume `root`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MountInfo {
    pub path: String,
    pub root: String,
    /// Where the mapping came from: `root`, `fstab`, `drive_letter`, `volume`.
    pub source: String,
}

/// A read-only file handle issued for one run.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FileInfo {
    pub file_id: String,
    pub name: String,
    pub size: u64,
    #[serde(default)]
    pub mime: Option<String>,
    /// Path inside the run's view (for files opened through one).
    #[serde(default)]
    pub view_path: Option<String>,
    /// Volume key the file lives on.
    #[serde(default)]
    pub root: Option<String>,
    /// Path inside that volume.
    #[serde(default)]
    pub root_path: Option<String>,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub timestamps: Timestamps,
}

/// File system timestamps (RFC 3339) as the file system records them.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Timestamps {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birth: Option<String>,
}

/// The reply to `run.start`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct RunFinish {
    #[serde(default)]
    pub summary: Option<String>,
}

/// `run.emit`: one batch of records, answered with [`EmitAck`] once the
/// host stored it (the batch is the plugin's backpressure).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EmitBatch {
    pub run_id: String,
    pub records: Vec<WireRecord>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct WireRecord {
    #[serde(rename = "type")]
    pub record_type: String,
    /// Values in schema field order.
    pub values: Vec<Value>,
    /// Overrides the schema's title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<SourceRef>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EmitAck {
    pub accepted: u64,
}

/// `run.warn`: something the run could not do, kept with its results.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RunWarn {
    pub run_id: String,
    pub code: String,
    pub message: String,
    /// The input the warning is about.
    #[serde(default)]
    pub file_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RunProgress {
    pub run_id: String,
    pub current: u64,
    #[serde(default)]
    pub total: Option<u64>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FileRead {
    pub file_id: String,
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FileReadv {
    pub file_id: String,
    /// `[offset, length]` pairs.
    pub ranges: Vec<(u64, u64)>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FileHandleId {
    pub file_id: String,
}

/// A host-owned temporary copy of a file (`file.materialize`).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Lease {
    pub lease_id: String,
    pub path: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LeaseId {
    pub lease_id: String,
}

/// `view.stat` / `view.open`: a path inside a view.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ViewPath {
    pub view_id: String,
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ViewList {
    pub view_id: String,
    pub path: String,
    pub skip: u64,
    pub limit: u64,
}

/// A directory entry or path lookup result.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct NodeInfo {
    pub name: String,
    /// `file`, `dir`, `link` or `other`.
    pub kind: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub link_target: Option<String>,
    #[serde(default)]
    pub timestamps: Timestamps,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct NodePage {
    pub nodes: Vec<NodeInfo>,
    pub total: u64,
}

/// `view.find`: paths matching glob patterns (`**` crosses directories,
/// `*` and `?` stay inside one name; ASCII case-insensitive).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ViewFind {
    pub view_id: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FindPage {
    pub paths: Vec<String>,
    pub visited: u64,
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Encodes a payload as a named MessagePack map.
pub fn encode<T: Serialize>(payload: &T) -> crate::Result<Vec<u8>> {
    rmp_serde::to_vec_named(payload)
        .map_err(|error| crate::Error::plugin(format!("MessagePack encoding failed: {error}")))
}

/// Decodes a payload.
pub fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> crate::Result<T> {
    rmp_serde::from_slice(bytes)
        .map_err(|error| crate::Error::invalid_params(format!("invalid payload: {error}")))
}

/// Converts a payload to a MessagePack value (frames carry values). Goes
/// through the named encoding: `rmpv::ext::to_value` writes structs as
/// positional arrays, which skipped optional fields would shift.
pub fn to_value<T: Serialize>(payload: &T) -> crate::Result<Value> {
    let bytes = encode(payload)?;
    rmpv::decode::read_value(&mut bytes.as_slice())
        .map_err(|error| crate::Error::plugin(format!("MessagePack encoding failed: {error}")))
}

/// Reads a payload from a MessagePack value, through the same decoder as
/// [`decode`] (`rmpv::ext::from_value` does not accept unit enum variants
/// written as names).
pub fn from_value<T: for<'de> Deserialize<'de>>(value: Value) -> crate::Result<T> {
    decode(&crate::value::encode(&value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_round_trip_through_bytes_and_values() {
        let start = RunStart {
            run_id: "run-1".to_owned(),
            analyzer: "base".to_owned(),
            target: Target::System {
                view: ViewInfo {
                    view_id: "view-1".to_owned(),
                    label: "Kali".to_owned(),
                    system: Some(SystemInfo {
                        id: "linux@part:0".to_owned(),
                        family: "linux".to_owned(),
                        product: "Kali GNU/Linux".to_owned(),
                        version: Some("2024.1".to_owned()),
                        root: "part:0".to_owned(),
                    }),
                    mounts: vec![MountInfo {
                        path: String::new(),
                        root: "part:0".to_owned(),
                        source: "root".to_owned(),
                    }],
                },
            },
            inputs: Vec::new(),
            options: BTreeMap::from([(
                "items".to_owned(),
                Value::Array(vec![Value::from("users")]),
            )]),
            profile: BTreeMap::new(),
            locale: "zh-CN".to_owned(),
        };
        let bytes = encode(&start).expect("encode");
        assert_eq!(decode::<RunStart>(&bytes).expect("decode"), start);
        let value = to_value(&start).expect("value");
        assert_eq!(from_value::<RunStart>(value).expect("from value"), start);
        let files = encode(&Target::Files).expect("files");
        assert_eq!(decode::<Target>(&files).expect("files"), Target::Files);
    }

    #[test]
    fn missing_optional_fields_default() {
        let value = rmpv::Value::Map(vec![
            (Value::from("file_id"), Value::from("f1")),
            (Value::from("name"), Value::from("a.bin")),
            (Value::from("size"), Value::from(3_u64)),
            (Value::from("future_field"), Value::from(true)),
        ]);
        let info: FileInfo = from_value(value).expect("file info");
        assert_eq!(info.root, None);
        assert_eq!(info.timestamps, Timestamps::default());
    }
}
