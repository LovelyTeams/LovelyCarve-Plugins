//! LovelyCarve plugin SDK.
//!
//! A LovelyCarve plugin is a native library (`.dll` / `.so` / `.dylib`) in
//! a package next to its `plugin.toml`. It exports one C ABI entry point
//! ([`abi::ENTRY_SYMBOL`]) and runs inside the out-of-process loader
//! `lc-plugin-host`; calls carry LPP v2 method names and MessagePack
//! payloads ([`protocol`]).
//!
//! An analyzer emits typed records as it goes. Declare each record type
//! with `#[derive(Record)]`, register the types and analyzers on a
//! [`Plugin`] and export it:
//!
//! ```ignore
//! use lovelycarve_plugin::{Plugin, Record, Run, Result};
//!
//! #[derive(Record)]
//! #[record(id = "demo.user", label = "用户")]
//! struct User {
//!     #[field(label = "用户名", key)]
//!     name: String,
//! }
//!
//! fn users(run: &Run) -> Result<()> {
//!     let view = run.require_view()?;
//!     if let Some(passwd) = view.open("etc/passwd")? {
//!         for line in passwd.read_lines(1 << 20)? {
//!             let name = line.split(':').next().unwrap_or_default();
//!             run.emit_from(&passwd, &User { name: name.to_owned() })?;
//!         }
//!     }
//!     Ok(())
//! }
//!
//! fn plugin() -> Plugin {
//!     Plugin::new("org.example.demo").record::<User>().analyzer("users", users)
//! }
//!
//! lovelycarve_plugin::export_plugin!(plugin);
//! ```
//!
//! Plugin code runs on host worker threads and may block; all API calls are
//! synchronous. Instances must not rely on process-global state: the host
//! starts a fresh instance for every run.

// Lets `#[derive(Record)]` (which names `::lovelycarve_plugin`) work in
// this crate's own tests.
extern crate self as lovelycarve_plugin;

pub mod abi;
#[cfg(feature = "loader")]
pub mod bridge;
mod error;
mod file;
mod filesystem;
pub mod glob;
mod host;
#[cfg(feature = "loader")]
pub mod loader;
mod plugin;
pub mod protocol;
pub mod record;
mod run;
pub mod runtime;
pub mod schema;
mod source;
#[cfg(feature = "testing")]
pub mod testing;
pub mod text;
pub mod value;
mod view;
pub mod wire;

pub use error::{Error, Result};
pub use file::{FileReader, FileRef, MaterializedFile};
pub use filesystem::{
    Attributes, FileSystemParser, FsNode, FsStat, NodeKind as FsNodeKind, NodePage, Probe,
    Timestamps as FsTimestamps, Volume,
};
pub use host::{Context, LogLevel};
#[cfg(feature = "derive")]
pub use lovelycarve_plugin_derive::Record;
pub use plugin::{Plugin, SDK_VERSION};
pub use protocol::{MountInfo, SystemInfo, Timestamps};
pub use record::{DynamicRecord, FieldType, Json, Record, Severity, SourceRef, Timestamp};
pub use rmpv::Value;
pub use run::{Analyzer, Emit, Options, Profile, Run};
pub use schema::{FieldKind, FieldSchema, PropertyLayout, RecordSchema};
pub use source::{Source, MAX_HOST_READ};
pub use view::{Node, NodeKind, View};
