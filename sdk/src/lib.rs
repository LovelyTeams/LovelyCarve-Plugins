//! LovelyCarve plugin SDK.
//!
//! A LovelyCarve plugin is a native library (`.dll` / `.so` / `.dylib`) next
//! to its `plugin.toml`. It exports one C ABI entry point
//! ([`abi::ENTRY_SYMBOL`]); the same library runs either inside the
//! out-of-process loader `lc-plugin-host` (`isolation = "process"`, the
//! default) or directly in LovelyCarve (`isolation = "in_process"`). Calls
//! carry LPP v1 method names and MessagePack payloads, so the method set,
//! DTOs and limits of `docs/PLUGIN_PROTOCOL.md` apply unchanged.
//!
//! Implement [`FileSystemParser`], [`FileAnalyzer`] and/or
//! [`EvidenceAnalyzer`], register them on a [`Plugin`] and export it:
//!
//! ```ignore
//! fn plugin() -> lovelycarve_plugin::Plugin {
//!     lovelycarve_plugin::Plugin::new("org.example.demo", "Demo", "0.1.0")
//!         .file_analyzer(MyAnalyzer)
//! }
//!
//! lovelycarve_plugin::export_plugin!(plugin);
//! ```
//!
//! Plugin code runs on host worker threads and may block; all API calls are
//! synchronous. Instances must not rely on process-global state: the host
//! creates a fresh instance after every restart, possibly while an
//! abandoned one is still finishing.

pub mod abi;
mod error;
mod evidence;
mod file;
mod filesystem;
mod host;
#[cfg(feature = "loader")]
pub mod loader;
mod plugin;
mod results;
pub mod runtime;
mod source;
pub mod text;
pub mod value;
pub mod wire;

pub use error::{Error, Result};
pub use evidence::{Evidence, EvidenceAnalyzer, EvidenceNode, EvidenceRoot, EvidenceVolume};
pub use file::{File, FileAnalyzer, MaterializedFile};
pub use filesystem::{
    FileSystemParser, FsNode, FsStat, NodeKind, NodePage, Probe, Timestamps, Volume,
};
pub use host::{Context, LogLevel};
pub use plugin::Plugin;
pub use results::{
    AnalysisResult, Artifact, Attributes, Finding, ResultColumn, ResultNode, Severity,
    TimelineEvent,
};
pub use rmpv::Value;
pub use source::{Source, MAX_HOST_READ};
