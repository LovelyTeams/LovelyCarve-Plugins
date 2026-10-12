use rmpv::Value;

use crate::{value, wire::PROTOCOL_VERSION, EvidenceAnalyzer, FileAnalyzer, FileSystemParser};

/// A plugin's identity and implementations. The constructor passed to
/// [`crate::export_plugin!`] builds one per instance; the identity must match
/// plugin.toml, and every capability declared there must be registered.
pub struct Plugin {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) parsers: Vec<Box<dyn FileSystemParser>>,
    pub(crate) file_analyzers: Vec<Box<dyn FileAnalyzer>>,
    pub(crate) evidence_analyzers: Vec<Box<dyn EvidenceAnalyzer>>,
}

impl Plugin {
    pub fn new(id: impl Into<String>, name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version: version.into(),
            parsers: Vec::new(),
            file_analyzers: Vec::new(),
            evidence_analyzers: Vec::new(),
        }
    }

    pub fn filesystem(mut self, parser: impl FileSystemParser + 'static) -> Self {
        self.parsers.push(Box::new(parser));
        self
    }

    pub fn file_analyzer(mut self, analyzer: impl FileAnalyzer + 'static) -> Self {
        self.file_analyzers.push(Box::new(analyzer));
        self
    }

    pub fn evidence_analyzer(mut self, analyzer: impl EvidenceAnalyzer + 'static) -> Self {
        self.evidence_analyzers.push(Box::new(analyzer));
        self
    }

    /// `plugin.hello` params: protocol range, identity and capabilities.
    pub(crate) fn describe(&self) -> Value {
        let mut capabilities = Vec::new();
        if !self.parsers.is_empty() {
            capabilities.push(Value::from("filesystem"));
        }
        if !self.file_analyzers.is_empty() {
            capabilities.push(Value::from("file_analyzer"));
        }
        if !self.evidence_analyzers.is_empty() {
            capabilities.push(Value::from("evidence_analyzer"));
        }
        value::map([
            ("protocol_min", Value::from(PROTOCOL_VERSION)),
            ("protocol_max", Value::from(PROTOCOL_VERSION)),
            (
                "plugin",
                value::map([
                    ("id", Value::from(self.id.as_str())),
                    ("name", Value::from(self.name.as_str())),
                    ("version", Value::from(self.version.as_str())),
                ]),
            ),
            ("capabilities", Value::Array(capabilities)),
        ])
    }
}
