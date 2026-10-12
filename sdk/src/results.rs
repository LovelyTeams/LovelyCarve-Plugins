//! Structured analysis results (`analyzer.analyze` / `analyzer.analyze_evidence`
//! replies). The host validates them against the LPP v1 limits: namespaced
//! lowercase types and attribute keys, RFC 3339 timeline timestamps, at most
//! 10,000 items and 64 result nodes.

use rmpv::Value;

use crate::value;

/// Ordered attribute map with dictionary semantics: inserting an existing
/// key replaces its value in place. Keys are namespaced (`linux.user`).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Attributes {
    entries: Vec<(String, Value)>,
}

impl Attributes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) {
        let key = key.into();
        let value = value.into();
        match self
            .entries
            .iter_mut()
            .find(|(existing, _)| *existing == key)
        {
            Some(entry) => entry.1 = value,
            None => self.entries.push((key, value)),
        }
    }

    /// Inserts `Some` strings and `nil` for `None`.
    pub fn insert_optional(&mut self, key: impl Into<String>, value: Option<impl Into<Value>>) {
        self.insert(key, value.map(Into::into).unwrap_or(Value::Nil));
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find_map(|(existing, value)| (existing == key).then_some(value))
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries
            .iter()
            .map(|(key, value)| (key.as_str(), value))
    }

    pub fn retain(&mut self, mut keep: impl FnMut(&str, &Value) -> bool) {
        self.entries.retain(|(key, value)| keep(key, value));
    }

    /// Inserts every entry of `other`, replacing existing keys.
    pub fn update(&mut self, other: &Attributes) {
        for (key, value) in &other.entries {
            self.insert(key.clone(), value.clone());
        }
    }

    pub fn to_value(&self) -> Value {
        Value::Map(
            self.entries
                .iter()
                .map(|(key, value)| (Value::from(key.as_str()), value.clone()))
                .collect(),
        )
    }
}

impl<K: Into<String>, V: Into<Value>> FromIterator<(K, V)> for Attributes {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(entries: I) -> Self {
        let mut attributes = Self::new();
        for (key, value) in entries {
            attributes.insert(key, value);
        }
        attributes
    }
}

/// One result-tree data item and its record-table columns.
#[derive(Clone, Debug, PartialEq)]
pub struct ResultNode {
    pub node_type: String,
    pub name: String,
    pub columns: Vec<ResultColumn>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResultColumn {
    /// Attribute key shown in the column.
    pub key: String,
    pub label: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Artifact {
    pub artifact_type: String,
    pub title: String,
    pub value: Option<Value>,
    pub attributes: Attributes,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TimelineEvent {
    /// RFC 3339 timestamp.
    pub timestamp: String,
    pub event_type: String,
    pub description: String,
    pub attributes: Attributes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub attributes: Attributes,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct AnalysisResult {
    pub summary: Option<String>,
    pub nodes: Vec<ResultNode>,
    pub artifacts: Vec<Artifact>,
    pub timeline: Vec<TimelineEvent>,
    pub findings: Vec<Finding>,
}

impl AnalysisResult {
    pub fn to_value(&self) -> Value {
        value::map([
            ("summary", value::optional_string(self.summary.as_deref())),
            (
                "nodes",
                Value::Array(self.nodes.iter().map(ResultNode::to_value).collect()),
            ),
            (
                "artifacts",
                Value::Array(self.artifacts.iter().map(Artifact::to_value).collect()),
            ),
            (
                "timeline",
                Value::Array(self.timeline.iter().map(TimelineEvent::to_value).collect()),
            ),
            (
                "findings",
                Value::Array(self.findings.iter().map(Finding::to_value).collect()),
            ),
        ])
    }
}

impl ResultNode {
    fn to_value(&self) -> Value {
        value::map([
            ("type", Value::from(self.node_type.as_str())),
            ("name", Value::from(self.name.as_str())),
            (
                "columns",
                Value::Array(
                    self.columns
                        .iter()
                        .map(|column| {
                            value::map([
                                ("key", Value::from(column.key.as_str())),
                                ("label", Value::from(column.label.as_str())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

impl Artifact {
    fn to_value(&self) -> Value {
        value::map([
            ("type", Value::from(self.artifact_type.as_str())),
            ("title", Value::from(self.title.as_str())),
            ("value", self.value.clone().unwrap_or(Value::Nil)),
            ("attributes", self.attributes.to_value()),
        ])
    }
}

impl TimelineEvent {
    fn to_value(&self) -> Value {
        value::map([
            ("timestamp", Value::from(self.timestamp.as_str())),
            ("type", Value::from(self.event_type.as_str())),
            ("description", Value::from(self.description.as_str())),
            ("attributes", self.attributes.to_value()),
        ])
    }
}

impl Finding {
    fn to_value(&self) -> Value {
        value::map([
            ("severity", Value::from(self.severity.as_str())),
            ("title", Value::from(self.title.as_str())),
            ("description", Value::from(self.description.as_str())),
            ("attributes", self.attributes.to_value()),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_keep_insertion_order_and_replace_in_place() {
        let mut attributes = Attributes::new();
        attributes.insert("linux.a", "1");
        attributes.insert("linux.b", 2_u64);
        attributes.insert("linux.a", "3");
        attributes.insert_optional("linux.c", None::<&str>);
        assert_eq!(
            attributes.iter().collect::<Vec<_>>(),
            vec![
                ("linux.a", &Value::from("3")),
                ("linux.b", &Value::from(2_u64)),
                ("linux.c", &Value::Nil),
            ]
        );
    }
}
