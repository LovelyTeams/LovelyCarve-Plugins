//! What the collectors find before it becomes a typed record: a record
//! type, a title, the identity value and the attributes read from the
//! evidence. `records` turns each one into the typed record it emits.

use lovelycarve_plugin::{Attributes, Value};

#[derive(Clone, Debug, PartialEq)]
pub struct Artifact {
    pub artifact_type: String,
    pub title: String,
    pub value: Option<Value>,
    pub attributes: Attributes,
}
