//! Optional presentation roles, separate from field storage and identity.
use super::FieldSchema;
use serde::{Deserialize, Serialize};

/// A vertical property list. Each record contributes one named value;
/// optional secondary text (for example an original key) sits below its label.
/// Every visible field must have exactly one role so the view loses no data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PropertyLayout {
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary: Option<String>,
}

impl PropertyLayout {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            label: None,
            secondary: None,
        }
    }

    pub fn label(mut self, field: impl Into<String>) -> Self {
        self.label = Some(field.into());
        self
    }

    pub fn secondary(mut self, field: impl Into<String>) -> Self {
        self.secondary = Some(field.into());
        self
    }

    pub(super) fn validate(&self, fields: &[FieldSchema]) -> Result<(), String> {
        let mut roles = std::collections::HashSet::new();
        for id in std::iter::once(&self.value)
            .chain(self.label.iter())
            .chain(self.secondary.iter())
        {
            let field = fields
                .iter()
                .find(|field| &field.id == id)
                .ok_or_else(|| format!("property layout references unknown field {id}"))?;
            if field.hidden || !roles.insert(id.as_str()) {
                return Err(format!("property field {id} must be visible and used once"));
            }
        }
        if fields
            .iter()
            .any(|field| !field.hidden && !roles.contains(field.id.as_str()))
        {
            return Err("property layout must include every visible field".to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{FieldKind, RecordSchema};

    fn schema() -> RecordSchema {
        RecordSchema::new("test.property", "属性")
            .field(FieldSchema::new("name", "名称", FieldKind::Text))
            .field(FieldSchema::new("value", "值", FieldKind::Text))
            .field(FieldSchema::new("extra", "其他", FieldKind::Json).hidden())
    }

    #[test]
    fn presentation_roundtrips_and_tables_keep_their_original_serialization() {
        let original = schema();
        let encoded = rmp_serde::to_vec_named(&original).expect("serialize");
        assert!(!encoded
            .windows(b"properties".len())
            .any(|bytes| bytes == b"properties"));
        assert!(rmp_serde::from_slice::<RecordSchema>(&encoded)
            .expect("old schema")
            .properties
            .is_none());
        let properties = original.properties(PropertyLayout::new("value").label("name"));
        properties.validate().expect("valid layout");
        let encoded = rmp_serde::to_vec_named(&properties).expect("serialize");
        assert_eq!(
            rmp_serde::from_slice::<RecordSchema>(&encoded).expect("decode"),
            properties
        );
    }

    #[test]
    fn rejects_missing_hidden_duplicate_and_omitted_fields() {
        for layout in [
            PropertyLayout::new("missing").label("name"),
            PropertyLayout::new("extra").label("name"),
            PropertyLayout::new("value").label("value"),
            PropertyLayout::new("value"),
        ] {
            assert!(schema().properties(layout).validate().is_err());
        }
    }
}
