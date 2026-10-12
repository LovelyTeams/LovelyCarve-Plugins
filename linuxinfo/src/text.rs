//! Text and value helpers with the semantics of the reference Python
//! implementation (`str.strip`, `str.split`, truthiness).

use chrono::{DateTime, Datelike, Utc};
use lovelycarve_plugin::{Attributes, Value};

/// Python `str.isspace()`: Unicode whitespace plus the `\x1c`–`\x1f`
/// separators.
pub fn is_space(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

/// Python `str.strip()`.
pub fn strip(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// Python `str.lstrip()`.
pub fn lstrip(text: &str) -> &str {
    text.trim_start_matches(is_space)
}

/// Python `str.split()` (runs of whitespace, no empty fields).
pub fn split_whitespace(text: &str) -> Vec<&str> {
    text.split(is_space)
        .filter(|part| !part.is_empty())
        .collect()
}

/// Python `str.split(None, max_splits)`: at most `max_splits` splits; the
/// last field keeps its inner and trailing whitespace.
pub fn split_whitespace_max(text: &str, max_splits: usize) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut rest = lstrip(text);
    while !rest.is_empty() {
        if fields.len() == max_splits {
            fields.push(rest);
            break;
        }
        match rest.find(is_space) {
            Some(end) => {
                fields.push(&rest[..end]);
                rest = lstrip(&rest[end..]);
            }
            None => {
                fields.push(rest);
                break;
            }
        }
    }
    fields
}

/// Python `str.isdigit()` for ASCII digits.
pub fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// Python `str.isupper()`.
pub fn is_upper(text: &str) -> bool {
    let mut cased = false;
    for character in text.chars() {
        if character.is_lowercase() {
            return false;
        }
        if character.is_uppercase() {
            cased = true;
        }
    }
    cased
}

/// Python `a or b` for optional strings.
pub fn or_else<'a>(first: Option<&'a str>, second: Option<&'a str>) -> Option<&'a str> {
    match first {
        Some(text) if !text.is_empty() => Some(text),
        _ => second,
    }
}

/// Strips whitespace, then one pair of matching surrounding quotes.
pub fn strip_quotes(value: &str) -> &str {
    let value = strip(value);
    let mut characters = value.chars();
    match (characters.next(), characters.next_back()) {
        (Some(first), Some(last)) if first == last && (first == '"' || first == '\'') => {
            &value[1..value.len() - 1]
        }
        _ => value,
    }
}

/// Collapses whitespace runs to single spaces and truncates to `cap`
/// characters with an ellipsis; `None` when nothing is left.
pub fn clean_text(value: &str, cap: usize) -> Option<String> {
    let cleaned = split_whitespace(value).join(" ");
    if cleaned.is_empty() {
        return None;
    }
    if cleaned.chars().count() > cap {
        let mut truncated: String = cleaned.chars().take(cap.saturating_sub(1)).collect();
        truncated.push('…');
        return Some(truncated);
    }
    Some(cleaned)
}

pub fn clean_optional(value: Option<&str>, cap: usize) -> Option<String> {
    value.and_then(|value| clean_text(value, cap))
}

/// RFC 3339 UTC time of a positive Unix timestamp within years 1–9999.
pub fn rfc3339(epoch_seconds: i64) -> Option<String> {
    if epoch_seconds <= 0 {
        return None;
    }
    let moment = DateTime::<Utc>::from_timestamp(epoch_seconds, 0)?;
    (moment.year() <= 9999).then(|| moment.to_rfc3339())
}

/// Dotted IPv4 netmask of a prefix length; `0.0.0.0` outside 0–32.
pub fn cidr_to_mask(prefix: &str) -> String {
    let bits = match prefix.parse::<u32>() {
        Ok(prefix) if prefix <= 32 => (0xFFFF_FFFF_u64 << (32 - prefix)) & 0xFFFF_FFFF,
        _ => 0,
    };
    [24, 16, 8, 0]
        .iter()
        .map(|shift| ((bits >> shift) & 0xFF).to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Python truthiness of a result value.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Nil => false,
        Value::Boolean(flag) => *flag,
        Value::Integer(number) => number.as_i64() != Some(0),
        Value::F32(number) => *number != 0.0,
        Value::F64(number) => *number != 0.0,
        Value::String(text) => !text.as_bytes().is_empty(),
        Value::Binary(bytes) => !bytes.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Map(entries) => !entries.is_empty(),
        Value::Ext(..) => true,
    }
}

/// Drops falsy attributes (`{k: v for k, v in … if v}`).
pub fn retain_truthy(attributes: &mut Attributes) {
    attributes.retain(|_, value| truthy(value));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_string_semantics() {
        assert_eq!(strip_quotes("  'Wired 1' "), "Wired 1");
        assert_eq!(strip_quotes("\"a'"), "\"a'");
        assert_eq!(clean_text(" a \t b\n", 200).as_deref(), Some("a b"));
        assert_eq!(clean_text("abcdef", 4).as_deref(), Some("abc…"));
        assert_eq!(clean_text(" \n ", 4), None);
        assert_eq!(
            split_whitespace_max("17 *\t* * *\troot cd / && run-parts", 6),
            vec!["17", "*", "*", "*", "*", "root", "cd / && run-parts"]
        );
        assert_eq!(split_whitespace_max("a b", 6), vec!["a", "b"]);
        assert!(is_upper("SHELL") && is_upper("_X1") && !is_upper("Path") && !is_upper("12"));
    }

    #[test]
    fn timestamps_and_masks() {
        assert_eq!(
            rfc3339(1_700_000_000).as_deref(),
            Some("2023-11-14T22:13:20+00:00")
        );
        assert_eq!(rfc3339(0), None);
        assert_eq!(rfc3339(i64::MAX / 2), None);
        assert_eq!(cidr_to_mask("24"), "255.255.255.0");
        assert_eq!(cidr_to_mask("0"), "0.0.0.0");
        assert_eq!(cidr_to_mask("33"), "0.0.0.0");
    }
}
