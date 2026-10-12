//! GTK recent documents (XBEL). URIs and application commands remain inert.
use lovelycarve_plugin::{Artifact, Attributes, Error, EvidenceVolume, Result, Value};
use quick_xml::{
    events::{BytesStart, Event},
    Reader,
};
use std::collections::BTreeSet;

fn fields(element: &BytesStart<'_>) -> Result<Attributes> {
    element
        .attributes()
        .map(|attribute| {
            let attribute = attribute.map_err(|error| Error::plugin(error.to_string()))?;
            Ok((
                format!(
                    "recent.{}",
                    String::from_utf8_lossy(attribute.key.local_name().as_ref()).to_lowercase()
                ),
                Value::from(
                    attribute
                        .unescape_value()
                        .map_err(|error| Error::plugin(error.to_string()))?
                        .into_owned(),
                ),
            ))
        })
        .collect()
}

fn parse(bytes: &[u8], user: &str, source: &str) -> Result<Vec<Artifact>> {
    let mut reader = Reader::from_reader(bytes);
    let mut records = Vec::new();
    let mut bookmark: Option<Attributes> = None;
    let mut events = 0;
    let mut stack = Vec::new();
    let mut root_seen = false;
    loop {
        let event = reader
            .read_event()
            .map_err(|error| Error::plugin(format!("{source} XBEL: {error}")))?;
        let start = matches!(&event, Event::Start(_));
        match event {
            Event::Start(element) | Event::Empty(element) => {
                if start {
                    if stack.len() >= 64 {
                        return Err(Error::new("RESOURCE_LIMIT", "XBEL 嵌套超过 64 层"));
                    }
                    stack.push(element.name().as_ref().to_vec());
                }
                match element.local_name().as_ref() {
                    b"xbel" => root_seen = true,
                    b"bookmark" if root_seen => {
                        if bookmark.is_some() {
                            return Err(Error::plugin("XBEL bookmark 嵌套"));
                        }
                        bookmark = Some(fields(&element)?);
                    }
                    b"mime-type" => {
                        if let Some(attributes) = &mut bookmark {
                            if let Some(value) = fields(&element)?.get("recent.type") {
                                attributes.insert("recent.mime", value.clone());
                            }
                        }
                    }
                    b"application" => {
                        if let Some(attributes) = &bookmark {
                            let mut attributes = attributes.clone();
                            for (key, value) in fields(&element)?.iter() {
                                attributes.insert(
                                    format!(
                                        "recent.application_{}",
                                        key.trim_start_matches("recent.")
                                    ),
                                    value.clone(),
                                );
                            }
                            attributes.insert("linux.user", user);
                            attributes.insert("linux.source", source);
                            let title = attributes
                                .get("recent.application_name")
                                .and_then(Value::as_str)
                                .unwrap_or("最近访问")
                                .to_owned();
                            let value = attributes.get("recent.href").cloned();
                            records.push(Artifact {
                                artifact_type: "linux.recent".into(),
                                title,
                                value,
                                attributes,
                            });
                            if records.len() > 10_000 {
                                return Err(Error::new("RESOURCE_LIMIT", "XBEL 超过 10000 条"));
                            }
                        }
                    }
                    _ => {}
                }
            }
            Event::End(element) => {
                if stack.pop().as_deref() != Some(element.name().as_ref()) {
                    return Err(Error::plugin("XBEL 标签不匹配"));
                }
                if element.local_name().as_ref() == b"bookmark" {
                    bookmark = None;
                }
            }
            Event::DocType(_) => return Err(Error::plugin("XBEL 不接受 DTD")),
            Event::Eof => break,
            _ => {}
        }
        events += 1;
        if events > 100_000 {
            return Err(Error::new("RESOURCE_LIMIT", "XBEL 事件数量超限"));
        }
    }
    if !root_seen || bookmark.is_some() || !stack.is_empty() {
        return Err(Error::plugin("XBEL 根元素缺失或文件未结束"));
    }
    Ok(records)
}

pub fn collect(volume: &EvidenceVolume) -> Result<Vec<Artifact>> {
    let mut homes = BTreeSet::new();
    for user in crate::users::parse_passwd(
        crate::evidence::text(volume, "etc/passwd", 8 * 1024 * 1024)?.as_deref(),
    ) {
        if let (Some(name), Some(home)) = (
            user.get("linux.username").and_then(Value::as_str),
            user.get("linux.home").and_then(Value::as_str),
        ) {
            if home != "/" && home != "/nonexistent" {
                homes.insert((name.to_owned(), home.trim_start_matches('/').to_owned()));
            }
        }
    }
    let mut records = Vec::new();
    for (user, home) in homes {
        let source = format!("{home}/.local/share/recently-used.xbel");
        volume.context().check_cancelled()?;
        if let Some(bytes) = crate::evidence::read(volume, &source, 8 * 1024 * 1024)? {
            records.extend(parse(&bytes, &user, &source)?);
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn applications_entities_and_invalid_xml() {
        let records = parse(br#"<xbel xmlns:b="urn:bookmark"><bookmark href="file:///a%20b" modified="2022-05-25T15:30:06Z"><b:mime-type type="text/plain"/><b:application name="gedit" exec="&apos;gedit %u&apos;" count="3"/><b:application name="other" count="1"/></bookmark></xbel>"#, "alice", "a.xbel").unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].attributes.get("recent.application_exec"),
            Some(&"'gedit %u'".into())
        );
        assert_eq!(
            records[1].attributes.get("recent.mime"),
            Some(&"text/plain".into())
        );
        assert!(parse(b"<!DOCTYPE xbel><xbel/>", "a", "a").is_err());
        assert!(parse(b"<xbel><bookmark>", "a", "a").is_err());
    }
}
