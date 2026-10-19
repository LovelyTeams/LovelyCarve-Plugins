//! 系统信息: os-release → redhat-release → debian_version, plus hostname,
//! timezone, kernel and hosts.

use std::collections::HashMap;

use lovelycarve_plugin::{text::split_lines, Result, View};

use crate::{
    item::Artifact,
    list_or_empty,
    text::{lstrip, strip, strip_quotes},
};

pub fn parse_os_release(text: Option<&str>) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    for line in text.map(split_lines).unwrap_or_default() {
        if lstrip(line).starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            fields.insert(strip(key).to_owned(), strip_quotes(value).to_owned());
        }
    }
    fields
}

/// One record per source field, matching the report's name/key/value layout.
pub fn collect(volume: &View) -> Result<Vec<Artifact>> {
    let source = if volume.exists("etc/os-release")? {
        "etc/os-release"
    } else {
        "usr/lib/os-release"
    };
    let fields = parse_os_release(crate::evidence::text(volume, source, 1024 * 1024)?.as_deref());
    let mut records = Vec::new();
    if let Some(hostname) = crate::evidence::text(volume, "etc/hostname", 4096)? {
        records.push(field("主机名", "hostname", hostname.trim(), "etc/hostname"));
    }
    for (key, name) in [
        ("PRETTY_NAME", "系统"),
        ("NAME", "操作系统类型"),
        ("VERSION_ID", "系统版本号"),
        ("VERSION", "操作系统版本"),
        ("VERSION_CODENAME", "版本代码"),
        ("ID", "操作系统名称"),
        ("ID_LIKE", "父发行版本"),
        ("HOME_URL", "主页"),
        ("SUPPORT_URL", "支持 URL"),
        ("BUG_REPORT_URL", "Bug 反馈地址"),
    ] {
        if let Some(value) = fields.get(key) {
            records.push(field(name, key, value, source));
        }
    }
    if fields.is_empty() {
        for source in ["etc/redhat-release", "etc/debian_version", "etc/issue"] {
            if let Some(text) = crate::evidence::text(volume, source, 4096)? {
                records.push(field("系统", "release", text.trim(), source));
                break;
            }
        }
    }
    for base in ["usr/lib/modules", "lib/modules"] {
        let modules = list_or_empty(volume, base)?;
        if !modules.is_empty() {
            for module in modules
                .into_iter()
                .filter(|node| !node.deleted && node.is_dir())
            {
                records.push(field(
                    "内核版本",
                    "Kernel",
                    &module.name,
                    &format!("{base}/{}", module.name),
                ));
            }
            break;
        }
    }
    Ok(records)
}

fn field(name: &str, key: &str, value: &str, source: &str) -> Artifact {
    Artifact {
        artifact_type: "linux.systeminfo".to_owned(),
        title: name.to_owned(),
        value: Some(value.into()),
        attributes: [
            ("linux.key", key),
            ("linux.field_value", value),
            ("linux.source", source),
        ]
        .into_iter()
        .collect(),
    }
}

/// The zone identifier comes from evidence; DST is date-dependent and is not inferred from the host clock.
pub fn timezone(volume: &View) -> Result<Vec<Artifact>> {
    let mut zone =
        crate::evidence::text(volume, "etc/timezone", 4096)?.map(|text| text.trim().to_owned());
    let mut source = "etc/timezone";
    if zone.as_ref().is_none_or(String::is_empty) {
        for node in list_or_empty(volume, "etc")? {
            if node.name == "localtime" {
                zone = node.link_target.and_then(|target| {
                    target
                        .split_once("zoneinfo/")
                        .map(|(_, name)| name.to_owned())
                });
                source = "etc/localtime";
            }
        }
    }
    Ok(zone
        .filter(|zone| !zone.is_empty())
        .into_iter()
        .map(|zone| Artifact {
            artifact_type: "linux.timezone".to_owned(),
            title: zone.clone(),
            value: Some(zone.clone().into()),
            attributes: [
                ("linux.timezone", zone),
                ("linux.source", source.to_owned()),
            ]
            .into_iter()
            .collect(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_and_family_detection() {
        let fields = parse_os_release(Some(
            "PRETTY_NAME=\"Kali GNU/Linux Rolling\"\nID=kali\nID_LIKE=debian\n# NAME=x\n",
        ));
        assert_eq!(
            fields.get("PRETTY_NAME").map(String::as_str),
            Some("Kali GNU/Linux Rolling")
        );
        assert!(!fields.contains_key("# NAME"));
    }
}
