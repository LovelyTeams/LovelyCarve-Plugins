//! 服务列表 + 开机启动项: systemd units, `.wants` / `.requires` links and
//! SysV init.d scripts. Both sub-items share one enumeration per analysis.

use std::collections::{BTreeMap, HashMap, HashSet};

use lovelycarve_plugin::{text::split_lines, Artifact, Attributes, EvidenceVolume, Result, Value};

use crate::{
    list_or_empty,
    text::{clean_optional, clean_text, retain_truthy, strip},
};

pub struct Collected {
    pub services: Vec<Artifact>,
    pub autostart: Vec<Artifact>,
}

/// `Section.Key` → value; later assignments win.
pub fn parse_systemd_unit(text: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    let mut section = "";
    for line in split_lines(text) {
        let line = strip(line);
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            section = name;
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            values.insert(format!("{section}.{}", strip(key)), strip(value).to_owned());
        }
    }
    values
}

/// LSB header fields of an init.d script head.
#[derive(Debug, Default, PartialEq)]
pub struct InitScriptHeader {
    pub description: Option<String>,
    pub default_start: Option<String>,
}

pub fn parse_init_script_header(head: &str) -> InitScriptHeader {
    let mut header = InitScriptHeader::default();
    for line in split_lines(head) {
        if let Some(value) = line.strip_prefix("# Short-Description:") {
            header.description = clean_text(value, 200);
        } else if let Some(value) = line.strip_prefix("# Description:") {
            if header.description.is_none() {
                header.description = clean_text(value, 200);
            }
        } else if let Some(value) = line.strip_prefix("# Default-Start:") {
            header.default_start = Some(strip(value).to_owned());
        }
    }
    header
}

pub fn collect(volume: &EvidenceVolume) -> Result<Collected> {
    let mut services = Vec::new();
    let mut autostart = Vec::new();
    let mut enabled_units = HashSet::new();

    for node in list_or_empty(volume, "etc/systemd/system")? {
        if node.deleted
            || !node.is_dir()
            || !(node.name.ends_with(".wants") || node.name.ends_with(".requires"))
        {
            continue;
        }
        for entry in volume.list(&format!("etc/systemd/system/{}", node.name))? {
            if entry.deleted {
                continue;
            }
            enabled_units.insert(entry.name.clone());
            let mut attributes = Attributes::new();
            attributes.insert("linux.name", entry.name.as_str());
            attributes.insert("linux.source", format!("systemd/{}", node.name));
            attributes.insert(
                "source.path",
                format!("etc/systemd/system/{}/{}", node.name, entry.name),
            );
            autostart.push(autostart_artifact(entry.name, attributes));
        }
    }

    // usr/lib units, overridden by etc ones of the same name.
    let mut unit_paths = BTreeMap::new();
    for base in ["usr/lib/systemd/system", "etc/systemd/system"] {
        for node in list_or_empty(volume, base)? {
            if !node.deleted && node.is_file() && node.name.ends_with(".service") {
                let path = format!("{base}/{}", node.name);
                unit_paths.insert(node.name, path);
            }
        }
    }
    for (unit, path) in unit_paths {
        let values = parse_systemd_unit(
            &crate::evidence::text(volume, &path, 256 * 1024)?.unwrap_or_default(),
        );
        let value = |key: &str| {
            values
                .get(key)
                .map(String::as_str)
                .filter(|value| !value.is_empty())
        };
        let mut attributes = Attributes::new();
        attributes.insert("linux.source", path.as_str());
        for key in [
            "Unit.Documentation",
            "Unit.After",
            "Unit.Requires",
            "Unit.Wants",
            "Service.User",
            "Service.EnvironmentFile",
            "Service.ExecStop",
            "Install.WantedBy",
            "Install.Alias",
        ] {
            let name = format!("linux.{}", key.replace('.', "_").to_lowercase());
            attributes.insert_optional(name, value(key));
        }
        attributes.insert_optional("linux.description", value("Unit.Description"));
        attributes.insert(
            "linux.service_type",
            value("Service.Type").unwrap_or("simple"),
        );
        attributes.insert("linux.restart", value("Service.Restart").unwrap_or("no"));
        attributes.insert_optional(
            "linux.exec_start",
            clean_optional(value("Service.ExecStart"), 300),
        );
        attributes.insert(
            "linux.enabled",
            if enabled_units.contains(&unit) {
                "是"
            } else {
                "否"
            },
        );
        retain_truthy(&mut attributes);
        for item in &mut autostart {
            if item.value.as_ref().and_then(Value::as_str) == Some(unit.as_str()) {
                let target = item.attributes.get("linux.source").cloned();
                let link_path = item.attributes.get("source.path").cloned();
                item.attributes.update(&attributes);
                item.attributes.insert_optional("linux.target", target);
                if let Some(link_path) = link_path {
                    item.attributes.insert(
                        "source.paths",
                        Value::Array(vec![link_path, Value::from(path.as_str())]),
                    );
                }
            }
        }
        services.push(service_artifact(unit, attributes));
    }

    for node in list_or_empty(volume, "etc/init.d")? {
        if node.deleted || !node.is_file() || node.name.starts_with('.') {
            continue;
        }
        let head =
            crate::evidence::text(volume, &format!("etc/init.d/{}", node.name), 1024 * 1024)?
                .unwrap_or_default();
        let header = parse_init_script_header(&head);
        let default_start = header
            .default_start
            .filter(|runlevels| !runlevels.is_empty());
        let mut attributes = Attributes::new();
        attributes.insert("linux.source", format!("etc/init.d/{}", node.name));
        attributes.insert_optional("linux.description", header.description);
        attributes.insert(
            "linux.enabled",
            if default_start.is_some() {
                "是"
            } else {
                "未知"
            },
        );
        services.push(service_artifact(node.name.clone(), attributes));
        if let Some(runlevels) = default_start {
            let mut attributes = Attributes::new();
            attributes.insert("linux.name", node.name.as_str());
            attributes.insert("linux.source", format!("etc/init.d/{}", node.name));
            attributes.insert("linux.runlevels", runlevels);
            autostart.push(autostart_artifact(node.name, attributes));
        }
    }
    Ok(Collected {
        services,
        autostart,
    })
}

fn service_artifact(name: String, attributes: Attributes) -> Artifact {
    Artifact {
        artifact_type: "linux.service".to_owned(),
        title: format!("服务 {name}"),
        value: Some(Value::from(name)),
        attributes,
    }
}

fn autostart_artifact(name: String, attributes: Attributes) -> Artifact {
    Artifact {
        artifact_type: "linux.autostart".to_owned(),
        title: "开机启动项".to_owned(),
        value: Some(Value::from(name)),
        attributes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_sections_prefix_their_keys() {
        let values = parse_systemd_unit(
            "[Unit]\nDescription=OpenBSD Secure Shell server\n; comment\n\
             [Service]\nExecStart=/usr/sbin/sshd -D $SSHD_OPTS\nType=notify\n",
        );
        assert_eq!(values["Unit.Description"], "OpenBSD Secure Shell server");
        assert_eq!(values["Service.ExecStart"], "/usr/sbin/sshd -D $SSHD_OPTS");
        assert_eq!(values["Service.Type"], "notify");
    }

    #[test]
    fn init_script_header_keeps_values_after_the_colon() {
        let header = parse_init_script_header(
            "#!/bin/sh\n### BEGIN INIT INFO\n# Provides: apache2\n\
             # Default-Start:     2 3 4 5\n# Short-Description: Apache2 web server\n\
             # Description: Start the web server\n### END INIT INFO\n",
        );
        assert_eq!(
            header,
            InitScriptHeader {
                description: Some("Apache2 web server".to_owned()),
                default_start: Some("2 3 4 5".to_owned()),
            }
        );
        assert_eq!(
            parse_init_script_header("# Default-Start:\n")
                .default_start
                .as_deref(),
            Some("")
        );
    }
}
