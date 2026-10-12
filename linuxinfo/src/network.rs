//! 网络信息: NetworkManager keyfiles, OpenWrt UCI and RedHat ifcfg-*.

use std::collections::HashMap;

use lovelycarve_plugin::{text::split_lines, Artifact, Attributes, EvidenceVolume, Result};

use crate::{
    list_or_empty,
    text::{
        cidr_to_mask, is_digits, or_else, retain_truthy, split_whitespace_max, strip, strip_quotes,
    },
};

type Section = HashMap<String, String>;

/// NetworkManager keyfile (INI) sections; keys before any header land in
/// the "" section.
pub fn parse_keyfile(text: &str) -> HashMap<String, Section> {
    let mut sections: HashMap<String, Section> = HashMap::new();
    let mut current = String::new();
    for line in split_lines(text) {
        let line = strip(line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            current = name.to_owned();
            sections.entry(current.clone()).or_default();
        } else if let Some((key, value)) = line.split_once('=') {
            sections
                .entry(current.clone())
                .or_default()
                .insert(strip(key).to_owned(), strip_quotes(value).to_owned());
        }
    }
    sections
}

/// OpenWrt `/etc/config/network` blocks as `uci.*` maps.
pub fn parse_uci_network(text: &str) -> Vec<Section> {
    let mut blocks = Vec::new();
    let mut current: Option<Section> = None;
    for line in split_lines(text) {
        let line = strip(line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("config ") {
            blocks.extend(current.take());
            let parts = split_whitespace_max(line, 2);
            let mut block = Section::new();
            block.insert(
                "uci.type".to_owned(),
                parts.get(1).copied().unwrap_or_default().to_owned(),
            );
            block.insert(
                "uci.name".to_owned(),
                parts
                    .get(2)
                    .map_or("", |name| strip_quotes(name))
                    .to_owned(),
            );
            current = Some(block);
        } else if line.starts_with("option ") {
            if let Some(block) = current.as_mut() {
                if let [_, key, value] = split_whitespace_max(line, 2).as_slice() {
                    block.insert(format!("uci.{key}"), strip_quotes(value).to_owned());
                }
            }
        }
    }
    blocks.extend(current);
    blocks
}

/// `KEY=value` shell assignments (RedHat ifcfg files).
pub fn parse_shell_assignments(text: &str) -> Section {
    let mut values = Section::new();
    for line in split_lines(text) {
        let line = strip(line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            values.insert(strip(key).to_owned(), strip_quotes(value).to_owned());
        }
    }
    values
}

pub fn collect(volume: &EvidenceVolume) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();

    for node in list_or_empty(volume, "etc/NetworkManager/system-connections")? {
        if !node.is_file() {
            continue;
        }
        let path = format!("etc/NetworkManager/system-connections/{}", node.name);
        let sections =
            parse_keyfile(&crate::evidence::text(volume, &path, 256 * 1024)?.unwrap_or_default());
        let empty = Section::new();
        let connection = sections.get("connection").unwrap_or(&empty);
        let ethernet = sections.get("ethernet").unwrap_or(&empty);
        let ipv4 = sections.get("ipv4").unwrap_or(&empty);
        let mut attributes = Attributes::new();
        attributes.insert("linux.source", "NetworkManager");
        attributes.insert("source.path", path.as_str());
        attributes.insert_optional(
            "linux.iface",
            or_else(field(connection, "interface-name"), field(connection, "id")),
        );
        attributes.insert_optional("linux.connection", field(connection, "id"));
        attributes.insert_optional("linux.type", field(connection, "type"));
        attributes.insert_optional("linux.mac", field(ethernet, "mac-address"));
        attributes.insert_optional("linux.method", field(ipv4, "method"));
        attributes.insert_optional("linux.autoconnect", field(connection, "autoconnect"));
        if let Some((address, prefix)) =
            field(ipv4, "address1").and_then(|address| address.split_once('/'))
        {
            attributes.insert("linux.ipv4", address);
            if is_digits(prefix) {
                attributes.insert("linux.mask", cidr_to_mask(prefix));
            }
        }
        if let Some(gateway) = field(ipv4, "gateway").filter(|gateway| !gateway.is_empty()) {
            attributes.insert("linux.gateway", gateway);
        }
        if let Some(dns) = field(ipv4, "dns").filter(|dns| !dns.is_empty()) {
            attributes.insert("linux.dns", dns);
        }
        artifacts.push(network_artifact("网络连接(NetworkManager)", attributes));
    }

    let uci = crate::evidence::text(volume, "etc/config/network", 1024 * 1024)?;
    for block in parse_uci_network(uci.as_deref().unwrap_or_default()) {
        if !matches!(
            block.get("uci.type").map(String::as_str),
            Some("interface" | "device")
        ) {
            continue;
        }
        let mut attributes = Attributes::new();
        attributes.insert("linux.source", "OpenWrt");
        attributes.insert("source.path", "etc/config/network");
        attributes.insert_optional(
            "linux.iface",
            or_else(field(&block, "uci.name"), field(&block, "uci.device")),
        );
        attributes.insert_optional("linux.proto", field(&block, "uci.proto"));
        attributes.insert_optional("linux.ipv4", field(&block, "uci.ipaddr"));
        attributes.insert_optional("linux.mask", field(&block, "uci.netmask"));
        attributes.insert_optional("linux.gateway", field(&block, "uci.gateway"));
        attributes.insert_optional("linux.dns", field(&block, "uci.dns"));
        attributes.insert_optional("linux.mac", field(&block, "uci.macaddr"));
        artifacts.push(network_artifact("网络配置(OpenWrt)", attributes));
    }

    for node in list_or_empty(volume, "etc/sysconfig/network-scripts")? {
        let Some(device) = node.name.strip_prefix("ifcfg-") else {
            continue;
        };
        if !node.is_file() {
            continue;
        }
        let path = format!("etc/sysconfig/network-scripts/{}", node.name);
        let values = parse_shell_assignments(
            &crate::evidence::text(volume, &path, 64 * 1024)?.unwrap_or_default(),
        );
        let mut attributes = Attributes::new();
        attributes.insert("linux.source", "RedHat");
        attributes.insert("source.path", path.as_str());
        attributes.insert_optional(
            "linux.iface",
            or_else(field(&values, "DEVICE"), Some(device)),
        );
        attributes.insert_optional("linux.mac", field(&values, "HWADDR"));
        attributes.insert_optional("linux.bootproto", field(&values, "BOOTPROTO"));
        attributes.insert_optional("linux.onboot", field(&values, "ONBOOT"));
        attributes.insert_optional("linux.ipv4", field(&values, "IPADDR"));
        attributes.insert_optional("linux.mask", field(&values, "NETMASK"));
        attributes.insert_optional("linux.gateway", field(&values, "GATEWAY"));
        attributes.insert_optional("linux.dns", field(&values, "DNS1"));
        artifacts.push(network_artifact("网络接口(RedHat)", attributes));
    }
    Ok(artifacts)
}

fn field<'a>(section: &'a Section, key: &str) -> Option<&'a str> {
    section.get(key).map(String::as_str)
}

fn network_artifact(title: &str, mut attributes: Attributes) -> Artifact {
    let value = attributes.get("linux.iface").cloned();
    retain_truthy(&mut attributes);
    Artifact {
        artifact_type: "linux.network".to_owned(),
        title: title.to_owned(),
        value,
        attributes,
    }
}

/// Keep every hosts mapping, including IPv6 and aliases, with its source line.
pub fn hosts(volume: &EvidenceVolume) -> Result<Vec<Artifact>> {
    let mut records = Vec::new();
    for (index, line) in crate::evidence::text(volume, "etc/hosts", 1024 * 1024)?
        .unwrap_or_default()
        .lines()
        .enumerate()
    {
        let fields: Vec<_> = line
            .split('#')
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        if fields.len() < 2 {
            continue;
        }
        if fields[0].parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        let mut attributes: Attributes = [
            ("linux.hostname", fields[1]),
            ("linux.address", fields[0]),
            ("linux.aliases", &fields[2..].join(" ")),
            ("linux.source", "etc/hosts"),
        ]
        .into_iter()
        .collect();
        attributes.insert("linux.line", index as u64 + 1);
        records.push(Artifact {
            artifact_type: "linux.host".into(),
            title: fields[1].into(),
            value: Some(fields[0].into()),
            attributes,
        });
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyfile_and_uci_parsers() {
        let sections = parse_keyfile(
            "[connection]\nid = 'Wired 1'\n[ipv4]\nmethod=manual\n\
             address1=192.168.1.10/24\ngateway=192.168.1.1\ndns=8.8.8.8;\n",
        );
        assert_eq!(sections["connection"]["id"], "Wired 1");
        assert_eq!(sections["ipv4"]["address1"], "192.168.1.10/24");

        let blocks = parse_uci_network(
            "config interface 'wan'\n  option proto 'static'\n  option ipaddr '192.168.3.1'\n\
             option netmask '255.255.255.0'\nconfig device\n",
        );
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0]["uci.type"], "interface");
        assert_eq!(blocks[0]["uci.name"], "wan");
        assert_eq!(blocks[0]["uci.proto"], "static");
        assert_eq!(blocks[1]["uci.name"], "");
    }

    #[test]
    fn shell_assignments_strip_quotes() {
        let values = parse_shell_assignments("# c\nDEVICE=\"eth0\"\nONBOOT=yes\nbad line\n");
        assert_eq!(values["DEVICE"], "eth0");
        assert_eq!(values["ONBOOT"], "yes");
        assert_eq!(values.len(), 2);
    }
}
