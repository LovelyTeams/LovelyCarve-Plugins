//! NetworkManager DHCP and Avahi IPv6 addresses retained as historical observations.
//! Explicit epoch timestamps in NM messages are UTC; the syslog clock is not.
use lovelycarve_plugin::{Artifact, Attributes, Error, EvidenceVolume, Result};
use std::{collections::BTreeMap, io::Read};

fn record(interface: &str, mut attributes: Attributes) -> Artifact {
    attributes.insert("linux.iface", interface);
    attributes.insert("linux.source_kind", "NetworkManager DHCP 日志历史记录");
    Artifact {
        artifact_type: "linux.network".into(),
        title: interface.into(),
        value: Some(interface.into()),
        attributes,
    }
}

fn parse(
    contents: &str,
    source: &str,
    mut cancelled: impl FnMut() -> Result<()>,
) -> Result<Vec<Artifact>> {
    let mut pending: BTreeMap<String, Attributes> = BTreeMap::new();
    let mut records = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        cancelled()?;
        if line.contains("avahi-daemon[") {
            if let Some((prefix, address)) = line.split_once(".IPv6 with address ") {
                if let Some((_, interface)) =
                    prefix.rsplit_once("Joining mDNS multicast group on interface ")
                {
                    let address = address.strip_suffix('.').unwrap_or(address);
                    if address.parse::<std::net::Ipv6Addr>().is_ok() {
                        let mut attributes = Attributes::new();
                        attributes.insert("linux.iface", interface);
                        attributes.insert("linux.ipv6", address);
                        attributes.insert("linux.source", source);
                        attributes.insert("linux.source_kind", "Avahi IPv6 日志历史记录");
                        attributes
                            .insert("linux.local_time_raw", line.get(..15).unwrap_or_default());
                        attributes.insert("source.line", index as u64 + 1);
                        records.push(Artifact {
                            artifact_type: "linux.network".into(),
                            title: interface.into(),
                            value: Some(interface.into()),
                            attributes,
                        });
                    }
                }
            }
        }
        let Some((prefix, message)) = line.split_once("dhcp4 (") else {
            continue;
        };
        if !prefix.contains("NetworkManager[") {
            continue;
        }
        let Some((interface, message)) = message.split_once("): ") else {
            continue;
        };
        if let Some(option) = message.strip_prefix("option ") {
            let Some((key, value)) = option.split_once("=>") else {
                continue;
            };
            let key = key.trim();
            let value = value
                .trim()
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
                .unwrap_or(value.trim());
            let field = match key {
                "ip_address" => "linux.ipv4",
                "domain_name_servers" => "linux.dns",
                "routers" => "linux.gateway",
                "subnet_mask" => "linux.mask",
                "dhcp_lease_time" => "linux.lease_seconds",
                "expiry" => "linux.lease_expiry_raw",
                "domain_name" => "linux.domain",
                "next_server" => "linux.dhcp_server",
                _ => continue,
            };
            // Repeated options begin a new lease, never overwrite an older observation.
            if pending
                .get(interface)
                .is_some_and(|attributes| attributes.contains_key(field))
            {
                if let Some(attributes) = pending.remove(interface) {
                    if attributes.contains_key("linux.ipv4") {
                        records.push(record(interface, attributes));
                    }
                }
            }
            let attributes = pending.entry(interface.into()).or_insert_with(|| {
                let mut attributes = Attributes::new();
                attributes.insert("linux.source", source);
                attributes.insert("source.line", index as u64 + 1);
                let epoch = prefix
                    .rsplit_once('[')
                    .and_then(|(_, epoch)| epoch.split_once(']'))
                    .and_then(|(epoch, _)| epoch.split('.').next())
                    .and_then(|epoch| epoch.parse::<i64>().ok());
                attributes
                    .insert_optional("linux.lease_observed", epoch.and_then(crate::text::rfc3339));
                attributes
            });
            attributes.insert("source.line_end", index as u64 + 1);
            attributes.insert(field, value);
            if key == "expiry" {
                attributes.insert_optional(
                    "linux.lease_expiry",
                    value.parse::<i64>().ok().and_then(crate::text::rfc3339),
                );
            }
        } else if message.contains("-> bound")
            || message.starts_with("activation:")
            || message.contains("cancelled")
        {
            if let Some(attributes) = pending.remove(interface) {
                if attributes.contains_key("linux.ipv4") {
                    records.push(record(interface, attributes));
                }
            }
        }
        if records.len() > 10_000 {
            return Err(Error::new("RESOURCE_LIMIT", "DHCP 记录超过 10000 条"));
        }
    }
    for (interface, attributes) in pending {
        if attributes.contains_key("linux.ipv4") {
            records.push(record(&interface, attributes));
        }
    }
    Ok(records)
}

pub fn collect(volume: &EvidenceVolume) -> Result<Vec<Artifact>> {
    let mut records = Vec::new();
    for file in crate::list_or_empty(volume, "var/log")? {
        if file.deleted
            || !file.is_file()
            || !["syslog", "messages"]
                .iter()
                .any(|prefix| file.name == *prefix || file.name.starts_with(&format!("{prefix}.")))
        {
            continue;
        }
        let path = format!("var/log/{}", file.name);
        let Some(bytes) = crate::evidence::read(volume, &path, 32 * 1024 * 1024)? else {
            continue;
        };
        let bytes = if file.name.ends_with(".gz") {
            let mut output = Vec::new();
            flate2::read::MultiGzDecoder::new(bytes.as_slice())
                .take(32 * 1024 * 1024 + 1)
                .read_to_end(&mut output)
                .map_err(|error| Error::plugin(format!("{path}: {error}")))?;
            if output.len() > 32 * 1024 * 1024 {
                return Err(Error::new("RESOURCE_LIMIT", "DHCP 日志解压超过 32 MiB"));
            }
            output
        } else {
            bytes
        };
        records.extend(parse(
            &lovelycarve_plugin::text::decode_lossy(&bytes),
            &path,
            || volume.context().check_cancelled(),
        )?);
        if records.len() > 10_000 {
            return Err(Error::new("RESOURCE_LIMIT", "DHCP 记录超过 10000 条"));
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn leases_remain_separate_and_sources_use_real_lines() {
        let contents = "Mar 11 08:17:42 h NetworkManager[719]: <info> [1773188262.6159] dhcp4 (ens33): option dhcp_lease_time => '1800'\nMar 11 08:17:42 h NetworkManager[719]: <info> [1773188262.6159] dhcp4 (ens33): option ip_address => '192.168.146.154'\nMar 11 08:17:42 h NetworkManager[719]: <info> [1773188262.6159] dhcp4 (ens33): option expiry => '1773190062'\nMar 11 08:17:42 h NetworkManager[719]: <info> [1773188262.6159] dhcp4 (ens33): state changed unknown -> bound\nMar 11 08:47:42 h NetworkManager[719]: <info> [1773190062.0] dhcp4 (ens33): option ip_address => '192.168.146.155'";
        let records = parse(contents, "var/log/syslog.1", || Ok(())).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].attributes.get("linux.lease_observed"),
            Some(&"2026-03-11T00:17:42+00:00".into())
        );
        assert_eq!(
            records[0].attributes.get("linux.lease_expiry"),
            Some(&"2026-03-11T00:47:42+00:00".into())
        );
        assert_eq!(
            records[1].attributes.get("source.line"),
            Some(&lovelycarve_plugin::Value::from(5_u64))
        );
        assert!(parse(contents, "x", || Err(Error::new("CANCELLED", "stop"))).is_err());
    }
    #[test]
    fn ipv6_observations_keep_interface_and_local_clock() {
        let records = parse("Mar 11 08:17:42 h avahi-daemon[713]: Joining mDNS multicast group on interface ens33.IPv6 with address fe80::308f:50a4:d0f9:8162.", "var/log/syslog.1", || Ok(())).unwrap();
        assert_eq!(
            records[0].attributes.get("linux.ipv6"),
            Some(&"fe80::308f:50a4:d0f9:8162".into())
        );
        assert_eq!(records[0].title, "ens33");
        assert_eq!(
            records[0].attributes.get("linux.local_time_raw"),
            Some(&"Mar 11 08:17:42".into())
        );
    }
}
