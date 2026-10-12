//! Linux 基本信息检材级分析器。
//!
//! 数据项与来源:
//!   系统信息    etc/os-release → redhat-release → debian_version 三级回退;
//!               叠加 hostname / hosts / timezone / 内核版本
//!   用户列表    etc/passwd + etc/shadow(口令策略) + etc/group + .bash_history
//!   登录信息    var/log/wtmp(utmp 384B 记录, ut_type==7)
//!   登录失败    var/log/btmp
//!   开关机时间  var/log/wtmp(ut_type==2 boot / ==11 shutdown)
//!   网络信息    NetworkManager system-connections / OpenWrt UCI / RedHat ifcfg-*
//!   USB使用记录 var/log 文本日志逐行匹配(usb-storage/udisks/Mounted...)
//!   服务列表    usr/lib/systemd/system + etc/systemd/system + etc/init.d
//!   软件信息    var/lib/dpkg/status + var/lib/rpm/rpmdb.sqlite
//!   定时任务    etc/crontab + var/spool/cron/*(支持 @reboot)
//!   开机启动项  etc/systemd/system/*.wants + init.d Default-Start
//!
//! 每个子项独立容错:单项失败只记日志与摘要备注,不影响其余项与任务提交。

mod cron;
mod dhcp;
mod evidence;
mod history;
mod network;
mod presentation;
mod recent;
mod services;
mod software;
mod system;
mod text;
mod usb;
mod users;
mod utmp;

use std::collections::BTreeMap;

use lovelycarve_plugin::{
    export_plugin, AnalysisResult, Artifact, Attributes, Evidence, EvidenceAnalyzer, EvidenceNode,
    EvidenceVolume, LogLevel, Plugin, Result, TimelineEvent, Value,
};

/// Largest binary database (wtmp, rpmdb.sqlite) read into memory.
pub(crate) const BINARY_DB_CAP: u64 = 256 * 1024 * 1024;

/// Quick-analysis sub-items, in collection order (plugin.toml `support`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubItem {
    SystemInfo,
    Timezone,
    Users,
    Groups,
    History,
    Logins,
    LoginFailures,
    BootTimes,
    Network,
    Usb,
    Services,
    Software,
    Cron,
    Autostart,
    Recent,
}

impl SubItem {
    const ALL: [Self; 15] = [
        Self::SystemInfo,
        Self::Timezone,
        Self::Users,
        Self::Groups,
        Self::History,
        Self::Logins,
        Self::LoginFailures,
        Self::BootTimes,
        Self::Network,
        Self::Usb,
        Self::Services,
        Self::Software,
        Self::Cron,
        Self::Autostart,
        Self::Recent,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::SystemInfo => "系统信息",
            Self::Timezone => "时区信息",
            Self::Users => "用户列表",
            Self::Groups => "用户组",
            Self::History => "历史命令",
            Self::Logins => "登录信息",
            Self::LoginFailures => "登录失败",
            Self::BootTimes => "开关机时间",
            Self::Network => "网络信息",
            Self::Usb => "USB使用记录",
            Self::Services => "服务列表",
            Self::Software => "软件信息",
            Self::Cron => "定时任务",
            Self::Autostart => "开机启动项",
            Self::Recent => "用户痕迹",
        }
    }
}

#[derive(Default)]
struct Collector {
    artifacts: Vec<Artifact>,
    timeline: Vec<TimelineEvent>,
    notes: Vec<String>,
    /// 服务列表与开机启动项共用一次 systemd / init.d 枚举。
    services: Option<services::Collected>,
}

impl Collector {
    fn collect(&mut self, item: SubItem, volume: &EvidenceVolume) -> Result<()> {
        match item {
            SubItem::SystemInfo => self.artifacts.extend(system::collect(volume)?),
            SubItem::Timezone => self.artifacts.extend(system::timezone(volume)?),
            SubItem::Users => self.artifacts.extend(users::collect(volume)?),
            SubItem::Groups => self.artifacts.extend(users::groups(volume)?),
            SubItem::History => self.artifacts.extend(history::collect(volume)?),
            SubItem::Logins => {
                let records = utmp::read(volume, "var/log/wtmp")?;
                self.extend(utmp::login_artifacts(&records, utmp::LoginOutcome::Success));
            }
            SubItem::LoginFailures => {
                let records = utmp::read(volume, "var/log/btmp")?;
                self.extend(utmp::login_artifacts(&records, utmp::LoginOutcome::Failure));
            }
            SubItem::BootTimes => {
                let records = utmp::read(volume, "var/log/wtmp")?;
                self.extend(utmp::boot_artifacts(&records));
            }
            SubItem::Network => {
                self.artifacts.extend(network::collect(volume)?);
                self.artifacts.extend(dhcp::collect(volume)?);
                self.artifacts.extend(network::hosts(volume)?);
            }
            SubItem::Usb => self.extend(usb::collect(volume)?),
            SubItem::Services => {
                let services = self.services(volume)?.services.clone();
                self.artifacts.extend(services);
            }
            SubItem::Software => self.artifacts.extend(software::collect(volume)?),
            SubItem::Cron => self.artifacts.extend(cron::collect(volume)?),
            SubItem::Autostart => {
                let autostart = self.services(volume)?.autostart.clone();
                self.artifacts.extend(autostart);
            }
            SubItem::Recent => self.artifacts.extend(recent::collect(volume)?),
        }
        Ok(())
    }

    fn services(&mut self, volume: &EvidenceVolume) -> Result<&services::Collected> {
        let collected = match self.services.take() {
            Some(collected) => collected,
            None => services::collect(volume)?,
        };
        Ok(self.services.insert(collected))
    }

    fn extend(&mut self, (artifacts, timeline): (Vec<Artifact>, Vec<TimelineEvent>)) {
        self.artifacts.extend(artifacts);
        self.timeline.extend(timeline);
    }
}

/// Lists a directory that may be missing; cancellation still propagates.
pub(crate) fn list_or_empty(volume: &EvidenceVolume, path: &str) -> Result<Vec<EvidenceNode>> {
    match volume.list(path) {
        Ok(nodes) => Ok(nodes),
        Err(error) if error.is_cancelled() => Err(error),
        Err(error) if error.code == "EVIDENCE_PATH_NOT_FOUND" => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

/// Give records and their timeline projections the same navigable provenance.
fn source_attributes(attributes: &mut Attributes, root: &str) {
    attributes.insert("linux.root", root);
    attributes.insert("source.root", root);
    if !attributes.contains_key("source.path") {
        if let Some(source) = attributes
            .get("linux.source")
            .and_then(Value::as_str)
            .map(str::to_owned)
        {
            let paths: Vec<Value> = source
                .split(';')
                .filter(|path| path.contains('/'))
                .map(Value::from)
                .collect();
            if let Some(first) = paths.first() {
                attributes.insert("source.path", first.clone());
                attributes.insert("source.paths", Value::Array(paths));
            }
        }
    }
}

/// linuxbaseinfo:Linux 基本信息采集(15 个子项)。
struct LinuxBaseInfo;

impl EvidenceAnalyzer for LinuxBaseInfo {
    fn analyzer(&self) -> &str {
        "linuxbaseinfo"
    }

    fn analyze_evidence(&self, evidence: &Evidence) -> Result<AnalysisResult> {
        let mut collector = Collector::default();
        let mut roots = Vec::new();
        for root in evidence.roots()? {
            let volume = evidence.volume(&root.root_id);
            if !volume.exists("etc/passwd")?
                && !(volume.exists("etc")? && (volume.exists("bin")? || volume.exists("usr")?))
            {
                continue;
            }
            roots.push(root.root_id.clone());
            let mut local = Collector::default();
            let total = SubItem::ALL.len() as u64;
            for (index, item) in SubItem::ALL.into_iter().enumerate() {
                let name = item.label();
                if !evidence.wants(name) {
                    local.notes.push(format!("{name}:未勾选,跳过"));
                    continue;
                }
                evidence.progress(index as u64 + 1, Some(total), Some(&format!("解析{name}")))?;
                if let Err(error) = local.collect(item, &volume) {
                    if error.is_cancelled()
                        || matches!(error.code.as_str(), "RESOURCE_LIMIT" | "SHORT_READ")
                    {
                        return Err(error);
                    }
                    evidence
                        .context()
                        .log(LogLevel::Warn, &format!("collect {name} err: {error}"));
                    local.notes.push(format!("{name}:解析失败({error})"));
                }
                if local.artifacts.len()
                    + local.timeline.len()
                    + collector.artifacts.len()
                    + collector.timeline.len()
                    > 10_000
                {
                    return Err(lovelycarve_plugin::Error::new(
                        "RESOURCE_LIMIT",
                        "基本信息结果超过 10000 项，请按子项分别分析",
                    ));
                }
            }
            for artifact in &mut local.artifacts {
                source_attributes(&mut artifact.attributes, volume.root_id());
            }
            for event in &mut local.timeline {
                source_attributes(&mut event.attributes, volume.root_id());
            }
            collector.extend((local.artifacts, local.timeline));
            collector.notes.extend(
                local
                    .notes
                    .into_iter()
                    .map(|note| format!("{}: {note}", volume.root_id())),
            );
        }
        if roots.is_empty() {
            return Ok(AnalysisResult {
                summary: Some("未找到 Linux 根分区".into()),
                ..AnalysisResult::default()
            });
        }
        if collector.artifacts.len() + collector.timeline.len() > 10_000 {
            return Err(lovelycarve_plugin::Error::new(
                "RESOURCE_LIMIT",
                "基本信息结果超过 10000 项，请按子项分别分析",
            ));
        }
        let mut summary = std::iter::once(format!("Linux 卷 {}", roots.join("、")))
            .chain(collector.notes.iter().cloned())
            .collect::<Vec<_>>()
            .join("、");
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for artifact in &collector.artifacts {
            *counts.entry(artifact.artifact_type.as_str()).or_default() += 1;
        }
        summary.push(';');
        summary.push_str(
            &counts
                .iter()
                .map(|(artifact_type, count)| format!("{artifact_type} {count}"))
                .collect::<Vec<_>>()
                .join(";"),
        );
        let nodes = presentation::prepare_result_nodes(&mut collector.artifacts);
        Ok(AnalysisResult {
            summary: Some(summary),
            nodes,
            artifacts: collector.artifacts,
            timeline: collector.timeline,
            findings: Vec::new(),
        })
    }
}

fn plugin() -> Plugin {
    Plugin::new(
        "org.lovelycarve.linuxinfo",
        "Linux信息",
        env!("CARGO_PKG_VERSION"),
    )
    .evidence_analyzer(LinuxBaseInfo)
}

export_plugin!(plugin);

#[cfg(test)]
mod provenance_tests {
    use super::*;

    #[test]
    fn timeline_provenance_matches_record_and_preserves_explicit_paths() {
        let mut attributes: Attributes = [("linux.source", "var/log/wtmp")].into_iter().collect();
        source_attributes(&mut attributes, "part:0");
        assert_eq!(
            attributes,
            [
                ("linux.source", Value::from("var/log/wtmp")),
                ("linux.root", Value::from("part:0")),
                ("source.root", Value::from("part:0")),
                ("source.path", Value::from("var/log/wtmp")),
                (
                    "source.paths",
                    Value::Array(vec![Value::from("var/log/wtmp")])
                ),
            ]
            .into_iter()
            .collect()
        );

        let mut explicit: Attributes = [
            ("linux.source", Value::from("systemd/test.service")),
            (
                "source.path",
                Value::from("etc/systemd/system/test;unit.service"),
            ),
        ]
        .into_iter()
        .collect();
        source_attributes(&mut explicit, "part:0");
        assert_eq!(
            explicit.get("source.path"),
            Some(&Value::from("etc/systemd/system/test;unit.service"))
        );
        assert!(!explicit.contains_key("source.paths"));
    }
}
