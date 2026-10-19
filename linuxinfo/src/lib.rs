//! Linux 基本信息分析器（`linuxbaseinfo`，系统级）。
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
//! The host runs the analyzer once per detected Linux system, with the
//! system's volumes mounted in one view (a separate /home is found through
//! /etc/fstab). Records go out as each sub-item finishes; a sub-item that
//! fails becomes a structured warning and the others still run. The time
//! zone, host name and user names are recorded as evidence profile facts.

mod cron;
mod dhcp;
mod evidence;
mod history;
mod item;
mod network;
mod recent;
mod records;
mod services;
mod software;
mod system;
mod text;
mod usb;
mod users;
mod utmp;

use lovelycarve_plugin::{export_plugin, LogLevel, Node, Plugin, Result, Run, Value, View};

use item::Artifact;

/// Largest binary database (wtmp, rpmdb.sqlite) read into memory.
pub(crate) const BINARY_DB_CAP: u64 = 256 * 1024 * 1024;

/// Option holding the selected sub-items.
const ITEMS_OPTION: &str = "items";

/// Sub-items, in collection order (choices of the `items` option).
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

    /// Stable choice id (manifest option and locales).
    fn id(self) -> &'static str {
        match self {
            Self::SystemInfo => "system_info",
            Self::Timezone => "timezone",
            Self::Users => "users",
            Self::Groups => "groups",
            Self::History => "history",
            Self::Logins => "logins",
            Self::LoginFailures => "login_failures",
            Self::BootTimes => "boot_times",
            Self::Network => "network",
            Self::Usb => "usb",
            Self::Services => "services",
            Self::Software => "software",
            Self::Cron => "cron",
            Self::Autostart => "autostart",
            Self::Recent => "recent",
        }
    }

    /// Progress and warning text (the UI labels come from the manifest).
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

struct Collector<'a> {
    view: &'a View,
    /// 服务列表与开机启动项共用一次 systemd / init.d 枚举。
    services: Option<services::Collected>,
}

impl Collector<'_> {
    fn collect(&mut self, item: SubItem) -> Result<Vec<Artifact>> {
        let view = self.view;
        Ok(match item {
            SubItem::SystemInfo => system::collect(view)?,
            SubItem::Timezone => system::timezone(view)?,
            SubItem::Users => users::collect(view)?,
            SubItem::Groups => users::groups(view)?,
            SubItem::History => history::collect(view)?,
            SubItem::Logins => utmp::login_artifacts(
                &utmp::read(view, "var/log/wtmp")?,
                utmp::LoginOutcome::Success,
            ),
            SubItem::LoginFailures => utmp::login_artifacts(
                &utmp::read(view, "var/log/btmp")?,
                utmp::LoginOutcome::Failure,
            ),
            SubItem::BootTimes => utmp::boot_artifacts(&utmp::read(view, "var/log/wtmp")?),
            SubItem::Network => {
                let mut artifacts = network::collect(view)?;
                artifacts.extend(dhcp::collect(view)?);
                artifacts.extend(network::hosts(view)?);
                artifacts
            }
            SubItem::Usb => usb::collect(view)?,
            SubItem::Services => self.services()?.services.clone(),
            SubItem::Software => software::collect(view)?,
            SubItem::Cron => cron::collect(view)?,
            SubItem::Autostart => self.services()?.autostart.clone(),
            SubItem::Recent => recent::collect(view)?,
        })
    }

    fn services(&mut self) -> Result<&services::Collected> {
        let collected = match self.services.take() {
            Some(collected) => collected,
            None => services::collect(self.view)?,
        };
        Ok(self.services.insert(collected))
    }
}

/// Lists a directory that may be missing; cancellation still propagates.
pub(crate) fn list_or_empty(volume: &View, path: &str) -> Result<Vec<Node>> {
    volume.list_or_empty(path)
}

/// Profile facts seen while collecting.
#[derive(Default)]
struct Facts {
    timezone: Option<String>,
    hostname: Option<String>,
    users: Vec<(Value, Value)>,
}

impl Facts {
    fn observe(&mut self, artifact: &Artifact) {
        let text = |key: &str| {
            artifact
                .attributes
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        match artifact.artifact_type.as_str() {
            "linux.timezone" if self.timezone.is_none() => self.timezone = text("linux.timezone"),
            "linux.systeminfo" if text("linux.key").as_deref() == Some("hostname") => {
                self.hostname = text("linux.field_value");
            }
            "linux.user" => {
                if let (Some(uid), Some(name)) = (text("linux.uid"), text("linux.username")) {
                    self.users.push((Value::from(uid), Value::from(name)));
                }
            }
            _ => {}
        }
    }

    fn provide(self, run: &Run) -> Result<()> {
        if let Some(timezone) = self.timezone.filter(|zone| !zone.is_empty()) {
            run.provide("timezone", timezone)?;
        }
        if let Some(hostname) = self.hostname.filter(|name| !name.is_empty()) {
            run.provide("hostname", hostname)?;
        }
        if !self.users.is_empty() {
            run.provide("users", Value::Map(self.users))?;
        }
        Ok(())
    }
}

/// linuxbaseinfo：Linux 基本信息采集（15 个子项）。
fn linux_base_info(run: &Run) -> Result<()> {
    let view = run.require_view()?;
    let mut collector = Collector {
        view,
        services: None,
    };
    let mut facts = Facts::default();
    let selected: Vec<SubItem> = SubItem::ALL
        .into_iter()
        .filter(|item| run.options().wants(ITEMS_OPTION, item.id()))
        .collect();
    let total = selected.len() as u64;
    for (index, item) in selected.into_iter().enumerate() {
        run.progress(index as u64, Some(total), Some(item.label()))?;
        match collector.collect(item) {
            Ok(artifacts) => {
                for artifact in &artifacts {
                    facts.observe(artifact);
                    records::emit(run, view, artifact)?;
                }
            }
            Err(error) if error.is_cancelled() => return Err(error),
            Err(error) => {
                run.log(
                    LogLevel::Warn,
                    &format!("collect {} failed: {error}", item.id()),
                );
                run.warn(&error.code, format!("{}：{}", item.label(), error.message))?;
            }
        }
    }
    facts.provide(run)?;
    run.progress(total, Some(total), None)
}

fn plugin() -> Plugin {
    records::register(Plugin::new("org.lovelycarve.linuxinfo"))
        .analyzer("linuxbaseinfo", linux_base_info)
}

export_plugin!(plugin);

#[cfg(test)]
mod tests;
