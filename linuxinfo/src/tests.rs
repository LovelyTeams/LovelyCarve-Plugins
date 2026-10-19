//! The analyzer end to end through the SDK harness, on a synthetic root
//! file system whose /home is a separate volume.

use std::{collections::BTreeMap, fs, path::Path};

use lovelycarve_plugin::{
    testing::{Fixture, Harness, TestRun},
    Value,
};

fn write(path: &Path, content: &[u8]) {
    fs::create_dir_all(path.parent().expect("parent")).expect("directories");
    fs::write(path, content).expect("fixture file");
}

/// One utmp record (`kind` 7 = login, 8 = logout, 2 = boot).
fn utmp(kind: i32, pid: i32, user: &[u8], line: &[u8], host: &[u8], seconds: i32) -> Vec<u8> {
    let mut bytes = vec![0_u8; 384];
    bytes[0..4].copy_from_slice(&kind.to_le_bytes());
    bytes[4..8].copy_from_slice(&pid.to_le_bytes());
    bytes[8..8 + line.len()].copy_from_slice(line);
    bytes[44..44 + user.len()].copy_from_slice(user);
    bytes[76..76 + host.len()].copy_from_slice(host);
    bytes[340..344].copy_from_slice(&seconds.to_le_bytes());
    bytes
}

struct Fixtures {
    root: tempfile::TempDir,
    home: tempfile::TempDir,
}

fn fixtures() -> Fixtures {
    let root = tempfile::tempdir().expect("root");
    let home = tempfile::tempdir().expect("home");
    let at = |path: &str| root.path().join(path);
    write(
        &at("etc/passwd"),
        b"root:x:0:0:root:/root:/bin/bash\nkali:x:1000:1000:Kali,,,:/home/kali:/usr/bin/zsh\n",
    );
    write(
        &at("etc/shadow"),
        b"root:$y$j9T$abc:19855:0:99999:7:::\nkali:!:19855:0:99999:7:::\n",
    );
    write(&at("etc/group"), b"root:x:0:\nsudo:x:27:kali\n");
    write(&at("etc/hostname"), b"kali-box\n");
    write(
        &at("etc/os-release"),
        b"PRETTY_NAME=\"Kali GNU/Linux Rolling\"\nNAME=\"Kali GNU/Linux\"\nID=kali\n",
    );
    write(&at("etc/timezone"), b"Asia/Shanghai\n");
    write(&at("etc/hosts"), b"127.0.0.1 localhost\n# comment\n");
    write(
        &at("var/log/wtmp"),
        &[
            utmp(7, 41, b"kali", b"pts/0", b"10.0.0.5", 1_700_000_000),
            utmp(8, 41, b"kali", b"pts/0", b"", 1_700_000_600),
            utmp(2, 0, b"reboot", b"~", b"", 1_699_999_000),
        ]
        .concat(),
    );
    write(
        &at("var/lib/dpkg/status"),
        b"Package: zsh\nStatus: install ok installed\nVersion: 5.9\nArchitecture: amd64\n\n",
    );
    write(
        &at("etc/crontab"),
        b"SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",
    );
    write(
        &at("usr/lib/systemd/system/ssh.service"),
        b"[Unit]\nDescription=OpenBSD Secure Shell server\n[Service]\nExecStart=/usr/sbin/sshd -D\n",
    );
    write(
        &at("etc/systemd/system/multi-user.target.wants/ssh.service"),
        b"",
    );
    write(&at("root/.bash_history"), b"#1700000100\nid\n");
    write(
        &home.path().join("kali/.zsh_history"),
        b": 1700000200:0;sudo -i\n",
    );
    Fixtures { root, home }
}

fn run(fixtures: &Fixtures, items: &[&str]) -> TestRun {
    let options = if items.is_empty() {
        BTreeMap::new()
    } else {
        BTreeMap::from([(
            "items".to_owned(),
            Value::Array(items.iter().map(|item| Value::from(*item)).collect()),
        )])
    };
    Harness::new(super::plugin)
        .run_with(
            "linuxbaseinfo",
            Fixture::system("linux", fixtures.root.path()).mount("home", fixtures.home.path()),
            options,
            BTreeMap::new(),
        )
        .expect("analysis")
}

#[test]
fn every_sub_item_emits_typed_records_with_sources() {
    let fixtures = fixtures();
    let run = run(&fixtures, &[]);
    assert_eq!(
        run.counts(),
        BTreeMap::from(
            [
                ("linux.autostart", 1),
                ("linux.boot", 1),
                ("linux.cron", 1),
                ("linux.group", 2),
                ("linux.host", 1),
                ("linux.login", 1),
                ("linux.service", 1),
                ("linux.shellhistory", 2),
                ("linux.software", 1),
                ("linux.systeminfo", 4),
                ("linux.timezone", 1),
                ("linux.user", 2),
                ("profile.fact", 3),
            ]
            .map(|(record_type, count)| (record_type.to_owned(), count))
        )
    );
    assert!(run.warnings.is_empty(), "{:?}", run.warnings);

    let root = run
        .of_type("linux.user")
        .into_iter()
        .find(|user| user.text("username") == Some("root"))
        .expect("root user");
    assert_eq!(root.title, "root");
    assert_eq!(root.int("uid"), Some(0));
    assert_eq!(root.text("password_algo"), Some("yescrypt"));
    assert_eq!(
        root.text("password_last_change"),
        Some("2024-05-12T00:00:00+00:00")
    );
    assert_eq!(
        root.sources
            .iter()
            .map(|source| source.path.as_deref().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec!["etc/passwd", "etc/shadow"]
    );

    let sudo = run
        .of_type("linux.shellhistory")
        .into_iter()
        .find(|record| record.text("command") == Some("sudo -i"))
        .expect("history from the separate /home volume");
    assert_eq!(sudo.sources[0].root.as_deref(), Some("part:1"));
    assert_eq!(sudo.sources[0].path.as_deref(), Some("kali/.zsh_history"));
    assert_eq!(sudo.sources[0].note.as_deref(), Some("第 1 行"));
    assert_eq!(sudo.text("time"), Some("2023-11-14T22:16:40+00:00"));

    let login = &run.of_type("linux.login")[0];
    assert_eq!(login.title, "kali @ pts/0");
    assert_eq!(login.text("remote_host"), Some("10.0.0.5"));
    assert_eq!(login.text("logout_time"), Some("2023-11-14T22:23:20+00:00"));
    assert_eq!(login.get("duration"), Some(&Value::F64(600.0)));
    assert_eq!(
        (login.sources[0].offset, login.sources[0].length),
        (Some(0), Some(384))
    );

    let service = &run.of_type("linux.service")[0];
    assert_eq!(service.title, "ssh.service");
    assert_eq!(service.text("enabled"), Some("是"));
    assert_eq!(
        service.text("unit"),
        Some("usr/lib/systemd/system/ssh.service")
    );

    let facts: BTreeMap<_, _> = run
        .of_type("profile.fact")
        .into_iter()
        .map(|fact| {
            (
                fact.text("key").unwrap_or_default().to_owned(),
                fact.get("value").cloned(),
            )
        })
        .collect();
    assert_eq!(facts["timezone"], Some(Value::from("Asia/Shanghai")));
    assert_eq!(facts["hostname"], Some(Value::from("kali-box")));
    assert!(facts["users"].as_ref().is_some_and(Value::is_map));
}

#[test]
fn selected_sub_items_limit_the_run() {
    let fixtures = fixtures();
    let run = run(&fixtures, &["users"]);
    assert_eq!(
        run.counts(),
        BTreeMap::from([("linux.user".to_owned(), 2), ("profile.fact".to_owned(), 1),])
    );
}

#[test]
fn a_failing_sub_item_becomes_a_warning() {
    let fixtures = fixtures();
    // A wtmp with a torn record: logins fail, everything else still runs.
    write(&fixtures.root.path().join("var/log/wtmp"), &[0_u8; 100]);
    let run = run(&fixtures, &["users", "logins"]);
    assert_eq!(run.count("linux.user"), 2);
    assert_eq!(run.count("linux.login"), 0);
    assert_eq!(run.warnings.len(), 1);
    assert!(
        run.warnings[0].1.starts_with("登录信息："),
        "{:?}",
        run.warnings
    );
}
