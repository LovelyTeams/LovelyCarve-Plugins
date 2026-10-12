# LovelyCarve-Plugins

[LovelyCarve](https://github.com/LovelyTeams/LovelyCarve) 的插件工作区，以 Git 子模块方式部署在主仓库的 `plugins/`。目前只提供 `linuxinfo` 分析插件，版本为 `1.0.0`。

| 目录 | 用途 |
| --- | --- |
| `linuxinfo` | Linux 基本信息检材级分析器，包含系统、时区、用户、登录、历史命令、网络、服务、软件、计划任务与用户痕迹等十五个子项 |
| `sdk` | `lovelycarve-plugin`，C ABI v1、LPP v1 和 Rust 插件接口 |
| `host` | `lc-plugin-host`，进程隔离加载器 |

## 开发

准备 Rust stable、Bun 和 just，在本仓库根目录执行：

```text
just build
just test
just clippy
just fmt
```

`just build --release` 构建发布库和宿主。构建脚本使用提交的 Cargo.lock，将平台动态库复制到 `linuxinfo/plugin.toml` 旁；宿主在 `target/debug/` 或 `target/release/`。

主应用中的集成与测试仍通过主仓库 `just build-plugins`、`just test-plugins`、`just clippy-plugins` 执行。主仓库固定子模块提交；修改插件后先提交、推送此仓库，再提交主仓库的子模块引用。

## 部署与接口

插件目录需同时包含清单和动态库，`lc-plugin-host` 放在主程序旁。更新前退出应用，启动后重新发现插件。已发现插件视为可信代码；隔离进程不提供操作系统权限沙箱。

分析器 ID 为 `org.lovelycarve.linuxinfo/linuxbaseinfo`，证据访问只读。协议与工件来源见主仓库的 [LPP 文档](https://github.com/LovelyTeams/LovelyCarve/blob/main/docs/PLUGIN_PROTOCOL.md) 和 [linuxinfo 文档](https://github.com/LovelyTeams/LovelyCarve/blob/main/docs/LINUXINFO.md)。

## 许可

项目代码采用 [AGPL-3.0-only](LICENSE)。依赖保留各自许可，来源与版本由 Cargo.toml / Cargo.lock 记录。不要提交真实检材、案件、凭据或生成的二进制。
