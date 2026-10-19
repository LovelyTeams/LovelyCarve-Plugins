# LovelyCarve-Plugins

[LovelyCarve](https://github.com/LovelyTeams/LovelyCarve) 的插件工作区，以 Git 子模块方式部署在主仓库的 `plugins/`。插件遵循 LPP v2：每个插件包由清单、动态库、记录结构（`schema.json`）与语言包组成。

| 目录 | 用途 |
| --- | --- |
| `linuxinfo` | Linux 基本信息系统级分析器（随 LovelyCarve 安装包附带），覆盖系统、时区、用户、登录、历史命令、网络、服务、软件、计划任务与用户痕迹等十五个子项 |
| `sdk` | `lovelycarve-plugin`：C ABI v1、LPP v2 载荷、记录结构、Rust 插件接口与 `testing` 测试工具 |
| `sdk-derive` | `#[derive(Record)]` |
| `host` | `lc-plugin-host`，进程隔离加载器；`--describe` 导出库的分析器与记录结构 |

## 开发

准备 Rust stable、Bun 和 just，在本仓库根目录执行：

```text
just build
just test
just clippy
just fmt
```

`just build` 构建宿主与插件库，把平台动态库复制到各插件的 `plugin.toml` 旁，并写出 `schema.json`；`just build --release` 构建发布库，`just build --plugin <目录>` 只构建一个插件库。构建脚本使用提交的 Cargo.lock；宿主在 `target/debug/` 或 `target/release/`。

插件的单元测试可以用 SDK 的 `testing::Harness` 在本地目录上运行分析器，不需要 LovelyCarve。主应用中的集成、打包与测试通过主仓库 `just build-plugins`、`just pack-plugins`、`just test-plugins`、`just clippy-plugins` 执行。主仓库固定子模块提交；修改插件后先提交、推送此仓库，再提交主仓库的子模块引用。

## 部署与接口

插件包目录包含 `plugin.toml`、动态库、`schema.json` 与 `locales/`；`lc-plugin-host` 位于 LovelyCarve 主程序旁。主仓库的 `just pack-plugins` 为每个插件生成 `.lcpkg`，在 LovelyCarve「设置 → 插件」或命令行 `plugins create` 安装。已发现的插件视为可信代码；隔离进程不提供操作系统权限沙箱。

协议、清单、记录结构与 SDK 见主仓库的 [插件协议](https://github.com/LovelyTeams/LovelyCarve/blob/main/docs/PLUGIN_PROTOCOL.md)，linuxinfo 的来源与限制见 [linuxinfo 文档](https://github.com/LovelyTeams/LovelyCarve/blob/main/docs/LINUXINFO.md)。

## 许可

项目代码采用 [AGPL-3.0-only](LICENSE)。依赖保留各自许可，来源与版本由 Cargo.toml / Cargo.lock 记录。不要提交真实检材、案件、凭据或生成的二进制。
