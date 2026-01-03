# Repository Guidelines

## 项目结构
- `core/`：Rust workspace 根目录（当前仓库仅保留后端逻辑，所有修改应聚焦于此）。
  - `core/flag-detector/`：核心分析与检测逻辑（字符串提取、解码链、规则、归档分析、缓存、`server` 二进制入口）。
  - `core/floss-integration/`：对外部 `floss` 工具的集成封装（runner + 类型定义）。
  - `core/tool-runner/`：统一外部命令执行器（timeout/输出截断/环境变量）；不要直接使用 `std::process::Command`。
- `core/target/`：本地构建产物（不应作为代码变更的一部分提交）。
- `core/Cargo.lock`：依赖锁文件（建议随仓库提交，确保 `--locked --offline` 可复现）。

## 构建、测试与开发命令
在 `core/` 目录下运行：
- `cargo check --workspace --all-targets --all-features --locked --offline`：全量编译检查（离线、锁定依赖）。
- `cargo test -p flag-detector --all-features --locked --offline`：运行核心单测与 doc tests。
- `cargo test -p tool-runner --locked --offline`：运行外部命令执行器单测。
- `cargo check -p floss-integration --locked --offline`：只编译 floss 集成层。
- `cargo fmt --all -- --check`：格式校验（提交前必跑）。
- `cargo clippy --all-targets --all-features -- -D warnings`：静态检查（以 0 warnings 为门槛）。
- 一键自检（PowerShell）：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --all-features --locked --offline
```

## 编码风格与命名约定
- Rust 代码遵循 `rustfmt` 默认风格；避免无关重构，优先小步、可回滚的原子改动。
- 命名：模块/文件 `snake_case`；类型/trait `PascalCase`；常量 `SCREAMING_SNAKE_CASE`。
- 错误处理：对外边界使用 `anyhow`，尽量附带上下文（`with_context`）。
- 生产代码避免 `unwrap/expect`（已启用 clippy gate）；需要快速失败的场景应返回可诊断错误。

## 测试指南
- 单测就近放置于模块内 `#[cfg(test)]`；测试名使用行为描述（如 `test_extract_to_dir_rejects_path_traversal`）。
- 修复缺陷优先补回归测试；新增能力必须附带最小覆盖测试与可复现实例。

## 运行与配置
- 启动 API：在 `core/` 下执行 `cargo run -p flag-detector --bin zmctf-server`（默认监听 `0.0.0.0:8080`）。
- 日志：PowerShell 示例 ` $env:RUST_LOG="info"; cargo run -p flag-detector --bin zmctf-server`。
- 配置：`AppConfig` 会读取 `config.toml`（默认路径由 `AppConfig::default_config_path()` 决定；实现见 `core/flag-detector/src/config.rs`）。

## 外部工具与安全
- 外部工具为可选依赖（如 `tshark`/`hashcat`/`unrar`/`floss`）；缺失时应保持核心逻辑可运行。
- 新增/修改外部命令调用必须走 `tool-runner`，并显式设置 `timeout` 与 `stdout/stderr` 上限，避免卡死与内存膨胀。
- 处理归档/路径输入时默认不信任来源，避免路径穿越与覆盖写入（相关用例见归档解包测试）。

## 提交与 PR 指南
- Git 历史提交多见格式：`[Claude Code] ... prompt #N`；新提交建议采用“动词 + 范围 + 原因”（如 `fix(cache): stream sha256 hashing`）。
- PR 必须包含：变更动机、影响范围、验证命令与输出、风险点与回滚方式。
- 作为大项目子模块：不要引入任何前端资源、UI 依赖或静态站点文件；保持后端逻辑独立可复用。

