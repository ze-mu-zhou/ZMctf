# ZMctf（模块化取证分析套件）

本仓库作为 **主控仓库（meta-repo）**，用于统一组织多个功能模块与桌面 GUI。

## 目录结构

- `flag-detector/core/`：Git submodule（模块 1：明文/常规编码 Flag 检测；workspace 内包含 `floss-integration` / `tool-runner` 等原子 crate）
- `zmctf-desktop/`：桌面 GUI（主入口：Tauri + React + Tailwind）
- `zmctf-desktop-legacy-egui/`：旧版 GUI（eframe/egui，已降级为可选）

## 子模块初始化

初始化并拉取子模块：

```powershell
git submodule update --init --recursive
```

## 启动 flag-detector 后端 API

在 `flag-detector/core/` 下运行：

```powershell
cargo run -p flag-detector --bin zmctf-server
```

默认监听：`0.0.0.0:8080`

## 启动桌面 GUI

在 `zmctf-desktop/` 下运行：

```powershell
npm install
npm run tauri dev
```

## 最严格自检（每次写代码后必跑）

在仓库根目录运行：

```powershell
.\scripts\verify.ps1
```

脚本标准（必须通过）：

- 严格 clippy：`cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings -D clippy::all -D clippy::pedantic -D clippy::nursery -D clippy::cargo`（输出：`clippy_flag_detector.log`）
- 格式校验：`cargo fmt --all -- --check`
- 全量测试：`cargo test --workspace --all-features --locked --offline`
- 规避检查扫描：未发现 workspace 成员源码存在 `#[allow(clippy::...)]`
- 多语言统一检测：若仓库中出现对应语言源码，将自动触发 Python（Ruff+Mypy）、JS/TS（Biome+Oxlint+tsc）、Go（golangci-lint）、C/C++（clang-tidy）、HTML（markuplint）、CSS（stylelint）的极限严格检查（缺少工具会直接失败）
- MegaLinter（YAML/JSON 基线）：需要 Docker；配置文件为 `.mega-linter.yml`；可用 `ZMCTF_SKIP_MEGALINTER=1` 跳过


