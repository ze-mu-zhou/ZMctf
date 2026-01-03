$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$env:PYTHONIOENCODING = "utf-8"

function Write-Section {
    param([Parameter(Mandatory = $true)][string]$Title)
    Write-Host ("== {0} ==" -f $Title) -ForegroundColor Cyan
}

function Assert-Exists {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        throw $Message
    }
}

function Assert-Command {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Hint
    )
    if ($null -eq (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw $Hint
    }
}

function Resolve-NodeTool {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$ExcludePathRegex
    )

    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        return [pscustomobject]@{
            Path    = $cmd.Source
            BaseDir = $null
        }
    }

    $candidateNames = @("$Name.cmd", $Name)
    $binDirs = New-Object System.Collections.Generic.List[string]

    $binDirs.Add((Join-Path $RepoRoot "node_modules/.bin"))

    $pkgFiles = Get-ChildItem -Path $RepoRoot -Recurse -File -Filter "package.json" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch $ExcludePathRegex }

    foreach ($pkg in $pkgFiles) {
        $binDirs.Add((Join-Path $pkg.Directory.FullName "node_modules/.bin"))
    }

    foreach ($binDir in $binDirs) {
        foreach ($candidate in $candidateNames) {
            $p = Join-Path $binDir $candidate
            if (Test-Path -LiteralPath $p) {
                $baseDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $p))
                return [pscustomobject]@{
                    Path    = $p
                    BaseDir = $baseDir
                }
            }
        }
    }

    return $null
}

function Test-AnyFiles {
    param(
        [Parameter(Mandatory = $true)][string[]]$Patterns,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$ExcludePathRegex
    )

    foreach ($pattern in $Patterns) {
        $found = Get-ChildItem -Path $Root -Recurse -File -Filter $pattern -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch $ExcludePathRegex } |
            Select-Object -First 1
        if ($null -ne $found) {
            return $true
        }
    }
    return $false
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$WorkDir,
        [Parameter(Mandatory = $true)][ScriptBlock]$Command,
        [Parameter(Mandatory = $true)][string]$FailMessage
    )

    Push-Location $WorkDir
    try {
        $prevPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            & $Command
        } finally {
            $ErrorActionPreference = $prevPreference
        }
        if ($LASTEXITCODE -ne 0) {
            throw $FailMessage
        }
    } finally {
        Pop-Location
    }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$excludeRegex = '[\\/](\.git|target|node_modules|\.venv|\.mypy_cache|\.ruff_cache|\.npm-cache|dist|build|vendor|megalinter-reports)[\\/]'
$prefetch = $env:ZMCTF_CI_PREFETCH -eq "1"
$skipMegaLinter = $env:ZMCTF_SKIP_MEGALINTER -eq "1"

Assert-Command -Name "cargo" -Hint "未找到 cargo（需要 Rust 工具链）。"

Write-Section "Rust: flag-detector/core（rustfmt）"
Assert-Exists -Path (Join-Path $repoRoot "flag-detector/core/Cargo.toml") -Message "缺少子模块：请先执行 git submodule update --init --recursive。"
if ($prefetch) {
    Write-Section "Rust: flag-detector/core（依赖预拉取）"
    Invoke-Checked -WorkDir (Join-Path $repoRoot "flag-detector/core") -FailMessage "cargo fetch 未通过（flag-detector/core）。" -Command {
        cargo fetch --locked
    }
}
Invoke-Checked -WorkDir (Join-Path $repoRoot "flag-detector/core") -FailMessage "rustfmt 未通过（flag-detector/core）。" -Command {
    cargo fmt --all -- --check
}

Write-Section "Rust: flag-detector/core（clippy 极限严格 + 记录日志）"
$clippyLog = Join-Path $repoRoot "clippy_flag_detector.log"
Push-Location (Join-Path $repoRoot "flag-detector/core")
try {
    $clippyCmd =
        'cargo clippy --workspace --all-targets --all-features --locked --offline -- ' +
        '-D warnings -D clippy::all -D clippy::pedantic -D clippy::nursery -D clippy::cargo ' +
        '> "' +
        $clippyLog +
        '" 2>&1'

    cmd /c $clippyCmd

    if ($LASTEXITCODE -ne 0) {
        if (Test-Path -LiteralPath $clippyLog) {
            Write-Host "clippy 输出尾部（最多 200 行）："
            Get-Content -LiteralPath $clippyLog -Tail 200
        }
        throw ("clippy 未通过（flag-detector/core）。详见：{0}" -f $clippyLog)
    }

    Assert-Exists -Path $clippyLog -Message ("clippy 已运行，但未生成日志文件：{0}" -f $clippyLog)
    Write-Host ("clippy 输出已写入：{0}" -f $clippyLog) -ForegroundColor Green
} finally {
    Pop-Location
}

Write-Section "Rust: flag-detector/core（全量测试）"
Invoke-Checked -WorkDir (Join-Path $repoRoot "flag-detector/core") -FailMessage "cargo test 未通过（flag-detector/core）。" -Command {
    cargo test --workspace --all-features --locked --offline
}

Write-Section "Rust: 规避检查扫描（禁止 #[allow(clippy::...)]）"
$rsFiles = Get-ChildItem -Path $repoRoot -Recurse -File -Filter "*.rs" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch $excludeRegex }
$pattern = '#\[\s*allow\(\s*clippy::'
$hits = $rsFiles | Select-String -Pattern $pattern
if ($null -ne $hits) {
    Write-Host "发现疑似规避 clippy 的 allow 标记（禁止）："
    $hits | ForEach-Object { Write-Host ("- {0}:{1}: {2}" -f $_.Path, $_.LineNumber, $_.Line.Trim()) }
    throw "规避检查扫描未通过：存在 #[allow(clippy::...)]。"
}
Write-Host "规避检查扫描：通过（未发现 #[allow(clippy::...)]）。" -ForegroundColor Green

Write-Section "Rust: zmctf-desktop/src-tauri（rustfmt + clippy 极限严格 + 测试）"
Assert-Exists -Path (Join-Path $repoRoot "zmctf-desktop/src-tauri/Cargo.toml") -Message "缺少 zmctf-desktop/src-tauri。"
if ($prefetch) {
    Write-Section "Rust: zmctf-desktop/src-tauri（依赖预拉取）"
    Invoke-Checked -WorkDir (Join-Path $repoRoot "zmctf-desktop/src-tauri") -FailMessage "cargo fetch 未通过（zmctf-desktop/src-tauri）。" -Command {
        cargo fetch --locked
    }
}
Invoke-Checked -WorkDir (Join-Path $repoRoot "zmctf-desktop/src-tauri") -FailMessage "rustfmt 未通过（zmctf-desktop/src-tauri）。" -Command {
    cargo fmt --all -- --check
}
Invoke-Checked -WorkDir (Join-Path $repoRoot "zmctf-desktop/src-tauri") -FailMessage "clippy 未通过（zmctf-desktop/src-tauri）。" -Command {
    cargo clippy --all-targets --all-features --locked --offline -- `
        -D warnings `
        -D clippy::all `
        -D clippy::pedantic `
        -D clippy::nursery `
        -D clippy::cargo `
        -A clippy::multiple_crate_versions
}
Invoke-Checked -WorkDir (Join-Path $repoRoot "zmctf-desktop/src-tauri") -FailMessage "cargo test 未通过（zmctf-desktop/src-tauri）。" -Command {
    cargo test --all-features --locked --offline
}

if (Test-Path -LiteralPath (Join-Path $repoRoot "zmctf-desktop-legacy-egui/Cargo.toml")) {
    Write-Section "Rust: zmctf-desktop-legacy-egui（可选：旧 egui GUI）"
    if ($prefetch) {
        Write-Section "Rust: zmctf-desktop-legacy-egui（依赖预拉取）"
        Invoke-Checked -WorkDir (Join-Path $repoRoot "zmctf-desktop-legacy-egui") -FailMessage "cargo fetch 未通过（zmctf-desktop-legacy-egui）。" -Command {
            cargo fetch --locked
        }
    }
    Invoke-Checked -WorkDir (Join-Path $repoRoot "zmctf-desktop-legacy-egui") -FailMessage "rustfmt 未通过（zmctf-desktop-legacy-egui）。" -Command {
        cargo fmt --all -- --check
    }
    Invoke-Checked -WorkDir (Join-Path $repoRoot "zmctf-desktop-legacy-egui") -FailMessage "clippy 未通过（zmctf-desktop-legacy-egui）。" -Command {
        cargo clippy --all-targets --all-features --locked --offline -- `
            -D warnings `
            -D clippy::all `
            -D clippy::pedantic `
            -D clippy::nursery `
            -D clippy::cargo `
            -A clippy::multiple_crate_versions
    }
    Invoke-Checked -WorkDir (Join-Path $repoRoot "zmctf-desktop-legacy-egui") -FailMessage "cargo test 未通过（zmctf-desktop-legacy-egui）。" -Command {
        cargo test --all-features --locked --offline
    }
} else {
    Write-Host "Rust: zmctf-desktop-legacy-egui：跳过（未发现）。" -ForegroundColor DarkGray
}

Write-Section "多语言：按需触发的极限严格检查"

if (Test-AnyFiles -Root $repoRoot -ExcludePathRegex $excludeRegex -Patterns @("*.py", "*.pyi")) {
    Write-Section "Python：Ruff + Mypy（极限严格）"
    Assert-Command -Name "python" -Hint "未找到 python（需要 Python 3.11+）。"
    if ($null -eq (Get-Command "ruff" -ErrorAction SilentlyContinue)) {
        throw "检测到 Python 代码，但未找到 ruff。建议：python -m pip install ruff"
    }
    if ($null -eq (Get-Command "mypy" -ErrorAction SilentlyContinue)) {
        throw "检测到 Python 代码，但未找到 mypy。建议：python -m pip install mypy"
    }

    Invoke-Checked -WorkDir $repoRoot -FailMessage "ruff check 未通过。" -Command {
        ruff check .
    }
    Invoke-Checked -WorkDir $repoRoot -FailMessage "ruff format --check 未通过。" -Command {
        ruff format --check .
    }
    Invoke-Checked -WorkDir $repoRoot -FailMessage "mypy strict 未通过。" -Command {
        mypy .
    }
} else {
    Write-Host "Python：跳过（未发现 *.py / *.pyi）。" -ForegroundColor DarkGray
}

$hasJsTs = Test-AnyFiles -Root $repoRoot -ExcludePathRegex $excludeRegex -Patterns @("*.js", "*.jsx", "*.ts", "*.tsx")
if ($hasJsTs) {
    Write-Section "JavaScript/TypeScript：Biome + Oxlint（极限严格）"
    Assert-Command -Name "node" -Hint "检测到 JS/TS 代码，但未找到 node。"

    $biomeTool = Resolve-NodeTool -Name "biome" -RepoRoot $repoRoot -ExcludePathRegex $excludeRegex
    if ($null -eq $biomeTool) {
        throw "检测到 JS/TS 代码，但未找到 biome（建议在包含 package.json 的目录执行 npm install）。"
    }
    $oxlintTool = Resolve-NodeTool -Name "oxlint" -RepoRoot $repoRoot -ExcludePathRegex $excludeRegex
    if ($null -eq $oxlintTool) {
        throw "检测到 JS/TS 代码，但未找到 oxlint（建议在包含 package.json 的目录执行 npm install）。"
    }

    Invoke-Checked -WorkDir $repoRoot -FailMessage "biome check 未通过。" -Command {
        & $biomeTool.Path check .
    }
    Invoke-Checked -WorkDir $repoRoot -FailMessage "oxlint 未通过。" -Command {
        & $oxlintTool.Path .
    }

    if (Test-AnyFiles -Root $repoRoot -ExcludePathRegex $excludeRegex -Patterns @("*.ts", "*.tsx")) {
        $tscTool = Resolve-NodeTool -Name "tsc" -RepoRoot $repoRoot -ExcludePathRegex $excludeRegex
        if ($null -eq $tscTool) {
            throw "检测到 TypeScript 代码，但未找到 tsc（建议在包含 package.json 的目录执行 npm install）。"
        }

        $tsConfigs = @(
            Get-ChildItem -Path $repoRoot -Recurse -File -Filter "tsconfig.json" -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch $excludeRegex } |
                Where-Object { Test-Path -LiteralPath (Join-Path $_.Directory.FullName "package.json") }
        )

        if ($tsConfigs.Count -eq 0) {
            throw "检测到 TypeScript 代码，但未找到可用的 tsconfig.json（要求与 package.json 同目录）。"
        }

        foreach ($cfg in $tsConfigs) {
            Invoke-Checked -WorkDir $cfg.Directory.FullName -FailMessage ("tsc strict 未通过：{0}" -f $cfg.FullName) -Command {
                & $tscTool.Path -p $cfg.FullName --noEmit
            }
        }
    } else {
        Write-Host "TypeScript：跳过（未发现 *.ts / *.tsx）。" -ForegroundColor DarkGray
    }
} else {
    Write-Host "JavaScript/TypeScript：跳过（未发现 *.js/*.ts 等）。" -ForegroundColor DarkGray
}

if (Test-AnyFiles -Root $repoRoot -ExcludePathRegex $excludeRegex -Patterns @("*.go")) {
    Write-Section "Go：golangci-lint（极限严格）"
    if ($null -eq (Get-Command "golangci-lint" -ErrorAction SilentlyContinue)) {
        throw "检测到 Go 代码，但未找到 golangci-lint。"
    }
    Invoke-Checked -WorkDir $repoRoot -FailMessage "golangci-lint 未通过。" -Command {
        golangci-lint run --enable-all
    }
} else {
    Write-Host "Go：跳过（未发现 *.go）。" -ForegroundColor DarkGray
}

$hasCpp = Test-AnyFiles -Root $repoRoot -ExcludePathRegex $excludeRegex -Patterns @("*.c", "*.cc", "*.cpp", "*.cxx", "*.h", "*.hh", "*.hpp", "*.hxx")
if ($hasCpp) {
    Write-Section "C/C++：clang-tidy（极限严格）"
    if ($null -eq (Get-Command "clang-tidy" -ErrorAction SilentlyContinue)) {
        throw "检测到 C/C++ 代码，但未找到 clang-tidy。"
    }

    $compileDb = Get-ChildItem -Path $repoRoot -Recurse -File -Filter "compile_commands.json" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch $excludeRegex } |
        Select-Object -First 1
    if ($null -eq $compileDb) {
        throw "检测到 C/C++ 代码，但未找到 compile_commands.json（clang-tidy 需要编译数据库）。"
    }

    $compileDbDir = Split-Path -Parent $compileDb.FullName
    $cxxFiles = Get-ChildItem -Path $repoRoot -Recurse -File -Include "*.c", "*.cc", "*.cpp", "*.cxx" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch $excludeRegex }

    foreach ($f in $cxxFiles) {
        Invoke-Checked -WorkDir $repoRoot -FailMessage ("clang-tidy 未通过：{0}" -f $f.FullName) -Command {
            clang-tidy -p $compileDbDir $f.FullName
        }
    }
} else {
    Write-Host "C/C++：跳过（未发现 *.c/*.cpp 等）。" -ForegroundColor DarkGray
}

if (Test-AnyFiles -Root $repoRoot -ExcludePathRegex $excludeRegex -Patterns @("*.html", "*.htm")) {
    Write-Section "HTML：markuplint（极限严格）"
    Assert-Command -Name "node" -Hint "检测到 HTML，但未找到 node。"
    $markuplintTool = Resolve-NodeTool -Name "markuplint" -RepoRoot $repoRoot -ExcludePathRegex $excludeRegex
    if ($null -eq $markuplintTool) {
        throw "检测到 HTML，但未找到 markuplint（建议在包含 package.json 的目录执行 npm install）。"
    }
    Invoke-Checked -WorkDir $repoRoot -FailMessage "markuplint 未通过。" -Command {
        & $markuplintTool.Path .
    }
} else {
    Write-Host "HTML：跳过（未发现 *.html）。" -ForegroundColor DarkGray
}

if (Test-AnyFiles -Root $repoRoot -ExcludePathRegex $excludeRegex -Patterns @("*.css", "*.scss", "*.sass")) {
    Write-Section "CSS：stylelint（极限严格）"
    Assert-Command -Name "node" -Hint "检测到 CSS/SCSS，但未找到 node。"
    $stylelintTool = Resolve-NodeTool -Name "stylelint" -RepoRoot $repoRoot -ExcludePathRegex $excludeRegex
    if ($null -eq $stylelintTool) {
        throw "检测到 CSS/SCSS，但未找到 stylelint（建议在包含 package.json 的目录执行 npm install）。"
    }
    Invoke-Checked -WorkDir $repoRoot -FailMessage "stylelint 未通过。" -Command {
        if ($null -eq $stylelintTool.BaseDir) {
            & $stylelintTool.Path "**/*.css" "**/*.scss" "**/*.sass"
        } else {
            & $stylelintTool.Path --config (Join-Path $repoRoot ".stylelintrc") --config-basedir $stylelintTool.BaseDir "**/*.css" "**/*.scss" "**/*.sass"
        }
    }
} else {
    Write-Host "CSS：跳过（未发现 *.css/*.scss）。" -ForegroundColor DarkGray
}

if (-not $skipMegaLinter) {
    Write-Section "MegaLinter：YAML/JSON（Docker）"
    Assert-Command -Name "docker" -Hint "未找到 docker（需要 Docker Desktop/Engine）。可设置 ZMCTF_SKIP_MEGALINTER=1 跳过。"
    Invoke-Checked -WorkDir $repoRoot -FailMessage "MegaLinter 未通过。" -Command {
        $repo = (Resolve-Path ".").Path
        docker run --rm -v "${repo}:/tmp/lint:rw" ghcr.io/oxsecurity/megalinter-ci_light:v9.2.0
    }
} else {
    Write-Host "MegaLinter：跳过（ZMCTF_SKIP_MEGALINTER=1）。" -ForegroundColor DarkGray
}

Write-Host "全部检查通过。" -ForegroundColor Green

