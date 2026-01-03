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
$excludeRegex = '[\\/](\.git|target|node_modules|\.venv|\.mypy_cache|\.ruff_cache|dist|build|vendor|megalinter-reports)[\\/]'
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
    if (Test-Path -LiteralPath $clippyLog) {
        Remove-Item -LiteralPath $clippyLog -Force
    }

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
$coreRoot = Join-Path $repoRoot "flag-detector/core"
$scanDirs = @(
    (Join-Path $coreRoot "flag-detector/src"),
    (Join-Path $coreRoot "floss-integration/src"),
    (Join-Path $coreRoot "tool-runner/src"),
    (Join-Path $coreRoot "zmctf-constraints/src"),
    (Join-Path $repoRoot "zmctf-desktop/src")
)
foreach ($d in $scanDirs) {
    Assert-Exists -Path $d -Message ("扫描目录不存在：{0}" -f $d)
}

$rsFiles = foreach ($d in $scanDirs) {
    Get-ChildItem -Path $d -Recurse -File -Filter "*.rs" -ErrorAction SilentlyContinue
}
$pattern = '#\[\s*allow\(\s*clippy::'
$hits = $rsFiles | Select-String -Pattern $pattern
if ($null -ne $hits) {
    Write-Host "发现疑似规避 clippy 的 allow 标记（禁止）："
    $hits | ForEach-Object { Write-Host ("- {0}:{1}: {2}" -f $_.Path, $_.LineNumber, $_.Line.Trim()) }
    throw "规避检查扫描未通过：存在 #[allow(clippy::...)]。"
}
Write-Host "规避检查扫描：通过（未发现 #[allow(clippy::...)]）。" -ForegroundColor Green

Write-Section "Rust: zmctf-desktop（rustfmt + clippy 极限严格 + 测试）"
Assert-Exists -Path (Join-Path $repoRoot "zmctf-desktop/Cargo.toml") -Message "缺少 zmctf-desktop。"
if ($prefetch) {
    Write-Section "Rust: zmctf-desktop（依赖预拉取）"
    Invoke-Checked -WorkDir (Join-Path $repoRoot "zmctf-desktop") -FailMessage "cargo fetch 未通过（zmctf-desktop）。" -Command {
        cargo fetch --locked
    }
}
Invoke-Checked -WorkDir (Join-Path $repoRoot "zmctf-desktop") -FailMessage "rustfmt 未通过（zmctf-desktop）。" -Command {
    cargo fmt --all -- --check
}
Invoke-Checked -WorkDir (Join-Path $repoRoot "zmctf-desktop") -FailMessage "clippy 未通过（zmctf-desktop）。" -Command {
    cargo clippy --all-targets --all-features --locked --offline -- `
        -D warnings `
        -D clippy::all `
        -D clippy::pedantic `
        -D clippy::nursery `
        -D clippy::cargo `
        -A clippy::multiple_crate_versions
}
Invoke-Checked -WorkDir (Join-Path $repoRoot "zmctf-desktop") -FailMessage "cargo test 未通过（zmctf-desktop）。" -Command {
    cargo test --all-features --locked --offline
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
    if ($null -eq (Get-Command "biome" -ErrorAction SilentlyContinue)) {
        throw "检测到 JS/TS 代码，但未找到 biome。请安装 Biome 并确保 biome 在 PATH。"
    }
    if ($null -eq (Get-Command "oxlint" -ErrorAction SilentlyContinue)) {
        throw "检测到 JS/TS 代码，但未找到 oxlint。请安装 oxlint 并确保 oxlint 在 PATH。"
    }

    Invoke-Checked -WorkDir $repoRoot -FailMessage "biome check 未通过。" -Command {
        biome check .
    }
    Invoke-Checked -WorkDir $repoRoot -FailMessage "oxlint 未通过。" -Command {
        oxlint .
    }

    if (Test-AnyFiles -Root $repoRoot -ExcludePathRegex $excludeRegex -Patterns @("*.ts", "*.tsx")) {
        if ($null -eq (Get-Command "tsc" -ErrorAction SilentlyContinue)) {
            throw "检测到 TypeScript 代码，但未找到 tsc（TypeScript 编译器）。"
        }
        Invoke-Checked -WorkDir $repoRoot -FailMessage "tsc strict 未通过。" -Command {
            tsc -p tsconfig.json --noEmit
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
    if ($null -eq (Get-Command "markuplint" -ErrorAction SilentlyContinue)) {
        throw "检测到 HTML，但未找到 markuplint。"
    }
    Invoke-Checked -WorkDir $repoRoot -FailMessage "markuplint 未通过。" -Command {
        markuplint .
    }
} else {
    Write-Host "HTML：跳过（未发现 *.html）。" -ForegroundColor DarkGray
}

if (Test-AnyFiles -Root $repoRoot -ExcludePathRegex $excludeRegex -Patterns @("*.css", "*.scss", "*.sass")) {
    Write-Section "CSS：stylelint（极限严格）"
    if ($null -eq (Get-Command "stylelint" -ErrorAction SilentlyContinue)) {
        throw "检测到 CSS/SCSS，但未找到 stylelint。"
    }
    Invoke-Checked -WorkDir $repoRoot -FailMessage "stylelint 未通过。" -Command {
        stylelint "**/*.css" "**/*.scss" "**/*.sass"
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

