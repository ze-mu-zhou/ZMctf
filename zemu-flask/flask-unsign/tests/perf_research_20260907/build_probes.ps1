$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$originalPath = $env:PATH
Push-Location $repoRoot
try {
    $env:PATH = 'C:/msys64/ucrt64/bin;' + $env:PATH
    & C:/msys64/ucrt64/bin/g++.exe -O3 -std=c++26 -Wall -municode -static -static-libgcc -static-libstdc++ src/main.cpp src/flask.cpp src/crack_cpu.cpp src/gpu/ocl.cpp src/gpu/nvrtc.cpp -o tests/perf_research_20260907/baseline.exe -lz
    if ($LASTEXITCODE -ne 0) { throw 'baseline compilation failed' }
    & C:/msys64/ucrt64/bin/g++.exe -O3 -std=c++26 -Wall -static -static-libgcc -static-libstdc++ tests/perf_research_20260907/loader_probe.cpp -o tests/perf_research_20260907/loader_probe.exe -lpsapi
    if ($LASTEXITCODE -ne 0) { throw 'loader compilation failed' }
} finally {
    $env:PATH = $originalPath
    Pop-Location
}
