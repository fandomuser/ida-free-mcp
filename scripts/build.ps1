# Builds the idamcp IDA plugin and its unit tests (Release, x64, Ninja + MSVC).
# Usage: powershell -ExecutionPolicy Bypass -File scripts/build.ps1 [-Test]
param([switch]$Test)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
. (Join-Path $root 'scripts\msvc_env.ps1')

$sdk = Join-Path $root 'third_party\ida-sdk'
if (-not (Test-Path (Join-Path $sdk 'src\include\pro.h'))) {
    throw "IDA SDK not found at $sdk. Run: git clone --depth 1 --branch v9.5.0-release https://github.com/HexRaysSA/ida-sdk third_party/ida-sdk"
}
$env:IDASDK = $sdk
$env:IDABIN = Join-Path $root 'build\out'
$build = Join-Path $root 'build\plugin'

cmake -S (Join-Path $root 'plugin') -B $build -G Ninja -DCMAKE_BUILD_TYPE=Release
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed" }
cmake --build $build
if ($LASTEXITCODE -ne 0) { throw "Build failed" }

$dll = Join-Path $env:IDABIN 'plugins\idamcp.dll'
Write-Host "Plugin: $dll"
if ($Test) {
    & (Join-Path $build 'idamcp_unit_tests.exe')
    if ($LASTEXITCODE -ne 0) { throw "Unit tests failed" }
}
