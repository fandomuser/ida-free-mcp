# Builds tests/fixtures/sample.exe with MSVC (x64, no optimisation, no PDB).
# Usage: powershell -ExecutionPolicy Bypass -File tests/fixtures/build_fixture.ps1
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $here '..\..\scripts\msvc_env.ps1')
Push-Location $here
try {
    & cl.exe /nologo /Od /Ob0 /GS- /MT /Fe:sample.exe sample.c /link /INCREMENTAL:NO /DEBUG:NONE kernel32.lib
    if ($LASTEXITCODE -ne 0) { throw "cl.exe failed with $LASTEXITCODE" }
    Remove-Item -ErrorAction SilentlyContinue sample.obj, sample.exp, sample.lib
    Write-Host "Built $(Join-Path $here 'sample.exe')"
} finally {
    Pop-Location
}
