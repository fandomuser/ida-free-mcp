# Installs idamcp:
#   1. builds the plugin (unless -SkipBuild)
#   2. copies idamcp.dll to %APPDATA%\Hex-Rays\IDA Pro\plugins (IDA's per-user plugin dir)
#   3. creates the server's virtualenv (uv sync, locked dependencies)
#   4. registers the MCP server with Claude Code (user scope)
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/install.ps1 [-SkipBuild] [-Scope user|project|local]
#   powershell -ExecutionPolicy Bypass -File scripts/install.ps1 -Uninstall
param(
    [switch]$SkipBuild,
    [ValidateSet('user', 'project', 'local')][string]$Scope = 'user',
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$pluginDir = Join-Path $env:APPDATA 'Hex-Rays\IDA Pro\plugins'
$dst = Join-Path $pluginDir 'idamcp.dll'
$serverDir = Join-Path $root 'server'

# `claude mcp remove` exits non-zero when nothing is registered; that is fine here.
function Remove-Registration {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & cmd /c "claude mcp remove idamcp --scope $Scope >nul 2>&1" } finally { $ErrorActionPreference = $prev }
}

if ($Uninstall) {
    if (Get-Command claude -ErrorAction SilentlyContinue) { Remove-Registration }
    if (Test-Path $dst) {
        try { Remove-Item $dst -Force; Write-Host "Removed $dst" }
        catch { throw "Could not remove $dst (close IDA first)." }
    }
    return
}

if (-not $SkipBuild) { & (Join-Path $root 'scripts\build.ps1') }
$src = Join-Path $root 'build\out\plugins\idamcp.dll'
if (-not (Test-Path $src)) { throw "Plugin not built: $src" }

New-Item -ItemType Directory -Force $pluginDir | Out-Null
# A running IDA keeps idamcp.dll locked, but Windows allows moving a loaded DLL. Park the old
# copy outside the plugins folder (IDA keeps using it until restart) and drop the new one in.
$oldDir = Join-Path $env:LOCALAPPDATA 'idamcp\old'
Get-ChildItem $oldDir -Filter 'idamcp-*.dll' -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }  # unlocked leftovers
try { Copy-Item $src $dst -Force }
catch {
    New-Item -ItemType Directory -Force $oldDir | Out-Null
    $parked = Join-Path $oldDir ("idamcp-{0:yyyyMMddHHmmss}.dll" -f (Get-Date))
    try { Move-Item $dst $parked -Force; Copy-Item $src $dst -Force }
    catch { throw "Could not replace $dst ($_). Close all IDA windows and retry." }
    Write-Warning "IDA is running with the previous plugin; it was moved to $parked. Restart IDA to load the new version."
}
Write-Host "Installed plugin: $dst"

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) { throw "uv is required: https://docs.astral.sh/uv/" }
Push-Location $serverDir
try {
    & uv sync --frozen
    if ($LASTEXITCODE -ne 0) {
        # A running MCP client (Claude Code, OpenCode, Codex) keeps idamcp-server.exe locked.
        if (Test-Path (Join-Path $serverDir '.venv')) {
            Write-Warning "Could not refresh the server environment (it is in use by a running MCP client). The code is installed in editable mode, so the update still takes effect; close your MCP clients and re-run this script to refresh package metadata."
        } else { throw "uv sync failed" }
    }
} finally { Pop-Location }

if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
    Write-Warning "Claude Code CLI not found; register manually (see README)."
    return
}
Remove-Registration
& claude mcp add --scope $Scope idamcp -- uv --directory $serverDir run --no-sync idamcp-server
if ($LASTEXITCODE -ne 0) { throw "claude mcp add failed" }
Write-Host "Registered MCP server 'idamcp' (scope: $Scope, all 58 tools)."
Write-Host "In IDA Free 9.5, open a database and choose Edit > Plugins > idamcp to turn MCP on."
