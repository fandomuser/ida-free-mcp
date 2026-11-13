# End-to-end test against real IDA Free 9.5 GUI instances.
#  1. copies tests/fixtures/sample.exe to a fresh temp dir (and, with -TwoDatabases, a second
#     copy named sample_b.exe opened in a second IDA window)
#  2. starts IDA with the freshly built plugin (via IDAUSR; your IDA install is untouched)
#  3. accepts the "Load a new file" dialog using UI Automation scoped to each IDA process
#  4. CHECKS that MCP is OFF after loading (no discovery file, no listening socket)
#  5. turns MCP ON through Edit > Plugins > idamcp (UI Automation, same process only)
#  6. waits for auto-analysis, runs `pytest -m live`
#  7. closes IDA with MCP still ON (without saving the throwaway databases) and CHECKS the
#     shutdown was clean: process exited, discovery file removed, bridge logged "stopped"
# Usage: powershell -ExecutionPolicy Bypass -File scripts/run_live_tests.ps1 [-Installed] [-TwoDatabases] [-KeepOpen] [-PytestArgs "..."]
param(
    [switch]$Installed,       # use the plugin installed in %APPDATA%\Hex-Rays\IDA Pro\plugins instead of build\out
    [switch]$TwoDatabases,    # also open sample_b.exe in a second IDA window (multi-database tests)
    [switch]$KeepOpen,        # leave IDA running afterwards
    [string]$IdaExe = 'C:\Program Files\IDA Free 9.5\ida.exe',
    [string]$PytestArgs = ''
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$ui = Join-Path $root 'scripts\ida_ui.ps1'
$work = Join-Path $env:TEMP ("idamcp-live-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force $work | Out-Null
$fixture = Join-Path $root 'tests\fixtures\sample.exe'
$files = @('sample.exe')
if ($TwoDatabases) { $files += 'sample_b.exe' }
foreach ($f in $files) { Copy-Item $fixture (Join-Path $work $f) }

$userDir = Join-Path $env:APPDATA 'Hex-Rays\IDA Pro'
# The build directory must come FIRST: IDA uses the first idamcp.dll it finds, and the user
# directory may contain an older installed copy.
if (-not $Installed) { $env:IDAUSR = "$(Join-Path $root 'build\out');$userDir" }
$instances = Join-Path $env:LOCALAPPDATA 'idamcp\instances'

function Invoke-Ui([int]$procId, [string[]]$uiArgs) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $ui -ProcessId $procId @uiArgs 2>$null
}

function Start-Ida([string]$file) {
    $log = "$work\$file.log"
    $p = Start-Process -FilePath $IdaExe -ArgumentList "-L`"$log`"", "`"$work\$file`"" -PassThru
    $disc = Join-Path $instances "ida-$($p.Id).json"
    $deadline = (Get-Date).AddSeconds(120)
    # Accept the load dialog until the plugin reports its (OFF) state for this database.
    while (-not ((Test-Path $log) -and (Select-String -Path $log -Pattern '\[idamcp\] MCP DISABLED' -Quiet))) {
        if ($p.HasExited) { throw "IDA exited early; see $log" }
        if ((Get-Date) -gt $deadline) { throw "plugin did not load; see $log" }
        try { Invoke-Ui $p.Id @('-Action', 'click', '-Name', 'OK') | Out-Null } catch {}
        Start-Sleep -Milliseconds 700
    }
    Start-Sleep -Seconds 2
    $listen = @(Get-NetTCPConnection -OwningProcess $p.Id -State Listen -ErrorAction SilentlyContinue)
    if ((Test-Path $disc) -or $listen.Count -ne 0) {
        throw "MCP must be OFF after loading $file (discovery: $(Test-Path $disc), listeners: $($listen.Count))"
    }
    Write-Host "IDA pid $($p.Id): $file loaded, MCP OFF (no discovery file, no listener)"
    Invoke-Ui $p.Id @('-Action', 'menu', '-MenuPath', 'Edit/Plugins/idamcp') | Out-Null
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Test-Path $disc)) {
        if ((Get-Date) -gt $deadline) { throw "MCP did not turn on via Edit > Plugins > idamcp; see $log" }
        Start-Sleep -Milliseconds 300
    }
    $msg = Select-String -Path $log -Pattern '\[idamcp\] MCP ENABLED' -Encoding UTF8 | Select-Object -Last 1
    Write-Host "IDA pid $($p.Id): turned ON via Edit > Plugins > idamcp -> '$($msg.Line)'"
    return $p
}

function Stop-Ida($p) {
    if ($p.HasExited) { return $true }
    $wasOn = Test-Path (Join-Path $instances "ida-$($p.Id).json")
    Add-Type -Namespace W -Name U -MemberDefinition '[DllImport("user32.dll")] public static extern bool PostMessage(System.IntPtr h, uint m, System.IntPtr w, System.IntPtr l);' -ErrorAction SilentlyContinue
    $p.Refresh()  # MainWindowHandle is cached; it may still point at the closed "Load a new file" dialog
    [W.U]::PostMessage($p.MainWindowHandle, 0x10, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null  # WM_CLOSE
    # The throwaway test database is discarded: answer IDA's "Save database" dialog with "Don't save".
    for ($i = 0; $i -lt 30 -and -not $p.HasExited; $i++) {
        Start-Sleep -Seconds 1
        try { Invoke-Ui $p.Id @('-Action', 'click', '-Name', "Don't save") | Out-Null } catch {}
    }
    if (-not $p.WaitForExit(15000)) { Write-Warning "IDA did not close; pid $($p.Id) left running"; return $false }
    $disc = Join-Path $instances "ida-$($p.Id).json"
    $logFile = Join-Path $env:LOCALAPPDATA "idamcp\logs\bridge-$($p.Id).log"
    $last = Get-Content $logFile -ErrorAction SilentlyContinue | Select-Object -Last 1 | ConvertFrom-Json
    $clean = (-not (Test-Path $disc)) -and ((-not $wasOn) -or ($last.event -eq 'stopped' -and $last.reason -eq 'database closed'))
    Write-Host ("IDA pid {0} exited (MCP was {1}); discovery removed: {2}; last bridge event: {3}/{4} -> {5}" -f `
        $p.Id, ($(if ($wasOn) { 'ON' } else { 'OFF' })), (-not (Test-Path $disc)), $last.event, $last.reason,
        ($(if ($clean) { 'CLEAN' } else { 'NOT CLEAN' })))
    return $clean
}

$procs = @()
$rc = 1
Push-Location (Join-Path $root 'server')
try {
    foreach ($f in $files) { $procs += Start-Ida $f }
    $wait = @'
import asyncio, sys, time
from idamcp_server.bridge import BridgeManager
async def main(pids):
    m = BridgeManager()
    end = time.time() + 180
    for pid in pids:
        while True:
            st = await m.call("status", database=pid)
            if st["auto_analysis_complete"]:
                print(f"pid {pid}: auto-analysis complete, {st['function_count']} functions")
                break
            if time.time() > end:
                sys.exit("auto-analysis did not finish")
            await asyncio.sleep(1)
    await m.aclose()
asyncio.run(main(sys.argv[1:]))
'@
    $wait | uv run python - @($procs | ForEach-Object { "$($_.Id)" })
    if ($LASTEXITCODE -ne 0) { throw "waiting for analysis failed" }
    $args = @('run', 'pytest', '-m', 'live', '-v') + ($PytestArgs -split ' ' | Where-Object { $_ })
    & uv @args
    $rc = $LASTEXITCODE
} finally {
    Pop-Location
    if (-not $KeepOpen) {
        foreach ($p in $procs) {
            if (-not (Stop-Ida $p)) { $rc = 1 }
        }
    }
}
exit $rc
