# Closes a test IDA instance by pid WITHOUT saving its database (throwaway test databases only).
# Sends WM_CLOSE to the main window, then answers "Don't save" via UI Automation in that process.
param([Parameter(Mandatory)][int]$ProcessId, [int]$TimeoutSec = 30)
$ErrorActionPreference = 'Stop'
$ui = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'ida_ui.ps1'
$p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
if (-not $p) { "pid $ProcessId is not running"; return }
# Find IDA's main window by title ("IDA - ..."): Process.MainWindowHandle can point at a
# leftover popup/menu window instead.
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$A = [System.Windows.Automation.AutomationElement]
$cond = New-Object System.Windows.Automation.PropertyCondition($A::ProcessIdProperty, $ProcessId)
$main = $A::RootElement.FindAll([System.Windows.Automation.TreeScope]::Children, $cond) |
    Where-Object { $_.Current.Name -like 'IDA - *' } | Select-Object -First 1
$hwnd = if ($main) { [IntPtr]$main.Current.NativeWindowHandle } else { $p.Refresh(); $p.MainWindowHandle }
Add-Type -Namespace W -Name U -MemberDefinition '[DllImport("user32.dll")] public static extern bool PostMessage(System.IntPtr h, uint m, System.IntPtr w, System.IntPtr l);' -ErrorAction SilentlyContinue
[W.U]::PostMessage($hwnd, 0x10, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
for ($i = 0; $i -lt $TimeoutSec -and -not $p.HasExited; $i++) {
    Start-Sleep -Seconds 1
    try { & powershell -NoProfile -ExecutionPolicy Bypass -File $ui -ProcessId $ProcessId -Action click -Name "Don't save" 2>$null | Out-Null } catch {}
}
if ($p.HasExited) { "pid $ProcessId closed" } else { throw "pid $ProcessId did not close" }
