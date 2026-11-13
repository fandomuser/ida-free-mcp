# UI Automation helpers for driving a test IDA instance, scoped to ONE process id.
# Never sends global keystrokes: elements are located inside the target process
# only and invoked through UIA patterns.
#   ida_ui.ps1 -ProcessId 1234 -Action list            # list top-level windows and buttons
#   ida_ui.ps1 -ProcessId 1234 -Action click -Name OK  # invoke a button by name
#   ida_ui.ps1 -ProcessId 1234 -Action menu -MenuPath 'Edit/Plugins/idamcp'  # run a menu command
param(
    [Parameter(Mandatory)][int]$ProcessId,
    [Parameter(Mandatory)][ValidateSet('list', 'click', 'shot', 'close', 'menu')][string]$Action,
    # For -Action menu: the menu path separated by '/', e.g. 'Edit/Plugins/idamcp'.
    [string]$MenuPath,
    [string]$Name,
    [string]$Path
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes

$root = [System.Windows.Automation.AutomationElement]::RootElement
$pidCond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ProcessIdProperty, $ProcessId)
$wins = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $pidCond)

function Get-Buttons($el) {
    $c = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
        [System.Windows.Automation.ControlType]::Button)
    $el.FindAll([System.Windows.Automation.TreeScope]::Descendants, $c)
}

switch ($Action) {
    'list' {
        foreach ($w in $wins) {
            "WINDOW: '$($w.Current.Name)'"
            foreach ($b in (Get-Buttons $w)) { "  button: '$($b.Current.Name)' enabled=$($b.Current.IsEnabled)" }
        }
    }
    'click' {
        foreach ($w in $wins) {
            foreach ($b in (Get-Buttons $w)) {
                if ($b.Current.Name -eq $Name -and $b.Current.IsEnabled) {
                    $p = $b.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
                    $p.Invoke()
                    "clicked '$Name' in window '$($w.Current.Name)'"
                    return
                }
            }
        }
        throw "button '$Name' not found in process $ProcessId"
    }
    'menu' {
        # Opens each submenu via ExpandCollapse and invokes the last item, all in one
        # process (popups close again when the automation client goes away).
        $parts = @($MenuPath -split '/' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($parts.Count -lt 2) { throw "-MenuPath needs at least two items, e.g. 'Edit/Plugins/idamcp'" }
        $mc = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::MenuItem)
        function Find-MenuItem([string]$name) {
            for ($try = 0; $try -lt 20; $try++) {
                foreach ($w in $root.FindAll([System.Windows.Automation.TreeScope]::Children, $pidCond)) {
                    foreach ($m in $w.FindAll([System.Windows.Automation.TreeScope]::Descendants, $mc)) {
                        if ($m.Current.Name -eq $name -and $m.Current.IsEnabled) { return $m }
                    }
                }
                Start-Sleep -Milliseconds 150
            }
            throw "menu item '$name' not found in process $ProcessId"
        }
        function Collapse-Top {
            # Close a menu left half-open by a previous attempt, so Expand() starts from a known state.
            try {
                $top = Find-MenuItem $parts[0]
                $ec = $top.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern)
                if ($ec.Current.ExpandCollapseState -ne [System.Windows.Automation.ExpandCollapseState]::Collapsed) {
                    $ec.Collapse()
                }
            } catch {}
        }
        $lastErr = $null
        for ($attempt = 1; $attempt -le 4; $attempt++) {
            try {
                Collapse-Top
                for ($k = 0; $k -lt $parts.Count - 1; $k++) {
                    $item = Find-MenuItem $parts[$k]
                    $item.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern).Expand()
                }
                $leaf = Find-MenuItem $parts[-1]
                $leaf.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
                "invoked $($parts -join ' > ') (attempt $attempt)"
                return
            } catch {
                $lastErr = $_
                Start-Sleep -Milliseconds 500
            }
        }
        throw $lastErr
    }
    'close' {
        foreach ($w in $wins) {
            $p = $w.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern)
            $p.Close()
            "close requested for '$($w.Current.Name)'"
            return
        }
        throw "no window found for process $ProcessId"
    }
    'shot' {
        Add-Type -AssemblyName System.Drawing
        $main = $wins | Sort-Object { $_.Current.BoundingRectangle.Width * $_.Current.BoundingRectangle.Height } -Descending | Select-Object -First 1
        $r = $main.Current.BoundingRectangle
        $bmp = New-Object System.Drawing.Bitmap ([int]$r.Width), ([int]$r.Height)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen([int]$r.X, [int]$r.Y, 0, 0, $bmp.Size)
        $bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
        $g.Dispose(); $bmp.Dispose()
        "saved $Path"
    }
}


