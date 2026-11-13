# Dot-source this to import the MSVC x64 developer environment (cl, link, cmake, ninja)
# into the current PowerShell session. Locates Visual Studio via vswhere.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw "vswhere.exe not found; install Visual Studio 2022+ with the C++ workload." }
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "No Visual Studio installation with the C++ x64 toolset was found." }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
$env:PATH = "$(Split-Path $vswhere);$env:PATH"
cmd /c "`"$vcvars`" >nul && set" | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') { Set-Item -Path "env:$($Matches[1])" -Value $Matches[2] }
}
$cmakeDir = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake'
if (Test-Path $cmakeDir) { $env:PATH = "$cmakeDir\CMake\bin;$cmakeDir\Ninja;$env:PATH" }
