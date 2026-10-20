<#
.SYNOPSIS
    Hawk Collector Builder - generates a portable, USB-ready collector package.
    Produces a self-contained collector folder to run on the target host.

.DESCRIPTION
    Assembles selected collection modules + preset config + runtime into a
    self-contained folder. Run the resulting RunCollector.bat on the target
    host (elevated); it produces a single .hawk session file for import into
    Hawk Analyzer.

.EXAMPLE
    .\New-HawkCollector.ps1 -Preset standard -OutputPath E:\HawkCollector
    .\New-HawkCollector.ps1 -Preset comprehensive -CaseNumber CASE-2026-014 -OutputPath E:\HawkCollector
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('standard', 'comprehensive', 'ioc-search')]
    [string]$Preset,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [string]$CaseNumber = '',
    [string]$Investigator = '',

    # Path to the module library (the refactored collection scripts)
    [string]$ModuleLibrary = (Join-Path $PSScriptRoot '..\Modules'),

    # Opt in to the outbound connectivity probe (records internet reachability
    # in the manifest at the cost of sending packets from the target host).
    [switch]$ConnectivityProbe
)

$ErrorActionPreference = 'Stop'
$SuiteRoot  = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$PresetFile = Join-Path $SuiteRoot "Configuration\Presets\$Preset.json"

if (-not (Test-Path $PresetFile)) { throw "Preset config not found: $PresetFile" }
$PresetConfig = Get-Content $PresetFile -Raw | ConvertFrom-Json

Write-Host "[*] Building Hawk Collector - preset: $Preset" -ForegroundColor Cyan

# --- Layout ---------------------------------------------------------------
$Dirs = @('Modules', 'Runtime', 'Tools')
New-Item -ItemType Directory -Force $OutputPath | Out-Null
$Dirs | ForEach-Object { New-Item -ItemType Directory -Force (Join-Path $OutputPath $_) | Out-Null }

# Tools\ guidance: optional acquisition binaries the collector auto-detects.
@'
HAWK COLLECTOR - Tools folder
=============================
Drop optional acquisition tools here; the collector auto-detects and uses them:

  winpmem_mini_x64.exe   Full physical RAM capture (recommended).
                         Get it from https://github.com/Velocidex/WinPmem
  DumpIt.exe             Alternative RAM capture.
  MagnetRAMCapture.exe   Alternative RAM capture.

With no tool present, full memory capture is skipped (the rest of the
collection still runs).

Pin the tool (recommended): add SHA256SUMS.txt here with one line per tool,
  <sha256>  winpmem_mini_x64.exe
When the file exists the collector REFUSES to run a tool whose hash does not
match. Without it the tool's hash is still recorded but marked UNVERIFIED. Memory capture runs FIRST, before disk activity, and
can produce a multi-GB image - make sure there is free space where the
package/output sits.
'@ | Out-File (Join-Path $OutputPath 'Tools\README.txt') -Encoding ascii

# --- Resolve module list ---------------------------------------------------
# Relative paths come from .NET enumeration of the root string itself, never
# FullName.Substring((Resolve-Path ...).Length): the two disagree when a path is
# an 8.3 short name (C:\Users\SUBASH~1\...), silently corrupting relative paths.
function Get-RelFiles([string]$Root, [string]$Filter = '*') {
    $di = New-Object System.IO.DirectoryInfo ($Root.TrimEnd('\') + '\')
    foreach ($f in $di.EnumerateFiles($Filter, [System.IO.SearchOption]::AllDirectories)) {
        [pscustomobject]@{ FullName = $f.FullName; Rel = $f.FullName.Substring($di.FullName.Length) }
    }
}
$ModuleLibrary = (Resolve-Path $ModuleLibrary).Path

if ($PresetConfig.modules -contains '*') {
    $ModuleFiles = @(Get-RelFiles $ModuleLibrary '*.ps1')
    if ($PresetConfig.excludeModules) {
        $ModuleFiles = $ModuleFiles | Where-Object {
            ($_.Rel -replace '\\', '/' -replace '\.ps1$', '') -notin $PresetConfig.excludeModules
        }
    }
} else {
    $ModuleFiles = foreach ($m in $PresetConfig.modules) {
        $rel = ($m -replace '/', '\') + '.ps1'
        $f = Join-Path $ModuleLibrary $rel
        if (Test-Path $f) { [pscustomobject]@{ FullName = $f; Rel = $rel } } else { Write-Warning "Module not found, skipped: $m" }
    }
}

# --- Copy modules preserving category subfolders ----------------------------
foreach ($f in $ModuleFiles) {
    $rel  = $f.Rel
    $dest = Join-Path $OutputPath "Modules\$rel"
    New-Item -ItemType Directory -Force (Split-Path $dest) | Out-Null
    Copy-Item $f.FullName $dest
}
Write-Host "[+] $(@($ModuleFiles).Count) modules packaged"

# --- Copy runtime (orchestrator + all runtime modules) -----------------------
Get-ChildItem (Join-Path $SuiteRoot 'Collector\Runtime') -File | ForEach-Object {
    Copy-Item $_.FullName (Join-Path $OutputPath "Runtime\$($_.Name)")
}

# --- Write collector config --------------------------------------------------
$CollectorConfig = [ordered]@{
    schemaVersion = '1.0'
    preset        = $Preset
    caseNumber    = $CaseNumber
    investigator  = $Investigator
    builtAtUtc    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    builtBy       = $env:USERNAME
    rawAcquisition = $PresetConfig.rawAcquisition
    eventLogDays   = $PresetConfig.eventLogDays
    # Outbound TCP reachability probe (8.8.8.8/1.1.1.1/9.9.9.9:53). OFF unless
    # the preset or -ConnectivityProbe asks for it: the default check sends no packets.
    connectivityProbe = [bool]($ConnectivityProbe -or ($PresetConfig.PSObject.Properties['connectivityProbe'] -and $PresetConfig.connectivityProbe))
}
$CollectorConfig | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputPath 'config.json') -Encoding utf8

# --- Launcher ----------------------------------------------------------------
# Built as an ASCII line array (avoids here-string / non-ASCII parsing issues).
$bat = @(
    '@echo off',
    ':: Hawk Collector launcher - run as Administrator on the TARGET host.',
    'net session >nul 2>&1',
    'if %errorlevel% neq 0 (',
    '    echo [!] Administrator privileges required. Right-click then Run as administrator.',
    '    pause',
    '    exit /b 1',
    ')',
    'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Runtime\Collector.ps1" -PackageRoot "%~dp0."',
    'pause'
)
($bat -join "`r`n") | Out-File (Join-Path $OutputPath 'RunCollector.bat') -Encoding ascii

# --- Integrity manifest of the package itself --------------------------------
$PackageHashes = @(Get-RelFiles (Resolve-Path $OutputPath).Path) | ForEach-Object {
    [ordered]@{
        path   = $_.Rel
        sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    }
}
@{ schemaVersion = '1.0'; files = $PackageHashes } | ConvertTo-Json -Depth 4 |
    Out-File (Join-Path $OutputPath 'package-integrity.json') -Encoding utf8

Write-Host "[+] Collector package ready: $OutputPath" -ForegroundColor Green
Write-Host "    Copy folder to USB / share, run RunCollector.bat elevated on target."
