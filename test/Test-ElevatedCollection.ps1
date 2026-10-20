<#
.SYNOPSIS
    REAL end-to-end collection on this host - requires Administrator.
    Runs in CI on GitHub's Windows runners (which are elevated); locally it skips
    unless run from an elevated prompt.

    Covers what the non-admin suite cannot:
      1. Script path: build a package, run Collector.ps1 for real (VSS shadow,
         raw hives, $MFT, SRUM, prefetch, Security/PowerShell EVTX), then
         `hawk verify` + `hawk import` and assert on the evidence.
      2. Exe path: wrap the same package in HawkCollector.exe and run it
         non-interactively (-NoPause -OutputDir -CaseNumber), as EDR live
         response / PsExec would; assert exit code 0 and a VERIFIED session.
      3. Constrained Language Mode: collector must refuse with exit 4 and
         write nothing.
    Exit code = number of failed assertions.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Continue'
$Suite  = Resolve-Path (Join-Path $PSScriptRoot '..')
$dotnet = if (Test-Path 'C:\Program Files\dotnet\dotnet.exe') { 'C:\Program Files\dotnet\dotnet.exe' } else { 'dotnet' }
$hawkDll = Join-Path $Suite 'Analyzer\src\Hawk.Analyzer\bin\Debug\net8.0-windows\hawk.dll'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')
if (-not $isAdmin) {
    if ($env:CI) { Write-Host '[FAIL] CI runner is not elevated' -ForegroundColor Red; exit 1 }
    Write-Host '[SKIP] Test-ElevatedCollection needs an elevated prompt (runs in CI).' -ForegroundColor Yellow; exit 0
}
if (-not (Test-Path $hawkDll)) { Write-Host "[FAIL] build the analyzer first: $hawkDll" -ForegroundColor Red; exit 1 }

$fail = 0
function Assert($name, [bool]$cond, $detail = '') {
    if ($cond) { Write-Host "  [PASS] $name" -ForegroundColor Green }
    else { Write-Host "  [FAIL] $name $detail" -ForegroundColor Red; $script:fail++ }
}
function Hawk { & $dotnet exec $hawkDll @args 2>&1 | Out-String }
function Read-Manifest($hawk) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $z = [IO.Compression.ZipFile]::OpenRead($hawk)
    try {
        $e = $z.Entries | Where-Object { ($_.FullName -replace '\\', '/') -eq 'manifest.json' }
        $r = New-Object IO.StreamReader($e.Open()); try { $r.ReadToEnd() | ConvertFrom-Json } finally { $r.Close() }
    } finally { $z.Dispose() }
}

$root = Join-Path ([IO.Path]::GetPathRoot($Suite)) ("hawk_elev_" + [guid]::NewGuid().ToString('N').Substring(0, 6))
$pkg = Join-Path $root 'pkg'
New-Item -ItemType Directory -Force $root | Out-Null

# --- package: small module set, full raw-acquisition path (VSS) ------------------
& (Join-Path $Suite 'Collector\Builder\New-HawkCollector.ps1') -Preset standard -OutputPath $pkg -CaseNumber 'CI-BAKED' -Investigator 'ci' | Out-Null
$keep = 'system_info', 'processes', 'network_connections', 'services', 'scheduled_tasks', 'local_users', 'logon_sessions'
Get-ChildItem (Join-Path $pkg 'Modules') -Recurse -Filter *.ps1 | Where-Object { $_.BaseName -notin $keep } | Remove-Item -Force
$cfgPath = Join-Path $pkg 'config.json'
$cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
$cfg.rawAcquisition = [pscustomobject]@{
    memory = $false; packetCapture = $false
    evtxChannels = @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational', 'Setup')
    registryHives = $true; mft = $true; usnJournal = $false; srum = $true; prefetchFiles = $true; archivedLogs = $true
}
$cfg.eventLogDays = 7
$cfg | ConvertTo-Json -Depth 6 | Out-File $cfgPath -Encoding utf8

# --- 1. script path ---------------------------------------------------------------
Write-Host "`n=== 1. Collector.ps1 (script path, elevated, real acquisition) ===" -ForegroundColor Cyan
$out1 = Join-Path $root 'out_script'; New-Item -ItemType Directory -Force $out1 | Out-Null
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $pkg 'Runtime\Collector.ps1') -PackageRoot $pkg -OutputDir $out1 -CaseNumber 'CI-SCRIPT'
$rc = $LASTEXITCODE
Assert 'collector exit 0' ($rc -eq 0) "(exit $rc)"
$hawk1 = Get-ChildItem $out1 -Filter '*.hawk' | Select-Object -First 1
Assert 'session sealed' ($null -ne $hawk1)
Assert 'work folder cleaned after verified seal' (@(Get-ChildItem $out1 -Directory -Filter 'hawk_work_*').Count -eq 0)
if ($hawk1) {
    Assert 'runtime -CaseNumber override applied' ($hawk1.Name -like 'CI-SCRIPT_*')
    $v = Hawk verify $hawk1.FullName
    Assert 'hawk verify: VERIFIED' ($LASTEXITCODE -eq 0 -and $v -match 'integrity: VERIFIED') "($v)"
    $m = Read-Manifest $hawk1.FullName
    $raw = @($m.rawArtifacts | ForEach-Object { $_.path })
    $sec = $m.evtxStatus | Where-Object { $_.channel -eq 'Security' }
    Assert 'Security.evtx exported in the PRIORITY pass' ($sec -and $sec.exported -and $sec.pass -eq 'priority') "($($sec | ConvertTo-Json -Compress))"
    Assert 'EVTX exported in-process (no wevtutil)' (@($m.rawArtifacts | Where-Object { $_.path -like 'raw/evtx/*' -and $_.method -ne 'eventlog-api' }).Count -eq 0)
    Assert 'VSS: SYSTEM hive acquired' ($raw -contains 'raw/registry/SYSTEM') "(raw: $($raw -join ', '))"
    Assert 'VSS: SOFTWARE hive acquired' ($raw -contains 'raw/registry/SOFTWARE')
    Assert 'VSS: Amcache acquired' ($raw -contains 'raw/registry/Amcache.hve')
    Assert 'raw NTFS: $MFT acquired' ($raw -contains 'raw/mft/$MFT')
    Assert 'VSS shadow created and removed' ($m.collectorFootprint.vssShadowId -and -not (Get-CimInstance Win32_ShadowCopy -Filter "ID='$($m.collectorFootprint.vssShadowId)'" -ErrorAction SilentlyContinue))

    $imp = Hawk import $hawk1.FullName
    Assert 'import: integrity VERIFIED' ($imp -match 'integrity: VERIFIED')
    Assert 'import: Security events parsed' ($imp -match 'parsed evtx: [1-9]') "($(($imp -split "`n" | Select-String 'evtx') -join ' '))"
    Assert 'import: $MFT parsed' ($imp -match 'parsed mft: [1-9]') "($(($imp -split "`n" | Select-String 'mft') -join ' '))"
    Assert 'import: registry hives parsed (shimcache/amcache)' ($imp -match 'parsed (shimcache|amcache): [1-9]')
}

# --- 2. exe path --------------------------------------------------------------------
Write-Host "`n=== 2. HawkCollector.exe (non-interactive, as EDR live response runs it) ===" -ForegroundColor Cyan
$exe = Join-Path $root 'HawkCollector.exe'
& (Join-Path $Suite 'Collector\Builder\New-HawkCollectorExe.ps1') -PackageRoot $pkg -OutputExe $exe | Out-Null
Assert 'exe built' (Test-Path $exe)
$out2 = Join-Path $root 'out exe with spaces'
$p = Start-Process -FilePath $exe -ArgumentList @('-NoPause', '-OutputDir', "`"$out2`"", '-CaseNumber', 'CI-EXE') -Wait -PassThru -NoNewWindow
Assert 'exe exit 0 (collector code passed through, no keypress hang)' ($p.ExitCode -eq 0) "(exit $($p.ExitCode))"
$hawk2 = Get-ChildItem $out2 -Filter '*.hawk' -ErrorAction SilentlyContinue | Select-Object -First 1
Assert 'exe: session sealed in -OutputDir (path with spaces)' ($null -ne $hawk2)
Assert 'exe: unpacked collector removed afterwards' (@(Get-ChildItem $out2 -Directory -Filter 'HawkCollector_pkg_*' -ErrorAction SilentlyContinue).Count -eq 0)
if ($hawk2) {
    Assert 'exe: -CaseNumber passed through' ($hawk2.Name -like 'CI-EXE_*')
    $v = Hawk verify $hawk2.FullName
    Assert 'exe: hawk verify VERIFIED' ($LASTEXITCODE -eq 0) "($v)"
}

# --- 3. Constrained Language Mode -----------------------------------------------------
Write-Host "`n=== 3. Constrained Language Mode refusal ===" -ForegroundColor Cyan
$out3 = Join-Path $root 'out_clm'; New-Item -ItemType Directory -Force $out3 | Out-Null
$collector = Join-Path $pkg 'Runtime\Collector.ps1'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "`$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; & '$collector' -PackageRoot '$pkg' -OutputDir '$out3'; exit `$LASTEXITCODE" | Out-Null
Assert 'CLM: exit 4' ($LASTEXITCODE -eq 4) "(exit $LASTEXITCODE)"
Assert 'CLM: nothing written' (@(Get-ChildItem $out3 -Recurse -ErrorAction SilentlyContinue).Count -eq 0)

Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("`n=== elevated collection: {0} ===" -f $(if ($fail) { "$fail FAILED" } else { 'ALL PASS' })) -ForegroundColor ($(if ($fail) { 'Red' } else { 'Green' }))
exit $fail
