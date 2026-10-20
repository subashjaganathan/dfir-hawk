<#
.SYNOPSIS
    Hawk Collector orchestrator - runs on the TARGET host.
    Executes packaged modules, acquires raw artifacts, produces one .hawk file.

.DESCRIPTION
    Exit codes (stable - automation, EDR live response and the .exe rely on them):
      0  complete session sealed
      1  not elevated (nothing collected)
      2  PARTIAL session sealed (collection interrupted; what was gathered is in the .hawk)
      3  SEAL FAILED - evidence left UNSEALED in the hawk_work_* folder (never deleted)
      4  PowerShell is in ConstrainedLanguage mode (AppLocker/WDAC) - nothing collected

.PARAMETER CaseNumber / Investigator
    Override the values baked into config.json at build time (e.g. per-host runs of one package).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackageRoot,
    [string]$OutputDir = $PackageRoot,   # session lands next to the package (USB) by default
    [string]$CaseNumber = '',
    [string]$Investigator = ''
)

$ErrorActionPreference = 'Continue'

# Constrained Language Mode (AppLocker / WDAC enforcing on unsigned scripts) blocks Add-Type and
# the .NET calls used for raw NTFS reads and ZIP sealing. Running anyway used to abort mid-way and
# then delete the work folder - losing everything gathered. Refuse up front, loudly.
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Host "[!] PowerShell is running in $($ExecutionContext.SessionState.LanguageMode) mode (AppLocker/WDAC policy)." -ForegroundColor Red
    Write-Host '    The collector needs FullLanguage. Options: sign the collector scripts with a certificate the' -ForegroundColor Red
    Write-Host '    host policy trusts, add a policy exception for the collector path, or collect with a tool the' -ForegroundColor Red
    Write-Host '    policy already allows. Nothing was collected and nothing was written.' -ForegroundColor Red
    exit 4
}

Import-Module (Join-Path $PackageRoot 'Runtime\Hawk.Common.psm1') -Force
Import-Module (Join-Path $PackageRoot 'Runtime\Hawk.RawNtfs.psm1') -Force -ErrorAction SilentlyContinue

if (-not (Test-HawkAdmin)) { Write-Host '[!] Run elevated.' -ForegroundColor Red; exit 1 }

$Config   = Get-Content (Join-Path $PackageRoot 'config.json') -Raw | ConvertFrom-Json
if ($CaseNumber)   { $Config.caseNumber = $CaseNumber }
if ($Investigator) { $Config.investigator = $Investigator }
$Hostname = $env:COMPUTERNAME
$StartUtc = (Get-Date).ToUniversalTime()
$Stamp    = $StartUtc.ToString('yyyyMMddTHHmmssZ')
$CaseNum  = if ($Config.caseNumber) { $Config.caseNumber } else { "CASE-$Stamp" }

# Stage the session on the OUTPUT volume (normally the collector USB), not in
# %TEMP%: every byte written to the system drive can overwrite unallocated
# clusters that hold deleted-file evidence - and a RAM image is multi-GB.
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path
$WorkRoot  = Join-Path $OutputDir "hawk_work_$Stamp"
Initialize-HawkSession -WorkRoot $WorkRoot | Out-Null
Write-HawkLog "Hawk Collector started - case $CaseNum, preset $($Config.preset)"
$StagedOnSystemDrive = $OutputDir.StartsWith($env:SystemDrive, [StringComparison]::OrdinalIgnoreCase)
if ($StagedOnSystemDrive) {
    Write-Host "[!] Output is on the system drive ($OutputDir). Collection writes there can overwrite deleted-file evidence - prefer running from external media." -ForegroundColor Yellow
    Write-HawkLog "output/staging is on the system drive ($OutputDir) - may overwrite unallocated space" 'WARN'
}

# --- Host role detection (drives analyzer role modifiers) --------------------
$Role = 'workstation'
try {
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    if ($cs.DomainRole -in 4,5)      { $Role = 'domain-controller' }
    elseif ($os.ProductType -eq 3)   { $Role = 'server' }
} catch { Write-HawkLog "role detection failed: $_" 'WARN' }

# --- Connectivity awareness (isolated / quarantined host) --------------------
# Provenance only - collection never depends on it. The default check is
# local-only and sends NO packets (an attacker watching egress must not see
# the collector); the outbound TCP probe runs only if the config opts in.
$ActiveProbe = [bool]($Config.PSObject.Properties['connectivityProbe'] -and $Config.connectivityProbe)
$Connectivity = 'unknown'
try { $Connectivity = Test-HawkOnline -Active:$ActiveProbe } catch {}
switch ($Connectivity) {
    'online'  { Write-Host '[*] Connectivity: internet reachable (active probe).' -ForegroundColor DarkGray }
    'offline' { Write-Host '[*] Connectivity: OFFLINE (isolated/quarantined host) - proceeding fully local.' -ForegroundColor Cyan }
    default   { Write-Host '[*] Connectivity: network present, internet not probed (no packets sent).' -ForegroundColor DarkGray }
}
Write-HawkLog ("connectivity: {0} ({1})" -f $Connectivity, $(if ($ActiveProbe) { 'active TCP probe' } else { 'local interface check only, no packets sent' }))

# --- Collector self-footprint (so the analyst can exclude/explain our traces) -
# Live triage inevitably leaves its own marks (this process, its prefetch, the
# VSS shadow we create, temp files). Recording them keeps the evidence
# defensible and lets the analyst filter the collector's own activity.
$collectorPs1 = $MyInvocation.MyCommand.Path
$runnerImage = $null
try { $runnerImage = (Get-Process -Id $PID -ErrorAction Stop).Path } catch {}
$Footprint = [ordered]@{
    pid             = $PID
    runnerImage     = $runnerImage
    collectorScript = $collectorPs1
    collectorSha256 = if ($collectorPs1 -and (Test-Path $collectorPs1)) { (Get-FileHash $collectorPs1 -Algorithm SHA256).Hash } else { $null }
    workRoot        = $WorkRoot
    stagedOnSystemDrive = $StagedOnSystemDrive
    connectivityCheck   = $(if ($ActiveProbe) { 'active-tcp-probe' } else { 'local-only' })
    tempVssMount    = $null   # set when a shadow copy is linked
    vssShadowId     = $null   # set when a shadow copy is created
    startedUtc      = $StartUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
}

# Accumulators are hoisted ABOVE the try so the seal in `finally` always has
# them - if a fatal error or Ctrl-C aborts collection partway, a PARTIAL but
# fully hash-sealed .hawk is still produced (never lose what was gathered).
$RawArtifacts  = @()
$ModuleResults = @()
$EvtxStatus    = @()
$aborted       = $false
$abortReason   = $null
$script:HawkExit = 3   # assume "not sealed" until the seal step proves otherwise

try {

# --- Volatile-first: full physical RAM capture (before any disk/VSS activity) -
# Order of volatility: memory is the most volatile evidence, so image it before
# modules read live state or VSS touches the disk. Requires a tool staged in
# Tools\ (winpmem/DumpIt); skips gracefully if absent.
if ($Config.rawAcquisition.memory) {
    Invoke-HawkMemoryAcquisition -ToolsDir (Join-Path $PackageRoot 'Tools') -WorkRoot $WorkRoot -RawArtifacts ([ref]$RawArtifacts)
}

# --- Raw EVTX acquisition -------------------------------------------------------
# Full native .evtx export (no truncation), IN-PROCESS (Export-HawkEventLog): no
# cmd/wevtutil child processes, which on a host auditing process creation would
# write thousands of 4688/4689 events into the circular Security log. Time-bounded
# by eventLogDays when set; per-channel status recorded in the manifest.
# Pass 1 runs NOW, before the modules: the logs most at risk of rolling over from
# the collector's own activity (Security: process/logon auditing; PowerShell:
# script-block logging of our own scripts) are captured before we perturb them.
$EvtxPriority = @(
    'Security', 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell',
    'Microsoft-Windows-Sysmon/Operational', 'System',
    'Microsoft-Windows-Windows Defender/Operational', 'Microsoft-Windows-TaskScheduler/Operational',
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
    'Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-WinRM/Operational',
    'Microsoft-Windows-Bits-Client/Operational', 'Application'
)
$EvtxPlan = @{ All = @(); Priority = @(); Remaining = @() }
if ($Config.rawAcquisition.evtxChannels) {
    $EvtxPlan.All = @(if ($Config.rawAcquisition.evtxChannels -contains '*') {
        try { [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetLogNames() | Where-Object { $_ } }
        catch { Write-HawkLog "channel enumeration failed: $_" 'WARN' }
    } else { $Config.rawAcquisition.evtxChannels })
    $EvtxPlan.Priority  = @($EvtxPriority | Where-Object { $EvtxPlan.All -contains $_ })
    $EvtxPlan.Remaining = @($EvtxPlan.All | Where-Object { $EvtxPlan.Priority -notcontains $_ })
}
$EvtxDays = if ($Config.eventLogDays -and [int]$Config.eventLogDays -gt 0) { [int]$Config.eventLogDays } else { 0 }
# Dot-sourced so it appends to this scope's $RawArtifacts / $EvtxStatus.
$ExportChannels = {
    param([string[]]$List, [string]$Pass)
    $n = 0
    foreach ($ch in $List) {
        $n++
        if ($n % 100 -eq 0) { Write-Host ("    ...EVTX {0}/{1}" -f $n, $List.Count) -ForegroundColor DarkGray }
        $safe = ($ch -replace '[\\/]', '%4') + '.evtx'
        $dest = Join-Path $WorkRoot "raw\evtx\$safe"
        $err = Export-HawkEventLog -Channel $ch -Destination $dest -Days $EvtxDays
        $exported = (-not $err) -and (Test-Path -LiteralPath $dest)
        if ($exported) {
            $RawArtifacts += [ordered]@{ path = "raw/evtx/$safe"; source = $ch; method = 'eventlog-api'; pass = $Pass
                sha256 = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash }
        } elseif (-not $err) { $err = 'no output (empty channel)' }
        $EvtxStatus += [ordered]@{ channel = $ch; exported = $exported; pass = $Pass; error = $err }
    }
}
if ($EvtxPlan.Priority.Count) {
    Write-Host ("[*] Exporting {0} high-value event logs first (Security, PowerShell, Sysmon, ...)" -f $EvtxPlan.Priority.Count) -ForegroundColor Cyan
    . $ExportChannels $EvtxPlan.Priority 'priority'
}

# --- Volatile: live packet capture (built-in netsh trace, passive) -----------
# Started here and left running in the background while the modules execute;
# stopped after them once the configured minimum duration has elapsed.
$PacketCapture = $null
if ($Config.rawAcquisition.packetCapture) {
    $pcMB = if ($Config.rawAcquisition.packetCaptureMaxMB) { [int]$Config.rawAcquisition.packetCaptureMaxMB } else { 500 }
    $PacketCapture = Start-HawkNetworkCapture -WorkRoot $WorkRoot -MaxSizeMB $pcMB
}

# --- Run collection modules ---------------------------------------------------
# Order of volatility (RFC 3227): live process / network / session state is
# captured FIRST, before slow disk-heavy modules (browser, SQL, AD, ...) give
# it time to change. Everything not listed runs afterwards, alphabetically.
$VolatileFirst = @(
    'Execution\processes', 'Network\network_connections', 'Network\dns_cache', 'Network\arp_entries',
    'Accounts\logon_sessions', 'Network\smb_shares_sessions', 'Memory\named_pipes',
    'Memory\injected_memory', 'Execution\loaded_dlls', 'Network\network_advanced', 'Network\rdp_client'
)
$Modules = Get-HawkFileTree -Root (Join-Path $PackageRoot 'Modules') |
    Where-Object { $_.Rel -like '*.ps1' } |
    Sort-Object @{ Expression = {
        $idx = [array]::IndexOf($VolatileFirst, ($_.Rel -replace '\.ps1$', '' -replace '/', '\'))
        if ($idx -ge 0) { $idx } else { 1000 }
    } }, Rel |
    ForEach-Object { Get-Item -LiteralPath $_.FullName }
$i = 0
foreach ($mod in $Modules) {
    $i++
    $name = $mod.BaseName
    Write-Host ("[{0}/{1}] {2}" -f $i, $Modules.Count, $name)
    $mStart = (Get-Date).ToUniversalTime()
    $status = 'success'; $errors = @(); $count = 0
    try {
        # Contract: module receives -SessionRoot and -Config, calls
        # Export-HawkArtifact, and RETURNS the record count.
        $count = & $mod.FullName -SessionRoot $WorkRoot -Config $Config
        if ($null -eq $count) { $count = 0 }
    } catch {
        $status = 'failed'; $errors += "$_"
        Write-HawkLog "module $name failed: $_" 'ERROR'
    }
    $ModuleResults += [ordered]@{
        name = $name; version = '2.0.0'; status = $status
        startedUtc = $mStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
        endedUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        artifactFile = "artifacts/$name.json"; recordCount = [int]"$count"; errors = $errors
    }
}

if ($PacketCapture) {
    $pcSecs = if ($Config.rawAcquisition.packetCaptureSeconds) { [int]$Config.rawAcquisition.packetCaptureSeconds } else { 120 }
    Stop-HawkNetworkCapture -Capture $PacketCapture -MinSeconds $pcSecs -RawArtifacts ([ref]$RawArtifacts)
    $PacketCapture = $null
}

# --- Raw EVTX acquisition, pass 2: every remaining configured channel -----------
if ($EvtxPlan.Remaining.Count) {
    Write-Host ("[*] Exporting {0} remaining event-log channels (in-process, no child processes)..." -f $EvtxPlan.Remaining.Count) -ForegroundColor Cyan
    . $ExportChannels $EvtxPlan.Remaining 'remaining'
}
if ($EvtxPlan.All.Count) {
    Write-HawkLog "EVTX channels exported: $(@($EvtxStatus | Where-Object { $_.exported }).Count) of $($EvtxPlan.All.Count)"
    # The Security channel is the highest-value DFIR source and requires elevation;
    # the orchestrator already enforces admin, but surface it loudly if it slipped.
    $secStatus = $EvtxStatus | Where-Object { $_.channel -eq 'Security' }
    if ($secStatus -and -not $secStatus.exported) {
        Write-HawkLog 'Security channel NOT exported - run elevated for authentication/logon evidence.' 'WARN'
    }
}

# --- Archived / rotated event logs (Archive-*.evtx) ------------------------------
if ($Config.rawAcquisition.archivedLogs) {
    try {
        $winevt = Join-Path $env:SystemRoot 'System32\winevt\Logs'
        $arch = Get-ChildItem -LiteralPath $winevt -Filter 'Archive-*.evtx' -ErrorAction SilentlyContinue
        foreach ($a in $arch) {
            $dst = Join-Path $WorkRoot "raw\evtx\$($a.Name)"
            try {
                Copy-Item -LiteralPath $a.FullName -Destination $dst -ErrorAction Stop
                $RawArtifacts += [ordered]@{ path = "raw/evtx/$($a.Name)"; source = $a.FullName; method = 'archived-copy'
                    sha256 = (Get-FileHash $dst -Algorithm SHA256).Hash }
            } catch { Write-HawkLog "archived log copy failed: $($a.Name) - $_" 'WARN' }
        }
        if ($arch) { Write-HawkLog "archived event logs copied: $(@($arch).Count)" }
    } catch { Write-HawkLog "archived log sweep failed: $_" 'WARN' }
}

# --- Raw hives / MFT / SRUM via VSS (comprehensive preset) -----------------------
# Paths are volume-relative (the shadow is mounted as the volume root) and
# derived from the environment rather than assuming C:\Windows.
$sysRoot = $env:SystemDrive.TrimEnd('\') + '\'
$winRel  = $env:SystemRoot.Substring($sysRoot.Length)
if ($Config.rawAcquisition.registryHives -or $Config.rawAcquisition.mft -or $Config.rawAcquisition.srum) {
    Write-Host '[*] Raw disk acquisition via VSS (registry hives / $MFT / $UsnJrnl / SRUM) - several minutes, please wait...' -ForegroundColor Cyan
    $createdShadowId = $null
    try {
        # Create a fresh shadow copy of the system drive. Win32_ShadowCopy.Create
        # works on BOTH client and server Windows; `vssadmin create shadow` is
        # Server-only and silently fails on Win10/11 clients (the common case),
        # which previously skipped all hive/MFT/SRUM/Amcache acquisition.
        $shadow = $null
        try {
            $cls = [wmiclass]'root\cimv2:Win32_ShadowCopy'
            $res = $cls.Create("$env:SystemDrive\", 'ClientAccessible')
            if ($res.ReturnValue -eq 0 -and $res.ShadowID) {
                $createdShadowId = $res.ShadowID
                $Footprint.vssShadowId = $createdShadowId
                $shadow = Get-CimInstance Win32_ShadowCopy -Filter "ID='$createdShadowId'" -ErrorAction SilentlyContinue
                Write-HawkLog "VSS shadow created ($createdShadowId)"
            } else {
                Write-HawkLog "VSS Win32_ShadowCopy.Create returned $($res.ReturnValue)" 'WARN'
            }
        } catch { Write-HawkLog "VSS shadow create failed: $_" 'WARN' }
        if (-not $shadow) {
            # fall back to the most recent pre-existing shadow, if any
            $shadow = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue |
                      Sort-Object InstallDate -Descending | Select-Object -First 1
        }
        if ($shadow) {
            $dev = $shadow.DeviceObject   # \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
            # Standard tooling can't address GLOBALROOT device paths. Mount the
            # shadow as a directory symlink - reliable on Win7 to Server 2025.
            $vssLink = Join-Path $env:TEMP "hawk_vss_$Stamp"
            cmd /c mklink /d "$vssLink" "$dev\" 1>$null 2>$null
            if (-not (Test-Path $vssLink)) { throw "could not link shadow copy device $dev" }
            $Footprint.tempVssMount = $vssLink
            try {
                $targets = @()   # paths relative to the volume root
                if ($Config.rawAcquisition.registryHives) {
                    $targets += @(
                        @{ rel = "$winRel\System32\config\SYSTEM";   dst = 'raw\registry\SYSTEM' },
                        @{ rel = "$winRel\System32\config\SOFTWARE"; dst = 'raw\registry\SOFTWARE' },
                        @{ rel = "$winRel\System32\config\SAM";      dst = 'raw\registry\SAM' },
                        @{ rel = "$winRel\System32\config\SECURITY"; dst = 'raw\registry\SECURITY' },
                        @{ rel = "$winRel\AppCompat\Programs\Amcache.hve"; dst = 'raw\registry\Amcache.hve' }
                    )
                    # Profiles from the registry ProfileList (not just C:\Users). The
                    # shadow covers the system volume only; profiles elsewhere are logged.
                    foreach ($u in (Get-HawkUserProfiles)) {
                        if (-not $u.Path.StartsWith($sysRoot, [StringComparison]::OrdinalIgnoreCase)) {
                            Write-HawkLog "profile $($u.Path) is not on the system volume; its hives are not in this shadow copy" 'WARN'; continue
                        }
                        $relProfile = $u.Path.Substring($sysRoot.Length)
                        $tag = $u.Name -replace '[^\w.-]', '_'
                        $targets += @{ rel = "$relProfile\NTUSER.DAT"; dst = "raw\registry\NTUSER_$tag.DAT" }
                        # UsrClass.dat holds shellbags (folder-access history incl. removable/deleted/UNC paths)
                        $targets += @{ rel = "$relProfile\AppData\Local\Microsoft\Windows\UsrClass.dat"; dst = "raw\registry\UsrClass_$tag.dat" }
                    }
                }
                Write-Host ("    copying {0} registry hive(s) from the shadow..." -f $targets.Count) -ForegroundColor DarkGray
                foreach ($t in $targets) {
                    try {
                        $src = Join-Path $vssLink $t.rel
                        if (-not (Test-Path -LiteralPath $src)) { continue }
                        $dst = Join-Path $WorkRoot $t.dst
                        Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
                        $RawArtifacts += [ordered]@{ path = ($t.dst -replace '\\','/'); source = "$sysRoot$($t.rel)"
                            method = 'vss'; sha256 = (Get-FileHash $dst -Algorithm SHA256).Hash }
                    } catch { Write-HawkLog "VSS copy failed: $($t.rel) - $_" 'WARN' }
                }
                Write-Host '    registry hives done.' -ForegroundColor DarkGray

                # SRUM: copy the whole sru folder (SRUDB.dat + SRU*.log + .jfm
                # checkpoint) so the ESE database can be recovered/parsed; the
                # logs are required to replay a dirty database.
                if ($Config.rawAcquisition.srum) {
                    $sruSrc = Join-Path $vssLink "$winRel\System32\sru"
                    if (Test-Path -LiteralPath $sruSrc) {
                        foreach ($sf in (Get-ChildItem -LiteralPath $sruSrc -File -ErrorAction SilentlyContinue)) {
                            try {
                                $sdst = Join-Path $WorkRoot "raw\srum\$($sf.Name)"
                                Copy-Item -LiteralPath $sf.FullName -Destination $sdst -Force -ErrorAction Stop
                                $RawArtifacts += [ordered]@{ path = "raw/srum/$($sf.Name)"; source = "$env:SystemRoot\System32\sru\$($sf.Name)"
                                    method = 'vss'; sha256 = (Get-FileHash $sdst -Algorithm SHA256).Hash }
                            } catch { Write-HawkLog "VSS copy failed: sru\$($sf.Name) - $_" 'WARN' }
                        }
                        Write-HawkLog 'SRUM database + transaction logs acquired'
                    }
                }

                # Raw NTFS metadata ($MFT / $UsnJrnl:$J) - cannot be file-copied;
                # extracted via raw cluster reads from the shadow device.
                if ($Config.rawAcquisition.mft -and (Get-Command Invoke-HawkMftAcquisition -ErrorAction SilentlyContinue)) {
                    Write-Host '    extracting $MFT / $UsnJrnl via raw device read (slowest step)...' -ForegroundColor DarkGray
                    $includeUsn = [bool]$Config.rawAcquisition.usnJournal
                    Invoke-HawkMftAcquisition -Device $dev -WorkRoot $WorkRoot -IncludeUsn $includeUsn -RawArtifacts ([ref]$RawArtifacts)
                }

                Write-Host '    SRUM acquired.' -ForegroundColor DarkGray
                Write-Host '[*] Raw acquisition complete. Sealing the .hawk...' -ForegroundColor Cyan
                Write-HawkLog "VSS acquisition complete via $dev"
            } finally {
                cmd /c rmdir "$vssLink" 1>$null 2>$null   # remove link only, not contents
            }
        } else { Write-HawkLog 'no shadow copy available; raw hive acquisition skipped' 'WARN' }
    } catch { Write-HawkLog "VSS acquisition error: $_" 'ERROR' }
    finally {
        # Delete the shadow copy we created (leave any pre-existing ones alone).
        if ($createdShadowId) {
            try {
                Get-CimInstance Win32_ShadowCopy -Filter "ID='$createdShadowId'" -ErrorAction SilentlyContinue |
                    Remove-CimInstance -ErrorAction SilentlyContinue
                Write-HawkLog "VSS shadow removed ($createdShadowId)"
            } catch { Write-HawkLog "VSS shadow cleanup failed: $_" 'WARN' }
        }
    }
}

# --- Prefetch -------------------------------------------------------------------
if ($Config.rawAcquisition.prefetchFiles) {
    Get-ChildItem (Join-Path $env:SystemRoot 'Prefetch\*.pf') -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $pfDst = Join-Path $WorkRoot "raw\prefetch\$($_.Name)"
            Copy-Item -LiteralPath $_.FullName $pfDst -ErrorAction Stop
            # hash the acquired copy (the live .pf can be rewritten between copy and hash)
            $RawArtifacts += [ordered]@{ path = "raw/prefetch/$($_.Name)"; source = $_.FullName; method = 'direct'
                sha256 = (Get-FileHash -LiteralPath $pfDst -Algorithm SHA256).Hash }
        } catch {}
    }
}

}  # end try (collection body)
catch {
    # A terminating error (or Ctrl-C) anywhere in collection lands here; we still
    # fall through to `finally` and seal whatever was gathered as a PARTIAL .hawk.
    $aborted = $true; $abortReason = "$_"
    Write-HawkLog "FATAL: collection aborted - $_" 'ERROR'
    Write-Host "[!] Collection error - sealing PARTIAL evidence and exiting: $_" -ForegroundColor Red
}
finally {

# An abort during the modules must not leave a netsh trace running on the host.
if ($PacketCapture) { try { Stop-HawkNetworkCapture -Capture $PacketCapture -MinSeconds 0 -RawArtifacts ([ref]$RawArtifacts) } catch {} }

# --- Manifest (ALWAYS written; flagged partial on abort) --------------------------
$Footprint.endedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$os = $null; try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch {}
$osCaption = $null; $osVersion = $null; $osBuild = 0
if ($os) { $osCaption = $os.Caption; $osVersion = $os.Version; try { $osBuild = [int]$os.BuildNumber } catch {} }
$tz = $null; try { $tz = (Get-TimeZone).DisplayName } catch {}
$Manifest = [ordered]@{
    schemaVersion = '1.0'
    tool = @{ name = 'HawkCollector'; version = '2.0.0' }
    partial = $aborted
    abortReason = $abortReason
    case = [ordered]@{
        caseNumber = $CaseNum; investigator = $Config.investigator
        collectionStartUtc = $StartUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        collectionEndUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    host = [ordered]@{
        hostname = $Hostname; domain = $env:USERDNSDOMAIN
        os = @{ caption = $osCaption; version = $osVersion; build = $osBuild }
        role = $Role
        timezone = $tz
        arch = $env:PROCESSOR_ARCHITECTURE
        # 'online' | 'offline' | 'unknown' - see collectorFootprint.connectivityCheck
        connectivity = $Connectivity
        internetReachable = $(if ($Connectivity -eq 'unknown') { $null } else { $Connectivity -eq 'online' })
        isolated = ($Connectivity -eq 'offline')
    }
    preset = $Config.preset
    eventLogDays = $Config.eventLogDays
    collectorFootprint = $Footprint
    modules = $ModuleResults
    rawArtifacts = $RawArtifacts
    evtxStatus = $EvtxStatus
}
$Manifest | ConvertTo-Json -Depth 8 | Out-File (Join-Path $WorkRoot 'manifest.json') -Encoding utf8

# --- Hash everything, zip to .hawk --------------------------------------------------
$AllHashes = @(Get-HawkFileTree -Root $WorkRoot | ForEach-Object {
    [ordered]@{ path = $_.Rel
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
})
@{ schemaVersion = '1.0'; files = $AllHashes } | ConvertTo-Json -Depth 4 |
    Out-File (Join-Path $WorkRoot 'hashes.json') -Encoding utf8

# Partial sessions get a _PARTIAL tag so the analyst sees the status at a glance.
$partTag = if ($aborted) { '_PARTIAL' } else { '' }
$SessionFile = Join-Path $OutputDir ("{0}_{1}_{2}{3}.hawk" -f $CaseNum, $Hostname, $Stamp, $partTag)
$SessionHash = $null; $sealError = $null
try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($WorkRoot, $SessionFile,
        [IO.Compression.CompressionLevel]::Optimal, $false)
    # Confirm the container really holds every staged file before anything is removed.
    $staged = @(Get-HawkFileTree -Root $WorkRoot).Count
    $zip = [IO.Compression.ZipFile]::OpenRead($SessionFile)
    try { $zipped = @($zip.Entries | Where-Object { $_.Name }).Count } finally { $zip.Dispose() }
    if ($zipped -ne $staged) { throw "container holds $zipped of $staged staged files" }
    $SessionHash = (Get-FileHash -LiteralPath $SessionFile -Algorithm SHA256).Hash
    "$SessionHash  $(Split-Path $SessionFile -Leaf)" | Out-File "$SessionFile.sha256" -Encoding ascii
} catch { $sealError = "$_" }

Write-Host ""
if ($sealError) {
    # NEVER delete unsealed evidence: leave the work folder for manual sealing / copy-off.
    Write-Host "[!] SEAL FAILED: $sealError" -ForegroundColor Red
    Write-Host "    Evidence is UNSEALED but intact in: $WorkRoot" -ForegroundColor Red
    Write-Host "    hashes.json inside it still lists every file's SHA256. Do not delete it." -ForegroundColor Red
    try { Write-HawkLog "SEAL FAILED: $sealError - work folder kept: $WorkRoot" 'ERROR' } catch {}
    $script:HawkExit = 3
} else {
    if ($aborted) {
        Write-Host "[!] PARTIAL session (collection was interrupted): $SessionFile" -ForegroundColor Yellow
        $script:HawkExit = 2
    } else {
        Write-Host "[+] Session: $SessionFile" -ForegroundColor Green
        $script:HawkExit = 0
    }
    Write-Host "[+] SHA256 : $SessionHash"
    Write-Host "    Import this file in Hawk Analyzer."
    # Clean working dir (evidence now sealed in the .hawk and verified above)
    Remove-Item $WorkRoot -Recurse -Force -ErrorAction SilentlyContinue
}

}  # end finally (seal)

exit $script:HawkExit
