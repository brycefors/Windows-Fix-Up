# --- SCRIPT OVERVIEW ---
# Get-WindowsUpdateErrorAnalysis.ps1 is an administrative diagnostic tool that parses local Windows Update
# and Servicing (CBS) logs, extracts the failure codes (HRESULT / Win32 hex codes), looks up their technical
# meaning in an embedded offline database, and prints an actionable, step-by-step remediation report.
#
# Data pipeline:
#   [Log Sources]
#     - Get-WinEvent   (System log, provider Microsoft-Windows-WindowsUpdateClient, Event IDs 20/25/31)
#     - CBS.log        (C:\Windows\Logs\CBS\CBS.log - opt in with -IncludeCbsLogs)
#         |
#         v
#   [Parse + Deduplicate]  -> Timestamp, KB ID, raw HRESULT / Win32 hex code
#         |
#         v
#   [Offline Error Lookup] -> Name, Technical Cause, Native Remediation (fallback: net helpmsg / FormatMessage)
#         |
#         v
#   [Output]
#     - Colour-coded console report
#     - JSON export (-ExportJsonPath)
#     - Generated, review-before-you-run remediation script Invoke-RepairWU.ps1
#     - Optional native auto-remediation (-AutoRemediate)
#
# DESIGN NOTE: Over 85% of update failures come from WinSxS component-store corruption or SoftwareDistribution
# cache deadlocks, not a single bad KB. This tool therefore operates primarily as an INTERACTIVE DIAGNOSTIC
# ENGINE: it reports the findings and generates a remediation script (Invoke-RepairWU.ps1) that an operator can
# review before executing, rather than blindly changing the system. -AutoRemediate is opt-in and only runs the
# deterministic, safe native repairs.
# -------------------------------------------------
# How to Run:
# NOTE: It is recommended to use "Run-Windows-Update-Error-Analysis.bat" to invoke this script. You can also run
#       the .PS1 directly from an elevated PowerShell prompt.
# 1.  Open PowerShell as an Administrator: Right-click your Start Menu and select "Terminal (Admin)".
# 2.  Enable Script Execution (if needed): Set-ExecutionPolicy Bypass -Force
# 3.  Run the Script: .\Get-WindowsUpdateErrorAnalysis.ps1
# -------------------------------------------------

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    # Look back period in days (Default: 30)
    [int]$Days = 30,

    # A failure whose most recent occurrence is within this many days is flagged 'Active'; older ones are 'Resolved' (Default: 7)
    [int]$ActiveThresholdDays = 7,

    # If no quality update has installed within this many days, warn that the build is not recent and patching may be impaired (Default: 45)
    [int]$StaleBuildDays = 45,

    # Export raw analysis to a JSON file path
    [string]$ExportJsonPath,

    # Also parse the CBS servicing log (C:\Windows\Logs\CBS\CBS.log)
    [switch]$IncludeCbsLogs,

    # Automatically execute the safe native repair tools (service reset / SoftwareDistribution rename / DISM / SFC)
    [switch]$AutoRemediate,

    # Return structured analysis objects to the pipeline
    [switch]$PassThru
)

# ---------------------------------------------------------------------------------------------------------------
# Environment guards
# ---------------------------------------------------------------------------------------------------------------

# Compatible with Windows PowerShell 5.1 and PowerShell 7.x+ Core.
if ($PSVersionTable.PSVersion.Major -lt 5) {
    throw "This script requires PowerShell 5.1 or higher. You are currently running $($PSVersionTable.PSVersion)."
}

# Require Administrator elevation. Self-elevate by relaunching in an elevated PowerShell session (UAC prompt).
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        # Rebuild the argument list, forwarding every bound parameter (with its value) to the elevated instance.
        $ArgumentList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$($MyInvocation.MyCommand.Path)`"")
        foreach ($Parameter in $PSBoundParameters.GetEnumerator()) {
            $Value = $Parameter.Value
            if ($Value -is [switch]) {
                if ($Value.IsPresent) { $ArgumentList += "-$($Parameter.Key)" }
            }
            else {
                $ArgumentList += "-$($Parameter.Key)"
                $ArgumentList += "`"$Value`""
            }
        }

        Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList $ArgumentList
        exit
    }

    throw 'Administrator elevation is required. Re-run this script from an elevated (Run as administrator) PowerShell session.'
}

$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------------------------------------------

$Script:SupportsAnsi = $Host.UI.SupportsVirtualTerminal -or ($PSVersionTable.PSVersion.Major -ge 7)

function Get-TimeStamp {
    return (Get-Date -Format '[MM/dd/yyyy|HH:mm:ss]')
}

function Write-Section {
    param([string]$Title)
    $width = try { $Host.UI.RawUI.BufferSize.Width - 1 } catch { 78 }
    if ($width -lt 20) { $width = 78 }
    $line = ('-' * $width)
    Write-Host ''
    Write-Host $line -ForegroundColor DarkGray
    Write-Host $Title -ForegroundColor Cyan
    Write-Host $line -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------------------------------------------
# Embedded offline error-lookup database
# Keyed by the normalized lowercase hex code (e.g. '0x800f081f').
#   Name        - The symbolic error name.
#   Cause       - Plain-language technical cause.
#   Action      - Human-readable remediation guidance shown in the report.
#   Command     - The native command(s) written into the generated Invoke-RepairWU.ps1 (or run by -AutoRemediate).
#   Safe        - $true when the remediation is a deterministic, non-destructive native repair that -AutoRemediate
#                 is allowed to execute automatically. $false requires manual operator review.
# ---------------------------------------------------------------------------------------------------------------
$Script:ErrorDatabase = [ordered]@{
    '0x80070002' = [pscustomobject]@{
        Name    = 'ERROR_FILE_NOT_FOUND'
        Cause   = 'Missing update file or a corrupted Windows Update cache (SoftwareDistribution) directory.'
        Action  = 'Stop wuauserv and bits, rename C:\Windows\SoftwareDistribution, then restart the services.'
        Command = @'
Stop-Service -Name wuauserv, bits -Force -ErrorAction SilentlyContinue
$sd = Join-Path $env:windir 'SoftwareDistribution'
if (Test-Path $sd) { Rename-Item -Path $sd -NewName ("SoftwareDistribution.old_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss')) -ErrorAction SilentlyContinue }
Start-Service -Name bits, wuauserv -ErrorAction SilentlyContinue
'@
        Safe    = $true
    }
    '0x80070005' = [pscustomobject]@{
        Name    = 'ERROR_ACCESS_DENIED'
        Cause   = 'File-system or registry permission blockade during servicing payload injection.'
        Action  = 'Reset Windows Update component permissions (subinacl / a permissions reset) and re-run the update. Requires manual review.'
        Command = @'
# ACCESS_DENIED is not auto-remediated - review before running.
# Reset the ACLs on the servicing keys/folders, e.g. with subinacl, then retry the update:
#   subinacl /subkeyreg HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing /grant=administrators=f
#   subinacl /subdirectories %windir%\SoftwareDistribution /grant=administrators=f
Write-Warning 'ERROR_ACCESS_DENIED (0x80070005): review permissions on the servicing store and SoftwareDistribution folder before proceeding.'
'@
        Safe    = $false
    }
    '0x800705b4' = [pscustomobject]@{
        Name    = 'ERROR_TIMEOUT'
        Cause   = 'The Windows Update service timed out waiting for a child process or a Defender scan.'
        Action  = 'Restart wuauserv and set its startup type back to Automatic, then retry.'
        Command = @'
Restart-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
'@
        Safe    = $true
    }
    '0x800f081f' = [pscustomobject]@{
        Name    = 'CBS_E_SOURCE_MISSING'
        Cause   = 'Servicing payload files (SxS) are missing from the local WinSxS component store.'
        Action  = 'Repair the component store with DISM /Online /Cleanup-Image /RestoreHealth.'
        Command = @'
DISM.exe /Online /Cleanup-Image /RestoreHealth
'@
        Safe    = $true
    }
    '0x800f0922' = [pscustomobject]@{
        Name    = 'CBS_E_INSTALL_FAILED'
        Cause   = 'Low System Reserved partition space, Secure Boot issues, or a VPN/network block during install.'
        Action  = 'Verify the System Reserved partition has >100 MB free and check the BitLocker status. Requires manual review.'
        Command = @'
# CBS_E_INSTALL_FAILED (0x800f0922) is not auto-remediated - review before acting.
# 1. Confirm the System Reserved partition has more than 100 MB free.
# 2. Check BitLocker status and suspend if needed (manage-bde -status / Suspend-BitLocker).
# 3. Disconnect any VPN and retry the update.
Get-Volume | Format-Table DriveLetter, FileSystemLabel, @{N='FreeMB';E={[math]::Round($_.SizeRemaining/1MB)}} -AutoSize
manage-bde -status
'@
        Safe    = $false
    }
    '0x800f0988' = [pscustomobject]@{
        Name    = 'PSFX_E_MATCHING_BINARY_MISSING'
        Cause   = 'A reset-base / WinSxS cleanup removed a delta-update dependency.'
        Action  = 'Perform a reset-base DISM repair or manually install the latest Servicing Stack Update (SSU). Requires manual review.'
        Command = @'
# PSFX_E_MATCHING_BINARY_MISSING (0x800f0988) is not auto-remediated - review before acting.
# Attempt a component-store repair; if it fails, manually install the latest SSU for this build.
DISM.exe /Online /Cleanup-Image /RestoreHealth
Write-Warning 'If repair fails, download and install the latest Servicing Stack Update (SSU) for this build from the Microsoft Update Catalog.'
'@
        Safe    = $false
    }
    '0x80240020' = [pscustomobject]@{
        Name    = 'WU_E_NO_INTERACTIVE_USER'
        Cause   = 'An automatic (non-interactive) update session failed because interactive authorization was required.'
        Action  = 'Trigger a detection scan from the SYSTEM context (e.g. wuauclt /detectnow or USOClient StartScan).'
        Command = @'
# WU_E_NO_INTERACTIVE_USER (0x80240020): trigger a fresh detection scan.
try { UsoClient.exe StartScan } catch {}
wuauclt.exe /detectnow 2>$null
'@
        Safe    = $true
    }
    '0x80248007' = [pscustomobject]@{
        Name    = 'WU_E_DS_NODRIVER'
        Cause   = 'A driver payload is missing from the local WSUS / Windows Update datastore.'
        Action  = 'Delete DataStore.edb under SoftwareDistribution\DataStore so the datastore rebuilds.'
        Command = @'
Stop-Service -Name wuauserv, bits -Force -ErrorAction SilentlyContinue
$edb = Join-Path $env:windir 'SoftwareDistribution\DataStore\DataStore.edb'
if (Test-Path $edb) { Remove-Item -Path $edb -Force -ErrorAction SilentlyContinue }
Start-Service -Name bits, wuauserv -ErrorAction SilentlyContinue
'@
        Safe    = $true
    }
    '0x80073d02' = [pscustomobject]@{
        Name    = 'ERROR_DEPLOYMENT_BLOCKED_BY_IN_USE_PACKAGE'
        Cause   = 'AppX/UWP deployment failed because the target app (or a dependent background process) is running, or the Store/AppX cache is corrupted. Most often a simple process lock on %LocalAppData%\Packages\<PackageName>.'
        Action  = 'Close the target UWP app and its background tasks to release the package file locks, then run wsreset.exe to clear the Store cache. If it persists, re-register the Store AppX manifest. Requires manual review (killing apps can lose unsaved data; never Remove-AppxPackage without re-registration media).'
        Command = @'
# ERROR_DEPLOYMENT_BLOCKED_BY_IN_USE_PACKAGE (0x80073D02) is not auto-remediated - review before acting.
# 1. Close the target UWP app and any background tasks holding a lock on %LocalAppData%\Packages\<PackageName>.
#    (Force-killing may discard unsaved application state.)
# 2. Clear the Microsoft Store cache without touching package registrations:
wsreset.exe
# 3. If the failure persists, re-register the Store AppX manifest (fixes broken manifests / missing dependencies).
#    Do NOT run Remove-AppxPackage on the Store client without offline media - it removes it permanently.
Get-AppxPackage -AllUsers *WindowsStore* | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
'@
        Safe    = $false
    }
}

# ---------------------------------------------------------------------------------------------------------------
# Error-code resolution (embedded table first, then OS fallback)
# ---------------------------------------------------------------------------------------------------------------

function Resolve-ErrorMeaning {
    param([Parameter(Mandatory)][string]$Code)

    $key = $Code.ToLowerInvariant()
    if ($Script:ErrorDatabase.Contains($key)) {
        return $Script:ErrorDatabase[$key]
    }

    # Fallback: ask the OS to describe the code. HRESULTs of the form 0x8007xxxx wrap a Win32 code in the low word.
    $meaning = $null
    try {
        $numeric = [Convert]::ToUInt32($Code, 16)
        # Extract the Win32 facility (0x8007) low word when applicable.
        if (($numeric -band 0xFFFF0000) -eq 0x80070000) {
            $win32 = [int]($numeric -band 0xFFFF)
            $meaning = ([System.ComponentModel.Win32Exception]$win32).Message
        }
        if ([string]::IsNullOrWhiteSpace($meaning)) {
            $meaning = ([System.ComponentModel.Win32Exception]([int]$numeric)).Message
        }
    }
    catch {
        $meaning = $null
    }

    if ([string]::IsNullOrWhiteSpace($meaning) -or $meaning -match 'Unknown error') {
        # Last resort: net helpmsg on the decimal low word.
        try {
            $numeric = [Convert]::ToUInt32($Code, 16)
            $decimal = [int]($numeric -band 0xFFFF)
            $help = (& net.exe helpmsg $decimal 2>$null) -join ' '
            if (-not [string]::IsNullOrWhiteSpace($help)) { $meaning = $help.Trim() }
        }
        catch { }
    }

    if ([string]::IsNullOrWhiteSpace($meaning)) { $meaning = 'Unknown / undocumented error code.' }

    return [pscustomobject]@{
        Name    = 'UNKNOWN'
        Cause   = $meaning
        Action  = 'No embedded remediation. Search the Microsoft Update Catalog / documentation for this code and review manually.'
        Command = "# No embedded remediation for $Code. Review manually. OS description: $meaning"
        Safe    = $false
    }
}

# ---------------------------------------------------------------------------------------------------------------
# Log extraction
# ---------------------------------------------------------------------------------------------------------------

$Script:HResultRegex = '0x8[0-9a-fA-F]{7}'
$Script:KbRegex = 'KB\d{6,7}'

function Get-WindowsUpdateEventFailures {
    param([int]$LookbackDays)

    $results = New-Object System.Collections.Generic.List[object]
    $startTime = (Get-Date).AddDays(-$LookbackDays)

    try {
        $filter = @{
            LogName      = 'System'
            ProviderName = 'Microsoft-Windows-WindowsUpdateClient'
            Id           = 20, 25, 31
            StartTime    = $startTime
        }
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    }
    catch {
        # Get-WinEvent throws when no events match the filter - that is not an error condition for us.
        if ($_.Exception.Message -notmatch 'No events were found') {
            Write-Warning "Could not read the System event log: $($_.Exception.Message)"
        }
        return $results
    }

    foreach ($evt in $events) {
        $message = $evt.Message
        $codeMatch = [regex]::Match($message, $Script:HResultRegex)
        if (-not $codeMatch.Success) { continue }

        $kbMatch = [regex]::Match($message, $Script:KbRegex)

        $results.Add([pscustomobject]@{
                Source    = 'EventLog'
                Timestamp = $evt.TimeCreated
                EventId   = $evt.Id
                Kb        = if ($kbMatch.Success) { $kbMatch.Value } else { $null }
                Code      = ('0x{0:x8}' -f [Convert]::ToUInt32($codeMatch.Value, 16))
                Detail    = ($message -replace '\s+', ' ').Trim()
            })
    }

    return $results
}

function Get-CbsLogFailures {
    param([int]$LookbackDays)

    $results = New-Object System.Collections.Generic.List[object]
    $cbsPath = Join-Path $env:windir 'Logs\CBS\CBS.log'
    if (-not (Test-Path $cbsPath)) {
        Write-Warning "CBS log not found at $cbsPath - skipping CBS analysis."
        return $results
    }

    $cutoff = (Get-Date).AddDays(-$LookbackDays)

    try {
        $cbsMatches = Select-String -Path $cbsPath -Pattern $Script:HResultRegex -ErrorAction Stop |
            Where-Object { $_.Line -match 'Failed|Error|STORE_ERROR' }
    }
    catch {
        Write-Warning "Could not read the CBS log: $($_.Exception.Message)"
        return $results
    }

    foreach ($m in $cbsMatches) {
        $line = $m.Line
        $codeMatch = [regex]::Match($line, $Script:HResultRegex)
        if (-not $codeMatch.Success) { continue }

        # CBS lines start with an ISO timestamp, e.g. "2026-07-19 08:15:03, Error ..."
        $ts = $null
        $tsMatch = [regex]::Match($line, '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
        if ($tsMatch.Success) {
            [datetime]$parsed = [datetime]::MinValue
            if ([datetime]::TryParse($tsMatch.Value, [ref]$parsed)) { $ts = $parsed }
        }
        if ($ts -and $ts -lt $cutoff) { continue }

        $kbMatch = [regex]::Match($line, $Script:KbRegex)

        $results.Add([pscustomobject]@{
                Source    = 'CBS'
                Timestamp = $ts
                EventId   = $null
                Kb        = if ($kbMatch.Success) { $kbMatch.Value } else { $null }
                Code      = ('0x{0:x8}' -f [Convert]::ToUInt32($codeMatch.Value, 16))
                Detail    = $line.Trim()
            })
    }

    return $results
}

# ---------------------------------------------------------------------------------------------------------------
# Deduplication + enrichment
# ---------------------------------------------------------------------------------------------------------------

function Group-FailureAnalysis {
    param(
        [System.Collections.Generic.List[object]]$RawFailures,
        [int]$ActiveThresholdDays = 7
    )

    $analysis = New-Object System.Collections.Generic.List[object]
    if ($RawFailures.Count -eq 0) { return $analysis }

    $activeCutoff = (Get-Date).AddDays(-$ActiveThresholdDays)
    $grouped = $RawFailures | Group-Object -Property Code
    foreach ($g in $grouped) {
        $code = $g.Name
        $meaning = Resolve-ErrorMeaning -Code $code
        $times = $g.Group | Where-Object { $_.Timestamp } | Select-Object -ExpandProperty Timestamp
        $kbs = $g.Group | Where-Object { $_.Kb } | Select-Object -ExpandProperty Kb -Unique
        $sources = $g.Group | Select-Object -ExpandProperty Source -Unique

        $lastSeen = if ($times) { ($times | Measure-Object -Maximum).Maximum } else { $null }
        # Status reflects recency only: it cannot confirm a fix, just that the code has not recurred lately.
        $status = if (-not $lastSeen) { 'Unknown' }
            elseif ($lastSeen -ge $activeCutoff) { 'Active' }
            else { 'Resolved' }

        $analysis.Add([pscustomobject]@{
                Code            = $code
                Name            = $meaning.Name
                Status          = $status
                Occurrences     = $g.Count
                AffectedKBs     = @($kbs)
                Sources         = @($sources)
                FirstSeen       = if ($times) { ($times | Measure-Object -Minimum).Minimum } else { $null }
                LastSeen        = $lastSeen
                Cause           = $meaning.Cause
                Remediation     = $meaning.Action
                RemediationSafe = $meaning.Safe
                RepairCommand   = $meaning.Command
                Sample          = ($g.Group | Select-Object -First 1 -ExpandProperty Detail)
            })
    }

    return ($analysis | Sort-Object -Property Occurrences -Descending)
}

# ---------------------------------------------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------------------------------------------

function Write-AnalysisReport {
    param([System.Collections.Generic.List[object]]$Analysis)

    Write-Section 'Windows Update Error Analysis'
    if ($Analysis.Count -eq 0) {
        Write-Host 'No Windows Update / Servicing failures were found in the analyzed window.' -ForegroundColor Green
        return
    }

    Write-Host ("Found {0} distinct failure code(s) in the last {1} day(s).`n" -f $Analysis.Count, $Days) -ForegroundColor Yellow

    foreach ($item in $Analysis) {
        $codeColor = if ($item.RemediationSafe) { 'Yellow' } else { 'Red' }
        Write-Host ("{0}  {1}" -f $item.Code, $item.Name) -ForegroundColor $codeColor
        $statusColor = switch ($item.Status) { 'Active' { 'Red' } 'Resolved' { 'DarkGray' } default { 'Yellow' } }
        $statusNote = switch ($item.Status) {
            'Active'   { "Active (recurred within $ActiveThresholdDays day(s))" }
            'Resolved' { "Resolved? (no recurrence in the last $ActiveThresholdDays day(s))" }
            default    { 'Unknown (no timestamp available)' }
        }
        Write-Host ("  Status      : {0}" -f $statusNote) -ForegroundColor $statusColor
        Write-Host ("  Occurrences : {0}   Sources: {1}" -f $item.Occurrences, ($item.Sources -join ', ')) -ForegroundColor Gray
        if ($item.AffectedKBs.Count -gt 0) {
            Write-Host ("  Affected KBs: {0}" -f ($item.AffectedKBs -join ', ')) -ForegroundColor Gray
        }
        if ($item.FirstSeen) {
            Write-Host ("  Window      : {0} -> {1}" -f $item.FirstSeen, $item.LastSeen) -ForegroundColor Gray
        }
        Write-Host ("  Cause       : {0}" -f $item.Cause) -ForegroundColor White
        Write-Host ("  Remediation : {0}" -f $item.Remediation) -ForegroundColor Cyan
        $safeLabel = if ($item.RemediationSafe) { 'safe / auto-remediable' } else { 'MANUAL REVIEW required' }
        Write-Host ("  Auto-fix    : {0}" -f $safeLabel) -ForegroundColor $(if ($item.RemediationSafe) { 'Green' } else { 'Red' })
        Write-Host ''
    }
}

function New-RepairScript {
    param(
        [System.Collections.Generic.List[object]]$Analysis,
        [string]$OutputPath
    )

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('# Invoke-RepairWU.ps1')
    [void]$sb.AppendLine('# Auto-generated by Get-WindowsUpdateErrorAnalysis.ps1 on ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    [void]$sb.AppendLine('#')
    [void]$sb.AppendLine('# REVIEW THIS SCRIPT BEFORE RUNNING IT. It applies remediation for the update failures that were')
    [void]$sb.AppendLine('# detected on this machine. Run from an elevated PowerShell prompt. A reboot is recommended afterward.')
    [void]$sb.AppendLine('# Commands flagged "MANUAL REVIEW" are commented-out guidance, not automatic actions.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('#Requires -RunAsAdministrator')
    [void]$sb.AppendLine('[CmdletBinding()]')
    [void]$sb.AppendLine('param()')
    [void]$sb.AppendLine('$ErrorActionPreference = ''Continue''')
    [void]$sb.AppendLine('')

    foreach ($item in $Analysis) {
        [void]$sb.AppendLine('# ============================================================================')
        [void]$sb.AppendLine(('# {0}  {1}' -f $item.Code, $item.Name))
        [void]$sb.AppendLine(('# Cause      : {0}' -f $item.Cause))
        [void]$sb.AppendLine(('# Remediation: {0}' -f $item.Remediation))
        $flag = if ($item.RemediationSafe) { 'SAFE (auto-remediable)' } else { 'MANUAL REVIEW required' }
        [void]$sb.AppendLine(('# Classification: {0}' -f $flag))
        [void]$sb.AppendLine('# ============================================================================')
        [void]$sb.AppendLine(("Write-Host 'Applying remediation for {0} {1}...' -ForegroundColor Cyan" -f $item.Code, $item.Name))
        [void]$sb.AppendLine($item.RepairCommand.Trim())
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('Write-Host ''Remediation complete. A restart is recommended.'' -ForegroundColor Green')

    Set-Content -Path $OutputPath -Value $sb.ToString() -Encoding UTF8 -Force
    return $OutputPath
}

function Invoke-SafeRemediation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param([System.Collections.Generic.List[object]]$Analysis)

    Write-Section 'Auto-Remediation (-AutoRemediate)'
    $safeItems = $Analysis | Where-Object { $_.RemediationSafe }
    if (-not $safeItems) {
        Write-Host 'No safe / auto-remediable failures were detected. Nothing was executed.' -ForegroundColor Yellow
        return
    }

    Write-Host 'WARNING: Running native repairs (service reset, SoftwareDistribution rename, DISM/SFC) can disrupt an' -ForegroundColor Yellow
    Write-Host 'in-flight update cycle. Do not run this during an active background patch install.' -ForegroundColor Yellow
    Write-Host ''

    foreach ($item in $safeItems) {
        $target = "$($item.Code) ($($item.Name))"
        if ($PSCmdlet.ShouldProcess($target, 'Apply native remediation')) {
            Write-Host ("Remediating {0}..." -f $target) -ForegroundColor Cyan
            try {
                $sb = [scriptblock]::Create($item.RepairCommand)
                & $sb
            }
            catch {
                Write-Warning "Remediation for $target failed: $($_.Exception.Message)"
            }
        }
    }

    # A component-store repair (DISM /RestoreHealth) is the single highest-yield fix for the ~85% of failures
    # rooted in WinSxS corruption. Follow it with an SFC pass.
    Write-Host ''
    if ($PSCmdlet.ShouldProcess('Component store (DISM /RestoreHealth + SFC)', 'Repair')) {
        Write-Host 'Running DISM /Online /Cleanup-Image /RestoreHealth ...' -ForegroundColor Cyan
        DISM.exe /Online /Cleanup-Image /RestoreHealth
        Write-Host 'Running sfc /scannow ...' -ForegroundColor Cyan
        sfc.exe /scannow
    }

    Write-Host ''
    Write-Host 'Auto-remediation finished. A restart is recommended.' -ForegroundColor Green
}

# ---------------------------------------------------------------------------------------------------------------
# Build / patch currency check
# ---------------------------------------------------------------------------------------------------------------

# Reads Windows' own component-store package data (via DISM) to find the highest cumulative-update revision
# (UBR) that has actually been laid down on this machine, and whether it is fully Installed or still pending.
# Cumulative-update package names carry the version as <build>.<UBR>.<x>.<y>, e.g.
# "Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.8894.1.9" -> build 26100, UBR 8894. This lets us
# derive the update UBR straight from what is installed inside Windows, with no online/offline reference
# table. Returns a PSCustomObject (Build, Ubr, State) for the newest cumulative update, or $null if unreadable.
function Get-InstalledUpdateUbr {
    param([int]$RunningBuild)

    try {
        $packages = Get-WindowsPackage -Online -ErrorAction Stop |
            Where-Object { $_.PackageName -match 'RollupFix' }
    }
    catch {
        return $null
    }
    if (-not $packages) { return $null }

    $best = $null
    foreach ($pkg in $packages) {
        if ($pkg.PackageName -match '~~(\d+)\.(\d+)\.\d+\.\d+') {
            $pkgBuild = [int]$Matches[1]
            $pkgUbr = [int]$Matches[2]
            # Only compare against updates for the build line the machine is actually on.
            if ($RunningBuild -and $pkgBuild -ne $RunningBuild) { continue }
            if (-not $best -or $pkgUbr -gt $best.Ubr) {
                $best = [pscustomobject]@{
                    Build = $pkgBuild
                    Ubr   = $pkgUbr
                    State = "$($pkg.PackageState)"
                }
            }
        }
    }
    return $best
}

# Determines whether the machine appears to be behind on quality updates. This is an OFFLINE heuristic: rather
# than looking up the latest available build online, it reports the OS build and the date of the most recent
# quality-update install. If nothing has installed within -StaleBuildDays, the build is likely not recent and
# patching may be impaired - which is exactly the condition that produces the servicing errors this tool decodes.
function Test-BuildCurrency {
    param([int]$StaleDays = 45)

    $caption = $null
    $buildUbr = $null
    $runningBuild = $null
    $runningUbr = $null
    try {
        $reg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        $caption = if ($reg.ProductName) { $reg.ProductName } else { $null }
        # The registry ProductName still reads "Windows 10 ..." on Windows 11 (Microsoft never updated it);
        # the real distinction is the build number - 22000 and higher is Windows 11.
        if ($caption -and $reg.CurrentBuildNumber -and [int]$reg.CurrentBuildNumber -ge 22000) {
            $caption = $caption -replace 'Windows 10', 'Windows 11'
        }
        if ($reg.DisplayVersion) { $caption = "$caption ($($reg.DisplayVersion))" }
        if ($reg.CurrentBuildNumber) { $runningBuild = [int]$reg.CurrentBuildNumber }
        if ($null -ne $reg.UBR) { $runningUbr = [int]$reg.UBR }
        if ($runningBuild -and $null -ne $runningUbr) {
            $buildUbr = "$runningBuild.$runningUbr"
        }
    }
    catch { }

    # Determine the most recent quality update - both its install date and its KB (Windows' own record).
    $lastUpdate = $null
    $lastKb = $null
    try {
        $lastHotfix = Get-HotFix -ErrorAction Stop |
            Where-Object { $_.InstalledOn } |
            Sort-Object -Property InstalledOn -Descending |
            Select-Object -First 1
        if ($lastHotfix) {
            $lastUpdate = $lastHotfix.InstalledOn
            $lastKb = $lastHotfix.HotFixID
        }
    }
    catch { }

    if (-not $lastUpdate) {
        # Fallback: the Windows Update agent's last successful install timestamp.
        try {
            $val = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' -Name 'LastSuccessTime' -ErrorAction Stop).LastSuccessTime
            if ($val) { $lastUpdate = [datetime]$val }
        }
        catch { }
    }

    $daysSince = if ($lastUpdate) { [int]((Get-Date) - $lastUpdate).TotalDays } else { $null }
    $isStale = ($null -eq $lastUpdate) -or ($daysSince -gt $StaleDays)

    # Cross-check the running revision against what Windows itself reports as installed. If a newer
    # cumulative-update revision (UBR) is present in the component store than the one the system is running,
    # the last update installed but is not active yet (restart pending, or it did not commit) - so the
    # machine is effectively behind even though an update was installed.
    $installed = if ($runningBuild) { Get-InstalledUpdateUbr -RunningBuild $runningBuild } else { $null }
    $installedUbr = if ($installed) { $installed.Ubr } else { $null }
    $installedUbrState = if ($installed) { $installed.State } else { $null }
    $updatePending = ($null -ne $installedUbr -and $null -ne $runningUbr -and $installedUbr -gt $runningUbr)

    return [pscustomobject]@{
        Caption           = $caption
        BuildUbr          = $buildUbr
        RunningBuild      = $runningBuild
        RunningUbr        = $runningUbr
        LastUpdate        = $lastUpdate
        LastKb            = $lastKb
        DaysSincePatch    = $daysSince
        StaleThreshold    = $StaleDays
        IsStale           = $isStale
        InstalledUbr      = $installedUbr
        InstalledUbrState = $installedUbrState
        UpdatePending     = $updatePending
    }
}

function Write-BuildCurrency {
    param([pscustomobject]$Currency)

    Write-Section 'Build & Patch Currency'
    Write-Host ("  OS          : {0}" -f $(if ($Currency.Caption) { $Currency.Caption } else { 'Unknown' })) -ForegroundColor Gray
    Write-Host ("  Build.UBR   : {0}" -f $(if ($Currency.BuildUbr) { $Currency.BuildUbr } else { 'Unknown' })) -ForegroundColor Gray

    if ($Currency.LastUpdate) {
        $kbNote = if ($Currency.LastKb) { " - $($Currency.LastKb)" } else { '' }
        Write-Host ("  Last update : {0} ({1} day(s) ago){2}" -f $Currency.LastUpdate.ToString('yyyy-MM-dd'), $Currency.DaysSincePatch, $kbNote) -ForegroundColor Gray
    }
    else {
        Write-Host '  Last update : Unknown (no installed quality update found)' -ForegroundColor Yellow
    }

    # Newest cumulative-update revision Windows reports as installed, and whether it is active yet.
    if ($null -ne $Currency.InstalledUbr) {
        Write-Host ("  Installed   : revision .{0} ({1})" -f $Currency.InstalledUbr, $Currency.InstalledUbrState) -ForegroundColor Gray
    }

    if ($Currency.UpdatePending) {
        Write-Host ''
        Write-Host 'WARNING: An installed update has not taken effect - updates might be behind.' -ForegroundColor Red
        Write-Host ("         Windows has cumulative-update revision .{0} installed, but the system is still running" -f $Currency.InstalledUbr) -ForegroundColor Yellow
        Write-Host ("         revision .{0} (build {1}.{2}). The update is applied but not active - a restart is likely" -f $Currency.RunningUbr, $Currency.RunningBuild, $Currency.RunningUbr) -ForegroundColor Yellow
        Write-Host '         pending, or the last update did not finish committing. Restart and re-check; if it persists,' -ForegroundColor Yellow
        Write-Host '         resolve the servicing errors below and run Windows Update again.' -ForegroundColor Yellow
    }

    if ($Currency.IsStale) {
        Write-Host ''
        Write-Host 'WARNING: This machine does not appear to be on a recent build.' -ForegroundColor Red
        if ($Currency.LastUpdate) {
            Write-Host ("         No quality update has installed in {0} day(s) (threshold {1}). It is behind on patching," -f $Currency.DaysSincePatch, $Currency.StaleThreshold) -ForegroundColor Yellow
        }
        else {
            Write-Host '         No installed quality update could be found. It may be badly behind on patching,' -ForegroundColor Yellow
        }
        Write-Host '         which frequently causes servicing failures. Any errors below may simply reflect a stuck' -ForegroundColor Yellow
        Write-Host '         update pipeline. Resolve the servicing errors, then run Windows Update to catch up.' -ForegroundColor Yellow
    }
    else {
        Write-Host '  Status      : Build appears reasonably current.' -ForegroundColor Green
    }
}

# ---------------------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------------------

$Host.UI.RawUI.WindowTitle = "Windows Update Error Analysis - $env:COMPUTERNAME"
Write-Host "$(Get-TimeStamp) Analyzing Windows Update failures over the last $Days day(s)..." -ForegroundColor Cyan

# Report build / patch currency first - a stale build is the most common context for servicing errors.
$currency = Test-BuildCurrency -StaleDays $StaleBuildDays
Write-BuildCurrency -Currency $currency

$rawFailures = New-Object System.Collections.Generic.List[object]

Get-WindowsUpdateEventFailures -LookbackDays $Days | ForEach-Object { $rawFailures.Add($_) }

if ($IncludeCbsLogs) {
    Write-Host "$(Get-TimeStamp) Parsing CBS servicing log (this can take a moment on large logs)..." -ForegroundColor Cyan
    Get-CbsLogFailures -LookbackDays $Days | ForEach-Object { $rawFailures.Add($_) }
}

$analysis = Group-FailureAnalysis -RawFailures $rawFailures -ActiveThresholdDays $ActiveThresholdDays

Write-AnalysisReport -Analysis $analysis

# Determine where to write generated artifacts (JSON + repair script).
$outputDir = if ($ExportJsonPath) { Split-Path -Path $ExportJsonPath -Parent } else { $PSScriptRoot }
if ([string]::IsNullOrWhiteSpace($outputDir)) { $outputDir = (Get-Location).Path }

# JSON export
if ($ExportJsonPath) {
    try {
        [pscustomobject]@{
            BuildCurrency = $currency
            Failures      = $analysis
        } | ConvertTo-Json -Depth 6 | Set-Content -Path $ExportJsonPath -Encoding UTF8 -Force
        Write-Host "$(Get-TimeStamp) JSON analysis exported to: $ExportJsonPath" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to export JSON to '$ExportJsonPath': $($_.Exception.Message)"
    }
}

# Generate the review-before-you-run remediation script when there is something to fix.
if ($analysis.Count -gt 0) {
    $repairPath = Join-Path $outputDir 'Invoke-RepairWU.ps1'
    try {
        New-RepairScript -Analysis $analysis -OutputPath $repairPath | Out-Null
        Write-Host "$(Get-TimeStamp) Remediation script generated for review: $repairPath" -ForegroundColor Green
        Write-Host '  Review it, then run it from an elevated PowerShell prompt to apply the fixes.' -ForegroundColor Gray
    }
    catch {
        Write-Warning "Failed to generate remediation script: $($_.Exception.Message)"
    }
}

# Optional auto-remediation.
if ($AutoRemediate -and $analysis.Count -gt 0) {
    Invoke-SafeRemediation -Analysis $analysis
}

if ($PassThru) {
    [pscustomobject]@{
        BuildCurrency = $currency
        Failures      = $analysis
    }
}
