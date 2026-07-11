# --- SCRIPT OVERVIEW ---
# This script is a specialized "fix-it" tool focused solely on repairing a broken Windows Update experience that is
# commonly caused by leftover or misconfigured Local Group Policy. It performs several targeted actions:
#   1. Clears the Local Group Policy store (C:\Windows\System32\GroupPolicy, and GroupPolicyUsers when opted in).
#   2. Removes the Windows Update policy registry keys that "tattoo" the system and block updates.
#   3. Resets the Windows Update cache (SoftwareDistribution, catroot2) and the BITS transfer queue.
#   4. Re-registers the Windows Update components (DLLs).
#   5. Verifies that all of the services required for Windows Update are enabled and set to a healthy startup type.
# After the cleanup, it forces a Group Policy refresh, optionally repairs the component store (DISM/SFC),
# and (optionally) triggers a fresh Windows Update scan.
#
# For hands-off use, run with -Remediate: the script inspects the update history and automatically scales the
# repair to how broken things are. A healthy system is left untouched; a mildly unhealthy one gets the baseline
# policy/cache/service repair; a severely broken one additionally resets the full Software Policies hive and
# repairs the component store (DISM/SFC).
# -------------------------------------------------
# How to Run .PS1 Script with PowerShell:
# NOTE: It is recommended to use the "Run-Windows-Update-Fix.bat" to invoke this script. However, you can run the .PS1 directly if needed.
# 1.  Open PowerShell as an Administrator: Right-click your Start Menu and select "Terminal (Admin)".
# 2.  Enable Script Execution (if needed): Set-ExecutionPolicy Bypass -Force
# 3.  Run the Script: Right-click the saved "Windows-Update-Fix.ps1" file and select "Run with PowerShell".
# -------------------------------------------------
# Parameters for the script
param(
    [switch]$Unattended, # Runs the script without any user prompts. It will not ask for confirmation to start
    [Parameter(HelpMessage = 'Automatically restart upon completion')]
    [switch]$AutoReboot,
    [Parameter(HelpMessage = 'Also remove the broader Software Policies registry hive (aggressive)')]
    [switch]$ResetAllPolicies,
    [Parameter(HelpMessage = 'Trigger a Windows Update detection scan after the fix')]
    [switch]$TriggerUpdateScan,
    [Parameter(HelpMessage = 'Also clear the per-user Local Group Policy store (GroupPolicyUsers)')]
    [switch]$IncludeGroupPolicyUsers,
    [Parameter(HelpMessage = 'Only run the fix if updates are stale or recent update failures exist (uses -StaleDays)')]
    [switch]$FixIfStale,
    [Parameter(HelpMessage = 'Adaptive mode: assess Windows Update health and automatically scale the repair to how broken it is')]
    [switch]$Remediate,
    [Parameter(HelpMessage = 'Number of days used by -FixIfStale to consider updates stale (default 45)')]
    [int]$StaleDays = 45,
    [Parameter(HelpMessage = 'Max unresolved standard update failures tolerated when a recent patch succeeded (default 5)')]
    [int]$FailureFixThreshold = 5,
    [Parameter(HelpMessage = 'Also run DISM /RestoreHealth and SFC to repair the component store (slow)')]
    [switch]$RepairComponentStore,
    [Parameter(HelpMessage = 'Skip the online lookup of the current build''s exact release date/KB (Microsoft release information)')]
    [switch]$SkipOnlineBuildDate,
    [switch]$SkipInteractive # Skips the interactive confirmation prompt
)

# Verify this is running on PowerShell 5 or higher
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "This script requires PowerShell 5.0 or higher. You are currently running $($PSVersionTable.PSVersion)." -ForegroundColor Red
    Write-Host "Please update your PowerShell version to proceed." -ForegroundColor Red
    Start-Sleep -Seconds 10
    exit 1
}

# Verify you are running on Windows 10 (or Windows Server 2016) or higher
$OsInfo = Get-CimInstance -Class Win32_OperatingSystem
if ([int]($OsInfo).BuildNumber -lt 10240) {
    Write-Host "This script is designed for Windows 10 or higher. You are running $($OsInfo.Caption) (Build $($OsInfo.BuildNumber))." -ForegroundColor Red
    Write-Host "Running on an unsupported OS may have unintended consequences." -ForegroundColor Yellow
    Write-Host "The script will exit in 10 seconds." -ForegroundColor Red
    Start-Sleep -Seconds 10
    exit 1
}

# Self-elevate the script if required
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $ArgumentList = @("-File", "`"$($MyInvocation.MyCommand.Path)`"")
        # Re-add any passed parameters
        foreach ($Parameter in $PSBoundParameters.Keys) {
            $ArgumentList += "-$Parameter"
        }

        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $ArgumentList
        exit
    }
}

# Add a Window Title
$Host.UI.RawUI.WindowTitle = "Windows Update Fix - Running as Administrator"

# --- Start Logging ---
# Create a log file in the same directory as the script
$LogFile = Join-Path -Path $PSScriptRoot -ChildPath "Windows-Update-Fix_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Start-Transcript -Path $LogFile | Out-Null

$ProgressPreference = 'SilentlyContinue'
$LineBreakCharacter = '-'
$LineBreak = $null
1..$($Host.UI.RawUI.BufferSize.Width) | ForEach-Object {
    $LineBreak += $LineBreakCharacter
}

function Get-TimeStamp {
    return (Get-Date -Format '[MM/dd/yyyy|HH:mm:ss]')
}

function Write-HostTimestamp {
    param (
        [string]$Message,
        [consolecolor]$ForegroundColor = $(try { ((Get-Host).ui.rawui.ForegroundColor) } catch { 'White' })
    )

    # Get the current timestamp and combine it with the user's message.
    # The output is then sent to the console using Write-Host with the specified color.
    Write-Host "$(Get-TimeStamp) $Message" -ForegroundColor $ForegroundColor
}

function Invoke-Task {
    param(
        [string]$Description,
        [scriptblock]$ScriptBlock
    )

    Write-HostTimestamp $Description
    & $ScriptBlock
    Write-Host $LineBreak
}

# Sets a service to the desired startup type, falling back to the registry for protected services
function Set-ServiceStartupType {
    param(
        [string]$Name,
        [ValidateSet('Automatic', 'Manual', 'Disabled')]
        [string]$StartupType
    )

    try {
        Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop
        return $true
    }
    catch {
        # Some services (e.g. wuauserv, gpsvc, DoSvc) are protected and reject Set-Service.
        # Fall back to writing the 'Start' value directly in the service registry key.
        $StartValue = switch ($StartupType) {
            'Automatic' { 2 }
            'Manual'    { 3 }
            'Disabled'  { 4 }
        }
        $ServiceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
        if (Test-Path $ServiceRegPath) {
            try {
                Set-ItemProperty -Path $ServiceRegPath -Name 'Start' -Value $StartValue -Type DWord -ErrorAction Stop
                return $true
            }
            catch {
                Write-HostTimestamp "  Could not set startup type for '$Name'. Error: $($_.Exception.Message)" -ForegroundColor Red
                return $false
            }
        }
        else {
            Write-HostTimestamp "  Service '$Name' not found. Skipping." -ForegroundColor Yellow
            return $false
        }
    }
}

# Best-effort online lookup of the exact release date and KB article for a specific Windows build
# revision (Build.UBR), using Microsoft's public release information page. Returns a PSCustomObject with
# Date and KB (either may be $null), or $null if the build cannot be found.
function Get-BuildReleaseDateOnline {
    param(
        [string]$BuildUbr,
        [bool]$IsWin11
    )
    $Url = if ($IsWin11) {
        'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information'
    }
    else {
        'https://learn.microsoft.com/en-us/windows/release-health/release-information'
    }
    try {
        $Html = (Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop).Content
    }
    catch {
        Write-HostTimestamp "  Could not reach the Microsoft release information page: $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
    # Flatten the HTML so each table row (date, build revision, KB article) sits on one line.
    $Text = ($Html -replace '<[^>]+>', ' ') -replace '\s+', ' '
    $Occurrences = [regex]::Matches($Text, [regex]::Escape($BuildUbr))
    if ($Occurrences.Count -eq 0) { return $null }

    $FallbackDate = $null
    foreach ($Occurrence in $Occurrences) {
        $Idx = $Occurrence.Index
        # The release date is the date column closest before the build revision.
        $Start = [Math]::Max(0, $Idx - 120)
        $Prefix = $Text.Substring($Start, $Idx - $Start)
        $Dates = [regex]::Matches($Prefix, '\d{4}-\d{2}-\d{2}')
        $Date = if ($Dates.Count -gt 0) { $Dates[$Dates.Count - 1].Value } else { $null }

        # In the release-history table the KB article follows immediately after the build revision.
        $AfterStart = $Idx + $BuildUbr.Length
        $AfterLength = [Math]::Min(20, $Text.Length - $AfterStart)
        $After = $Text.Substring($AfterStart, $AfterLength)
        $KbMatch = [regex]::Match($After, 'KB\d+')

        if ($KbMatch.Success) {
            # This occurrence has an associated KB - the most specific match.
            return [PSCustomObject]@{ Date = $Date; KB = $KbMatch.Value }
        }
        if (-not $FallbackDate -and $Date) { $FallbackDate = $Date }
    }
    return [PSCustomObject]@{ Date = $FallbackDate; KB = $null }
}

# Resolves the currently-installed build revision (from the registry) and, unless online lookup is
# disabled, its exact release date and KB from Microsoft's release information. Returns a PSCustomObject
# with BuildUbr, ReleaseDate ([datetime] or $null) and KB, or $null if the build revision is unavailable.
function Get-CurrentBuildReleaseInfo {
    if ($script:BuildReleaseInfoResolved) { return $script:BuildReleaseInfo }
    $script:BuildReleaseInfoResolved = $true
    $Reg = $null
    try { $Reg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop } catch { }
    if (-not $Reg -or -not $Reg.CurrentBuildNumber -or $null -eq $Reg.UBR) {
        $script:BuildReleaseInfo = $null
        return $null
    }
    $Build = $Reg.CurrentBuildNumber
    $Ubr = $Reg.UBR
    $IsWin11 = ([int]$Build -ge 22000)
    $BuildUbr = "$Build.$Ubr"
    if ($SkipOnlineBuildDate) {
        $script:BuildReleaseInfo = [PSCustomObject]@{ BuildUbr = $BuildUbr; ReleaseDate = $null; KB = $null }
        return $script:BuildReleaseInfo
    }
    $Online = Get-BuildReleaseDateOnline -BuildUbr $BuildUbr -IsWin11 $IsWin11
    $ReleaseDate = $null
    if ($Online -and $Online.Date) {
        try { $ReleaseDate = [datetime]::ParseExact($Online.Date, 'yyyy-MM-dd', $null) } catch { $ReleaseDate = $null }
    }
    $script:BuildReleaseInfo = [PSCustomObject]@{
        BuildUbr    = $BuildUbr
        ReleaseDate = $ReleaseDate
        KB          = if ($Online) { $Online.KB } else { $null }
    }
    return $script:BuildReleaseInfo
}

# Writes the full Windows build version and, where known, the feature update's general-availability
# date and the date the build was applied to this PC.
function Show-WindowsBuildInfo {
    $RegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $Reg = $null
    try { $Reg = Get-ItemProperty -Path $RegPath -ErrorAction Stop } catch { }
    $Os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

    # Build the full version number: Major.Minor.Build.UBR (e.g. 10.0.26200.1234)
    $Major = if ($Reg -and $Reg.CurrentMajorVersionNumber) { $Reg.CurrentMajorVersionNumber } else { 10 }
    $Minor = if ($Reg -and $null -ne $Reg.CurrentMinorVersionNumber) { $Reg.CurrentMinorVersionNumber } else { 0 }
    $Build = if ($Reg -and $Reg.CurrentBuildNumber) { $Reg.CurrentBuildNumber } else { $Os.BuildNumber }
    $Ubr = if ($Reg) { $Reg.UBR } else { $null }
    $FullVersion = if ($null -ne $Ubr) { "$Major.$Minor.$Build.$Ubr" } else { "$Major.$Minor.$Build" }

    # The registry ProductName can still say "Windows 10" on Windows 11, so correct it by build number.
    $IsWin11 = ([int]$Build -ge 22000)
    $ProductName = if ($Reg) { $Reg.ProductName } else { $Os.Caption }
    if ($IsWin11 -and $ProductName -like 'Windows 10*') {
        $ProductName = $ProductName -replace '^Windows 10', 'Windows 11'
    }
    $Edition = if ($Reg) { $Reg.EditionID } else { $null }
    $DisplayVersion = if ($Reg -and $Reg.DisplayVersion) { $Reg.DisplayVersion } elseif ($Reg) { $Reg.ReleaseId } else { $null }

    # Approximate general-availability dates for each Windows feature update (DisplayVersion),
    # keyed by "<11|10>-<DisplayVersion>". This only reflects when the feature update first shipped,
    # not the exact release date of the current monthly (UBR) patch, which cannot be determined offline.
    $ReleaseDates = @{
        '11-21H2' = 'October 4, 2021'
        '11-22H2' = 'September 20, 2022'
        '11-23H2' = 'October 31, 2023'
        '11-24H2' = 'October 1, 2024'
        '11-25H2' = 'September 2025'
        '10-1507' = 'July 29, 2015'
        '10-1511' = 'November 10, 2015'
        '10-1607' = 'August 2, 2016'
        '10-1703' = 'April 5, 2017'
        '10-1709' = 'October 17, 2017'
        '10-1803' = 'April 30, 2018'
        '10-1809' = 'November 13, 2018'
        '10-1903' = 'May 21, 2019'
        '10-1909' = 'November 12, 2019'
        '10-2004' = 'May 27, 2020'
        '10-20H2' = 'October 20, 2020'
        '10-21H1' = 'May 18, 2021'
        '10-21H2' = 'November 16, 2021'
        '10-22H2' = 'October 18, 2022'
    }
    $ReleaseKey = ('{0}-{1}' -f $(if ($IsWin11) { '11' } else { '10' }), $DisplayVersion)
    $ReleaseDate = $ReleaseDates[$ReleaseKey]

    Write-Host $LineBreak
    Write-HostTimestamp "Operating System: $ProductName$(if ($Edition) { " (Edition: $Edition)" })" -ForegroundColor Cyan
    Write-Host "  Feature update : $DisplayVersion"
    Write-Host "  Full version   : $FullVersion"
    if ($ReleaseDate) {
        Write-Host "  $DisplayVersion first released: $ReleaseDate (feature update general availability)"
    }
    else {
        Write-Host "  Release date   : not available in local reference for '$DisplayVersion'"
    }
    # By default, look up the exact release date and KB of this specific build revision online.
    if (-not $SkipOnlineBuildDate -and $null -ne $Ubr) {
        Write-Host "  Looking up the exact release for build $Build.$Ubr online..."
        $BuildRelease = Get-CurrentBuildReleaseInfo
        if ($BuildRelease -and ($BuildRelease.ReleaseDate -or $BuildRelease.KB)) {
            $ReleasedOn = if ($BuildRelease.ReleaseDate) { $BuildRelease.ReleaseDate.ToString('yyyy-MM-dd') } else { 'unknown date' }
            $ViaKb = if ($BuildRelease.KB) { " via $($BuildRelease.KB)" } else { '' }
            Write-Host "  Build $Build.$Ubr released: $ReleasedOn$ViaKb (per Microsoft release information)"
        }
        else {
            Write-Host "  Exact build release could not be determined online." -ForegroundColor Yellow
        }
    }
    if ($Os -and $Os.InstallDate) {
        Write-Host "  Applied on this PC: $($Os.InstallDate) (when this build/feature update was installed here)"
    }
    Write-Host $LineBreak
}

# Returns the most recent successfully installed Windows Update patch (Date and Title), excluding
# driver updates and Microsoft Defender/antivirus definition updates. Returns $null if none found.
function Get-LastUpdatePatch {
    try {
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Searcher = $Session.CreateUpdateSearcher()
        $HistoryCount = $Searcher.GetTotalHistoryCount()
        if ($HistoryCount -le 0) { return $null }
        $History = $Searcher.QueryHistory(0, $HistoryCount)
    }
    catch {
        Write-HostTimestamp "Could not query Windows Update history: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }

    $LastEntry = $null
    foreach ($Entry in $History) {
        # Operation 1 = Installation, ResultCode 2 = Succeeded
        if ($Entry.Operation -ne 1 -or $Entry.ResultCode -ne 2) { continue }
        $IsExcluded = $false
        foreach ($Category in $Entry.Categories) {
            if ($Category.Name -eq 'Drivers' -or $Category.Name -eq 'Definition Updates') { $IsExcluded = $true }
        }
        if ($IsExcluded) { continue }
        if ($Entry.Title -match 'driver|Defender|Security Intelligence|Definition Update|Antivirus') { continue }
        if (-not $LastEntry -or $Entry.Date -gt $LastEntry.Date) { $LastEntry = $Entry }
    }
    if (-not $LastEntry) { return $null }
    return [PSCustomObject]@{ Date = $LastEntry.Date; Title = $LastEntry.Title }
}

# Returns failed Windows Update installations within the given number of days, excluding driver
# updates and Microsoft Defender/antivirus definition updates. Always returns an array (may be empty).
# Each failure is flagged as 'Resolved' when the same update later installed successfully.
function Get-RecentUpdateFailures {
    param([int]$Days = 45)

    $Failures = @()
    try {
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Searcher = $Session.CreateUpdateSearcher()
        $HistoryCount = $Searcher.GetTotalHistoryCount()
        if ($HistoryCount -le 0) { return $Failures }
        $History = $Searcher.QueryHistory(0, $HistoryCount)
    }
    catch {
        Write-HostTimestamp "Could not query Windows Update history: $($_.Exception.Message)" -ForegroundColor Red
        return $Failures
    }

    # Build lookups of the latest successful install date, keyed by UpdateID and by Title,
    # so a failed attempt can be matched against a later success of the same update.
    $SuccessByUpdateId = @{}
    $SuccessByTitle = @{}
    foreach ($Entry in $History) {
        if ($Entry.Operation -eq 1 -and $Entry.ResultCode -eq 2) {
            $Uid = $null
            try { $Uid = $Entry.UpdateIdentity.UpdateID } catch { $Uid = $null }
            if ($Uid) {
                if (-not $SuccessByUpdateId.ContainsKey($Uid) -or $Entry.Date -gt $SuccessByUpdateId[$Uid]) {
                    $SuccessByUpdateId[$Uid] = $Entry.Date
                }
            }
            if ($Entry.Title) {
                if (-not $SuccessByTitle.ContainsKey($Entry.Title) -or $Entry.Date -gt $SuccessByTitle[$Entry.Title]) {
                    $SuccessByTitle[$Entry.Title] = $Entry.Date
                }
            }
        }
    }

    $Cutoff = (Get-Date).AddDays(-$Days)
    foreach ($Entry in $History) {
        # Operation 1 = Installation; ResultCode 4 = Failed, 5 = Aborted
        if ($Entry.Operation -ne 1) { continue }
        if ($Entry.ResultCode -ne 4 -and $Entry.ResultCode -ne 5) { continue }
        if ($Entry.Date -lt $Cutoff) { continue }
        $IsExcluded = $false
        foreach ($Category in $Entry.Categories) {
            if ($Category.Name -eq 'Drivers' -or $Category.Name -eq 'Definition Updates') { $IsExcluded = $true }
        }
        if ($IsExcluded) { continue }
        if ($Entry.Title -match 'driver|Defender|Security Intelligence|Definition Update|Antivirus') { continue }

        # Determine whether this failure was later resolved by a successful install of the same update.
        $Resolved = $false
        $ResolvedDate = $null
        $Uid = $null
        try { $Uid = $Entry.UpdateIdentity.UpdateID } catch { $Uid = $null }
        if ($Uid -and $SuccessByUpdateId.ContainsKey($Uid) -and $SuccessByUpdateId[$Uid] -gt $Entry.Date) {
            $Resolved = $true
            $ResolvedDate = $SuccessByUpdateId[$Uid]
        }
        elseif (-not $Uid -and $Entry.Title -and $SuccessByTitle.ContainsKey($Entry.Title) -and $SuccessByTitle[$Entry.Title] -gt $Entry.Date) {
            $Resolved = $true
            $ResolvedDate = $SuccessByTitle[$Entry.Title]
        }

        $Failures += [PSCustomObject]@{
            Date         = $Entry.Date
            Title        = $Entry.Title
            HResult      = ('0x{0:X8}' -f ($Entry.HResult -band 0xFFFFFFFF))
            Resolved     = $Resolved
            ResolvedDate = $ResolvedDate
        }
    }
    return @($Failures | Sort-Object Date -Descending)
}

# Removes the SoftwareDistribution.old_* and catroot2.old_* backup folders that earlier runs of this
# script create when they rename those folders, so the backups do not accumulate on repeated runs.
function Remove-OldUpdateBackups {
    $System32 = Join-Path -Path $env:windir -ChildPath 'System32'
    $BackupLocations = @(
        @{ Parent = $env:windir; Pattern = 'SoftwareDistribution.old_*' },
        @{ Parent = $System32;   Pattern = 'catroot2.old_*' }
    )
    foreach ($Location in $BackupLocations) {
        if (Test-Path $Location.Parent) {
            Get-ChildItem -Path $Location.Parent -Directory -Filter $Location.Pattern -Force -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction Stop
                    Write-HostTimestamp "  Removed old backup: $($_.FullName)"
                }
                catch {
                    Write-HostTimestamp "  Could not remove old backup $($_.FullName): $($_.Exception.Message)" -ForegroundColor Yellow
                }
            }
        }
    }
}

# Returns the free space on the system drive (e.g. C:) in GB, rounded to two decimals, or $null if it
# cannot be determined.
function Get-SystemDriveFreeGB {
    try {
        $Drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction Stop
        if ($Drive -and $Drive.FreeSpace) {
            return [math]::Round($Drive.FreeSpace / 1GB, 2)
        }
    }
    catch { }
    return $null
}

# Best-effort, safe disk cleanup to free space before attempting updates: removes leftover update-folder
# backups from previous runs, clears the Windows Update download cache (Windows re-downloads as needed),
# and empties the user and Windows temp folders.
function Invoke-LightDiskCleanup {
    Write-HostTimestamp 'Performing light disk cleanup to free space...' -ForegroundColor Cyan

    # Remove leftover *.old_* backups created by previous runs of this script.
    Remove-OldUpdateBackups

    # Clear the Windows Update download cache.
    $DownloadCache = Join-Path -Path $env:windir -ChildPath 'SoftwareDistribution\Download'
    if (Test-Path $DownloadCache) {
        Get-ChildItem -Path $DownloadCache -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-HostTimestamp '  Cleared the Windows Update download cache.'
    }

    # Clear the user and Windows temp folders.
    foreach ($Temp in @($env:TEMP, (Join-Path -Path $env:windir -ChildPath 'Temp'))) {
        if ($Temp -and (Test-Path $Temp)) {
            Get-ChildItem -Path $Temp -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Write-HostTimestamp '  Cleared temporary files.'
}

# --- Disk space check ---
# Windows Update needs free space to download and stage updates. Gate the run on available space:
#   * under 1 GB  -> refuse to run (updates cannot function reliably);
#   * under 5 GB  -> run a light proactive cleanup to free space, then continue;
#   * under 20 GB -> warn (feature updates may need more room) but continue.
$FreeGB = Get-SystemDriveFreeGB
if ($null -eq $FreeGB) {
    Write-HostTimestamp 'Could not determine free disk space on the system drive. Continuing.' -ForegroundColor Yellow
}
else {
    Write-HostTimestamp "Free space on $env:SystemDrive : $FreeGB GB"
    if ($FreeGB -lt 1) {
        Write-HostTimestamp "CRITICAL: Less than 1 GB of free disk space ($FreeGB GB). Windows Update cannot function reliably, so this script will not run. Free up space and try again." -ForegroundColor Red
        Stop-Transcript | Out-Null
        exit 1
    }
    elseif ($FreeGB -lt 5) {
        Write-HostTimestamp "WARNING: Low disk space ($FreeGB GB free). Running a light proactive cleanup to free space before continuing..." -ForegroundColor Yellow
        Invoke-LightDiskCleanup
        $FreeGB = Get-SystemDriveFreeGB
        if ($null -ne $FreeGB) {
            Write-HostTimestamp "Free space after cleanup: $FreeGB GB"
            if ($FreeGB -lt 1) {
                Write-HostTimestamp "CRITICAL: Still under 1 GB of free disk space after cleanup ($FreeGB GB). This script will not run." -ForegroundColor Red
                Stop-Transcript | Out-Null
                exit 1
            }
        }
    }
    elseif ($FreeGB -lt 20) {
        Write-HostTimestamp "WARNING: Free disk space is below 20 GB ($FreeGB GB). Windows feature updates may need more room, but the script will continue." -ForegroundColor Yellow
    }
}
Write-Host $LineBreak

# --- Adaptive remediation (optional) ---
# When -Remediate is used, the script inspects the Windows Update history and automatically decides both
# WHETHER to act and HOW aggressively, based on how broken things look:
#   * Healthy   (recent patch, no action-worthy failures)      -> nothing is done and the script exits.
#   * Mild      (stale, or a few unresolved failures)          -> baseline repair (policy/cache/services/DLLs).
#   * Severe    (never patched / very stale, or many failures) -> baseline repair PLUS -ResetAllPolicies and
#                                                                  -RepairComponentStore (DISM/SFC).
# In every remediation case a fresh update scan is triggered afterwards. Remediation runs hands-off (no prompts).
if ($Remediate) {
    Clear-Host
    Write-HostTimestamp "Running in adaptive Remediation mode on $($env:ComputerName) - assessing Windows Update health..." -ForegroundColor Cyan

    $LastPatch = Get-LastUpdatePatch
    $RecentFailures = Get-RecentUpdateFailures -Days $StaleDays
    $UnresolvedFailures = @($RecentFailures | Where-Object { -not $_.Resolved })
    $UnresolvedCount = $UnresolvedFailures.Count
    $Cutoff = (Get-Date).AddDays(-$StaleDays)
    $VeryStaleCutoff = (Get-Date).AddDays(-2 * $StaleDays)

    if ($LastPatch) {
        $DaysSince = [math]::Round(((Get-Date) - $LastPatch.Date).TotalDays, 1)
        Write-HostTimestamp "Last successful patch: $($LastPatch.Title) - installed $($LastPatch.Date) ($DaysSince days ago)."
    }
    else {
        Write-HostTimestamp 'No qualifying Windows Update patch was found in the update history.' -ForegroundColor Yellow
    }

    if ($RecentFailures.Count -gt 0) {
        Write-HostTimestamp "Detected $($RecentFailures.Count) failed Windows Update installation(s) within the last $StaleDays days ($UnresolvedCount still unresolved)." -ForegroundColor Yellow
        $RecentFailures | Select-Object -First 5 | ForEach-Object {
            if ($_.Resolved) {
                Write-Host "  - $($_.Date)  $($_.Title) ($($_.HResult)) - later succeeded on $($_.ResolvedDate), ignored" -ForegroundColor DarkGray
            }
            else {
                Write-Host "  - $($_.Date)  $($_.Title) ($($_.HResult))"
            }
        }
    }

    # Additional staleness signal: how long ago the currently-installed build revision was released by
    # Microsoft. If a newer monthly build exists that this PC never installed, its build will look old,
    # which can catch staleness that the update history alone misses (e.g. a truncated/cleared history).
    $BuildInfo = Get-CurrentBuildReleaseInfo
    $BuildStale = $false
    $BuildVeryStale = $false
    if ($BuildInfo -and $BuildInfo.ReleaseDate) {
        $BuildAgeDays = [math]::Round(((Get-Date) - $BuildInfo.ReleaseDate).TotalDays, 1)
        $BuildStale = ($BuildInfo.ReleaseDate -lt $Cutoff)
        $BuildVeryStale = ($BuildInfo.ReleaseDate -lt $VeryStaleCutoff)
        $KbNote = if ($BuildInfo.KB) { " ($($BuildInfo.KB))" } else { '' }
        Write-HostTimestamp "Installed build $($BuildInfo.BuildUbr)$KbNote was released $($BuildInfo.ReleaseDate.ToString('yyyy-MM-dd')) ($BuildAgeDays days ago)."
    }

    # Classify severity.
    # The legacy update history is often empty on modern Windows 11 (updates installed via the Unified
    # Update Platform do not populate it), so an absent history is only treated as stale when the
    # installed build is not recent either. The build-release date remains an independent stale signal
    # that can also catch a recently-recorded patch sitting on an old build.
    $NeverPatched = (-not $LastPatch)
    $HaveBuildDate = ($BuildInfo -and $BuildInfo.ReleaseDate)
    $BuildRecent = ($HaveBuildDate -and $BuildInfo.ReleaseDate -ge $Cutoff)
    $BuildVeryRecent = ($HaveBuildDate -and $BuildInfo.ReleaseDate -ge $VeryStaleCutoff)
    $PatchStale = ($LastPatch -and $LastPatch.Date -lt $Cutoff)
    $PatchVeryStale = ($LastPatch -and $LastPatch.Date -lt $VeryStaleCutoff)
    # An empty/absent history counts as stale only when a recent build does not rescue it.
    $UnknownStale = ($NeverPatched -and -not $BuildRecent)
    $UnknownVeryStale = ($NeverPatched -and -not $BuildVeryRecent)
    $IsStale = ($PatchStale -or $BuildStale -or $UnknownStale)
    $IsVeryStale = ($PatchVeryStale -or $BuildVeryStale -or $UnknownVeryStale)
    $ManyFailures = ($UnresolvedCount -gt $FailureFixThreshold)
    # A few unresolved failures alongside a recent successful patch are treated as likely false positives.
    $FailuresRequireFix = ($UnresolvedCount -gt 0 -and $IsStale) -or $ManyFailures

    if (-not $IsStale -and -not $FailuresRequireFix) {
        Write-HostTimestamp "Windows Update looks healthy (patched within the last $StaleDays days by patch history or build release date, and no action-worthy failures were found). No remediation needed." -ForegroundColor Green
        Write-Host $LineBreak
        Stop-Transcript | Out-Null
        exit 0
    }

    # Severe when the machine has effectively not been patched in a long time, or has a high number of
    # unresolved failures - both point to deeper corruption that the baseline fix alone may not resolve.
    $Severe = ($IsVeryStale -or $ManyFailures)

    if ($UnresolvedCount -gt 0 -and -not $IsStale -and -not $ManyFailures) {
        Write-HostTimestamp "A standard Windows update succeeded recently, so these $UnresolvedCount unresolved failure(s) are likely false positives and will be ignored." -ForegroundColor Yellow
    }

    # Always trigger a scan after remediation so the results are immediately visible.
    $TriggerUpdateScan = $true

    if ($Severe) {
        $Reason = if ($UnknownVeryStale) { 'no patch in history and the installed build is not recent' }
                  elseif ($PatchVeryStale) { "no patch within the last $([int](2 * $StaleDays)) days" }
                  elseif ($BuildVeryStale) { "the installed build was released more than $([int](2 * $StaleDays)) days ago" }
                  else { "more than $FailureFixThreshold unresolved update failures" }
        Write-HostTimestamp "Severity: SEVERE ($Reason). Applying the full repair, including -ResetAllPolicies and -RepairComponentStore." -ForegroundColor Red
        $ResetAllPolicies = $true
        $RepairComponentStore = $true
    }
    else {
        $Reason = if ($PatchStale) { "no patch within the last $StaleDays days" }
                  elseif ($BuildStale) { "the installed build was released more than $StaleDays days ago" }
                  elseif ($UnknownStale) { 'no patch in history and the installed build is not recent' }
                  else { 'unresolved update failures' }
        Write-HostTimestamp "Severity: MILD ($Reason). Applying the baseline Windows Update repair." -ForegroundColor Yellow
    }

    # Remediation is hands-off: skip the interactive confirmation and the final wait prompt.
    $SkipInteractive = $true
    Write-Host $LineBreak
}

# --- Interactive confirmation ---
if (-not $Unattended -and -not $SkipInteractive) {
    Clear-Host
    Write-HostTimestamp "Running Windows Update Fix on $($env:ComputerName)..." -Foreground Yellow
    # Show the full Windows build version (and optional online release date) before asking to continue
    Show-WindowsBuildInfo
    Write-Host "This tool repairs Windows Update by resetting Local Group Policy and Windows Update policy settings."
    Write-Host ""
    Write-Host "It will perform the following actions:"
    Write-Host "  - Clear C:\Windows\System32\GroupPolicy"
    if ($IncludeGroupPolicyUsers) {
        Write-Host "  - Clear C:\Windows\System32\GroupPolicyUsers (per-user Local Group Policy)"
    }
    Write-Host "  - Remove the Windows Update policy registry keys"
    Write-Host "  - Reset the Windows Update cache (SoftwareDistribution, catroot2) and BITS queue"
    Write-Host "  - Re-register the Windows Update components (DLLs)"
    Write-Host "  - Verify and enable all services required by Windows Update"
    Write-Host "  - Force a Group Policy refresh (gpupdate /force)"
    if ($ResetAllPolicies) {
        Write-Host "  - Remove the ENTIRE Software Policies registry hive (aggressive)" -ForegroundColor Yellow
    }
    if ($RepairComponentStore) {
        Write-Host "  - Repair the component store with DISM /RestoreHealth and SFC (slow)"
    }
    if ($TriggerUpdateScan) {
        Write-Host "  - Trigger a fresh Windows Update detection scan"
    }
    Write-Host ""
    # Show the last real Windows Update patch and whether it is considered stale
    $LastPatchInfo = Get-LastUpdatePatch
    $HasRecentPatch = $false
    if ($LastPatchInfo) {
        $DaysSincePatch = [math]::Round(((Get-Date) - $LastPatchInfo.Date).TotalDays, 1)
        if ($LastPatchInfo.Date -ge (Get-Date).AddDays(-$StaleDays)) {
            $HasRecentPatch = $true
            Write-Host "Last Windows Update patch: $($LastPatchInfo.Title) - installed $($LastPatchInfo.Date) ($DaysSincePatch days ago) - within the $StaleDays day threshold (not stale)." -ForegroundColor Green
        }
        else {
            Write-Host "Last Windows Update patch: $($LastPatchInfo.Title) - installed $($LastPatchInfo.Date) ($DaysSincePatch days ago) - STALE (older than $StaleDays days)." -ForegroundColor Yellow
        }
    }
    else {
        # The legacy Windows Update history can be empty on modern Windows 11 (cumulative updates
        # installed via the Unified Update Platform do not populate the WUA history). Fall back to the
        # installed build's Microsoft release date as the patch signal instead of assuming STALE.
        $BuildInfo = Get-CurrentBuildReleaseInfo
        if ($BuildInfo -and $BuildInfo.ReleaseDate) {
            $DaysSinceBuild = [math]::Round(((Get-Date) - $BuildInfo.ReleaseDate).TotalDays, 1)
            $KbNote = if ($BuildInfo.KB) { " ($($BuildInfo.KB))" } else { '' }
            if ($BuildInfo.ReleaseDate -ge (Get-Date).AddDays(-$StaleDays)) {
                $HasRecentPatch = $true
                Write-Host "Last Windows Update patch: build $($BuildInfo.BuildUbr)$KbNote - released $($BuildInfo.ReleaseDate.ToString('yyyy-MM-dd')) ($DaysSinceBuild days ago) - within the $StaleDays day threshold (not stale)." -ForegroundColor Green
            }
            else {
                Write-Host "Last Windows Update patch: build $($BuildInfo.BuildUbr)$KbNote - released $($BuildInfo.ReleaseDate.ToString('yyyy-MM-dd')) ($DaysSinceBuild days ago) - STALE (older than $StaleDays days)." -ForegroundColor Yellow
            }
            Write-Host "  (No entries in the legacy Windows Update history; using the installed build's release date instead.)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "Last Windows Update patch: none found in history - considered STALE." -ForegroundColor Yellow
        }
    }
    # Show any recent failed update installations
    $RecentFailures = Get-RecentUpdateFailures -Days $StaleDays
    $UnresolvedFailures = @($RecentFailures | Where-Object { -not $_.Resolved })
    if ($RecentFailures.Count -gt 0) {
        Write-Host "Recent Windows Update FAILURES in the last $StaleDays days: $($RecentFailures.Count) ($($UnresolvedFailures.Count) unresolved)" -ForegroundColor Red
        $RecentFailures | Select-Object -First 5 | ForEach-Object {
            if ($_.Resolved) {
                Write-Host "  - $($_.Date)  $($_.Title) ($($_.HResult)) - later SUCCEEDED on $($_.ResolvedDate), can be ignored" -ForegroundColor DarkGray
            }
            else {
                Write-Host "  - $($_.Date)  $($_.Title) ($($_.HResult))" -ForegroundColor Red
            }
        }
        if ($UnresolvedFailures.Count -gt $FailureFixThreshold) {
            Write-Host "  More than $FailureFixThreshold unresolved standard update failures - this should be fixed." -ForegroundColor Red
        }
        elseif ($HasRecentPatch -and $UnresolvedFailures.Count -gt 0) {
            Write-Host "  A standard Windows update succeeded recently, so these $($UnresolvedFailures.Count) unresolved failure(s) may be false positives." -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "No recent Windows Update failures detected." -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "NOTE: Any settings applied via Local Group Policy will be reset to 'Not Configured'." -ForegroundColor Yellow
    Write-Host ""
    $Confirm = Read-Host "Type 'Y' to continue, or anything else to cancel"
    if ($Confirm -notin @('Y', 'y', 'Yes', 'yes')) {
        Write-HostTimestamp 'Operation cancelled by user.' -ForegroundColor Yellow
        Stop-Transcript | Out-Null
        exit 0
    }
    Write-Host $LineBreak
}

if ($Unattended) {
    Write-HostTimestamp 'Running in Unattended mode. User prompts will be skipped.' -ForegroundColor Cyan
    Write-Host $LineBreak
}

# Report the full Windows build version for non-interactive runs (the interactive prompt shows it above)
if ($Unattended -or $SkipInteractive) {
    Show-WindowsBuildInfo
}

# Change directory to System32 in case path is not set correctly
try {
    $System32Path = "$env:windir\System32"
    Set-Location -Path $System32Path -ErrorAction Stop -ErrorVariable NoSystem32
}
catch {
    $System32Path = 'C:\Windows\System32'
    Set-Location -Path $System32Path -ErrorAction SilentlyContinue -ErrorVariable NoSystem32
}

# If we can't set location to System32, we have some huge problems
if ($NoSystem32) {
    Write-HostTimestamp 'STOPPING SCRIPT: Unable to change directory to System32. This maybe an issue with the script or a major issue with Windows system that this script cannot fix.' -ForegroundColor Red
    Start-Sleep -Seconds 10; exit 1
}

# --- Staleness gate (optional) ---
# When -FixIfStale is used, the script only proceeds with the repair if Windows Update looks unhealthy:
# either no genuine patch (excluding drivers and Defender/antivirus definitions) has been installed
# within -StaleDays days, OR there are unresolved update failures that warrant a fix. When a standard
# patch succeeded recently, a small number of unresolved failures are treated as likely false positives;
# more than -FailureFixThreshold unresolved failures still triggers a repair.
if ($FixIfStale -and -not $Remediate) {
    Write-HostTimestamp "Checking Windows Update health (-FixIfStale, threshold = $StaleDays days)..."
    $LastPatch = Get-LastUpdatePatch
    $RecentFailures = Get-RecentUpdateFailures -Days $StaleDays
    $UnresolvedFailures = @($RecentFailures | Where-Object { -not $_.Resolved })
    $Cutoff = (Get-Date).AddDays(-$StaleDays)
    if ($LastPatch) {
        $DaysSince = [math]::Round(((Get-Date) - $LastPatch.Date).TotalDays, 1)
        Write-HostTimestamp "Last successful patch: $($LastPatch.Title) - installed $($LastPatch.Date) ($DaysSince days ago)."
    }
    else {
        Write-HostTimestamp 'No qualifying Windows Update patch was found in the update history.' -ForegroundColor Yellow
    }

    if ($RecentFailures.Count -gt 0) {
        Write-HostTimestamp "Detected $($RecentFailures.Count) failed Windows Update installation(s) within the last $StaleDays days ($($UnresolvedFailures.Count) still unresolved)." -ForegroundColor Yellow
        $RecentFailures | Select-Object -First 5 | ForEach-Object {
            if ($_.Resolved) {
                Write-Host "  - $($_.Date)  $($_.Title) ($($_.HResult)) - later succeeded on $($_.ResolvedDate), ignored"
            }
            else {
                Write-Host "  - $($_.Date)  $($_.Title) ($($_.HResult))"
            }
        }
    }

    # Additional staleness signal: how long ago the currently-installed build revision was released.
    $BuildInfo = Get-CurrentBuildReleaseInfo
    $BuildStale = $false
    $BuildRecent = $false
    if ($BuildInfo -and $BuildInfo.ReleaseDate) {
        $BuildAgeDays = [math]::Round(((Get-Date) - $BuildInfo.ReleaseDate).TotalDays, 1)
        $BuildStale = ($BuildInfo.ReleaseDate -lt $Cutoff)
        $BuildRecent = ($BuildInfo.ReleaseDate -ge $Cutoff)
        $KbNote = if ($BuildInfo.KB) { " ($($BuildInfo.KB))" } else { '' }
        Write-HostTimestamp "Installed build $($BuildInfo.BuildUbr)$KbNote was released $($BuildInfo.ReleaseDate.ToString('yyyy-MM-dd')) ($BuildAgeDays days ago)."
    }
    # The legacy update history is often empty on modern Windows 11, so treat an absent history as stale
    # only when a recent build does not rescue it; a recorded patch that is old (or an old build) is stale.
    $PatchStale = if (-not $LastPatch) { -not $BuildRecent } else { $LastPatch.Date -lt $Cutoff }
    $IsStale = ($PatchStale -or $BuildStale)
    $UnresolvedCount = $UnresolvedFailures.Count
    # Failures force a repair when there is no recent successful patch, or when they exceed the tolerated count.
    $FailuresRequireFix = ($UnresolvedCount -gt 0 -and $IsStale) -or ($UnresolvedCount -gt $FailureFixThreshold)

    if ($UnresolvedCount -gt $FailureFixThreshold) {
        Write-HostTimestamp "More than $FailureFixThreshold unresolved standard update failures detected - repair is warranted." -ForegroundColor Yellow
    }
    elseif ($UnresolvedCount -gt 0 -and -not $IsStale) {
        Write-HostTimestamp "A standard Windows update succeeded recently, so these $UnresolvedCount unresolved failure(s) are likely false positives and will be ignored." -ForegroundColor Yellow
    }

    if (-not $IsStale -and -not $FailuresRequireFix) {
        Write-HostTimestamp "Patched within the last $StaleDays days (by patch history or build release date) and no action-worthy failures were found. Windows Update looks healthy - no action needed." -ForegroundColor Green
        Write-Host $LineBreak
        Stop-Transcript | Out-Null
        exit 0
    }
    else {
        $Reason = if ($IsStale -and $FailuresRequireFix) { "no recent patch and unresolved update failures" }
                  elseif ($PatchStale) { "no patch within the last $StaleDays days" }
                  elseif ($BuildStale) { "the installed build was released more than $StaleDays days ago" }
                  else { "more than $FailureFixThreshold unresolved update failures" }
        Write-HostTimestamp "Proceeding with the Windows Update policy repair ($Reason)..." -ForegroundColor Cyan
    }
    Write-Host $LineBreak
}

# --- The Windows Update services that must be healthy ---
# StartupType reflects the Windows 10/11 default so we never leave a service in a broken state.
$RequiredServices = @(
    [PSCustomObject]@{ Name = 'BITS';             StartupType = 'Manual';    Display = 'Background Intelligent Transfer Service' }
    [PSCustomObject]@{ Name = 'wuauserv';         StartupType = 'Manual';    Display = 'Windows Update' }
    [PSCustomObject]@{ Name = 'UsoSvc';           StartupType = 'Automatic'; Display = 'Update Orchestrator Service' }
    [PSCustomObject]@{ Name = 'WaaSMedicSvc';     StartupType = 'Manual';    Display = 'Windows Update Medic Service' }
    [PSCustomObject]@{ Name = 'CryptSvc';         StartupType = 'Automatic'; Display = 'Cryptographic Services' }
    [PSCustomObject]@{ Name = 'msiserver';        StartupType = 'Manual';    Display = 'Windows Installer' }
    [PSCustomObject]@{ Name = 'TrustedInstaller'; StartupType = 'Manual';    Display = 'Windows Modules Installer' }
    [PSCustomObject]@{ Name = 'DoSvc';            StartupType = 'Automatic'; Display = 'Delivery Optimization' }
    [PSCustomObject]@{ Name = 'AppIDSvc';         StartupType = 'Manual';    Display = 'Application Identity' }
    [PSCustomObject]@{ Name = 'gpsvc';            StartupType = 'Automatic'; Display = 'Group Policy Client' }
)

# Services that must actually be running (not just enabled) for policy/update to function
$ServicesToStart = @('CryptSvc', 'gpsvc', 'BITS', 'wuauserv')

# Stop the update services first so files/keys are not locked while we clean up
Invoke-Task -Description 'Stopping Windows Update services before cleanup...' -ScriptBlock {
    foreach ($Svc in @('wuauserv', 'UsoSvc', 'BITS', 'DoSvc', 'CryptSvc', 'msiserver')) {
        $Service = Get-Service -Name $Svc -ErrorAction SilentlyContinue
        if ($Service -and $Service.Status -ne 'Stopped') {
            Write-Host "- Stopping $($Service.DisplayName) ($Svc)"
            Stop-Service -Name $Svc -Force -ErrorAction SilentlyContinue
        }
    }
}

# 1. Clear the Local Group Policy store
Invoke-Task -Description 'Clearing the Local Group Policy store...' -ScriptBlock {
    $GroupPolicyPaths = @(
        (Join-Path -Path $System32Path -ChildPath 'GroupPolicy')
    )
    # GroupPolicyUsers holds per-user/per-group Local GPOs and is unrelated to Windows Update.
    # Only clear it when explicitly requested to avoid wiping intentional per-user policy config.
    if ($IncludeGroupPolicyUsers) {
        $GroupPolicyPaths += (Join-Path -Path $System32Path -ChildPath 'GroupPolicyUsers')
    }
    foreach ($GpPath in $GroupPolicyPaths) {
        if (Test-Path $GpPath) {
            Write-Host "- Removing contents of $GpPath"
            try {
                Get-ChildItem -Path $GpPath -Force -ErrorAction Stop | Remove-Item -Recurse -Force -ErrorAction Stop
                Write-HostTimestamp "  Cleared $GpPath"
            }
            catch {
                Write-HostTimestamp "  Could not fully clear $GpPath. Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-HostTimestamp "  $GpPath does not exist. Nothing to clear." -ForegroundColor Yellow
        }
    }
}

# 2. Remove the Windows Update policy registry keys
Invoke-Task -Description 'Removing Windows Update policy registry keys...' -ScriptBlock {
    $PolicyKeys = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
        'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsUpdate'
        # 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    )
    foreach ($Key in $PolicyKeys) {
        if (Test-Path $Key) {
            Write-Host "- Removing $Key"
            try {
                Remove-Item -Path $Key -Recurse -Force -ErrorAction Stop
                Write-HostTimestamp "  Removed $Key"
            }
            catch {
                Write-HostTimestamp "  Could not remove $Key. Error: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-HostTimestamp "  $Key not present. Skipping." -ForegroundColor Yellow
        }
    }

    if ($ResetAllPolicies) {
        Write-HostTimestamp '-ResetAllPolicies detected. Removing the entire Software Policies hive...' -ForegroundColor Cyan
        $AllPolicyKeys = @(
            'HKLM:\SOFTWARE\Policies\Microsoft\Windows',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'
            # 'HKCU:\SOFTWARE\Policies\Microsoft\Windows',
            # 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'
        )
        foreach ($Key in $AllPolicyKeys) {
            if (Test-Path $Key) {
                Write-Host "- Removing $Key"
                Remove-Item -Path $Key -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# 3. Reset the Windows Update cache and BITS transfer queue
Invoke-Task -Description 'Resetting the Windows Update cache (SoftwareDistribution, catroot2, BITS queue)...' -ScriptBlock {
    $Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'

    # Remove any leftover *.old_* backups from previous runs so they do not accumulate.
    Remove-OldUpdateBackups

    # Clear the BITS transfer queue (qmgr*.dat)
    $BitsQueue = Join-Path -Path $env:ALLUSERSPROFILE -ChildPath 'Microsoft\Network\Downloader'
    if (Test-Path $BitsQueue) {
        Get-ChildItem -Path $BitsQueue -Filter 'qmgr*.dat' -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "- Removing BITS queue file $($_.Name)"
            Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
        }
    }

    # Rename the SoftwareDistribution and catroot2 folders so Windows rebuilds them cleanly
    $ResetFolders = @(
        (Join-Path -Path $env:windir -ChildPath 'SoftwareDistribution'),
        (Join-Path -Path $System32Path -ChildPath 'catroot2')
    )
    foreach ($Folder in $ResetFolders) {
        if (Test-Path $Folder) {
            $BackupName = "$(Split-Path -Leaf $Folder).old_$Stamp"
            try {
                Rename-Item -Path $Folder -NewName $BackupName -ErrorAction Stop
                Write-HostTimestamp "  Renamed $Folder to $BackupName"
            }
            catch {
                Write-HostTimestamp "  Could not rename $Folder (in use). Clearing its contents instead..." -ForegroundColor Yellow
                Get-ChildItem -Path $Folder -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        else {
            Write-HostTimestamp "  $Folder does not exist. Nothing to reset." -ForegroundColor Yellow
        }
    }
}

# 4. Re-register the Windows Update components (DLLs)
Invoke-Task -Description 'Re-registering Windows Update components (DLLs)...' -ScriptBlock {
    $Dlls = @(
        'atl.dll', 'urlmon.dll', 'mshtml.dll', 'shdocvw.dll', 'browseui.dll', 'jscript.dll', 'vbscript.dll',
        'scrrun.dll', 'msxml.dll', 'msxml3.dll', 'msxml6.dll', 'actxprxy.dll', 'softpub.dll', 'wintrust.dll',
        'dssenh.dll', 'rsaenh.dll', 'gpkcsp.dll', 'sccbase.dll', 'slbcsp.dll', 'cryptdlg.dll', 'oleaut32.dll',
        'ole32.dll', 'shell32.dll', 'initpki.dll', 'wuapi.dll', 'wuaueng.dll', 'wups.dll', 'wups2.dll',
        'qmgr.dll', 'qmgrprxy.dll', 'wucltux.dll', 'muweb.dll', 'wuwebv.dll'
    )
    $Registered = 0
    foreach ($Dll in $Dlls) {
        $DllPath = Join-Path -Path $System32Path -ChildPath $Dll
        if (Test-Path $DllPath) {
            Start-Process -FilePath 'regsvr32.exe' -ArgumentList "/s `"$DllPath`"" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            $Registered++
        }
    }
    Write-HostTimestamp "  Re-registered $Registered Windows Update component(s)."
}

# 5. Verify and enable all services required by Windows Update
Invoke-Task -Description 'Verifying and enabling required Windows Update services...' -ScriptBlock {
    foreach ($Svc in $RequiredServices) {
        $Service = Get-Service -Name $Svc.Name -ErrorAction SilentlyContinue
        if (-not $Service) {
            Write-HostTimestamp "- $($Svc.Display) ($($Svc.Name)) is not present on this system. Skipping." -ForegroundColor Yellow
            continue
        }

        Write-Host "- $($Svc.Display) ($($Svc.Name))"

        # Ensure the service is not disabled and matches the healthy default startup type
        $CurrentStartType = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$($Svc.Name)'" -ErrorAction SilentlyContinue).StartMode
        if ($CurrentStartType -eq 'Disabled' -or $Service.StartType -ne $Svc.StartupType) {
            Write-Host "    Setting startup type to $($Svc.StartupType) (was $($Service.StartType))."
            [void](Set-ServiceStartupType -Name $Svc.Name -StartupType $Svc.StartupType)
        }
        else {
            Write-Host "    Startup type already set to $($Svc.StartupType)."
        }

        # Start the services that must be running now
        if ($Svc.Name -in $ServicesToStart) {
            $Service.Refresh()
            if ($Service.Status -ne 'Running') {
                Write-Host "    Starting service..."
                Start-Service -Name $Svc.Name -ErrorAction SilentlyContinue
            }
        }
    }
}

# Force a Group Policy refresh so the machine rebuilds a clean policy set
Invoke-Task -Description 'Forcing a Group Policy refresh (gpupdate /force)...' -ScriptBlock {
    if (Get-Command gpupdate.exe -ErrorAction SilentlyContinue) {
        gpupdate.exe /force
    }
    else {
        Write-HostTimestamp 'gpupdate.exe not found. Skipping Group Policy refresh.' -ForegroundColor Yellow
    }
}

# Optionally repair the component store, a common underlying cause of update failures
if ($RepairComponentStore) {
    Invoke-Task -Description 'Repairing the component store with DISM /RestoreHealth (this can take a while)...' -ScriptBlock {
        try {
            DISM.exe /Online /Cleanup-Image /RestoreHealth
            if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3010) {
                Write-HostTimestamp "DISM returned exit code $LASTEXITCODE." -ForegroundColor Yellow
            }
        }
        catch {
            Write-HostTimestamp "DISM error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Invoke-Task -Description 'Scanning and repairing system files with SFC...' -ScriptBlock {
        sfc.exe /scannow
    }
}

# Optionally trigger a fresh Windows Update detection scan
if ($TriggerUpdateScan) {
    Invoke-Task -Description 'Triggering a Windows Update detection scan...' -ScriptBlock {
        if (Get-Command UsoClient.exe -ErrorAction SilentlyContinue) {
            UsoClient.exe StartScan
            Write-HostTimestamp 'Update scan requested. Check Settings > Windows Update for results.'
        }
        else {
            # Fallback for older builds
            (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
            Write-HostTimestamp 'Update scan requested via COM. Check Settings > Windows Update for results.'
        }
    }
}

# Done, restart when necessary
Write-HostTimestamp 'Windows Update Fix completed!' -Foreground Green
Write-Host 'A restart is recommended to fully apply the Group Policy and service changes.'
if ($AutoReboot) {
    (60..1) | ForEach-Object {
        if ($_ -lt 10) {
            Write-HostTimestamp "Restart in $_ $(if ($_ -eq 1){'second'}else{'seconds'})" -ForegroundColor Yellow
        }
        else {
            if ($_ % 10 -eq 0) {
                Write-HostTimestamp "Restart in $_ seconds"
            }
        }
        Start-Sleep 1
    }
    shutdown.exe -r -t 5 -c 'Restarting to finish Windows Update fix...'
}
else {
    Write-HostTimestamp 'Restart not initiated. Please remember to restart your computer manually to complete the repairs.' -ForegroundColor Yellow
    if (-not $Unattended -and -not $Remediate) {
        Read-Host -Prompt 'Close window or press enter to exit.'
    }
}

# Stop logging
Stop-Transcript
# --- End Logging ---
