# --- SCRIPT OVERVIEW ---
# This script is a specialized "clean-up" tool focused solely on reclaiming disk space on the system drive.
# It performs a tiered, escalating set of cleanup actions and can automatically scale how aggressively it
# cleans based on how little free space is left. It performs several targeted actions:
#   1. Level 1 (Light):      Clears temp folders, caches, the Recycle Bin, crash dumps, and update download caches.
#   2. Level 2 (Medium):     Adds Windows Disk Cleanup (cleanmgr), CBS/DISM/Panther logs, prefetch, and font cache.
#   3. Level 3 (Severe):     Adds the DISM component-store cleanup (WinSxS) and removes leftover Windows upgrade folders.
#   4. Level 4 (Aggressive): Adds hibernation-file removal, old System Restore point pruning, and clearing event logs.
# Each level includes everything the lower levels do, so a higher level always cleans more.
#
# For hands-off use, run with -Remediate: the script measures free space on the system drive and automatically
# scales the cleanup to how full the disk is. Plenty of free space is left untouched; a moderately full disk
# gets a light clean; a nearly-full disk gets the full aggressive treatment.
#
# To preview without changing anything, run with -Audit: nothing is deleted and the script instead reports
# what each step WOULD remove and estimates how much space would be freed at the selected level.
# -------------------------------------------------
# How to Run .PS1 Script with PowerShell:
# NOTE: It is recommended to use the "Run-Windows-Clean-Up.bat" to invoke this script. However, you can run the .PS1 directly if needed.
# 1.  Open PowerShell as an Administrator: Right-click your Start Menu and select "Terminal (Admin)".
# 2.  Enable Script Execution (if needed): Set-ExecutionPolicy Bypass -Force
# 3.  Run the Script: Right-click the saved "Windows-Clean-Up.ps1" file and select "Run with PowerShell".
# -------------------------------------------------
# Parameters for the script
param(
    [switch]$Unattended, # Runs the script without any user prompts. It will not ask for confirmation to start
    [Parameter(HelpMessage = 'Automatically restart upon completion')]
    [switch]$AutoReboot,
    [Parameter(HelpMessage = 'Read-only audit: do not delete anything, just report what WOULD be cleaned and estimate how much space would be freed')]
    [switch]$Audit,
    [Parameter(HelpMessage = 'Adaptive mode: measure free disk space and automatically scale the cleanup to how full the drive is')]
    [switch]$Remediate,
    [Parameter(HelpMessage = 'Skip the free-space assessment and force a specific cleanup level directly')]
    [ValidateSet('Light', 'Medium', 'Severe', 'Aggressive')]
    [string]$ForceLevel,
    [Parameter(HelpMessage = 'Free space (GB) at or below which a LIGHT cleanup is triggered (default 30)')]
    [int]$LightThresholdGB = 30,
    [Parameter(HelpMessage = 'Free space (GB) at or below which a MEDIUM cleanup is triggered (default 20)')]
    [int]$MediumThresholdGB = 20,
    [Parameter(HelpMessage = 'Free space (GB) at or below which a SEVERE cleanup is triggered (default 10)')]
    [int]$SevereThresholdGB = 10,
    [Parameter(HelpMessage = 'Free space (GB) at or below which an AGGRESSIVE cleanup is triggered (default 5)')]
    [int]$AggressiveThresholdGB = 5,
    [Parameter(HelpMessage = 'Do not empty the Recycle Bin during cleanup')]
    [switch]$SkipRecycleBin,
    [Parameter(HelpMessage = 'EXPERIMENTAL: Remove orphaned .msi/.msp packages from C:\Windows\Installer that are no longer referenced by any installed product or patch')]
    [switch]$CleanupOrphanedInstaller,
    [Parameter(HelpMessage = 'EXPERIMENTAL: Delete stale local user profiles that have not been signed into for -ProfileAgeDays days')]
    [switch]$CleanupOldProfiles,
    [Parameter(HelpMessage = 'Age in days a local profile must be unused before -CleanupOldProfiles removes it (default 90)')]
    [int]$ProfileAgeDays = 90,
    [Parameter(HelpMessage = 'Minimum number of cached local profiles in C:\Users required before -CleanupOldProfiles will run (default 5; cleanup only runs when there are MORE than this many)')]
    [int]$MinCachedProfiles = 5,
    [Parameter(HelpMessage = 'Days before -Remediate or -ForceLevel can run again on the same machine (default 7, set to 0 to disable)')]
    [int]$CooldownDays = 7,
    [Parameter(HelpMessage = 'Bypass the cooldown and run -Remediate or -ForceLevel regardless of when it last ran')]
    [switch]$IgnoreCooldown,
    [Parameter(HelpMessage = 'Directory to write log files to (defaults to the script folder)')]
    [string]$LogPath,
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
        # Re-add any passed parameters (including their values for non-switch parameters)
        foreach ($Parameter in $PSBoundParameters.Keys) {
            $Value = $PSBoundParameters[$Parameter]
            if ($Value -is [switch]) {
                if ($Value.IsPresent) { $ArgumentList += "-$Parameter" }
            }
            else {
                $ArgumentList += "-$Parameter"
                $ArgumentList += "`"$Value`""
            }
        }

        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $ArgumentList
        exit
    }
}

# Add a Window Title
$Host.UI.RawUI.WindowTitle = "Windows Clean-Up - Running as Administrator"

# --- Start Logging ---
# Resolve the log directory: use -LogPath if provided, otherwise default to the script folder
$LogDir = $PSScriptRoot
if ($LogPath) {
    try {
        if (-not (Test-Path $LogPath)) {
            New-Item -ItemType Directory -Path $LogPath -Force -ErrorAction Stop | Out-Null
        }
        $LogDir = $LogPath
    }
    catch {
        Write-Warning "Could not use -LogPath '$LogPath': $($_.Exception.Message). Falling back to script folder."
    }
}
$LogFile = Join-Path -Path $LogDir -ChildPath "Windows-Clean-Up_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Start-Transcript -Path $LogFile | Out-Null

# Rotate logs: keep only the 30 most recent, delete the rest
Get-ChildItem -Path $LogDir -Filter 'Windows-Clean-Up_*.log' -File |
    Sort-Object -Property LastWriteTime -Descending |
    Select-Object -Skip 30 |
    Remove-Item -Force -ErrorAction SilentlyContinue

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

# Maps free space on the system drive to a numeric cleanup level using the configured thresholds:
#   0 = Healthy (above the light threshold, no cleanup needed)
#   1 = Light, 2 = Medium, 3 = Severe, 4 = Aggressive
function Get-CleanupLevelFromFreeSpace {
    param([double]$FreeGB)
    if ($FreeGB -le $AggressiveThresholdGB) { return 4 }
    if ($FreeGB -le $SevereThresholdGB) { return 3 }
    if ($FreeGB -le $MediumThresholdGB) { return 2 }
    if ($FreeGB -le $LightThresholdGB) { return 1 }
    return 0
}

# Converts a numeric cleanup level to its display name.
function Get-CleanupLevelName {
    param([int]$Level)
    switch ($Level) {
        1 { 'Light' }
        2 { 'Medium' }
        3 { 'Severe' }
        4 { 'Aggressive' }
        default { 'None' }
    }
}

# Safely removes the contents of a folder (not the folder itself), logging what it touches.
# Returns the total size in bytes of a file or folder (recursive for folders), or 0 if unavailable.
function Get-PathSizeBytes {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path)) { return 0 }
    try {
        $Item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($Item.PSIsContainer) {
            $Sum = (Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
            if ($Sum) { return [long]$Sum }
            return 0
        }
        return [long]$Item.Length
    }
    catch { return 0 }
}

# Records an audit finding: adds the byte count to the running total and reports it. Used only in
# -Audit mode so the user can see what WOULD be removed and roughly how much space it would free.
function Add-AuditFinding {
    param(
        [string]$Label,
        [long]$Bytes
    )
    $script:AuditTotalBytes += $Bytes
    $SizeMB = [math]::Round($Bytes / 1MB, 2)
    Write-HostTimestamp "  [AUDIT] Would free ~$SizeMB MB from $Label"
}

# Safely removes the contents of a folder (not the folder itself), logging what it touches.
# In audit mode nothing is deleted; instead the size of what WOULD be removed is measured and recorded.
function Clear-FolderContents {
    param(
        [string]$Path,
        [string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path)) { return }
    if ($script:AuditMode) {
        $Bytes = 0
        foreach ($Child in (Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue)) {
            $Bytes += Get-PathSizeBytes -Path $Child.FullName
        }
        $FindingLabel = if ($Label) { $Label } else { $Path }
        Add-AuditFinding -Label $FindingLabel -Bytes $Bytes
        return
    }
    try {
        Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        if ($Label) { Write-HostTimestamp "  Cleared $Label" }
    }
    catch {
        Write-HostTimestamp "  Could not fully clear $($Label): $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Definitive activity check for -CleanupOldProfiles: returns $true if the profile folder shows signs of
# recent activity (any sampled file/folder modified after $Cutoff). This is the authoritative signal for
# whether a profile is in use - Win32_UserProfile.LastUseTime is only informational, since it can be
# bumped by background/system activity. We sample a subset of high-signal locations within the user
# folder and treat the profile as still active if anything there was modified recently.
function Test-ProfileRecentlyActive {
    param(
        [string]$ProfilePath,
        [datetime]$Cutoff
    )
    if ([string]::IsNullOrWhiteSpace($ProfilePath) -or -not (Test-Path $ProfilePath)) { return $false }

    # Sample these locations rather than scanning the whole profile (which could be huge and slow).
    # NTUSER.DAT is intentionally excluded: it can be touched by background/system activity even when
    # the user has not actually signed in, which would produce false "active" results.
    $SamplePaths = @(
        (Join-Path $ProfilePath 'Desktop'),
        (Join-Path $ProfilePath 'Documents'),
        (Join-Path $ProfilePath 'Downloads'),
        (Join-Path $ProfilePath 'Pictures'),
        (Join-Path $ProfilePath 'AppData\Roaming'),
        (Join-Path $ProfilePath 'AppData\Local')
    )
    foreach ($SamplePath in $SamplePaths) {
        if (-not (Test-Path $SamplePath)) { continue }
        $Item = Get-Item -Path $SamplePath -Force -ErrorAction SilentlyContinue
        if ($Item -and $Item.LastWriteTime -gt $Cutoff) { return $true }
        # For folders, check the most recently modified files inside (shallow scan, capped for speed).
        if ($Item -and $Item.PSIsContainer) {
            $Recent = Get-ChildItem -Path $SamplePath -File -Force -ErrorAction SilentlyContinue |
                Sort-Object -Property LastWriteTime -Descending | Select-Object -First 25
            foreach ($File in $Recent) {
                if ($File.LastWriteTime -gt $Cutoff) { return $true }
            }
        }
    }
    return $false
}

# --- Validate thresholds ---
# Thresholds must descend (Light > Medium > Severe > Aggressive) for level selection to make sense.
if (-not (($LightThresholdGB -gt $MediumThresholdGB) -and ($MediumThresholdGB -gt $SevereThresholdGB) -and ($SevereThresholdGB -gt $AggressiveThresholdGB))) {
    Write-HostTimestamp "Threshold values must descend: Light ($LightThresholdGB) > Medium ($MediumThresholdGB) > Severe ($SevereThresholdGB) > Aggressive ($AggressiveThresholdGB)." -ForegroundColor Red
    Write-HostTimestamp 'Please correct the -*ThresholdGB parameters and try again.' -ForegroundColor Red
    Stop-Transcript | Out-Null
    exit 1
}

# --- Audit (read-only) mode ---
# When -Audit is set, no files are deleted and no system changes are made. Every cleanup step instead
# estimates how much space it WOULD free and adds it to a running total reported at the end.
$script:AuditMode = [bool]$Audit
$script:AuditTotalBytes = 0
# Tracks whether any step made a change that a restart would finalize (e.g. disabling hibernation).
$script:RebootRecommended = $false
if ($script:AuditMode) {
    $Host.UI.RawUI.WindowTitle = "Windows Clean-Up - AUDIT (read-only)"
    Write-HostTimestamp 'AUDIT MODE: read-only. Nothing will be deleted or changed; only estimates will be reported.' -ForegroundColor Cyan
    Write-Host $LineBreak
}

# Record the starting free space so we can report how much was reclaimed at the end.
$script:FreeSpaceBefore = Get-SystemDriveFreeGB
if ($null -ne $script:FreeSpaceBefore) {
    Write-HostTimestamp "Free space on $env:SystemDrive before cleanup: $($script:FreeSpaceBefore) GB"
}
else {
    Write-HostTimestamp 'Could not determine free disk space on the system drive. Continuing.' -ForegroundColor Yellow
}
Write-Host $LineBreak

# --- Cooldown check for automated modes ---
# Prevents -Remediate and -ForceLevel from running more often than -CooldownDays on the same machine.
# The last-run timestamp is stored in a small file alongside the script.
# Set -CooldownDays 0 or pass -IgnoreCooldown to bypass. Audit runs are read-only and ignore the cooldown.
if (($Remediate -or $ForceLevel) -and $CooldownDays -gt 0 -and -not $IgnoreCooldown -and -not $script:AuditMode) {
    $script:CooldownFile = Join-Path -Path $PSScriptRoot -ChildPath '.last_cleanup'
    if (Test-Path $script:CooldownFile) {
        try {
            $LastRun = [datetime]::ParseExact((Get-Content $script:CooldownFile -Raw -ErrorAction Stop).Trim(), 'yyyy-MM-dd HH:mm:ss', $null)
            $DaysSinceLastRun = [math]::Round(((Get-Date) - $LastRun).TotalDays, 1)
            if ($DaysSinceLastRun -lt $CooldownDays) {
                Write-HostTimestamp "Cooldown active: cleanup last ran $DaysSinceLastRun day(s) ago on $($env:ComputerName) (cooldown = $CooldownDays days). Use -IgnoreCooldown to bypass." -ForegroundColor Yellow
                Write-Host $LineBreak
                Stop-Transcript | Out-Null
                exit 0
            }
            Write-HostTimestamp "Cooldown elapsed: last ran $DaysSinceLastRun day(s) ago. Proceeding."
            # Remove a significantly stale stamp file; the cleanup will write a fresh one when it commits.
            if ($DaysSinceLastRun -ge (2 * $CooldownDays)) {
                Remove-Item -Path $script:CooldownFile -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-HostTimestamp "Could not read cooldown file ($($_.Exception.Message)). Proceeding." -ForegroundColor Yellow
        }
    }
    Write-Host $LineBreak
}

# --- Decide the cleanup level ---
# $CleanupLevel: 0 = none/healthy, 1 = Light, 2 = Medium, 3 = Severe, 4 = Aggressive
$CleanupLevel = 0

# --- Adaptive remediation (optional) ---
# When -Remediate is used, the script measures free space and automatically decides both WHETHER to act
# and HOW aggressively, based on how full the system drive is:
#   * Free above the light threshold  -> nothing is done and the script exits.
#   * At/under the light threshold     -> Light cleanup.
#   * At/under the medium threshold     -> Medium cleanup.
#   * At/under the severe threshold     -> Severe cleanup.
#   * At/under the aggressive threshold -> Aggressive cleanup.
# Remediation runs hands-off (no prompts).
if ($Remediate) {
    Clear-Host
    Write-HostTimestamp "Running in adaptive Remediation mode on $($env:ComputerName) - assessing free disk space..." -ForegroundColor Cyan
    $FreeGB = Get-SystemDriveFreeGB
    if ($null -eq $FreeGB) {
        Write-HostTimestamp 'Could not determine free disk space, so the adaptive level cannot be chosen. Defaulting to a LIGHT cleanup.' -ForegroundColor Yellow
        $CleanupLevel = 1
    }
    else {
        $CleanupLevel = Get-CleanupLevelFromFreeSpace -FreeGB $FreeGB
    }

    if ($CleanupLevel -eq 0) {
        Write-HostTimestamp "Free space on $env:SystemDrive is $FreeGB GB, which is above the light-cleanup threshold ($LightThresholdGB GB). No cleanup needed." -ForegroundColor Green
        Write-Host $LineBreak
        Stop-Transcript | Out-Null
        exit 0
    }

    $LevelName = Get-CleanupLevelName -Level $CleanupLevel
    $LevelColor = switch ($CleanupLevel) { 1 { 'Green' } 2 { 'Yellow' } 3 { 'Yellow' } 4 { 'Red' } }
    Write-HostTimestamp "Free space is $FreeGB GB. Selected cleanup level: $LevelName (level $CleanupLevel of 4)." -ForegroundColor $LevelColor
    # Remediation is hands-off: skip the interactive confirmation.
    $SkipInteractive = $true
    Write-Host $LineBreak
}

# --- Forced level (optional) ---
# Skips the free-space assessment entirely and applies the specified level directly.
if ($ForceLevel -and -not $Remediate) {
    Clear-Host
    $CleanupLevel = switch ($ForceLevel) { 'Light' { 1 } 'Medium' { 2 } 'Severe' { 3 } 'Aggressive' { 4 } }
    $LevelColor = switch ($CleanupLevel) { 1 { 'Green' } 2 { 'Yellow' } 3 { 'Yellow' } 4 { 'Red' } }
    Write-HostTimestamp "Running in Forced level mode ($ForceLevel) on $($env:ComputerName)..." -ForegroundColor Cyan
    Write-HostTimestamp "Selected cleanup level: $ForceLevel (level $CleanupLevel of 4)." -ForegroundColor $LevelColor
    $SkipInteractive = $true
    Write-Host $LineBreak
}

# --- Interactive confirmation / level selection ---
# When not in an automated mode, show the free space, recommend a level based on the thresholds,
# and let the user confirm or choose a different level.
if (-not $Unattended -and -not $SkipInteractive) {
    Clear-Host
    if ($script:AuditMode) {
        Write-HostTimestamp "Running Windows Clean-Up in AUDIT mode (read-only) on $($env:ComputerName)..." -ForegroundColor Cyan
    }
    else {
        Write-HostTimestamp "Running Windows Clean-Up on $($env:ComputerName)..." -ForegroundColor Yellow
    }
    Write-Host ""
    $FreeGB = Get-SystemDriveFreeGB
    $Recommended = 1
    if ($null -ne $FreeGB) {
        $DiskColor = if ($FreeGB -le $SevereThresholdGB) { 'Red' } elseif ($FreeGB -le $MediumThresholdGB) { 'Yellow' } else { 'Green' }
        Write-Host "Free disk space on $env:SystemDrive : $FreeGB GB" -ForegroundColor $DiskColor
        $AutoLevel = Get-CleanupLevelFromFreeSpace -FreeGB $FreeGB
        $Recommended = if ($AutoLevel -eq 0) { 1 } else { $AutoLevel }
    }
    Write-Host ""
    Write-Host "This tool reclaims disk space on the system drive using four escalating levels."
    Write-Host "Each level includes everything the levels below it do:"
    Write-Host ""
    Write-Host "  1. Light      - Temp folders, caches, Recycle Bin, crash dumps, update download cache."
    Write-Host "  2. Medium     - Light + Disk Cleanup (cleanmgr), CBS/DISM/Panther logs, prefetch, font cache."
    Write-Host "  3. Severe     - Medium + DISM component-store cleanup (WinSxS) and Windows upgrade folders." -ForegroundColor Yellow
    Write-Host "  4. Aggressive - Severe + remove hibernation file, prune restore points, clear event logs." -ForegroundColor Red
    Write-Host ""
    Write-Host "Adaptive thresholds (used by -Remediate): Light <= $LightThresholdGB GB, Medium <= $MediumThresholdGB GB, Severe <= $SevereThresholdGB GB, Aggressive <= $AggressiveThresholdGB GB."
    Write-Host ""
    if ($CleanupOrphanedInstaller -or $CleanupOldProfiles) {
        Write-Host "EXPERIMENTAL options enabled (run regardless of level):" -ForegroundColor Red
        if ($CleanupOrphanedInstaller) {
            Write-Host "  - Remove orphaned .msi/.msp packages from C:\Windows\Installer" -ForegroundColor Red
        }
        if ($CleanupOldProfiles) {
            Write-Host "  - Delete local profiles unused for more than $ProfileAgeDays day(s) (permanently removes their data)" -ForegroundColor Red
        }
        Write-Host ""
    }
    Write-Host "Recommended level for this system: $Recommended ($(Get-CleanupLevelName -Level $Recommended))" -ForegroundColor Cyan
    Write-Host ""
    if ($script:AuditMode) {
        Write-Host "AUDIT MODE: nothing will be deleted. The selected level only controls what gets estimated." -ForegroundColor Cyan
        Write-Host ""
    }
    $Selection = Read-Host "Enter a cleanup level (1-4), or press Enter to accept the recommended level ($Recommended), or type 'C' to cancel"
    if ($Selection -in @('C', 'c', 'Cancel', 'cancel')) {
        Write-HostTimestamp 'Operation cancelled by user.' -ForegroundColor Yellow
        Stop-Transcript | Out-Null
        exit 0
    }
    if ([string]::IsNullOrWhiteSpace($Selection)) {
        $CleanupLevel = $Recommended
    }
    elseif ($Selection -match '^[1-4]$') {
        $CleanupLevel = [int]$Selection
    }
    else {
        Write-HostTimestamp "Unrecognized selection '$Selection'. Using the recommended level ($Recommended)." -ForegroundColor Yellow
        $CleanupLevel = $Recommended
    }
    Write-Host $LineBreak
}

# In Unattended mode with no explicit level, fall back to the adaptive free-space level.
if ($Unattended -and $CleanupLevel -eq 0) {
    $FreeGB = Get-SystemDriveFreeGB
    if ($null -ne $FreeGB) {
        $CleanupLevel = Get-CleanupLevelFromFreeSpace -FreeGB $FreeGB
    }
    if ($CleanupLevel -eq 0) {
        Write-HostTimestamp "Unattended mode: free space is above the light threshold ($LightThresholdGB GB). Defaulting to a LIGHT cleanup." -ForegroundColor Cyan
        $CleanupLevel = 1
    }
    Write-HostTimestamp "Running in Unattended mode. Selected cleanup level: $(Get-CleanupLevelName -Level $CleanupLevel)." -ForegroundColor Cyan
    Write-Host $LineBreak
}

# Safety net: if nothing selected a level, do the light cleanup.
if ($CleanupLevel -lt 1) { $CleanupLevel = 1 }

if ($script:AuditMode) {
    Write-HostTimestamp "Auditing $(Get-CleanupLevelName -Level $CleanupLevel) cleanup (level $CleanupLevel of 4) - read-only, nothing will be deleted..." -ForegroundColor Cyan
}
else {
    Write-HostTimestamp "Starting $(Get-CleanupLevelName -Level $CleanupLevel) cleanup (level $CleanupLevel of 4)..." -ForegroundColor Cyan
}
Write-Host $LineBreak

# Write the cooldown timestamp now that we are committed to running the cleanup.
if (($Remediate -or $ForceLevel) -and $CooldownDays -gt 0 -and -not $script:AuditMode) {
    if (-not $script:CooldownFile) {
        $script:CooldownFile = Join-Path -Path $PSScriptRoot -ChildPath '.last_cleanup'
    }
    try {
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Set-Content -Path $script:CooldownFile -Encoding UTF8 -ErrorAction Stop
        Write-HostTimestamp "Cooldown stamp written. Next -Remediate / -ForceLevel run allowed in $CooldownDays day(s)." -ForegroundColor DarkGray
    }
    catch {
        Write-HostTimestamp "Could not write cooldown stamp: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    Write-Host $LineBreak
}

# =====================================================================================================
# LEVEL 1 (LIGHT) - safe, non-destructive to user data
# =====================================================================================================

# Empty the system and per-user Temp folders
Invoke-Task -Description 'Clearing system and per-user Temp folders...' -ScriptBlock {
    Clear-FolderContents -Path (Join-Path -Path $env:windir -ChildPath 'Temp') -Label 'Windows Temp folder'
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $UserTemp = Join-Path $_.FullName 'AppData\Local\Temp'
        Clear-FolderContents -Path $UserTemp -Label "$($_.Name) Temp folder"
    }
}

# Clear the Windows Update download cache (Windows re-downloads as needed)
Invoke-Task -Description 'Clearing the Windows Update download cache...' -ScriptBlock {
    Clear-FolderContents -Path (Join-Path -Path $env:windir -ChildPath 'SoftwareDistribution\Download') -Label 'Windows Update download cache'
    Clear-FolderContents -Path (Join-Path -Path $env:windir -ChildPath 'SoftwareDistribution\DataStore\Logs') -Label 'Windows Update DataStore logs'
}

# Remove leftover SoftwareDistribution.old_* / catroot2.old_* backups created by the Windows-Update-Fix tool
Invoke-Task -Description 'Removing leftover Windows Update backup folders...' -ScriptBlock {
    $System32 = Join-Path -Path $env:windir -ChildPath 'System32'
    $BackupLocations = @(
        @{ Parent = $env:windir; Pattern = 'SoftwareDistribution.old_*' },
        @{ Parent = $System32;   Pattern = 'catroot2.old_*' }
    )
    $Backups = foreach ($Location in $BackupLocations) {
        if (Test-Path $Location.Parent) {
            Get-ChildItem -Path $Location.Parent -Directory -Filter $Location.Pattern -Force -ErrorAction SilentlyContinue
        }
    }
    if (-not $Backups) {
        Write-HostTimestamp '  No leftover Windows Update backup folders found.'
    }
    elseif ($script:AuditMode) {
        foreach ($Backup in $Backups) {
            Add-AuditFinding -Label "old backup $($Backup.FullName)" -Bytes (Get-PathSizeBytes -Path $Backup.FullName)
        }
    }
    else {
        foreach ($Backup in $Backups) {
            try {
                Remove-Item -Path $Backup.FullName -Recurse -Force -ErrorAction Stop
                Write-HostTimestamp "  Removed old backup: $($Backup.FullName)"
            }
            catch {
                Write-HostTimestamp "  Could not remove $($Backup.FullName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
}

# Clear the Delivery Optimization peer cache (can be several GB)
Invoke-Task -Description 'Clearing the Delivery Optimization cache...' -ScriptBlock {
    if ($script:AuditMode) {
        # Report the current DO cache size; the folder location can vary, so sample the common path.
        $DoCache = Join-Path -Path $env:windir -ChildPath 'SoftwareDistribution\DeliveryOptimization'
        if (Get-Command Get-DeliveryOptimizationStatus -ErrorAction SilentlyContinue) {
            $DoBytes = (Get-DeliveryOptimizationStatus -ErrorAction SilentlyContinue | Measure-Object -Property FileSizeInCache -Sum).Sum
            if ($DoBytes) { Add-AuditFinding -Label 'Delivery Optimization cache' -Bytes ([long]$DoBytes); return }
        }
        Add-AuditFinding -Label 'Delivery Optimization cache' -Bytes (Get-PathSizeBytes -Path $DoCache)
        return
    }
    if (Get-Command Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue) {
        Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue
        Write-HostTimestamp '  Cleared Delivery Optimization cache.'
    }
    else {
        Write-HostTimestamp '  Delete-DeliveryOptimizationCache not available. Skipping.' -ForegroundColor Yellow
    }
}

# Clear Windows Error Reporting archives (system-wide and per-user)
Invoke-Task -Description 'Clearing Windows Error Reporting archives...' -ScriptBlock {
    $WerPaths = @(
        "$env:ProgramData\Microsoft\Windows\WER\ReportArchive",
        "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
    )
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $WerPaths += Join-Path $_.FullName 'AppData\Local\Microsoft\Windows\WER\ReportArchive'
        $WerPaths += Join-Path $_.FullName 'AppData\Local\Microsoft\Windows\WER\ReportQueue'
    }
    foreach ($WerPath in $WerPaths) {
        Clear-FolderContents -Path $WerPath -Label $null
    }
    Write-HostTimestamp '  Cleared Windows Error Reporting archives.'
}

# Clear crash dump files
Invoke-Task -Description 'Clearing crash dump files...' -ScriptBlock {
    Clear-FolderContents -Path (Join-Path -Path $env:windir -ChildPath 'Minidump') -Label 'Minidump folder'
    $FullDump = Join-Path -Path $env:windir -ChildPath 'MEMORY.DMP'
    if (Test-Path $FullDump) {
        if ($script:AuditMode) {
            Add-AuditFinding -Label 'MEMORY.DMP' -Bytes (Get-PathSizeBytes -Path $FullDump)
        }
        else {
            Remove-Item -Path $FullDump -Force -ErrorAction SilentlyContinue
            Write-HostTimestamp '  Removed MEMORY.DMP'
        }
    }
    # Per-user crash dumps
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        Clear-FolderContents -Path (Join-Path $_.FullName 'AppData\Local\CrashDumps') -Label $null
    }
}

# Clear thumbnail and icon caches (Explorer regenerates these on demand)
Invoke-Task -Description 'Clearing thumbnail and icon caches...' -ScriptBlock {
    $CacheBytes = 0
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $ExplorerCache = Join-Path $_.FullName 'AppData\Local\Microsoft\Windows\Explorer'
        if (Test-Path $ExplorerCache) {
            $CacheFiles = Get-ChildItem -Path $ExplorerCache -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like 'thumbcache_*.db' -or $_.Name -like 'iconcache_*.db' }
            if ($script:AuditMode) {
                $CacheBytes += (($CacheFiles | Measure-Object -Property Length -Sum).Sum)
            }
            else {
                $CacheFiles | Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }
    }
    if ($script:AuditMode) {
        Add-AuditFinding -Label 'thumbnail and icon caches' -Bytes ([long]$CacheBytes)
    }
    else {
        Write-HostTimestamp '  Cleared thumbnail and icon caches.'
    }
}

# Empty the Recycle Bin (unless the user opted out)
if (-not $SkipRecycleBin) {
    Invoke-Task -Description 'Emptying the Recycle Bin...' -ScriptBlock {
        if ($script:AuditMode) {
            # Sum the size of every $Recycle.Bin folder across all fixed drives.
            $BinBytes = 0
            foreach ($Vol in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
                $BinPath = Join-Path -Path $Vol.Root -ChildPath '$Recycle.Bin'
                $BinBytes += Get-PathSizeBytes -Path $BinPath
            }
            Add-AuditFinding -Label 'Recycle Bin' -Bytes ([long]$BinBytes)
            return
        }
        try {
            Clear-RecycleBin -Force -ErrorAction Stop
            Write-HostTimestamp '  Recycle Bin emptied.'
        }
        catch {
            # Clear-RecycleBin throws when the bin is already empty; treat that as success.
            if ($_.Exception.Message -match 'empty') {
                Write-HostTimestamp '  Recycle Bin was already empty.'
            }
            else {
                Write-HostTimestamp "  Could not empty the Recycle Bin: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
}

# =====================================================================================================
# LEVEL 2 (MEDIUM) - adds Disk Cleanup and log/cache pruning
# =====================================================================================================
if ($CleanupLevel -ge 2) {

    # Run the built-in Windows Disk Cleanup for all categories except the Downloads folder
    Invoke-Task -Description 'Configuring and running Disk Cleanup for all categories (excludes Downloads)...' -ScriptBlock {
        if ($script:AuditMode) {
            Write-HostTimestamp '  [AUDIT] Would run Disk Cleanup (cleanmgr) for all categories except Downloads; reclaimable amount cannot be estimated in advance.' -ForegroundColor DarkGray
            return
        }
        $RegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
        Get-ChildItem -Path $RegPath -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.PSChildName -ne 'DownloadsFolder') {
                Set-ItemProperty -Path $_.PSPath -Name 'StateFlags0333' -Value 2 -ErrorAction SilentlyContinue
            }
        }
        Start-Process -FilePath 'cleanmgr.exe' -ArgumentList '/sagerun:333' -WindowStyle Hidden
        # cleanmgr commonly gets stuck; wait until neither cleanmgr nor dismhost is doing any work, then stop it.
        do {
            $CleanmgrTime = (Get-Process -Name cleanmgr -ErrorAction SilentlyContinue).TotalProcessorTime
            $DismHostTime = (Get-Process -Name dismhost -ErrorAction SilentlyContinue).TotalProcessorTime
            if ($CleanmgrTime -or $DismHostTime) {
                Start-Sleep -Seconds 30
            }
        } until (($CleanmgrTime -eq (Get-Process -Name cleanmgr -ErrorAction SilentlyContinue).TotalProcessorTime) -and ($DismHostTime -eq (Get-Process -Name dismhost -ErrorAction SilentlyContinue).TotalProcessorTime))
        Stop-Process -Name cleanmgr -Force -ErrorAction SilentlyContinue
        Write-HostTimestamp '  Disk Cleanup finished.'
    }

    # Clear CBS/DISM log files (can grow large after SFC/DISM runs)
    Invoke-Task -Description 'Clearing CBS and DISM log files...' -ScriptBlock {
        Clear-FolderContents -Path (Join-Path -Path $env:windir -ChildPath 'Logs\CBS') -Label 'CBS/DISM logs'
        Clear-FolderContents -Path (Join-Path -Path $env:windir -ChildPath 'Logs\DISM') -Label $null
    }

    # Clear Windows setup (Panther) logs left by in-place upgrades
    Invoke-Task -Description 'Clearing Windows setup (Panther) logs...' -ScriptBlock {
        Clear-FolderContents -Path (Join-Path -Path $env:windir -ChildPath 'Panther') -Label 'Panther setup logs'
    }

    # Clear the Prefetch cache (Windows rebuilds it automatically)
    Invoke-Task -Description 'Clearing the Prefetch cache...' -ScriptBlock {
        Clear-FolderContents -Path (Join-Path -Path $env:windir -ChildPath 'Prefetch') -Label 'Prefetch cache'
    }

    # Clear the font cache (rebuilt automatically by the Windows Font Cache Service)
    Invoke-Task -Description 'Clearing the font cache...' -ScriptBlock {
        $FontCachePath = Join-Path -Path $env:windir -ChildPath 'ServiceProfiles\LocalService\AppData\Local\FontCache'
        if ($script:AuditMode) {
            # Do not touch the service in audit mode; just report the cache size.
            Clear-FolderContents -Path $FontCachePath -Label 'font cache'
            return
        }
        $FontCacheSvc = 'FontCache'
        $WasRunning = $false
        $Svc = Get-Service -Name $FontCacheSvc -ErrorAction SilentlyContinue
        if ($Svc -and $Svc.Status -eq 'Running') {
            $WasRunning = $true
            Stop-Service -Name $FontCacheSvc -Force -ErrorAction SilentlyContinue
        }
        Clear-FolderContents -Path $FontCachePath -Label 'font cache'
        if ($WasRunning) {
            Start-Service -Name $FontCacheSvc -ErrorAction SilentlyContinue
        }
    }

    # Clear the Configuration Manager (SCCM) client cache, if present. Preferred approach is the
    # CCM UIResourceMgr COM API, which lets the cache manager purge each item cleanly; if that is
    # unavailable, fall back to clearing the ccmcache folder directly.
    $CcmCachePath = Join-Path -Path $env:windir -ChildPath 'ccmcache'
    if (Test-Path $CcmCachePath) {
        Invoke-Task -Description 'Clearing the Configuration Manager (SCCM) client cache (ccmcache)...' -ScriptBlock {
            if ($script:AuditMode) {
                # Do not invoke the CCM client in audit mode; just report the on-disk cache size.
                Clear-FolderContents -Path $CcmCachePath -Label 'Configuration Manager cache (ccmcache)'
                return
            }
            try {
                $ResourceMgr = New-Object -ComObject 'UIResource.UIResourceMgr' -ErrorAction Stop
                $CacheInfo = $ResourceMgr.GetCacheInfo()
                $CacheElements = $CacheInfo.GetCacheElements()
                $Count = 0
                foreach ($Element in $CacheElements) {
                    $CacheInfo.DeleteCacheElement($Element.CacheElementID)
                    $Count++
                }
                Write-HostTimestamp "  Purged $Count Configuration Manager cache element(s) via the CCM client."
            }
            catch {
                Write-HostTimestamp "  CCM client COM API unavailable ($($_.Exception.Message)). Clearing the ccmcache folder directly..." -ForegroundColor Yellow
            }
            # Clear any remaining contents directly, in case the COM API is unavailable or left orphaned files behind.
            Clear-FolderContents -Path $CcmCachePath -Label 'Configuration Manager cache (ccmcache)'
        }
    }
}

# =====================================================================================================
# LEVEL 3 (SEVERE) - adds component-store cleanup and upgrade-folder removal
# =====================================================================================================
if ($CleanupLevel -ge 3) {

    # Clean up the component store (WinSxS) with DISM. /ResetBase makes existing updates permanent
    # (they can no longer be uninstalled) but reclaims the most space.
    Invoke-Task -Description 'Cleaning up the component store (WinSxS) with DISM (this can take a while)...' -ScriptBlock {
        if ($script:AuditMode) {
            # Read-only analysis of the component store reports the reclaimable size without changing anything.
            Write-HostTimestamp '  [AUDIT] Analyzing the component store (DISM /AnalyzeComponentStore)...' -ForegroundColor DarkGray
            $Analysis = DISM.exe /Online /Cleanup-Image /AnalyzeComponentStore 2>&1
            $Analysis | Where-Object { $_ -match 'Reclaimable|Component Store|recommended' } | ForEach-Object {
                Write-Host "    $($_.ToString().Trim())"
            }
            return
        }
        try {
            DISM.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase
            if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3010) {
                Write-HostTimestamp "DISM returned exit code $LASTEXITCODE." -ForegroundColor Yellow
            }
        }
        catch {
            Write-HostTimestamp "DISM error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Remove leftover Windows upgrade folders (can reclaim 10-30 GB after an in-place upgrade)
    Invoke-Task -Description 'Removing leftover Windows upgrade folders...' -ScriptBlock {
        $Drive = $env:SystemDrive
        $UpgradePaths = @(
            "$Drive\Windows.old",
            "$Drive\`$Windows.~BT",
            "$Drive\`$Windows.~WS",
            "$Drive\`$WinREAgent",
            "$Drive\`$GetCurrent"
        )
        foreach ($UpgradePath in $UpgradePaths) {
            if (Test-Path $UpgradePath) {
                if ($script:AuditMode) {
                    Add-AuditFinding -Label $UpgradePath -Bytes (Get-PathSizeBytes -Path $UpgradePath)
                    continue
                }
                Write-HostTimestamp "  Removing $UpgradePath..."
                takeown.exe /F $UpgradePath /R /A /D Y 2>&1 | Out-Null
                icacls.exe $UpgradePath /grant Administrators:F /T /C /Q 2>&1 | Out-Null
                Remove-Item -Path $UpgradePath -Recurse -Force -ErrorAction SilentlyContinue
            }
            else {
                Write-HostTimestamp "  $UpgradePath not found. Skipping."
            }
        }
    }
}

# =====================================================================================================
# LEVEL 4 (AGGRESSIVE) - last-resort reclamation on a nearly-full disk
# =====================================================================================================
if ($CleanupLevel -ge 4) {

    Write-HostTimestamp 'AGGRESSIVE level: the following actions remove restore points, the hibernation file, and event logs.' -ForegroundColor Red
    Write-Host $LineBreak

    # Prune old System Restore points, keeping only the most recent (frees the volume shadow copy storage)
    Invoke-Task -Description 'Pruning old System Restore points (keeping the most recent)...' -ScriptBlock {
        try {
            $Shadows = @(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop | Sort-Object -Property InstallDate -Descending)
            if ($Shadows.Count -le 1) {
                Write-HostTimestamp '  No old restore points to prune.'
            }
            elseif ($script:AuditMode) {
                Write-HostTimestamp "  [AUDIT] Would prune $($Shadows.Count - 1) old restore point/shadow copy(ies), keeping the most recent (size not directly measurable)." -ForegroundColor DarkGray
            }
            else {
                $ToRemove = $Shadows | Select-Object -Skip 1
                foreach ($Shadow in $ToRemove) {
                    Remove-CimInstance -InputObject $Shadow -ErrorAction SilentlyContinue
                }
                Write-HostTimestamp "  Removed $($ToRemove.Count) old restore point/shadow copy(ies), kept the most recent."
            }
        }
        catch {
            Write-HostTimestamp "  Could not prune restore points: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # Remove the hibernation file (hiberfil.sys). This also disables Fast Startup.
    Invoke-Task -Description 'Disabling hibernation to remove hiberfil.sys (also disables Fast Startup)...' -ScriptBlock {
        if ($script:AuditMode) {
            $HiberFile = Join-Path -Path $env:SystemDrive -ChildPath 'hiberfil.sys'
            Add-AuditFinding -Label 'hiberfil.sys (would disable hibernation/Fast Startup)' -Bytes (Get-PathSizeBytes -Path $HiberFile)
            return
        }
        if (Get-Command powercfg.exe -ErrorAction SilentlyContinue) {
            powercfg.exe /hibernate off 2>&1 | Out-Null
            $script:RebootRecommended = $true
            Write-HostTimestamp '  Hibernation disabled and hiberfil.sys removed. Re-enable later with: powercfg /hibernate on' -ForegroundColor Yellow
        }
        else {
            Write-HostTimestamp '  powercfg.exe not found. Skipping hibernation removal.' -ForegroundColor Yellow
        }
    }

    # Clear all Windows event logs
    Invoke-Task -Description 'Clearing all Windows event logs...' -ScriptBlock {
        if ($script:AuditMode) {
            $LogBytes = 0
            try {
                $LogBytes = (Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Measure-Object -Property FileSize -Sum).Sum
            }
            catch { $LogBytes = 0 }
            if (-not $LogBytes) { $LogBytes = 0 }
            Add-AuditFinding -Label 'Windows event logs' -Bytes ([long]$LogBytes)
            return
        }
        if (Get-Command wevtutil.exe -ErrorAction SilentlyContinue) {
            $Cleared = 0
            wevtutil.exe el | ForEach-Object {
                wevtutil.exe cl "$_" 2>$null
                if ($LASTEXITCODE -eq 0) { $Cleared++ }
            }
            Write-HostTimestamp "  Cleared $Cleared event log(s)."
        }
        else {
            Write-HostTimestamp '  wevtutil.exe not found. Skipping event log cleanup.' -ForegroundColor Yellow
        }
    }
}

# =====================================================================================================
# EXPERIMENTAL - opt-in cleanups that run regardless of the selected level
# =====================================================================================================

# Remove orphaned .msi/.msp packages from C:\Windows\Installer.
# Every installed product/patch keeps a cached copy of its installer package here so it can be repaired
# or uninstalled later. Over time, cached packages for products/patches that no longer exist become
# orphaned and just waste space. We ask the Windows Installer for every package that IS still referenced
# and delete only the .msi/.msp files that are NOT in that set. This is EXPERIMENTAL: if the referenced-
# package list is incomplete, deleting a still-needed package can break future repair/uninstall.
if ($CleanupOrphanedInstaller) {
    Invoke-Task -Description 'EXPERIMENTAL: Removing orphaned .msi/.msp packages from C:\Windows\Installer...' -ScriptBlock {
        $InstallerDir = Join-Path -Path $env:windir -ChildPath 'Installer'
        if (-not (Test-Path $InstallerDir)) {
            Write-HostTimestamp '  C:\Windows\Installer not found. Skipping.' -ForegroundColor Yellow
            return
        }

        # Build the set of packages that are still referenced by an installed product or applied patch.
        $UsedPackages = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $EnumSucceeded = $false
        try {
            $MsiInstaller = New-Object -ComObject WindowsInstaller.Installer -ErrorAction Stop
            # msiInstallContextAll = 7, msiPatchStateApplied = 1
            foreach ($Product in $MsiInstaller.ProductsEx('', '', 7)) {
                try {
                    $LocalPackage = $Product.InstallProperty('LocalPackage')
                    if ($LocalPackage) { [void]$UsedPackages.Add($LocalPackage) }
                }
                catch { }
                try {
                    foreach ($Patch in $MsiInstaller.PatchesEx($Product.ProductCode, '', 7, 1)) {
                        try {
                            $PatchPackage = $Patch.PatchProperty('LocalPackage')
                            if ($PatchPackage) { [void]$UsedPackages.Add($PatchPackage) }
                        }
                        catch { }
                    }
                }
                catch { }
            }
            $EnumSucceeded = $true
        }
        catch {
            Write-HostTimestamp "  Could not query the Windows Installer database ($($_.Exception.Message)). Skipping for safety." -ForegroundColor Yellow
        }

        # Only delete when we successfully enumerated the referenced packages; an empty/failed enumeration
        # must not be treated as "everything is orphaned".
        if (-not $EnumSucceeded -or $UsedPackages.Count -eq 0) {
            Write-HostTimestamp '  No referenced packages could be confirmed. Skipping deletion to avoid breaking installed software.' -ForegroundColor Yellow
            return
        }

        Write-HostTimestamp "  $($UsedPackages.Count) installer package(s) are still referenced and will be kept."
        $Orphans = Get-ChildItem -Path $InstallerDir -File -Force -ErrorAction SilentlyContinue |
            Where-Object { ($_.Extension -eq '.msi' -or $_.Extension -eq '.msp') -and -not $UsedPackages.Contains($_.FullName) }

        if (-not $Orphans) {
            Write-HostTimestamp '  No orphaned .msi/.msp packages found.'
            return
        }

        $OrphanSizeMB = [math]::Round((($Orphans | Measure-Object -Property Length -Sum).Sum) / 1MB, 2)
        if ($script:AuditMode) {
            $OrphanBytes = ($Orphans | Measure-Object -Property Length -Sum).Sum
            Write-HostTimestamp "  Found $($Orphans.Count) orphaned package(s)." -ForegroundColor Yellow
            Add-AuditFinding -Label 'orphaned .msi/.msp packages in C:\Windows\Installer' -Bytes ([long]$OrphanBytes)
            return
        }
        Write-HostTimestamp "  Found $($Orphans.Count) orphaned package(s) totaling $OrphanSizeMB MB. Removing..." -ForegroundColor Yellow
        $Removed = 0
        foreach ($Orphan in $Orphans) {
            try {
                Remove-Item -Path $Orphan.FullName -Force -ErrorAction Stop
                $Removed++
            }
            catch {
                Write-HostTimestamp "  Could not remove $($Orphan.Name): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        Write-HostTimestamp "  Removed $Removed orphaned installer package(s)."
    }
}

# Delete stale local user profiles that show no recent file activity.
# Uses Win32_UserProfile so the profile folder AND its registry references are removed cleanly.
# The recent-file-activity check (Test-ProfileRecentlyActive) is the DEFINITIVE signal for whether a
# profile is in use: Win32_UserProfile.LastUseTime is treated as informational only, because it can be
# bumped by background/system activity and make an abandoned profile look recently used.
# EXPERIMENTAL: removing a profile permanently deletes that user's local data (desktop, documents,
# app data). Special/system profiles, currently-loaded profiles, and the running user are always skipped.
if ($CleanupOldProfiles) {
    Invoke-Task -Description "EXPERIMENTAL: Removing local profiles with no file activity in the last $ProfileAgeDays day(s)..." -ScriptBlock {
        $Cutoff = (Get-Date).AddDays(-$ProfileAgeDays)
        $CurrentSid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value

        try {
            $Profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop
        }
        catch {
            Write-HostTimestamp "  Could not enumerate user profiles ($($_.Exception.Message)). Skipping." -ForegroundColor Yellow
            return
        }

        # Only run when there are more than -MinCachedProfiles cached local profiles under C:\Users.
        $LocalProfiles = @($Profiles | Where-Object {
            -not $_.Special -and $_.LocalPath -like "$env:SystemDrive\Users\*"
        })
        if ($LocalProfiles.Count -le $MinCachedProfiles) {
            Write-HostTimestamp "  Only $($LocalProfiles.Count) cached local profile(s) in $env:SystemDrive\Users (cleanup requires more than $MinCachedProfiles). Skipping." -ForegroundColor Yellow
            return
        }
        Write-HostTimestamp "  $($LocalProfiles.Count) cached local profile(s) found (threshold is more than $MinCachedProfiles). Evaluating file activity..."

        # Consider every local profile except those currently loaded or belonging to the running user.
        $Candidates = @($LocalProfiles | Where-Object {
            -not $_.Loaded -and $_.SID -ne $CurrentSid
        })

        if (-not $Candidates) {
            Write-HostTimestamp '  No eligible local profiles to evaluate.'
            return
        }

        foreach ($UserProfile in $Candidates) {
            $LastUse = if ($UserProfile.LastUseTime) { $UserProfile.LastUseTime.ToString('yyyy-MM-dd') } else { 'unknown' }
            # Definitive check: recent file modifications inside the user folder mean the profile is really
            # in use, so it is kept even if LastUseTime looks old. Conversely, the absence of recent file
            # activity is proof the profile is abandoned, so it is removed even if LastUseTime looks recent.
            if (Test-ProfileRecentlyActive -ProfilePath $UserProfile.LocalPath -Cutoff $Cutoff) {
                Write-HostTimestamp "  Keeping '$($UserProfile.LocalPath)' (LastUseTime $LastUse): recently modified files found, profile is active." -ForegroundColor Cyan
                continue
            }
            if ($script:AuditMode) {
                Write-HostTimestamp "  Would remove profile '$($UserProfile.LocalPath)' (LastUseTime $LastUse): no file activity in the last $ProfileAgeDays day(s)." -ForegroundColor Yellow
                Add-AuditFinding -Label "profile $($UserProfile.LocalPath)" -Bytes (Get-PathSizeBytes -Path $UserProfile.LocalPath)
                continue
            }
            Write-HostTimestamp "  Removing profile '$($UserProfile.LocalPath)' (LastUseTime $LastUse): no file activity in the last $ProfileAgeDays day(s)..." -ForegroundColor Yellow
            try {
                Remove-CimInstance -InputObject $UserProfile -ErrorAction Stop
                Write-HostTimestamp "    Removed."
            }
            catch {
                Write-HostTimestamp "    Could not remove '$($UserProfile.LocalPath)': $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
}

# =====================================================================================================
# Summary
# =====================================================================================================
if ($script:AuditMode) {
    $TotalGB = [math]::Round($script:AuditTotalBytes / 1GB, 2)
    $TotalMB = [math]::Round($script:AuditTotalBytes / 1MB, 2)
    Write-HostTimestamp "AUDIT COMPLETE: no files were deleted and no changes were made." -ForegroundColor Cyan
    Write-HostTimestamp "Estimated space that could be freed at the $(Get-CleanupLevelName -Level $CleanupLevel) level: ~$TotalMB MB (~$TotalGB GB)." -ForegroundColor Green
    Write-HostTimestamp 'Note: some steps (Disk Cleanup, DISM component cleanup, restore points) cannot be estimated exactly and are not included in this total.' -ForegroundColor DarkGray
    Write-Host $LineBreak
    Write-HostTimestamp 'Windows Clean-Up audit finished!' -ForegroundColor Green
    if (-not $Unattended -and -not $Remediate -and -not $ForceLevel) {
        Read-Host -Prompt 'Close window or press enter to exit.'
    }
    Stop-Transcript
    exit 0
}

$script:FreeSpaceAfter = Get-SystemDriveFreeGB
if ($null -ne $script:FreeSpaceBefore -and $null -ne $script:FreeSpaceAfter) {
    $Reclaimed = [math]::Round($script:FreeSpaceAfter - $script:FreeSpaceBefore, 2)
    $ReclaimColor = if ($Reclaimed -gt 0) { 'Green' } else { 'Yellow' }
    Write-HostTimestamp "Free space on $env:SystemDrive : $($script:FreeSpaceBefore) GB before -> $($script:FreeSpaceAfter) GB after." -ForegroundColor Cyan
    Write-HostTimestamp "Reclaimed approximately $Reclaimed GB." -ForegroundColor $ReclaimColor
}
elseif ($null -ne $script:FreeSpaceAfter) {
    Write-HostTimestamp "Free space on $env:SystemDrive after cleanup: $($script:FreeSpaceAfter) GB" -ForegroundColor Cyan
}
Write-Host $LineBreak

# Done. Decide whether a restart is genuinely warranted before offering / performing one.
Write-HostTimestamp 'Windows Clean-Up completed!' -ForegroundColor Green

# A restart is worthwhile if a step made a change that needs one (e.g. hibernation), or if Windows
# itself now reports a pending reboot / queued file-rename operations.
$RebootRecommended = $script:RebootRecommended
if (-not $RebootRecommended) {
    $PendingRebootKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    foreach ($Key in $PendingRebootKeys) {
        if (Test-Path $Key) { $RebootRecommended = $true; break }
    }
    if (-not $RebootRecommended) {
        try {
            $SessionMgr = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
            $Pending = (Get-ItemProperty -Path $SessionMgr -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue).PendingFileRenameOperations
            if ($Pending) { $RebootRecommended = $true }
        }
        catch { }
    }
}

if ($RebootRecommended) {
    Write-HostTimestamp 'A restart is recommended to finish applying these changes.' -ForegroundColor Yellow
}
else {
    Write-HostTimestamp 'No restart is required for this cleanup.' -ForegroundColor Green
}

if ($AutoReboot -and -not $RebootRecommended) {
    # Do not reboot a machine that does not need it just because -AutoReboot was passed.
    Write-HostTimestamp '-AutoReboot was requested, but nothing here requires a restart - skipping the reboot.' -ForegroundColor Cyan
}
elseif ($AutoReboot) {
    # An interactive user (not an unattended/automated run) can abort the pending reboot with a keypress.
    $CanCancel = $false
    try { $CanCancel = ([Environment]::UserInteractive -and -not $Unattended) } catch { $CanCancel = $false }
    if ($CanCancel) {
        Write-HostTimestamp 'Auto-restart scheduled. Press any key to CANCEL...' -ForegroundColor Yellow
    }
    else {
        Write-HostTimestamp 'Auto-restart scheduled.' -ForegroundColor Yellow
    }

    $Cancelled = $false
    foreach ($Remaining in 60..1) {
        if ($Remaining % 10 -eq 0 -or $Remaining -le 5) {
            Write-HostTimestamp "Restarting in $Remaining $(if ($Remaining -eq 1) { 'second' } else { 'seconds' })..." -ForegroundColor Yellow
        }
        if ($CanCancel) {
            try {
                if ([System.Console]::KeyAvailable) {
                    [void][System.Console]::ReadKey($true)
                    $Cancelled = $true
                    break
                }
            }
            catch { $CanCancel = $false }
        }
        Start-Sleep -Seconds 1
    }

    if ($Cancelled) {
        Write-HostTimestamp 'Auto-restart cancelled. Please remember to restart your computer manually.' -ForegroundColor Cyan
    }
    else {
        Write-HostTimestamp 'Restarting now...' -ForegroundColor Yellow
        shutdown.exe /r /t 0 /c 'Restarting to finish Windows Clean-Up...'
    }
}
elseif (-not $Unattended -and -not $Remediate -and -not $ForceLevel) {
    Read-Host -Prompt 'Close window or press enter to exit.'
}

# Stop logging
Stop-Transcript
# --- End Logging ---
