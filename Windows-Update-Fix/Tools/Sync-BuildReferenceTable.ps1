# =====================================================================================
# Sync-BuildReferenceTable.ps1
# -------------------------------------------------------------------------------------
# Runs Update-BuildReferenceTable.ps1 -AllReleases -MaxAgeYears 2 and automatically
# patches the $script:KnownBuildReleases block inside Windows-Update-Fix.ps1 with the
# result, giving every month's build and KB article for the past 2 years.
#
# Can also register (or remove) a monthly Windows Scheduled Task so the patch happens
# automatically after every Patch Tuesday.
#
# USAGE:
#   .\Sync-BuildReferenceTable.ps1                    # scrape & patch now
#   .\Sync-BuildReferenceTable.ps1 -Register          # register monthly scheduled task
#   .\Sync-BuildReferenceTable.ps1 -Register -DayOfMonth 14 -RunTime 10:00
#   .\Sync-BuildReferenceTable.ps1 -Unregister        # remove the scheduled task
# =====================================================================================
#Requires -Version 5
[CmdletBinding(DefaultParameterSetName = 'Sync', SupportsShouldProcess)]
param(
    # Register a monthly scheduled task that runs this script automatically.
    [Parameter(ParameterSetName = 'Register')]
    [switch]$Register,

    # Remove the scheduled task created by -Register.
    [Parameter(ParameterSetName = 'Unregister')]
    [switch]$Unregister,

    # Day of the month the scheduled task should run (default 13, one day after the
    # earliest possible Patch Tuesday so new data is already online).
    [Parameter(ParameterSetName = 'Register')]
    [ValidateRange(1, 28)]
    [int]$DayOfMonth = 13,

    # Time of day for the scheduled task in 24-hour HH:mm format (default 10:00).
    [Parameter(ParameterSetName = 'Register')]
    [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
    [string]$RunTime = '10:00',

    # Number of years of build history to include (default 2, passed to Update-BuildReferenceTable.ps1).
    [Parameter(ParameterSetName = 'Sync')]
    [ValidateRange(1, 10)]
    [double]$MaxAgeYears = 2,

    # Timeout in seconds for web requests, passed through to Update-BuildReferenceTable.ps1.
    [Parameter(ParameterSetName = 'Sync')]
    [int]$TimeoutSec = 30
)

$ErrorActionPreference = 'Stop'

$TaskName   = 'Windows-Fix-Up Monthly Build Sync'
$ToolsDir   = $PSScriptRoot
$MainScript = Join-Path (Split-Path $ToolsDir -Parent) 'Windows-Update-Fix.ps1'
$Updater    = Join-Path $ToolsDir 'Update-BuildReferenceTable.ps1'

# ---- -Unregister ----------------------------------------------------------------
if ($Unregister) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister scheduled task')) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-Host "Scheduled task '$TaskName' removed." -ForegroundColor Green
        }
    }
    else {
        Write-Host "Scheduled task '$TaskName' not found - nothing to remove." -ForegroundColor Yellow
    }
    return
}

# ---- -Register ------------------------------------------------------------------
if ($Register) {
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $IsAdmin) {
        Write-Error 'Registering a scheduled task requires an elevated (Administrator) session.'
        exit 1
    }

    $ThisScript = $PSCommandPath
    $Action  = New-ScheduledTaskAction `
        -Execute 'powershell.exe' `
        -Argument "-NonInteractive -ExecutionPolicy Bypass -File `"$ThisScript`""

    $Trigger = New-ScheduledTaskTrigger -Monthly -DaysOfMonth $DayOfMonth -At $RunTime

    $Settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable

    $Principal = New-ScheduledTaskPrincipal `
        -UserId 'SYSTEM' `
        -LogonType ServiceAccount `
        -RunLevel Highest

    if ($PSCmdlet.ShouldProcess($TaskName, 'Register scheduled task')) {
        Register-ScheduledTask `
            -TaskName  $TaskName `
            -Action    $Action `
            -Trigger   $Trigger `
            -Settings  $Settings `
            -Principal $Principal `
            -Force | Out-Null

        Write-Host "Scheduled task '$TaskName' registered." -ForegroundColor Green
        Write-Host "  Runs as : SYSTEM" -ForegroundColor Cyan
        Write-Host "  Schedule: day $DayOfMonth of every month at $RunTime" -ForegroundColor Cyan
        Write-Host "  Script  : $ThisScript" -ForegroundColor Cyan
        Write-Host ''
        Write-Host 'Each run fetches every non-preview build and KB for the past 2 years (-AllReleases -MaxAgeYears 2).' -ForegroundColor Cyan
    }
    return
}

# ---- Sync (default) -------------------------------------------------------------
foreach ($Required in $MainScript, $Updater) {
    if (-not (Test-Path $Required)) {
        Write-Error "Required file not found: $Required"
        exit 1
    }
}

Write-Host "Fetching every non-preview build and KB for the past $MaxAgeYears year(s) from Microsoft..." -ForegroundColor Cyan

# -AllReleases: emit every non-preview monthly build (not just the newest per version line).
# -MaxAgeYears: controls how far back to reach (default 2 years).
$NewBlock = & $Updater -AllReleases -MaxAgeYears $MaxAgeYears -TimeoutSec $TimeoutSec 2>&1

$NewBlock = $NewBlock | ForEach-Object {
    if ($_ -is [System.Management.Automation.ErrorRecord])   { Write-Error   $_; $null }
    elseif ($_ -is [System.Management.Automation.WarningRecord]) { Write-Warning $_; $null }
    else { $_ }
} | Where-Object { $_ -ne $null }

if (-not $NewBlock) {
    Write-Error 'Update-BuildReferenceTable.ps1 produced no output. Aborting patch.'
    exit 1
}

# Validate the output looks like the expected block.
$BlockLines = $NewBlock -split "`r?`n"
if (-not ($BlockLines[0] -match '^# Last verified') -or
    -not ($BlockLines[1] -match '^\$script:KnownBuildReleases\s*=\s*@\{')) {
    Write-Error 'Unexpected output format from Update-BuildReferenceTable.ps1. Aborting patch.'
    exit 1
}

# Read the main script and locate the block to replace: the "# Last verified..." comment
# line through the closing "}" of $script:KnownBuildReleases.
$Content  = Get-Content $MainScript
$StartIdx = -1
$EndIdx   = -1
$InBlock  = $false

for ($i = 0; $i -lt $Content.Count; $i++) {
    if ($Content[$i] -match '^# Last verified against Microsoft release information:') {
        $StartIdx = $i
    }
    if ($StartIdx -ge 0 -and $Content[$i] -match '^\$script:KnownBuildReleases\s*=\s*@\{') {
        $InBlock = $true
    }
    if ($InBlock -and $Content[$i] -match '^}') {
        $EndIdx = $i
        break
    }
}

if ($StartIdx -lt 0 -or $EndIdx -lt 0) {
    Write-Error 'Could not locate the $script:KnownBuildReleases block in Windows-Update-Fix.ps1. Aborting.'
    exit 1
}

$Before  = if ($StartIdx -gt 0) { $Content[0..($StartIdx - 1)] } else { @() }
$After   = if ($EndIdx -lt ($Content.Count - 1)) { $Content[($EndIdx + 1)..($Content.Count - 1)] } else { @() }
$Updated = ($Before + $BlockLines + $After) -join [Environment]::NewLine

if ($PSCmdlet.ShouldProcess($MainScript, 'Patch $script:KnownBuildReleases block')) {
    [System.IO.File]::WriteAllText($MainScript, $Updated, [System.Text.Encoding]::UTF8)
    $EntryCount = ($BlockLines | Where-Object { $_ -match "^\s+'[\d.]+" }).Count
    Write-Host "Patched $MainScript" -ForegroundColor Green
    Write-Host "  Replaced lines $($StartIdx + 1)-$($EndIdx + 1) with $($BlockLines.Count) lines ($EntryCount build entries)." -ForegroundColor Cyan
}
