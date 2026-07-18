# --- SCRIPT OVERVIEW ---
# This script performs an in-place upgrade ("repair install") of Windows to fix a broken Windows Update
# experience and other servicing/component-store corruption that the lighter repair tools cannot resolve.
# An in-place upgrade re-lays the entire operating system while keeping your apps, settings, and files,
# and it rebuilds the servicing stack from scratch - which is the single most effective fix for updates
# that will not install (0x800f081f, 0x80073712, 0x800f0988, stuck at a percentage, etc.).
#
# It performs the following actions:
#   1. Detects the installed Windows version, edition, architecture, and UI language.
#   2. Automatically obtains the matching official Microsoft ISO download link (via the community "Fido"
#      helper, which queries Microsoft's own software-download servers) and downloads the ISO - unless you
#      supply your own with -IsoPath.
#   3. Mounts the ISO and launches Windows Setup in in-place-upgrade mode, keeping apps and data by
#      default (/auto upgrade), with the Setup GUI hidden (/quiet) and Dynamic Update disabled by default.
#   4. Dismounts the ISO when done.
#
# The ISO download is large (~5-6 GB) and the upgrade needs roughly 20 GB of free space to stage, so the
# script checks disk space up front. Setup itself takes 20-90 minutes and will restart the machine several
# times; by default it prompts before it begins. For hands-off use pass -Unattended (and optionally
# -NoReboot to hold the final restart).
# -------------------------------------------------
# How to Run .PS1 Script with PowerShell:
# NOTE: It is recommended to use the "Run-Windows-InPlace-Upgrade.bat" to invoke this script. However, you can run the .PS1 directly if needed.
# 1.  Open PowerShell as an Administrator: Right-click your Start Menu and select "Terminal (Admin)".
# 2.  Enable Script Execution (if needed): Set-ExecutionPolicy Bypass -Force
# 3.  Run the Script: Right-click the saved "Windows-InPlace-Upgrade.ps1" file and select "Run with PowerShell".
# -------------------------------------------------
# Parameters for the script
param(
    [Parameter(HelpMessage = 'Runs the script without any confirmation prompts')]
    [switch]$Unattended,

    [Parameter(HelpMessage = 'Path to an existing Windows ISO to use instead of downloading one from Microsoft')]
    [string]$IsoPath,

    [Parameter(HelpMessage = 'Windows version to download/upgrade to: 10 or 11. Defaults to 11')]
    [ValidateSet('10', '11')]
    [string]$WindowsVersion = '11',

    [Parameter(HelpMessage = 'Fido release to request (e.g. 24H2, 23H2) or "Latest". Defaults to Latest')]
    [string]$Release = 'Latest',

    [Parameter(HelpMessage = 'ISO language as named by Microsoft/Fido (e.g. English, "English International"). Defaults to English')]
    [string]$Language = 'English',

    [Parameter(HelpMessage = 'What Setup keeps: KeepAll (apps + data, default) or KeepNothing (clean install)')]
    [ValidateSet('KeepAll', 'KeepNothing')]
    [string]$KeepMode = 'KeepAll',

    [Parameter(HelpMessage = 'Directory to download the ISO into (defaults to the script folder). Needs ~6 GB free')]
    [string]$DownloadPath,

    [Parameter(HelpMessage = 'Only obtain/download the ISO; do not launch the in-place upgrade')]
    [switch]$DownloadOnly,

    [Parameter(HelpMessage = 'Do not let Setup restart the machine automatically at the end (/noreboot)')]
    [switch]$NoReboot,

    [Parameter(HelpMessage = 'Enable Dynamic Update so Setup pulls the latest fixes online before upgrading (disabled by default)')]
    [switch]$DynamicUpdate,

    [Parameter(HelpMessage = 'Show the Windows Setup GUI. By default Setup runs with its GUI hidden (/quiet)')]
    [switch]$ShowUI,

    [Parameter(HelpMessage = 'Bypass the Windows 11 hardware compatibility checks (TPM/CPU/RAM) on incompatible machines using Setup''s /product server switch')]
    [switch]$BypassCompatChecks,

    [Parameter(HelpMessage = 'Override the URL used to fetch the Fido download helper')]
    [string]$FidoUrl = 'https://github.com/pbatard/Fido/raw/master/Fido.ps1',

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
        # Re-add any passed parameters
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
$Host.UI.RawUI.WindowTitle = "Windows In-Place Upgrade - Running as Administrator"

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
$LogFile = Join-Path -Path $LogDir -ChildPath "Windows-InPlace-Upgrade_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Start-Transcript -Path $LogFile | Out-Null

# Rotate logs: keep only the 30 most recent, delete the rest
Get-ChildItem -Path $LogDir -Filter 'Windows-InPlace-Upgrade_*.log' -File |
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

# Detects the currently-installed Windows version/edition/architecture and returns them as a
# PSCustomObject so both the upgrade preflight display and the Fido download request can reuse it.
function Get-InstalledWindowsInfo {
    $Reg = $null
    try { $Reg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop } catch { }
    $Os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

    $Build = if ($Reg -and $Reg.CurrentBuildNumber) { [int]$Reg.CurrentBuildNumber } else { [int]$Os.BuildNumber }
    $IsWin11 = ($Build -ge 22000)
    $ProductName = if ($Reg) { $Reg.ProductName } else { $Os.Caption }
    if ($IsWin11 -and $ProductName -like 'Windows 10*') {
        $ProductName = $ProductName -replace '^Windows 10', 'Windows 11'
    }

    # Map the processor architecture to the value Fido/Setup expects.
    $Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'x64' }
        'ARM64' { 'arm64' }
        'x86'   { 'x86' }
        default { 'x64' }
    }

    [PSCustomObject]@{
        Build          = $Build
        Version        = if ($IsWin11) { '11' } else { '10' }
        ProductName    = $ProductName
        EditionId      = if ($Reg) { $Reg.EditionID } else { $null }
        DisplayVersion = if ($Reg -and $Reg.DisplayVersion) { $Reg.DisplayVersion } elseif ($Reg) { $Reg.ReleaseId } else { $null }
        Ubr            = if ($Reg) { $Reg.UBR } else { $null }
        Architecture   = $Arch
    }
}

# Downloads a file with BITS when available (resumable, shows progress) and falls back to
# Invoke-WebRequest. Returns $true on success. Never throws.
function Get-FileDownload {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination
    )

    # Prefer BITS: it is resumable and far more reliable for multi-GB downloads.
    if (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue) {
        try {
            Write-HostTimestamp '  Downloading with BITS (this can take a while for a multi-GB ISO)...'
            Start-BitsTransfer -Source $Url -Destination $Destination -Description 'Windows ISO' -ErrorAction Stop
            if (Test-Path -LiteralPath $Destination) { return $true }
        }
        catch {
            Write-HostTimestamp "  BITS transfer failed ($($_.Exception.Message)). Falling back to a direct download..." -ForegroundColor Yellow
            Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
        }
    }

    # Fallback: Invoke-WebRequest. Slower and not resumable, but dependency-free.
    try {
        Write-HostTimestamp '  Downloading with Invoke-WebRequest...'
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -ErrorAction Stop
        if (Test-Path -LiteralPath $Destination) { return $true }
    }
    catch {
        Write-HostTimestamp "  Download failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    return $false
}

# Verifies a download URL points at an official Microsoft host over HTTPS, so the script never downloads
# a Windows "ISO" from somewhere it should not. Microsoft serves the ISOs from hosts under microsoft.com
# (e.g. software.download.prss.microsoft.com, software-download.microsoft.com). Returns $true only for an
# https:// URL whose host is microsoft.com or a *.microsoft.com subdomain.
function Test-MicrosoftDownloadUrl {
    param([string]$Url)
    if (-not $Url) { return $false }
    try {
        $Uri = [Uri]$Url
    }
    catch {
        return $false
    }
    if ($Uri.Scheme -ne 'https') { return $false }
    # Match the exact host or any subdomain of microsoft.com (case-insensitive). Using the parsed Host
    # (not a substring of the raw URL) avoids spoofing like "microsoft.com.evil.example".
    return ($Uri.Host -match '(?i)(^|\.)microsoft\.com$')
}

# Uses the community "Fido" helper (which queries Microsoft's own software-download servers) to resolve
# the official, matching Windows ISO download URL. Downloads Fido to a temp file, runs it with -GetUrl,
# and returns the resulting URL string, or $null on failure. The resolved URL is verified to point at an
# official Microsoft host before being returned. Fido: https://github.com/pbatard/Fido
function Get-WindowsIsoUrl {
    param(
        [Parameter(Mandatory)][string]$Version,      # 10 or 11
        [Parameter(Mandatory)][string]$Release,       # e.g. Latest, 24H2
        [Parameter(Mandatory)][string]$Language,      # e.g. English
        [Parameter(Mandatory)][string]$Architecture   # x64 / arm64 / x86
    )

    $FidoScript = Join-Path -Path $env:TEMP -ChildPath "Fido_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"
    Write-HostTimestamp '  Fetching the Fido download helper from GitHub...'
    if (-not (Get-FileDownload -Url $FidoUrl -Destination $FidoScript)) {
        Write-HostTimestamp '  Could not download the Fido helper. Provide an ISO manually with -IsoPath instead.' -ForegroundColor Red
        return $null
    }

    Write-HostTimestamp "  Asking Microsoft (via Fido) for the Windows $Version ($Release, $Language, $Architecture) ISO link..."
    $Url = $null
    try {
        # -GetUrl makes Fido print only the resolved download URL and exit, without downloading anything.
        $FidoArgs = @{
            Win    = $Version
            Rel    = $Release
            Lang   = $Language
            Arch   = $Architecture
            GetUrl = $true
        }
        $Output = & $FidoScript @FidoArgs 2>&1
        # Fido prints the direct download URL as its final output line.
        $Url = ($Output | Where-Object { $_ -match '^https?://' } | Select-Object -Last 1)
        if ($Url) { $Url = $Url.ToString().Trim() }
    }
    catch {
        Write-HostTimestamp "  Fido could not resolve a download URL: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        Remove-Item -LiteralPath $FidoScript -Force -ErrorAction SilentlyContinue
    }

    if (-not $Url) {
        Write-HostTimestamp '  Fido did not return a download URL. Microsoft may have changed its download page, or the requested release/language is unavailable.' -ForegroundColor Red
        Write-HostTimestamp '  Download an ISO yourself and re-run with -IsoPath "C:\path\to\Windows.iso".' -ForegroundColor Yellow
        return $null
    }

    # Safety check: only download from an official Microsoft host over HTTPS.
    if (-not (Test-MicrosoftDownloadUrl -Url $Url)) {
        $BadHost = try { ([Uri]$Url).Host } catch { '(unparseable)' }
        Write-HostTimestamp "  The resolved download URL does not point at an official Microsoft host (host: $BadHost). Refusing to download it." -ForegroundColor Red
        Write-HostTimestamp '  Download an ISO yourself from https://www.microsoft.com/software-download and re-run with -IsoPath.' -ForegroundColor Yellow
        return $null
    }
    Write-HostTimestamp "  Verified the ISO download comes from an official Microsoft host: $(([Uri]$Url).Host)" -ForegroundColor Green
    return $Url
}

# Builds the Windows Setup argument list for the requested keep-mode and options. In-place-upgrade repair
# keeps apps and data by default (/auto upgrade). The Setup GUI is hidden (/quiet) and Dynamic Update is
# disabled by default; pass -ShowUI or -DynamicUpdate to change either.
function Get-SetupArguments {
    $SetupArgs = @('/auto', 'upgrade', '/eula', 'accept', '/compat', 'ignorewarning', '/migratedrivers', 'all', '/showoobe', 'none')

    switch ($KeepMode) {
        'KeepAll'     { }  # /auto upgrade already keeps apps + data
        'KeepNothing' { $SetupArgs = @('/auto', 'clean', '/eula', 'accept', '/compat', 'ignorewarning', '/showoobe', 'none') }
    }

    # /product server makes Setup run as the Server SKU installer, which skips the Windows 11 hardware
    # compatibility checks (TPM 2.0, Secure Boot, supported CPU, RAM) so incompatible PCs can upgrade.
    if ($BypassCompatChecks) { $SetupArgs += @('/product', 'server') }

    if ($DynamicUpdate) { $SetupArgs += @('/dynamicupdate', 'enable') }
    else                { $SetupArgs += @('/dynamicupdate', 'disable') }

    # Reduce telemetry from the Setup process itself.
    $SetupArgs += @('/telemetry', 'disable')

    if ($NoReboot) { $SetupArgs += '/noreboot' }
    # The Setup GUI is hidden by default (/quiet); pass -ShowUI to display it.
    if (-not $ShowUI) { $SetupArgs += '/quiet' }

    return $SetupArgs
}

# Confirms the mounted drive really is Windows installation media before we launch Setup from it, so we
# never hand a random/corrupt ISO to setup.exe. A valid Windows ISO has setup.exe at the root AND an OS
# image at sources\install.wim (or install.esd). When DISM can read the image, its metadata is also used
# to confirm it is a Windows image, to surface the editions inside, and to flag an architecture mismatch.
# Returns a PSCustomObject: IsValid, ImagePath, Architecture, Editions, Reason.
function Test-WindowsInstallMedia {
    param(
        [Parameter(Mandatory)][string]$DriveLetter,
        [string]$ExpectedArchitecture
    )

    $Root = "$DriveLetter`:\"
    $Result = [PSCustomObject]@{ IsValid = $false; ImagePath = $null; Architecture = $null; Editions = @(); Reason = $null }

    if (-not (Test-Path -LiteralPath (Join-Path $Root 'setup.exe'))) {
        $Result.Reason = 'setup.exe was not found at the root of the image.'
        return $Result
    }

    $Wim = Join-Path $Root 'sources\install.wim'
    $Esd = Join-Path $Root 'sources\install.esd'
    $ImagePath = if (Test-Path -LiteralPath $Wim) { $Wim } elseif (Test-Path -LiteralPath $Esd) { $Esd } else { $null }
    if (-not $ImagePath) {
        $Result.Reason = 'No Windows OS image (sources\install.wim or sources\install.esd) was found - this is not a Windows installation ISO.'
        return $Result
    }
    $Result.ImagePath = $ImagePath

    # Best-effort metadata read. If DISM cannot parse it we still accept the media (setup.exe + install
    # image are present), but a successful read lets us confirm the architecture and list editions.
    try {
        $Images = Get-WindowsImage -ImagePath $ImagePath -ErrorAction Stop
        if ($Images) {
            $Result.Editions = @($Images | ForEach-Object { $_.ImageName } | Where-Object { $_ })
            $ArchCode = ($Images | Select-Object -First 1).Architecture
            $Result.Architecture = switch ($ArchCode) {
                0       { 'x86' }
                9       { 'x64' }
                12      { 'arm64' }
                default { "code $ArchCode" }
            }
        }
    }
    catch {
        $Result.Reason = "Could not read image metadata via DISM ($($_.Exception.Message)); proceeding on the presence of setup.exe and the install image."
    }

    $Result.IsValid = $true
    return $Result
}

# Returns $true if any Windows Setup process is currently running. Setup.exe is only a small launcher
# that spawns the real long-running workers, so we watch for the whole family, not just setup.exe.
function Test-SetupRunning {
    $Names = @('setup', 'SetupHost', 'SetupPrep', 'SetupPlatform', 'Windows10UpgraderApp')
    return [bool](Get-Process -Name $Names -ErrorAction SilentlyContinue)
}

# Returns $true if Windows currently has a pending-reboot indicator set. Setup sets these once the
# down-level (pre-restart) phase finishes and it is ready to reboot to continue the upgrade.
function Test-PendingReboot {
    $Keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    foreach ($Key in $Keys) { if (Test-Path $Key) { return $true } }
    try {
        $Pfro = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue).PendingFileRenameOperations
        if ($Pfro) { return $true }
    }
    catch { }
    return $false
}

# Watches the Windows Setup process family and does NOT return until Setup has finished running (the
# whole family has exited) or the safety timeout is reached. Along the way it parses the live
# setupact.log and reports the overall percentage. Because Setup restarts the machine automatically at
# the end of the down-level phase (unless -NoReboot), this call typically blocks until that restart
# terminates the session; with -NoReboot it blocks until Setup exits so the script never quits early.
# Returns a PSCustomObject: Progressed, RebootPending, LastProgress. Never throws.
function Watch-SetupProgress {
    param(
        [int]$TimeoutMinutes = 180,
        [int]$StartupGraceMinutes = 5
    )

    $PantherDirs = @(
        (Join-Path -Path $env:SystemDrive -ChildPath '$WINDOWS.~BT\Sources\Panther'),
        (Join-Path -Path $env:windir -ChildPath 'Panther')
    )
    $Deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $StartupDeadline = (Get-Date).AddMinutes($StartupGraceMinutes)
    $LastProgress = -1
    $Progressed = $false
    $RebootPending = $false
    $SawSetup = $false
    $LogFile = $null

    $ReadProgress = {
        # Resolve/refresh the active setupact.log (newest one Setup is writing to) and print any new %.
        if (-not $LogFile -or -not (Test-Path -LiteralPath $LogFile)) {
            foreach ($Dir in $PantherDirs) {
                if (Test-Path $Dir) {
                    $Found = Get-ChildItem -Path $Dir -Filter 'setupact.log' -File -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($Found) { $script:_WatchLogFile = $Found.FullName; break }
                }
            }
            if ($script:_WatchLogFile) { $LogFile = $script:_WatchLogFile }
        }
        if ($LogFile -and (Test-Path -LiteralPath $LogFile)) {
            try {
                $Content = Get-Content -LiteralPath $LogFile -Raw -ErrorAction SilentlyContinue
                if ($Content) {
                    $ProgressMatches = [regex]::Matches($Content, 'Overall progress:\s*\[(\d+)%\]')
                    if ($ProgressMatches.Count -gt 0) {
                        $Pct = [int]$ProgressMatches[$ProgressMatches.Count - 1].Groups[1].Value
                        if ($Pct -ne $script:_WatchLastProgress) {
                            $script:_WatchLastProgress = $Pct
                            Write-HostTimestamp "    Setup progress: $Pct%"
                        }
                    }
                }
            }
            catch { }
        }
    }
    $script:_WatchLastProgress = -1
    $script:_WatchLogFile = $null

    Write-HostTimestamp '  Monitoring the Setup process - this window will not exit until Setup completes...' -ForegroundColor Cyan

    # Phase 1: wait for a Setup process to appear (Setup.exe extracts and spawns its workers first).
    while (-not (Test-SetupRunning) -and (Get-Date) -lt $StartupDeadline) {
        & $ReadProgress
        if ($script:_WatchLastProgress -ge 0) { break }  # progress already means Setup is underway
        Start-Sleep -Seconds 5
    }
    if (Test-SetupRunning) { $SawSetup = $true }

    # Phase 2: keep watching until the Setup process family has fully exited (Setup completed), reporting
    # progress as it advances. Do NOT stop on the first pending-reboot signal - stay until Setup is gone.
    while ((Get-Date) -lt $Deadline) {
        & $ReadProgress
        if (Test-SetupRunning) {
            $SawSetup = $true
        }
        elseif ($SawSetup) {
            # Setup was running and is now gone -> it has finished (or triggered the restart).
            break
        }
        elseif ($script:_WatchLastProgress -lt 0 -and (Get-Date) -ge $StartupDeadline) {
            # Setup never appeared and no progress within the grace window -> it did not start.
            break
        }
        if (Test-PendingReboot) { $RebootPending = $true }
        Start-Sleep -Seconds 15
    }

    $LastProgress = $script:_WatchLastProgress
    $Progressed = ($SawSetup -or $LastProgress -ge 0)
    if (-not $RebootPending) { $RebootPending = (Test-PendingReboot) }

    if ($SawSetup) {
        Write-HostTimestamp "  Setup has finished running$(if ($LastProgress -ge 0) { " (last reported progress: $LastProgress%)" })." -ForegroundColor Green
    }
    return [PSCustomObject]@{ Progressed = $Progressed; RebootPending = $RebootPending; LastProgress = $LastProgress }
}

# Registers a one-shot SYSTEM scheduled task that deletes the DOWNLOADED ISO once the upgrade is out of
# the way. The ISO stays mounted while Setup runs and the machine reboots during the upgrade, so we
# cannot safely delete it in-line; instead the task fires at startup (after a short delay), waits for any
# Setup process to finish, dismounts the image if needed, deletes the ISO, and then removes itself. It is
# only ever called for an ISO this run downloaded - never for -IsoPath or a reused existing ISO.
function Register-IsoCleanupTask {
    param([Parameter(Mandatory)][string]$IsoPath)

    $TaskName = 'WindowsInPlaceUpgrade_IsoCleanup'
    $WorkDir = Join-Path -Path $env:ProgramData -ChildPath 'Windows-InPlace-Upgrade'
    try { if (-not (Test-Path $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force -ErrorAction Stop | Out-Null } }
    catch { $WorkDir = $env:TEMP }
    $WorkerFile = Join-Path -Path $WorkDir -ChildPath 'Cleanup-Iso.ps1'
    $WorkerLog = Join-Path -Path $WorkDir -ChildPath 'Cleanup-Iso.log'

    # Worker script: wait out any running Setup, dismount/delete the ISO, then unregister and self-delete.
    $WorkerContent = @"
`$ErrorActionPreference = 'SilentlyContinue'
`$Iso = '$($IsoPath.Replace("'", "''"))'
`$TaskName = '$TaskName'
try { Start-Transcript -Path '$($WorkerLog.Replace("'", "''"))' -Force | Out-Null } catch { }
# Do not pull the ISO out from under an active Setup: wait until no Setup process is running (max ~2 hrs).
`$Names = @('setup','SetupHost','SetupPrep','SetupPlatform','Windows10UpgraderApp')
for (`$i = 0; `$i -lt 240; `$i++) {
    if (-not (Get-Process -Name `$Names -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Seconds 30
}
try { Dismount-DiskImage -ImagePath `$Iso -ErrorAction SilentlyContinue | Out-Null } catch { }
if (Test-Path -LiteralPath `$Iso) { Remove-Item -LiteralPath `$Iso -Force -ErrorAction SilentlyContinue }
try { Unregister-ScheduledTask -TaskName `$TaskName -Confirm:`$false -ErrorAction SilentlyContinue } catch { }
try { Stop-Transcript | Out-Null } catch { }
Remove-Item -LiteralPath `$PSCommandPath -Force -ErrorAction SilentlyContinue
"@
    Set-Content -Path $WorkerFile -Value $WorkerContent -Encoding UTF8 -Force -ErrorAction Stop

    $Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$WorkerFile`""
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    # Give the machine a few minutes after boot before the cleanup fires.
    try { $Trigger.Delay = 'PT3M' } catch { }
    $Principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force -ErrorAction Stop | Out-Null
}

Write-Host $LineBreak
Write-HostTimestamp "Windows In-Place Upgrade (repair install) on $($env:ComputerName)" -ForegroundColor Cyan
Write-Host $LineBreak

# --- Gather system info ---
$WinInfo = Get-InstalledWindowsInfo

Write-HostTimestamp "Installed OS   : $($WinInfo.ProductName)$(if ($WinInfo.EditionId) { " (Edition: $($WinInfo.EditionId))" })" -ForegroundColor Cyan
Write-Host "  Feature update : $($WinInfo.DisplayVersion)"
Write-Host "  Build          : $($WinInfo.Build)$(if ($null -ne $WinInfo.Ubr) { ".$($WinInfo.Ubr)" })"
Write-Host "  Architecture   : $($WinInfo.Architecture)"
Write-Host "  Upgrade target : Windows $WindowsVersion ($Release, $Language)"
Write-Host $LineBreak

# --- Disk space check ---
# An in-place upgrade downloads a ~5-6 GB ISO and needs roughly 20 GB free to stage the new OS alongside
# the current one. Gate the run on available space so it does not fail partway through.
$FreeGB = Get-SystemDriveFreeGB
if ($null -eq $FreeGB) {
    Write-HostTimestamp 'Could not determine free disk space on the system drive. Continuing with caution.' -ForegroundColor Yellow
}
else {
    Write-HostTimestamp "Free space on $env:SystemDrive : $FreeGB GB"

    # A leftover $WINDOWS.~BT folder from a previous/pending upgrade already holds the staged OS payload.
    # Windows Setup reuses/replaces it, so the space it occupies is effectively available to this upgrade.
    # Make a conservative judgement call that it is worth at least 10 GB and credit that toward free space.
    $EffectiveFreeGB = $FreeGB
    $BtFolder = Join-Path -Path $env:SystemDrive -ChildPath '$WINDOWS.~BT'
    if (-not $DownloadOnly -and (Test-Path -LiteralPath $BtFolder)) {
        $BtCreditGB = 10
        $EffectiveFreeGB = [math]::Round($FreeGB + $BtCreditGB, 2)
        Write-HostTimestamp "  Found an existing $BtFolder folder from a prior upgrade; Setup will reuse it. Crediting ~$BtCreditGB GB toward the space requirement (effective free: $EffectiveFreeGB GB)." -ForegroundColor DarkGray
    }

    # Only the ISO is needed when we are just downloading; the full upgrade needs much more headroom.
    $RequiredGB = if ($DownloadOnly -or $IsoPath) { 8 } else { 20 }
    if ($EffectiveFreeGB -lt $RequiredGB) {
        Write-HostTimestamp "CRITICAL: Less than $RequiredGB GB of free disk space ($EffectiveFreeGB GB effective). An in-place upgrade cannot complete reliably. Free up space and try again." -ForegroundColor Red
        Stop-Transcript | Out-Null
        exit 1
    }
    elseif (-not $DownloadOnly -and $EffectiveFreeGB -lt 25) {
        Write-HostTimestamp "WARNING: Free disk space is a little tight ($EffectiveFreeGB GB effective). The upgrade should still work, but 25 GB+ is recommended." -ForegroundColor Yellow
    }
}
Write-Host $LineBreak

# --- Interactive confirmation ---
if (-not $Unattended -and -not $SkipInteractive -and -not $DownloadOnly) {
    Write-Host "This tool performs an IN-PLACE UPGRADE (repair install) of Windows to fix Windows Update and"
    Write-Host "servicing corruption. It re-installs the operating system while keeping your files and apps."
    Write-Host ""
    Write-Host "It will:"
    if (-not $IsoPath) {
        Write-Host "  - Download the matching official Windows $WindowsVersion ISO from Microsoft (~5-6 GB)"
    }
    else {
        Write-Host "  - Use the ISO you provided: $IsoPath"
    }
    Write-Host "  - Mount the ISO and launch Windows Setup in upgrade mode ($KeepMode)"
    switch ($KeepMode) {
        'KeepAll'     { Write-Host "      -> Keeps your apps, settings, and personal files" -ForegroundColor Green }
        'KeepNothing' { Write-Host "      -> CLEAN install: apps, settings, and files are NOT kept" -ForegroundColor Red }
    }
    if ($DynamicUpdate) { Write-Host "  - Let Setup pull the latest fixes online first (Dynamic Update)" }
    if ($BypassCompatChecks) { Write-Host "  - Bypass the Windows 11 hardware compatibility checks (/product server) - for incompatible PCs" -ForegroundColor Yellow }
    Write-Host ""
    Write-Host "The upgrade takes 20-90 minutes and WILL RESTART the computer several times." -ForegroundColor Yellow
    Write-Host "Close your apps and save your work before continuing." -ForegroundColor Yellow
    Write-Host "Once Setup starts, closing this window will NOT stop the upgrade." -ForegroundColor Yellow
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
    Write-HostTimestamp 'Running in Unattended mode. Setup will run silently and prompts will be skipped.' -ForegroundColor Cyan
    Write-Host $LineBreak
}

# --- Obtain the ISO ---
$ResolvedIso = $null
# Tracks whether THIS run downloaded the ISO. Only a downloaded ISO is eligible for auto-cleanup - an
# ISO supplied with -IsoPath or one found already sitting in the download folder is left untouched.
$IsoWasDownloaded = $false

if ($IsoPath) {
    if (Test-Path -LiteralPath $IsoPath) {
        $ResolvedIso = (Resolve-Path -LiteralPath $IsoPath).Path
        Write-HostTimestamp "Using the provided ISO: $ResolvedIso" -ForegroundColor Green
    }
    else {
        Write-HostTimestamp "The ISO path '$IsoPath' does not exist. Cannot continue." -ForegroundColor Red
        Stop-Transcript | Out-Null
        exit 1
    }
}
else {
    # Resolve the download destination folder first so we can check it for an ISO already downloaded
    # by a previous run and skip the Fido lookup and the multi-GB download entirely.
    $DlDir = if ($DownloadPath) { $DownloadPath } else { $PSScriptRoot }
    try {
        if (-not (Test-Path $DlDir)) { New-Item -ItemType Directory -Path $DlDir -Force -ErrorAction Stop | Out-Null }
    }
    catch {
        Write-HostTimestamp "Could not use download folder '$DlDir': $($_.Exception.Message). Using the temp folder." -ForegroundColor Yellow
        $DlDir = $env:TEMP
    }

    # If a valid Windows ISO (larger than 3 GB) is already present in the download folder, reuse it
    # rather than downloading again. Prefer the largest/newest matching file.
    $ExistingIso = Get-ChildItem -Path $DlDir -Filter '*.iso' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -gt 3GB } |
        Sort-Object -Property Length -Descending |
        Select-Object -First 1
    if ($ExistingIso) {
        $ResolvedIso = $ExistingIso.FullName
        $SizeGB = [math]::Round($ExistingIso.Length / 1GB, 2)
        Write-HostTimestamp "An ISO is already downloaded - reusing it instead of downloading again: $ResolvedIso ($SizeGB GB)" -ForegroundColor Green
        Write-HostTimestamp '  Delete it (or use -DownloadPath to point elsewhere) if you want a fresh download.' -ForegroundColor DarkGray
        Write-Host $LineBreak
    }
    else {
        Invoke-Task -Description 'Obtaining the Windows ISO download link from Microsoft...' -ScriptBlock {
            $script:IsoUrl = Get-WindowsIsoUrl -Version $WindowsVersion -Release $Release -Language $Language -Architecture $WinInfo.Architecture
        }

        if (-not $script:IsoUrl) {
            Stop-Transcript | Out-Null
            exit 1
        }

        # Derive a friendly file name from the URL, falling back to a generic name.
        $FileName = $null
        try { $FileName = [System.IO.Path]::GetFileName(([Uri]$script:IsoUrl).AbsolutePath) } catch { }
        if (-not $FileName -or $FileName -notmatch '\.iso$') {
            $FileName = "Windows$WindowsVersion`_$Language`_$($WinInfo.Architecture).iso"
        }
        $ResolvedIso = Join-Path -Path $DlDir -ChildPath $FileName

        Invoke-Task -Description "Downloading the Windows $WindowsVersion ISO to $ResolvedIso ..." -ScriptBlock {
            if (-not (Get-FileDownload -Url $script:IsoUrl -Destination $ResolvedIso)) {
                Write-HostTimestamp 'ISO download failed. Cannot continue.' -ForegroundColor Red
                Stop-Transcript | Out-Null
                exit 1
            }
            # Sanity-check the size: a genuine Windows ISO is well over 3 GB. A tiny file means an error page.
            $SizeGB = [math]::Round((Get-Item -LiteralPath $ResolvedIso).Length / 1GB, 2)
            if ($SizeGB -lt 3) {
                Write-HostTimestamp "The downloaded file is only $SizeGB GB - that is too small to be a Windows ISO. The download likely failed." -ForegroundColor Red
                Stop-Transcript | Out-Null
                exit 1
            }
            Write-HostTimestamp "  Download complete ($SizeGB GB)." -ForegroundColor Green
        }
        $IsoWasDownloaded = $true
    }
}

if ($DownloadOnly) {
    Write-HostTimestamp "Download-only mode: the ISO is ready at $ResolvedIso" -ForegroundColor Green
    Write-HostTimestamp 'Re-run without -DownloadOnly (and with -IsoPath pointing here) to start the in-place upgrade.'
    Write-Host $LineBreak
    Stop-Transcript | Out-Null
    exit 0
}

# --- Mount the ISO and launch Setup ---
$MountedImage = $null
$SetupExitCode = $null
$SetupStarted = $false
$SetupOutcome = $null
$CleanupScheduled = $false
try {
    Invoke-Task -Description "Mounting the ISO: $ResolvedIso ..." -ScriptBlock {
        $script:MountedImage = Mount-DiskImage -ImagePath $ResolvedIso -PassThru -ErrorAction Stop
        Start-Sleep -Seconds 2
    }
    $MountedImage = $script:MountedImage

    # Resolve the drive letter of the freshly-mounted ISO.
    $DriveLetter = ($MountedImage | Get-Volume -ErrorAction SilentlyContinue).DriveLetter
    if (-not $DriveLetter) {
        # Fallback: re-query the mounted image for its volume.
        $DriveLetter = (Get-DiskImage -ImagePath $ResolvedIso | Get-Volume -ErrorAction SilentlyContinue).DriveLetter
    }
    if (-not $DriveLetter) {
        throw "Could not determine the drive letter of the mounted ISO."
    }
    Write-HostTimestamp "  ISO mounted at $($DriveLetter):\" -ForegroundColor Green

    # Verify this really is Windows installation media before handing it to Setup.
    Invoke-Task -Description 'Verifying the ISO is valid Windows installation media...' -ScriptBlock {
        $script:Media = Test-WindowsInstallMedia -DriveLetter $DriveLetter -ExpectedArchitecture $WinInfo.Architecture
        if (-not $script:Media.IsValid) {
            throw "The mounted image is not a valid Windows ISO: $($script:Media.Reason)"
        }
        Write-HostTimestamp "  Verified: found setup.exe and $(Split-Path -Leaf $script:Media.ImagePath)." -ForegroundColor Green
        if ($script:Media.Architecture) {
            Write-HostTimestamp "  Image architecture: $($script:Media.Architecture)"
            if ($script:Media.Architecture -notmatch '^code ' -and $script:Media.Architecture -ne $WinInfo.Architecture) {
                Write-HostTimestamp "  WARNING: the ISO architecture ($($script:Media.Architecture)) does not match this PC ($($WinInfo.Architecture)). An in-place upgrade requires a matching architecture and will likely be refused." -ForegroundColor Yellow
            }
        }
        if ($script:Media.Editions.Count -gt 0) {
            Write-HostTimestamp "  Editions in image: $($script:Media.Editions -join ', ')"
        }
        if ($script:Media.Reason) {
            Write-HostTimestamp "  Note: $($script:Media.Reason)" -ForegroundColor DarkGray
        }
    }

    $SetupExe = "$($DriveLetter):\setup.exe"
    $SetupArguments = Get-SetupArguments
    Invoke-Task -Description 'Launching Windows Setup for the in-place upgrade...' -ScriptBlock {
        Write-HostTimestamp "  Running: $SetupExe $($SetupArguments -join ' ')"
        Write-HostTimestamp '  Setup runs directly from the mounted ISO and copies what it needs into $WINDOWS.~BT.' -ForegroundColor Yellow
        Write-HostTimestamp '  The ISO stays mounted while Setup runs. It takes 20-90 minutes and restarts the machine several times.' -ForegroundColor Yellow
        Write-HostTimestamp '  Once Setup restarts the machine, any remaining steps in this script will not run - that is expected.' -ForegroundColor DarkGray

        # Launch Setup without blocking so we can actively monitor its progress in both modes.
        $Process = Start-Process -FilePath $SetupExe -ArgumentList $SetupArguments -PassThru -ErrorAction Stop
        Start-Sleep -Seconds 5

        # IMPORTANT: from here on Setup can restart the machine at any time (unless -NoReboot), which can
        # kill this script. Schedule the ISO cleanup NOW - before the monitoring loop that the reboot
        # interrupts - so it is guaranteed to be registered even though later steps may never run.
        if ($IsoWasDownloaded -and $ResolvedIso) {
            try {
                Register-IsoCleanupTask -IsoPath $ResolvedIso
                $script:CleanupScheduled = $true
                Write-HostTimestamp "  Scheduled a one-time task to delete the downloaded ISO after the upgrade completes: $ResolvedIso" -ForegroundColor Cyan
            }
            catch {
                Write-HostTimestamp "  Could not schedule the ISO cleanup task: $($_.Exception.Message). Delete it manually later: $ResolvedIso" -ForegroundColor Yellow
            }
        }

        # Block here watching the Setup process until it completes (or the machine restarts). This does
        # not return until Setup is done, so the script never exits while the upgrade is still running.
        $Outcome = Watch-SetupProgress
        $script:SetupOutcome = $Outcome
        $script:SetupExitCode = try { if ($Process.HasExited) { $Process.ExitCode } else { $null } } catch { $null }

        # Setup is considered started if it ever ran / made progress / left a pending reboot.
        $script:SetupStarted = ($Outcome.Progressed -or $Outcome.RebootPending -or (Test-SetupRunning))
    }
    $SetupExitCode = $script:SetupExitCode
    $SetupStarted = [bool]$script:SetupStarted
    $SetupOutcome = $script:SetupOutcome
    if ($script:CleanupScheduled) { $CleanupScheduled = $true }
}
catch {
    Write-HostTimestamp "The in-place upgrade could not be started: $($_.Exception.Message)" -ForegroundColor Red
    $SetupStarted = $false
}
finally {
    # Only dismount if Setup did NOT start. When Setup is running it copies everything it needs from the
    # mounted ISO into $WINDOWS.~BT, so the ISO MUST stay mounted for the upgrade to complete - do not
    # dismount it here on success. Windows releases the mount automatically on the next restart.
    if ($MountedImage -and -not $SetupStarted) {
        try {
            Dismount-DiskImage -ImagePath $ResolvedIso -ErrorAction SilentlyContinue | Out-Null
            Write-HostTimestamp 'Setup did not start - dismounted the ISO.' -ForegroundColor Yellow
        }
        catch { }
    }
}

if (-not $SetupStarted) {
    $ExitNote = if ($null -ne $SetupExitCode) { " (exit code $SetupExitCode)" } else { '' }
    Write-HostTimestamp "Windows Setup did not start or did not make progress$ExitNote. Check C:\`$WINDOWS.~BT\Sources\Panther\setupact.log for details." -ForegroundColor Yellow
}
elseif ($SetupOutcome -and $SetupOutcome.RebootPending) {
    Write-HostTimestamp 'Windows Setup finished its down-level phase and a restart is required to continue the upgrade.' -ForegroundColor Green
    if ($NoReboot) {
        Write-Host 'Restart the computer when ready to let Setup finish the upgrade.'
    }
    else {
        Write-Host 'The computer will restart automatically to continue. Do not power it off during the upgrade.'
    }
}
elseif ($NoReboot) {
    # -NoReboot was requested, so Setup intentionally does NOT restart at the end of the down-level phase.
    # In that case "no automatic reboot" is expected, not a failure signal - and the pending-reboot flag is
    # not always registered before setup.exe exits. Do not cry failure here; give a neutral, cautious note.
    $ExitHex = if ($null -ne $SetupExitCode) { '0x{0:X8}' -f ([uint32]($SetupExitCode -band 0xFFFFFFFF)) } else { $null }
    $ExitNote = if ($ExitHex) { " (exit code $SetupExitCode / $ExitHex)" } else { '' }
    Write-HostTimestamp "Windows Setup finished its down-level phase without restarting because -NoReboot was set$ExitNote." -ForegroundColor Cyan
    Write-Host 'Restart the computer when ready to let Setup finish the upgrade.'
    Write-Host 'If, after rebooting, the upgrade does not continue, review C:\$WINDOWS.~BT\Sources\Panther\setupact.log and setuperr.log (or run SetupDiag: https://aka.ms/SetupDiag).'
}
else {
    # Setup ran and then exited WITHOUT leaving a pending-reboot indicator AND -NoReboot was not requested.
    # A successful in-place upgrade always finishes its down-level phase by scheduling a restart to continue,
    # so reaching here means Setup quit before that point - which almost always means the upgrade FAILED
    # (blocking compat issue, driver/app hold, media/space problem, etc.), not that it succeeded silently.
    # Treat it as a probable failure and point at the diagnostics.
    $ExitHex = if ($null -ne $SetupExitCode) { '0x{0:X8}' -f ([uint32]($SetupExitCode -band 0xFFFFFFFF)) } else { $null }
    $ExitNote = if ($ExitHex) { " (exit code $SetupExitCode / $ExitHex)" } else { '' }
    Write-HostTimestamp "Windows Setup finished but did NOT schedule a restart$ExitNote." -ForegroundColor Yellow
    Write-HostTimestamp 'A successful in-place upgrade would have queued an automatic reboot to continue, so this almost certainly means Setup FAILED and rolled back.' -ForegroundColor Yellow
    Write-Host 'Review these logs to find the reason:'
    Write-Host '  - C:\$WINDOWS.~BT\Sources\Panther\setupact.log   (search for "Overall progress" and lines near "error")'
    Write-Host '  - C:\$WINDOWS.~BT\Sources\Panther\setuperr.log'
    Write-Host '  - Run SetupDiag (https://aka.ms/SetupDiag) for a plain-language diagnosis of the failure.'
    if ($ExitHex) {
        Write-Host "  - Look up the Setup exit code $ExitHex (e.g. 0xC1900208 = an app/compat block, 0xC1900101 = a driver/rollback failure)."
    }
}

if ($SetupStarted) {
    Write-HostTimestamp 'NOTE: Windows Setup runs as its own process - closing this window will NOT stop the upgrade.' -ForegroundColor Cyan
}

# The ISO cleanup task is normally scheduled right after Setup launches (above), so it survives Setup's
# automatic reboot. This is only a fallback for the rare case where we got here without it being
# scheduled (e.g. -NoReboot and Setup exited before the launch block reached that point).
if ($SetupStarted -and $IsoWasDownloaded -and $ResolvedIso -and -not $CleanupScheduled) {
    try {
        Register-IsoCleanupTask -IsoPath $ResolvedIso
        Write-HostTimestamp "Scheduled a one-time cleanup task to delete the downloaded ISO ($ResolvedIso) after the upgrade completes." -ForegroundColor Cyan
    }
    catch {
        Write-HostTimestamp "Could not schedule the ISO cleanup task: $($_.Exception.Message). You can delete the ISO manually later: $ResolvedIso" -ForegroundColor Yellow
    }
}
elseif ($SetupStarted -and -not $IsoWasDownloaded -and $ResolvedIso) {
    Write-HostTimestamp "The ISO was supplied or reused (not downloaded by this run), so it will be left in place: $ResolvedIso" -ForegroundColor DarkGray
}

Write-HostTimestamp 'Windows In-Place Upgrade script finished.' -ForegroundColor Green
if (-not $Unattended -and -not $SkipInteractive) {
    Read-Host -Prompt 'Closing this window will NOT stop the upgrade. Press enter to exit.'
}

# Stop logging
Stop-Transcript
# --- End Logging ---
