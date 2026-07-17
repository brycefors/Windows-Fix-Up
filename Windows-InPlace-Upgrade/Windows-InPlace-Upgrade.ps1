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
#      default (/auto upgrade), with Dynamic Update enabled so the latest setup fixes are pulled first.
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
    [Parameter(HelpMessage = 'Runs the script without any confirmation prompts and launches Setup silently (/quiet)')]
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

    [Parameter(HelpMessage = 'Turn off Dynamic Update so Setup does not pull the latest fixes online before upgrading')]
    [switch]$NoDynamicUpdate,

    [Parameter(HelpMessage = 'Delete the downloaded ISO after Setup has started')]
    [switch]$CleanupIso,

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

# Uses the community "Fido" helper (which queries Microsoft's own software-download servers) to resolve
# the official, matching Windows ISO download URL. Downloads Fido to a temp file, runs it with -GetUrl,
# and returns the resulting URL string, or $null on failure. Fido: https://github.com/pbatard/Fido
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
    }
    return $Url
}

# Builds the Windows Setup argument list for the requested keep-mode and options. In-place-upgrade repair
# keeps apps and data by default (/auto upgrade). Dynamic Update is enabled so Setup pulls the newest
# setup/servicing fixes before it runs, which is what makes this repair updates so reliably.
function Get-SetupArguments {
    $SetupArgs = @('/auto', 'upgrade', '/eula', 'accept', '/compat', 'ignorewarning', '/migratedrivers', 'all', '/showoobe', 'none')

    switch ($KeepMode) {
        'KeepAll'     { }  # /auto upgrade already keeps apps + data
        'KeepNothing' { $SetupArgs = @('/auto', 'clean', '/eula', 'accept', '/compat', 'ignorewarning', '/showoobe', 'none') }
    }

    if ($NoDynamicUpdate) { $SetupArgs += @('/dynamicupdate', 'disable') }
    else                  { $SetupArgs += @('/dynamicupdate', 'enable') }

    # Reduce telemetry from the Setup process itself.
    $SetupArgs += @('/telemetry', 'disable')

    if ($NoReboot)   { $SetupArgs += '/noreboot' }
    if ($Unattended) { $SetupArgs += '/quiet' }

    return $SetupArgs
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
    # Only the ISO is needed when we are just downloading; the full upgrade needs much more headroom.
    $RequiredGB = if ($DownloadOnly -or $IsoPath) { 8 } else { 20 }
    if ($FreeGB -lt $RequiredGB) {
        Write-HostTimestamp "CRITICAL: Less than $RequiredGB GB of free disk space ($FreeGB GB). An in-place upgrade cannot complete reliably. Free up space and try again." -ForegroundColor Red
        Stop-Transcript | Out-Null
        exit 1
    }
    elseif (-not $DownloadOnly -and $FreeGB -lt 25) {
        Write-HostTimestamp "WARNING: Free disk space is a little tight ($FreeGB GB). The upgrade should still work, but 25 GB+ is recommended." -ForegroundColor Yellow
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
    if (-not $NoDynamicUpdate) { Write-Host "  - Let Setup pull the latest fixes online first (Dynamic Update)" }
    Write-Host ""
    Write-Host "The upgrade takes 20-90 minutes and WILL RESTART the computer several times." -ForegroundColor Yellow
    Write-Host "Close your apps and save your work before continuing." -ForegroundColor Yellow
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
    $SetupExe = "$($DriveLetter):\setup.exe"
    Write-HostTimestamp "  ISO mounted at $($DriveLetter):\" -ForegroundColor Green

    if (-not (Test-Path -LiteralPath $SetupExe)) {
        throw "setup.exe was not found on the mounted ISO ($SetupExe). The ISO may be corrupt or not a Windows installation image."
    }

    $SetupArguments = Get-SetupArguments
    Invoke-Task -Description 'Launching Windows Setup for the in-place upgrade...' -ScriptBlock {
        Write-HostTimestamp "  Running: $SetupExe $($SetupArguments -join ' ')"
        Write-HostTimestamp '  Setup will now take over. It runs for 20-90 minutes and restarts the machine several times.' -ForegroundColor Yellow
        if ($Unattended) {
            # Silent/automated: wait for the setup launcher to hand off, then report its initial exit code.
            $Process = Start-Process -FilePath $SetupExe -ArgumentList $SetupArguments -PassThru -Wait -ErrorAction Stop
            $script:SetupExitCode = $Process.ExitCode
        }
        else {
            # Interactive: launch Setup and let it drive its own UI/restarts; do not block this window.
            Start-Process -FilePath $SetupExe -ArgumentList $SetupArguments -ErrorAction Stop
            $script:SetupExitCode = 0
        }
    }
    $SetupExitCode = $script:SetupExitCode
}
catch {
    Write-HostTimestamp "The in-place upgrade could not be started: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    # If Setup did not take over (error, or -NoReboot/quiet returned), dismount the ISO so it is not left
    # mounted. When Setup runs interactively and continues in the background, we intentionally leave the
    # ISO mounted until the machine restarts.
    if ($MountedImage -and ($Unattended -or $SetupExitCode -ne 0 -or -not $SetupExitCode)) {
        try {
            Dismount-DiskImage -ImagePath $ResolvedIso -ErrorAction SilentlyContinue | Out-Null
            Write-HostTimestamp 'Dismounted the ISO.'
        }
        catch { }
    }
}

if ($null -ne $SetupExitCode -and $SetupExitCode -ne 0) {
    Write-HostTimestamp "Windows Setup returned exit code $SetupExitCode. The upgrade may not have started successfully - check C:\`$WINDOWS.~BT\Sources\Panther\setupact.log for details." -ForegroundColor Yellow
}
else {
    Write-HostTimestamp 'Windows Setup has started the in-place upgrade.' -ForegroundColor Green
    Write-Host 'The computer will restart several times. Do not power it off during the upgrade.'
    if ($CleanupIso -and -not $IsoPath) {
        Write-HostTimestamp 'The downloaded ISO will be removed once Setup has copied what it needs (after this session).' -ForegroundColor DarkGray
    }
}

# Optionally remove the downloaded ISO now that Setup has staged its files (only for ISOs we downloaded).
if ($CleanupIso -and -not $IsoPath -and $ResolvedIso -and (Test-Path -LiteralPath $ResolvedIso)) {
    try {
        # Ensure it is not still mounted before deleting.
        Dismount-DiskImage -ImagePath $ResolvedIso -ErrorAction SilentlyContinue | Out-Null
        Remove-Item -LiteralPath $ResolvedIso -Force -ErrorAction SilentlyContinue
        Write-HostTimestamp "Removed the downloaded ISO: $ResolvedIso"
    }
    catch { }
}

Write-HostTimestamp 'Windows In-Place Upgrade script finished.' -ForegroundColor Green
if (-not $Unattended -and -not $SkipInteractive) {
    Read-Host -Prompt 'Close window or press enter to exit.'
}

# Stop logging
Stop-Transcript
# --- End Logging ---
