# --- SCRIPT OVERVIEW ---
# Windows-Update-Maintenance.ps1 is an unattended "Automated Windows Update Maintenance Engine". It identifies the
# newest applicable Cumulative Update for the local OS build/architecture directly from the Microsoft Update
# Catalog, downloads it, installs it silently, diagnoses failures, and cleans up after itself.
#
# Workflow:
#   [1. Detect OS & Build] -> [2. Query Catalog] -> [3. Check Installed Status]
#                                                        |
#                                (Already Current) ------+------ (Update Needed)
#                                        |                              |
#                              [7. Maintenance Cleanup]        [4. BITS Download]
#                                        |                              |
#                                   [Exit Code 0]              [5. Install MSU]
#                                                                       |
#                                                     (Success) --------+-------- (Failure)
#                                                          |                          |
#                                                  [Log & Reboot]           [6. Parse Logs/Events]
#                                                          |                          |
#                                                          +------------+-------------+
#                                                                       |
#                                                          [7. Maintenance Cleanup]
#
# DESIGN NOTE: Module 7 (cleanup) runs from a finally block so multi-hundred-megabyte .msu/.cab payloads and
# stalled BITS jobs are always removed - even on a fatal error - while execution logs are pruned on a rolling
# retention window (default 30 days) so diagnostics survive long enough to be useful.
# -------------------------------------------------
# How to Run:
# NOTE: It is recommended to use "Run-Windows-Update-Maintenance.bat" to invoke this script. You can also run the
#       .PS1 directly from an elevated PowerShell prompt, a SYSTEM scheduled task, Intune, or an RMM agent.
# 1.  Open PowerShell as an Administrator: Right-click your Start Menu and select "Terminal (Admin)".
# 2.  Enable Script Execution (if needed): Set-ExecutionPolicy Bypass -Force
# 3.  Run the Script: .\Windows-Update-Maintenance.ps1
#
# Exit codes:
#   0    - System already current, or the update installed successfully with no reboot required.
#   3010 - Update installed successfully and a restart is required to complete servicing.
#   1    - The run failed (catalog, download, or installation error). See the JSON failure report in the log folder.
# -------------------------------------------------

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(HelpMessage = 'Staging folder used for the downloaded .msu, extracted .cab files, and logs')]
    [string]$StagingPath = (Join-Path -Path $env:ProgramData -ChildPath 'UpdateStaging'),

    [Parameter(HelpMessage = 'Directory for execution logs and JSON reports (defaults to <StagingPath>\Logs)')]
    [string]$LogPath,

    [Parameter(HelpMessage = 'Installer engine. DISM expands the MSU and injects the CAB (faster, verbose logging); WUSA uses wusa.exe /quiet /norestart (stricter applicability checks)')]
    [ValidateSet('DISM', 'WUSA')]
    [string]$InstallMethod = 'DISM',

    [Parameter(HelpMessage = 'Download engine. BITS is resilient and throttle-aware; HTTP is a direct stream used automatically if BITS is unavailable')]
    [ValidateSet('BITS', 'HTTP')]
    [string]$DownloadMethod = 'BITS',

    [Parameter(HelpMessage = 'Override the Microsoft Update Catalog search term instead of building it from the detected OS/build/architecture')]
    [string]$SearchQuery,

    [Parameter(HelpMessage = 'Allow optional "Preview" (C/D-week) cumulative updates to be selected')]
    [switch]$IncludePreview,

    [Parameter(HelpMessage = 'Detect and report only - never download or install anything')]
    [switch]$ReportOnly,

    [Parameter(HelpMessage = 'Install the update even if the KB already appears to be present')]
    [switch]$Force,

    [Parameter(HelpMessage = 'Days of execution logs/reports to retain in the log folder (default 30, 0 disables pruning)')]
    [ValidateRange(0, 3650)]
    [int]$LogRetentionDays = 30,

    [Parameter(HelpMessage = 'Keep the downloaded .msu and extracted .cab payload instead of purging it during cleanup')]
    [switch]$KeepPayload,

    [Parameter(HelpMessage = 'After a successful install, run Dism.exe /Online /Cleanup-Image /StartComponentCleanup to trim the WinSxS store')]
    [switch]$ComponentCleanup,

    [Parameter(HelpMessage = 'Automatically restart the computer when the installed update requires a reboot')]
    [switch]$AutoReboot,

    [Parameter(HelpMessage = 'Seconds to wait before the -AutoReboot restart is issued (default 60)')]
    [ValidateRange(0, 86400)]
    [int]$RebootDelaySeconds = 60,

    [Parameter(HelpMessage = 'Skip the CBS.log regex parsing performed when an installation fails (CBS.log can exceed 100 MB)')]
    [switch]$SkipCbsLogParsing,

    [Parameter(HelpMessage = 'Minimum free disk space, in GB, required on the staging volume before downloading (default 8)')]
    [ValidateRange(1, 500)]
    [int]$MinimumFreeSpaceGB = 8
)

# ---------------------------------------------------------------------------------------------------------------
# Environment guards
# ---------------------------------------------------------------------------------------------------------------

if ($PSVersionTable.PSVersion.Major -lt 5) {
    throw "This script requires PowerShell 5.1 or higher. You are currently running $($PSVersionTable.PSVersion)."
}

$OsCimInfo = Get-CimInstance -ClassName Win32_OperatingSystem
if ([int]$OsCimInfo.BuildNumber -lt 10240) {
    throw "This script is designed for Windows 10 / Windows Server 2016 or higher. Detected $($OsCimInfo.Caption) (Build $($OsCimInfo.BuildNumber))."
}

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    # Unattended hosts (SYSTEM task, Intune, RMM) cannot answer a UAC prompt, so only self-elevate interactively.
    if (-not [Environment]::UserInteractive) {
        throw 'Administrator privileges are required. Run this script as SYSTEM or from an elevated session.'
    }

    $ArgumentList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$($MyInvocation.MyCommand.Path)`"")
    foreach ($Parameter in $PSBoundParameters.GetEnumerator()) {
        if ($Parameter.Value -is [switch]) {
            if ($Parameter.Value.IsPresent) { $ArgumentList += "-$($Parameter.Key)" }
        }
        else {
            $ArgumentList += "-$($Parameter.Key)"
            $ArgumentList += "`"$($Parameter.Value)`""
        }
    }

    Start-Process -FilePath PowerShell.exe -Verb RunAs -ArgumentList $ArgumentList
    exit
}

$ProgressPreference = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
try { $Host.UI.RawUI.WindowTitle = "Windows Update Maintenance - $env:COMPUTERNAME" } catch { }

# ---------------------------------------------------------------------------------------------------------------
# Script state
# ---------------------------------------------------------------------------------------------------------------

$Script:RunStartTime = Get-Date
$Script:ExitCode = 0
$Script:BitsJobName = 'WindowsUpdateMaintenance_KB_Download'
$Script:InstallSuccessCodes = @(0, 3010, 2359302)
# 0x80240017 (WU_E_NOT_APPLICABLE), 0x800F081E (CBS_E_NOT_APPLICABLE), 0x240006 (WU_S_ALREADY_INSTALLED),
# as reported by wusa.exe (unsigned) and by DISM HRESULTs (signed).
$Script:NotApplicableCodes = @(2149842967, -2145124329, 2148468766, -2146498530, 2359302)
$Script:CatalogSearchUri = 'https://www.catalog.update.microsoft.com/Search.aspx'
$Script:CatalogDownloadUri = 'https://catalog.update.microsoft.com/DownloadDialog.aspx'
$Script:AllowedDownloadHosts = @('download.windowsupdate.com', 'catalog.s.download.windowsupdate.com', 'catalog.sf.dl.delivery.mp.microsoft.com', 'dl.delivery.mp.microsoft.com')

$Script:PayloadPath = Join-Path -Path $StagingPath -ChildPath 'Payload'
$Script:ExtractPath = Join-Path -Path $StagingPath -ChildPath 'Extract'
if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = Join-Path -Path $StagingPath -ChildPath 'Logs' }

foreach ($Directory in @($StagingPath, $Script:PayloadPath, $Script:ExtractPath, $LogPath)) {
    if (-not (Test-Path -LiteralPath $Directory)) {
        New-Item -ItemType Directory -Path $Directory -Force -ErrorAction Stop | Out-Null
    }
}

$Script:LogFile = Join-Path -Path $LogPath -ChildPath ("WindowsUpdateMaintenance_{0}.log" -f $Script:RunStartTime.ToString('yyyy-MM-dd_HH-mm-ss'))
$Script:DismLogFile = Join-Path -Path $LogPath -ChildPath ("DISM_Install_{0}.log" -f $Script:RunStartTime.ToString('yyyy-MM-dd_HH-mm-ss'))
$Script:ReportFile = Join-Path -Path $LogPath -ChildPath ("Report_{0}.json" -f $Script:RunStartTime.ToString('yyyy-MM-dd_HH-mm-ss'))

# Rolling structured report emitted at the end of every run, successful or not.
$Script:Report = [ordered]@{
    Computer        = $env:COMPUTERNAME
    StartTimeUtc    = $Script:RunStartTime.ToUniversalTime().ToString('o')
    EndTimeUtc      = $null
    Status          = 'Unknown'
    System          = $null
    SearchQuery     = $null
    SelectedUpdate  = $null
    AlreadyInstalled = $false
    Download        = $null
    Installation    = $null
    Diagnostics     = $null
    Cleanup         = $null
    RebootRequired  = $false
    ExitCode        = $null
}

# ---------------------------------------------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------------------------------------------

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    $Line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'MM/dd/yyyy|HH:mm:ss'), $Level.PadRight(7), $Message

    switch ($Level) {
        'ERROR' { Write-Host $Line -ForegroundColor Red }
        'WARN' { Write-Host $Line -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $Line -ForegroundColor Green }
        'DEBUG' { Write-Verbose $Line }
        default { Write-Host $Line }
    }

    try { Add-Content -LiteralPath $Script:LogFile -Value $Line -Encoding UTF8 -ErrorAction Stop } catch { }
}

function Write-LogSection {
    param([Parameter(Mandatory = $true)][string]$Title)
    Write-Host ''
    Write-Host ('-' * 100) -ForegroundColor DarkGray
    Write-Log -Message $Title
    Write-Host ('-' * 100) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------------------------------------------
# Module 1: System inspection and build detection
# ---------------------------------------------------------------------------------------------------------------

function Get-SystemProfile {
    $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $CurrentVersion = Get-ItemProperty -Path $RegistryPath -ErrorAction Stop

    $Build = 0
    if ($CurrentVersion.CurrentBuildNumber) { $Build = [int]$CurrentVersion.CurrentBuildNumber }
    elseif ($CurrentVersion.CurrentBuild) { $Build = [int]$CurrentVersion.CurrentBuild }

    $Ubr = 0
    if ($null -ne $CurrentVersion.UBR) { $Ubr = [int]$CurrentVersion.UBR }

    # DisplayVersion (22H2/23H2/24H2) replaced ReleaseId starting with Windows 10 20H2.
    $ReleaseVersion = $CurrentVersion.DisplayVersion
    if ([string]::IsNullOrWhiteSpace($ReleaseVersion)) { $ReleaseVersion = $CurrentVersion.ReleaseId }

    switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { $Architecture = 'x64'; $CatalogArchitecture = 'x64-based Systems' }
        'ARM64' { $Architecture = 'arm64'; $CatalogArchitecture = 'ARM64-based Systems' }
        'x86' { $Architecture = 'x86'; $CatalogArchitecture = 'x86-based Systems' }
        default { $Architecture = $env:PROCESSOR_ARCHITECTURE; $CatalogArchitecture = 'x64-based Systems' }
    }

    # ProductType 1 = Workstation, 2 = Domain Controller, 3 = Server.
    $IsServer = ([int]$OsCimInfo.ProductType -ne 1)
    $IsWindows11 = ($Build -ge 22000)

    [pscustomobject]@{
        Caption             = $OsCimInfo.Caption
        ProductName         = $CurrentVersion.ProductName
        Edition             = $CurrentVersion.EditionID
        InstallationType    = $CurrentVersion.InstallationType
        Build               = $Build
        Ubr                 = $Ubr
        FullBuild           = ('{0}.{1}' -f $Build, $Ubr)
        ReleaseVersion      = $ReleaseVersion
        Architecture        = $Architecture
        CatalogArchitecture = $CatalogArchitecture
        IsServer            = $IsServer
        IsWindows11         = $IsWindows11
    }
}

function Get-CatalogSearchQuery {
    param([Parameter(Mandatory = $true)][pscustomobject]$SystemProfile)

    if ($SystemProfile.IsServer) {
        # Server 2022 and newer are published under the "Microsoft server operating system" moniker.
        switch ($true) {
            { $SystemProfile.Build -ge 26100 } { $Product = 'Microsoft server operating system version 24H2'; break }
            { $SystemProfile.Build -ge 25398 } { $Product = 'Microsoft server operating system version 23H2'; break }
            { $SystemProfile.Build -ge 20348 } { $Product = 'Microsoft server operating system version 21H2'; break }
            { $SystemProfile.Build -ge 17763 } { $Product = 'Windows Server 2019'; break }
            default { $Product = 'Windows Server 2016' }
        }
    }
    elseif ($SystemProfile.IsWindows11) {
        $Product = 'Windows 11'
        if ($SystemProfile.ReleaseVersion) { $Product = "Windows 11 Version $($SystemProfile.ReleaseVersion)" }
    }
    else {
        $Product = 'Windows 10'
        if ($SystemProfile.ReleaseVersion) { $Product = "Windows 10 Version $($SystemProfile.ReleaseVersion)" }
    }

    return ('Cumulative Update for {0} for {1}' -f $Product, $SystemProfile.CatalogArchitecture)
}

# ---------------------------------------------------------------------------------------------------------------
# Module 2: Microsoft Update Catalog querying
# ---------------------------------------------------------------------------------------------------------------

function ConvertFrom-HtmlText {
    param([string]$Html)
    if ([string]::IsNullOrEmpty($Html)) { return '' }
    $Text = [regex]::Replace($Html, '<[^>]+>', ' ')
    $Text = [System.Net.WebUtility]::HtmlDecode($Text)
    return ($Text -replace '\s+', ' ').Trim()
}

function Invoke-CatalogSearch {
    param(
        [Parameter(Mandatory = $true)][string]$Query,
        [Parameter(Mandatory = $true)][pscustomobject]$SystemProfile
    )

    $Uri = '{0}?q={1}' -f $Script:CatalogSearchUri, [uri]::EscapeDataString($Query)
    Write-Log -Message "Querying the Microsoft Update Catalog: $Query"

    $Response = $null
    for ($Attempt = 1; $Attempt -le 3; $Attempt++) {
        try {
            $Response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 90 -ErrorAction Stop
            break
        }
        catch {
            Write-Log -Level WARN -Message "Catalog query attempt $Attempt failed: $($_.Exception.Message)"
            if ($Attempt -eq 3) { throw "Unable to reach the Microsoft Update Catalog: $($_.Exception.Message)" }
            Start-Sleep -Seconds (5 * $Attempt)
        }
    }

    $Html = $Response.Content
    if ($Html -match 'We did not find any results|no results were found') {
        Write-Log -Level WARN -Message 'The catalog returned no results for this search term.'
        return @()
    }

    $Results = New-Object System.Collections.Generic.List[object]
    foreach ($Row in [regex]::Matches($Html, '(?is)<tr[^>]*id="([0-9a-f\-]{36})_R\d+"[^>]*>(.*?)</tr>')) {
        $UpdateId = $Row.Groups[1].Value
        $RowHtml = $Row.Groups[2].Value

        $Cells = @()
        foreach ($Cell in [regex]::Matches($RowHtml, '(?is)<td[^>]*>(.*?)</td>')) {
            $Cells += (ConvertFrom-HtmlText -Html $Cell.Groups[1].Value)
        }
        if ($Cells.Count -lt 5) { continue }

        $Title = $Cells[1]
        $LastUpdatedText = $Cells[4]
        $LastUpdated = [datetime]::MinValue
        [datetime]::TryParse($LastUpdatedText, [ref]$LastUpdated) | Out-Null

        $SizeText = ''
        if ($Cells.Count -ge 7) { $SizeText = $Cells[6] }

        $KbMatch = [regex]::Match($Title, 'KB(\d{6,9})')
        if (-not $KbMatch.Success) { continue }

        # Most cumulative update titles end with the resulting build revision, e.g. "(26200.8894)".
        $TargetBuild = 0
        $TargetUbr = 0
        $BuildMatch = [regex]::Match($Title, '\((\d{5})\.(\d{1,6})\)')
        if ($BuildMatch.Success) {
            $TargetBuild = [int]$BuildMatch.Groups[1].Value
            $TargetUbr = [int]$BuildMatch.Groups[2].Value
        }

        $Results.Add([pscustomobject]@{
                UpdateId    = $UpdateId
                Title       = $Title
                KbId        = 'KB' + $KbMatch.Groups[1].Value
                Products    = $Cells[2]
                Classification = $Cells[3]
                LastUpdated = $LastUpdated
                SizeText    = $SizeText
                TargetBuild = $TargetBuild
                TargetUbr   = $TargetUbr
            })
    }

    Write-Log -Message "Catalog returned $($Results.Count) parsed result(s)."
    return $Results
}

function Select-ApplicableUpdate {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$CatalogResults,
        [Parameter(Mandatory = $true)][pscustomobject]$SystemProfile
    )

    $ArchToken = $SystemProfile.CatalogArchitecture
    $Filtered = $CatalogResults | Where-Object {
        $_.Title -like '*Cumulative Update*' -and
        $_.Title -notlike '*.NET Framework*' -and
        $_.Title -notlike '*Dynamic Update*' -and
        $_.Title -like "*$ArchToken*"
    }

    if (-not $IncludePreview) {
        $Filtered = $Filtered | Where-Object { $_.Title -notlike '*Preview*' }
    }

    if ($SystemProfile.ReleaseVersion) {
        # Keep the strictest match first; fall back to the unfiltered set if the release token is absent from titles.
        $VersionMatched = $Filtered | Where-Object { $_.Title -like "*$($SystemProfile.ReleaseVersion)*" }
        if ($VersionMatched) { $Filtered = $VersionMatched }
    }

    $Selected = $Filtered | Sort-Object -Property LastUpdated, TargetUbr -Descending | Select-Object -First 1
    return $Selected
}

function Get-CatalogDownloadUrl {
    param([Parameter(Mandatory = $true)][string]$UpdateId)

    $UpdateInfo = '[{{"size":0,"languages":"","uidInfo":"{0}","updateID":"{0}"}}]' -f $UpdateId
    $Body = 'updateIDs={0}&updateIDsBlockedForImport=&wsusApiPresent=&contentImport=&sku=&serverName=&ssl=&portNumber=&version=' -f [uri]::EscapeDataString($UpdateInfo)

    $Response = Invoke-WebRequest -Uri $Script:CatalogDownloadUri -Method Post -Body $Body -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -TimeoutSec 90 -ErrorAction Stop

    $Urls = New-Object System.Collections.Generic.List[string]
    foreach ($Match in [regex]::Matches($Response.Content, "(?i)'(https?://[^']+\.msu)'")) {
        $Url = $Match.Groups[1].Value
        if (-not $Urls.Contains($Url)) { $Urls.Add($Url) }
    }

    if ($Urls.Count -eq 0) { throw "The catalog did not return a .msu download link for update $UpdateId." }

    # Never follow an arbitrary host returned by scraped markup - restrict to the Microsoft CDN and force TLS.
    # The catalog returns prerequisite packages (checkpoint/SSU) before the cumulative payload, so order is preserved.
    $Trusted = New-Object System.Collections.Generic.List[string]
    foreach ($Url in $Urls) {
        $ParsedUri = [uri]$Url
        if ($Script:AllowedDownloadHosts -contains $ParsedUri.Host -or $ParsedUri.Host -like '*.download.windowsupdate.com' -or $ParsedUri.Host -like '*.delivery.mp.microsoft.com') {
            $Trusted.Add(('https://{0}{1}' -f $ParsedUri.Host, $ParsedUri.PathAndQuery))
        }
        else {
            Write-Log -Level WARN -Message "Rejected non-Microsoft download host returned by the catalog: $($ParsedUri.Host)"
        }
    }

    if ($Trusted.Count -eq 0) { throw "No download link from a trusted Microsoft host was returned for update $UpdateId." }

    return $Trusted.ToArray()
}

# ---------------------------------------------------------------------------------------------------------------
# Module 3: Installed state and pre-flight verification
# ---------------------------------------------------------------------------------------------------------------

function Test-UpdateInstalled {
    param([Parameter(Mandatory = $true)][string]$KbId)

    $Number = $KbId -replace '\D', ''

    try {
        if (Get-HotFix -Id "KB$Number" -ErrorAction Stop) { return $true }
    }
    catch { }

    try {
        $Package = Get-WindowsPackage -Online -ErrorAction Stop |
            Where-Object { $_.PackageName -match "KB$Number" -and $_.PackageState -in @('Installed', 'Superseded', 'InstallPending') }
        if ($Package) { return $true }
    }
    catch {
        Write-Log -Level DEBUG -Message "Get-WindowsPackage check skipped: $($_.Exception.Message)"
    }

    return $false
}

function Test-PendingReboot {
    $Paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress'
    )
    foreach ($Path in $Paths) {
        if (Test-Path -LiteralPath $Path) { return $true }
    }

    $SessionManager = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
    return [bool]$SessionManager.PendingFileRenameOperations
}

function Test-StagingFreeSpace {
    $Drive = (Split-Path -Path $StagingPath -Qualifier)
    $Volume = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $Drive) -ErrorAction SilentlyContinue
    if (-not $Volume) { return $true }

    $FreeGB = [math]::Round($Volume.FreeSpace / 1GB, 2)
    Write-Log -Message "Free space on ${Drive} $FreeGB GB (minimum required: $MinimumFreeSpaceGB GB)."
    return ($FreeGB -ge $MinimumFreeSpaceGB)
}

# ---------------------------------------------------------------------------------------------------------------
# Module 4: Download (BITS with HTTP fallback)
# ---------------------------------------------------------------------------------------------------------------

function Invoke-PayloadDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if (Test-Path -LiteralPath $Destination) {
        Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
    }

    $Engine = 'HTTP'
    if ($DownloadMethod -eq 'BITS') {
        $BitsService = Get-Service -Name BITS -ErrorAction SilentlyContinue
        if ($BitsService -and $BitsService.StartType -ne 'Disabled') {
            try {
                if ($BitsService.Status -ne 'Running') { Start-Service -Name BITS -ErrorAction Stop }
                Write-Log -Message 'Downloading payload via BITS (Start-BitsTransfer).'
                Start-BitsTransfer -Source $Url -Destination $Destination -DisplayName $Script:BitsJobName -Priority Foreground -ErrorAction Stop
                $Engine = 'BITS'
            }
            catch {
                Write-Log -Level WARN -Message "BITS transfer failed ($($_.Exception.Message)). Falling back to direct HTTP."
            }
        }
        else {
            Write-Log -Level WARN -Message 'The BITS service is unavailable or disabled. Falling back to direct HTTP.'
        }
    }

    if (-not (Test-Path -LiteralPath $Destination)) {
        Write-Log -Message 'Downloading payload via direct HTTP stream.'
        Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
        $Client = [System.Net.Http.HttpClient]::new()
        $FileStream = $null
        $HttpStream = $null
        try {
            $Client.Timeout = [TimeSpan]::FromMinutes(60)
            $Response = $Client.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            $Response.EnsureSuccessStatusCode() | Out-Null
            $HttpStream = $Response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $FileStream = [System.IO.File]::Create($Destination)
            $HttpStream.CopyTo($FileStream)
        }
        finally {
            if ($FileStream) { $FileStream.Dispose() }
            if ($HttpStream) { $HttpStream.Dispose() }
            $Client.Dispose()
        }
        $Engine = 'HTTP'
    }

    $File = Get-Item -LiteralPath $Destination -ErrorAction Stop
    if ($File.Length -lt 1MB) {
        throw "The downloaded payload is only $($File.Length) bytes, which is not a valid .msu package."
    }

    Write-Log -Level SUCCESS -Message ("Downloaded {0} ({1:N2} MB) using {2}." -f $File.Name, ($File.Length / 1MB), $Engine)

    return [pscustomobject]@{
        Engine   = $Engine
        Url      = $Url
        Path     = $File.FullName
        SizeBytes = $File.Length
    }
}

# ---------------------------------------------------------------------------------------------------------------
# Module 5: Unattended installation
# ---------------------------------------------------------------------------------------------------------------

function Install-UpdateWithWusa {
    param([Parameter(Mandatory = $true)][string]$MsuPath)

    Write-Log -Message "Installing via wusa.exe: $MsuPath"
    $Process = Start-Process -FilePath "$env:SystemRoot\System32\wusa.exe" -ArgumentList "`"$MsuPath`" /quiet /norestart" -Wait -PassThru -ErrorAction Stop
    return [pscustomobject]@{
        Method   = 'WUSA'
        ExitCode = $Process.ExitCode
        Packages = @([System.IO.Path]::GetFileName($MsuPath))
    }
}

function Install-UpdateWithDism {
    param([Parameter(Mandatory = $true)][string]$MsuPath)

    if (Test-Path -LiteralPath $Script:ExtractPath) {
        Get-ChildItem -LiteralPath $Script:ExtractPath -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Log -Message "Expanding MSU payload to $($Script:ExtractPath)"
    $ExpandOutput = & "$env:SystemRoot\System32\expand.exe" -f:* "$MsuPath" "$Script:ExtractPath" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "expand.exe failed with exit code $LASTEXITCODE. $($ExpandOutput -join ' ')"
    }

    $Cabs = Get-ChildItem -LiteralPath $Script:ExtractPath -Filter '*.cab' -File -ErrorAction Stop |
        Where-Object { $_.Name -notmatch '^(WSUSSCAN|WSUSSCAN\.cab)' -and $_.Name -notlike 'WSUSSCAN*' }

    if (-not $Cabs) { throw 'No installable .cab package was found inside the expanded MSU payload.' }

    # A servicing stack update bundled inside the MSU must be applied before the cumulative payload.
    $Ordered = @($Cabs | Where-Object { $_.Name -match 'SSU|ServicingStack' }) + @($Cabs | Where-Object { $_.Name -notmatch 'SSU|ServicingStack' })

    $ExitCode = 0
    $Installed = New-Object System.Collections.Generic.List[string]
    foreach ($Cab in $Ordered) {
        Write-Log -Message "Applying package: $($Cab.Name)"
        try {
            $Result = Add-WindowsPackage -Online -PackagePath $Cab.FullName -NoRestart -LogPath $Script:DismLogFile -ErrorAction Stop
            $Installed.Add($Cab.Name)
            if ($Result.RestartNeeded) { $ExitCode = 3010 }
        }
        catch {
            $HResult = $_.Exception.HResult
            Write-Log -Level ERROR -Message "Add-WindowsPackage failed for $($Cab.Name): $($_.Exception.Message)"
            return [pscustomobject]@{
                Method   = 'DISM'
                ExitCode = $HResult
                Packages = $Installed.ToArray()
            }
        }
    }

    return [pscustomobject]@{
        Method   = 'DISM'
        ExitCode = $ExitCode
        Packages = $Installed.ToArray()
    }
}

function Install-UpdatePayload {
    param([Parameter(Mandatory = $true)][string[]]$MsuPaths)

    $Packages = New-Object System.Collections.Generic.List[string]
    $AggregateExitCode = 0

    for ($Index = 0; $Index -lt $MsuPaths.Count; $Index++) {
        $MsuPath = $MsuPaths[$Index]
        $IsPrerequisite = ($Index -lt ($MsuPaths.Count - 1))

        if ($InstallMethod -eq 'WUSA') { $Result = Install-UpdateWithWusa -MsuPath $MsuPath }
        else { $Result = Install-UpdateWithDism -MsuPath $MsuPath }

        foreach ($Package in $Result.Packages) { $Packages.Add($Package) }

        # A prerequisite (checkpoint/SSU) package that is already present or not applicable must not fail the run.
        if ($IsPrerequisite -and $Script:NotApplicableCodes -contains $Result.ExitCode) {
            Write-Log -Level WARN -Message ("Prerequisite package '{0}' reported {1} - already present or not applicable. Continuing." -f [System.IO.Path]::GetFileName($MsuPath), (ConvertTo-HResultHex -Code $Result.ExitCode))
            continue
        }

        if ($Script:InstallSuccessCodes -notcontains $Result.ExitCode) {
            return [pscustomobject]@{
                Method   = $Result.Method
                ExitCode = $Result.ExitCode
                Packages = $Packages.ToArray()
            }
        }

        if ($Result.ExitCode -eq 3010) { $AggregateExitCode = 3010 }
    }

    return [pscustomobject]@{
        Method   = $InstallMethod
        ExitCode = $AggregateExitCode
        Packages = $Packages.ToArray()
    }
}

# ---------------------------------------------------------------------------------------------------------------
# Module 6: Diagnostic logging and error parsing
# ---------------------------------------------------------------------------------------------------------------

$Script:ErrorCodeTable = @{
    '0x00000000' = 'ERROR_SUCCESS - The operation completed successfully.'
    '0x00000BC2' = 'ERROR_SUCCESS_REBOOT_REQUIRED - The update installed and a restart is required.'
    '0x00240006' = 'WU_S_ALREADY_INSTALLED - The update is already installed on this system.'
    '0x00240005' = 'WU_S_ALREADY_DOWNLOADED - The update has already been downloaded.'
    '0x80070002' = 'ERROR_FILE_NOT_FOUND - A required update file or the SoftwareDistribution cache is missing/corrupt.'
    '0x80070003' = 'ERROR_PATH_NOT_FOUND - The servicing stack could not resolve a required path.'
    '0x80070005' = 'ERROR_ACCESS_DENIED - Insufficient privileges or a policy is blocking servicing.'
    '0x80070020' = 'ERROR_SHARING_VIOLATION - A file needed by the installer is locked by another process (often AV).'
    '0x800705B4' = 'ERROR_TIMEOUT - The servicing operation timed out.'
    '0x8007000D' = 'ERROR_INVALID_DATA - The downloaded package is corrupt or incomplete.'
    '0x80070422' = 'ERROR_SERVICE_DISABLED - The Windows Update or BITS service is disabled.'
    '0x8007371B' = 'ERROR_SXS_TRANSACTION_CLOSURE_INCOMPLETE - Component store corruption; run DISM /RestoreHealth.'
    '0x80073701' = 'ERROR_SXS_ASSEMBLY_MISSING - A referenced assembly is missing from the component store.'
    '0x800F081F' = 'CBS_E_SOURCE_MISSING - Source files required for servicing could not be found.'
    '0x800F081E' = 'CBS_E_NOT_APPLICABLE - The package is not applicable to this image (already installed or wrong build).'
    '0x800F0922' = 'CBS_E_INSTALLERS_FAILED - Installation failed, commonly a too-small System Reserved partition.'
    '0x800F0831' = 'CBS_E_STORE_CORRUPTION - The component store is missing a required prior update.'
    '0x800F0984' = 'PSFX_E_MATCHING_BINARY_MISSING - Servicing stack update mismatch; install the latest SSU first.'
    '0x800F0986' = 'PSFX_E_APPLY_FORWARD_DELTA_FAILED - Delta patch application failed; reset the update cache.'
    '0x80240017' = 'WU_E_NOT_APPLICABLE - The update is not applicable to this system (wrong build/edition/arch).'
    '0x80240034' = 'WU_E_DOWNLOAD_FAILED - The update failed to download.'
    '0x80240438' = 'WU_E_PT_ENDPOINT_UNREACHABLE - The update endpoint could not be reached (proxy/WSUS policy).'
    '0x80244022' = 'WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL - The update service returned HTTP 503.'
    '0x80248007' = 'WU_E_DS_NODATA - The Windows Update data store is missing required data.'
}

function ConvertTo-HResultHex {
    param([Parameter(Mandatory = $true)][int]$Code)
    # Negative HRESULTs returned by DISM must be reinterpreted as unsigned to match the documented hex codes.
    return ('0x{0:X8}' -f [BitConverter]::ToUInt32([BitConverter]::GetBytes($Code), 0))
}

function Resolve-ErrorCode {
    param([Parameter(Mandatory = $true)][int]$Code)

    $Hex = ConvertTo-HResultHex -Code $Code
    $Meaning = $Script:ErrorCodeTable[$Hex]
    if (-not $Meaning) {
        try {
            $Meaning = ([ComponentModel.Win32Exception]$Code).Message
        }
        catch { $Meaning = 'No description available for this code.' }
    }

    return [pscustomobject]@{
        ExitCode = $Code
        HResult  = $Hex
        Meaning  = $Meaning
    }
}

function Get-CbsLogErrors {
    param([Parameter(Mandatory = $true)][datetime]$Since)

    $CbsLog = Join-Path -Path $env:SystemRoot -ChildPath 'Logs\CBS\CBS.log'
    if (-not (Test-Path -LiteralPath $CbsLog)) { return @() }

    $Findings = New-Object System.Collections.Generic.List[string]
    try {
        # CBS.log routinely exceeds 100 MB, so only the tail is inspected.
        $Lines = Get-Content -LiteralPath $CbsLog -Tail 20000 -ErrorAction Stop
        foreach ($Line in $Lines) {
            if ($Line -notmatch '(?i)\b(error|failed|0x8[0-9a-f]{7})\b') { continue }

            $TimestampMatch = [regex]::Match($Line, '^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})')
            if ($TimestampMatch.Success) {
                $LineTime = [datetime]::MinValue
                if ([datetime]::TryParse($TimestampMatch.Groups[1].Value, [ref]$LineTime) -and $LineTime -lt $Since) { continue }
            }

            $Findings.Add($Line.Trim())
        }
    }
    catch {
        Write-Log -Level WARN -Message "Unable to parse CBS.log: $($_.Exception.Message)"
    }

    return ($Findings | Select-Object -Last 25)
}

function Get-ServicingEventLogErrors {
    param([Parameter(Mandatory = $true)][datetime]$Since)

    $Events = New-Object System.Collections.Generic.List[object]

    $Queries = @(
        @{ LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'; Level = @(1, 2, 3) },
        @{ LogName = 'System'; Level = @(1, 2, 3); Provider = @('Microsoft-Windows-WindowsUpdateClient', 'Microsoft-Windows-Servicing', 'Microsoft-Windows-WUSA') },
        @{ LogName = 'Setup'; Level = @(1, 2, 3) }
    )

    foreach ($Query in $Queries) {
        $Filter = @{ LogName = $Query.LogName; StartTime = $Since; Level = $Query.Level }
        if ($Query.Provider) { $Filter['ProviderName'] = $Query.Provider }
        try {
            Get-WinEvent -FilterHashtable $Filter -MaxEvents 25 -ErrorAction Stop | ForEach-Object {
                $Events.Add([pscustomobject]@{
                        TimeCreated = $_.TimeCreated.ToString('o')
                        LogName     = $_.LogName
                        Provider    = $_.ProviderName
                        Id          = $_.Id
                        Level       = $_.LevelDisplayName
                        Message     = ($_.Message -replace '\s+', ' ').Trim()
                    })
            }
        }
        catch {
            Write-Log -Level DEBUG -Message "No matching events in $($Query.LogName): $($_.Exception.Message)"
        }
    }

    return $Events.ToArray()
}

function Get-InstallDiagnostics {
    param(
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [Parameter(Mandatory = $true)][datetime]$Since
    )

    Write-LogSection -Title 'Module 6: Collecting failure diagnostics'
    $Resolved = Resolve-ErrorCode -Code $ExitCode
    Write-Log -Level ERROR -Message ("Installer exit code {0} ({1}): {2}" -f $Resolved.ExitCode, $Resolved.HResult, $Resolved.Meaning)

    $CbsErrors = @()
    if (-not $SkipCbsLogParsing) {
        Write-Log -Message 'Parsing CBS.log for servicing errors within the execution window.'
        $CbsErrors = Get-CbsLogErrors -Since $Since
        Write-Log -Message "Matched $($CbsErrors.Count) CBS log line(s)."
    }

    Write-Log -Message 'Querying Windows Update / servicing event logs.'
    $EventErrors = Get-ServicingEventLogErrors -Since $Since
    Write-Log -Message "Collected $($EventErrors.Count) event log record(s)."

    $ComponentStore = $null
    try {
        $ComponentStore = Repair-WindowsImage -Online -CheckHealth -ErrorAction Stop |
            Select-Object -Property ImageHealthState, RestartNeeded
    }
    catch {
        Write-Log -Level WARN -Message "Component store health check failed: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        ExitCode              = $Resolved.ExitCode
        HResult               = $Resolved.HResult
        Meaning               = $Resolved.Meaning
        CbsLogMatches         = $CbsErrors
        EventLogRecords       = $EventErrors
        ComponentServicingState = $ComponentStore
        DismLog               = $Script:DismLogFile
    }
}

# ---------------------------------------------------------------------------------------------------------------
# Module 7: Automated cleanup and lifecycle management
# ---------------------------------------------------------------------------------------------------------------

function Invoke-MaintenanceCleanup {
    param([bool]$InstallSucceeded)

    Write-LogSection -Title 'Module 7: Maintenance cleanup and lifecycle management'

    $Summary = [ordered]@{
        PayloadRemoved     = $false
        BitsJobsRemoved    = 0
        LogsPruned         = 0
        ComponentCleanupRun = $false
    }

    # Cancel orphaned or suspended BITS jobs created by this script.
    try {
        $Jobs = @(Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $Script:BitsJobName })
        foreach ($Job in $Jobs) {
            Remove-BitsTransfer -BitsJob $Job -ErrorAction SilentlyContinue
            $Summary.BitsJobsRemoved++
        }
        if ($Summary.BitsJobsRemoved -gt 0) { Write-Log -Message "Removed $($Summary.BitsJobsRemoved) orphaned BITS job(s)." }
    }
    catch {
        Write-Log -Level WARN -Message "BITS job sanitation failed: $($_.Exception.Message)"
    }

    # Purge staged payloads. The servicing stack has already committed the package by this point, so the
    # .msu/.cab files are no longer needed - even when a reboot is still pending.
    if ($KeepPayload) {
        Write-Log -Message '-KeepPayload specified: staged .msu/.cab files were left in place.'
    }
    else {
        foreach ($Directory in @($Script:PayloadPath, $Script:ExtractPath)) {
            try {
                if (Test-Path -LiteralPath $Directory) {
                    Get-ChildItem -LiteralPath $Directory -Force -ErrorAction SilentlyContinue |
                        Remove-Item -Recurse -Force -ErrorAction Stop
                }
            }
            catch {
                Write-Log -Level WARN -Message "Could not purge '$Directory': $($_.Exception.Message)"
            }
        }
        $Summary.PayloadRemoved = $true
        Write-Log -Message 'Purged staged .msu installers and extracted .cab files.'
    }

    # Log retention policy.
    if ($LogRetentionDays -gt 0) {
        $Cutoff = (Get-Date).AddDays(-$LogRetentionDays)
        $Stale = Get-ChildItem -LiteralPath $LogPath -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $Cutoff -and $_.FullName -ne $Script:LogFile }
        foreach ($File in $Stale) {
            try {
                Remove-Item -LiteralPath $File.FullName -Force -ErrorAction Stop
                $Summary.LogsPruned++
            }
            catch { }
        }
        Write-Log -Message "Pruned $($Summary.LogsPruned) log file(s) older than $LogRetentionDays day(s)."
    }

    # Optional WinSxS trim, only meaningful after a successful install.
    if ($ComponentCleanup -and $InstallSucceeded) {
        Write-Log -Message 'Running Dism.exe /Online /Cleanup-Image /StartComponentCleanup.'
        try {
            $Process = Start-Process -FilePath "$env:SystemRoot\System32\Dism.exe" -ArgumentList '/Online /Cleanup-Image /StartComponentCleanup /Quiet /NoRestart' -Wait -PassThru -ErrorAction Stop
            $Summary.ComponentCleanupRun = $true
            Write-Log -Message "Component cleanup finished with exit code $($Process.ExitCode)."
        }
        catch {
            Write-Log -Level WARN -Message "Component cleanup failed: $($_.Exception.Message)"
        }
    }

    return $Summary
}

function Write-RunReport {
    $Script:Report.EndTimeUtc = (Get-Date).ToUniversalTime().ToString('o')
    $Script:Report.ExitCode = $Script:ExitCode
    try {
        ($Script:Report | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $Script:ReportFile -Encoding UTF8 -ErrorAction Stop
        Write-Log -Message "Structured report written to $($Script:ReportFile)"
    }
    catch {
        Write-Log -Level WARN -Message "Could not write the JSON report: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------------------------

$InstallSucceeded = $false

try {
    Write-LogSection -Title "Windows Update Maintenance started on $env:COMPUTERNAME"
    Write-Log -Message "Staging path: $StagingPath | Log path: $LogPath"
    Write-Log -Message "Install method: $InstallMethod | Download method: $DownloadMethod"

    # --- Module 1 -------------------------------------------------------------------------------------------
    Write-LogSection -Title 'Module 1: System inspection and build detection'
    $SystemProfile = Get-SystemProfile
    $Script:Report.System = $SystemProfile
    Write-Log -Message "OS: $($SystemProfile.Caption) ($($SystemProfile.Edition))"
    Write-Log -Message "Build: $($SystemProfile.FullBuild) | Release: $($SystemProfile.ReleaseVersion) | Architecture: $($SystemProfile.Architecture) | Server: $($SystemProfile.IsServer)"

    if (Test-PendingReboot) {
        Write-Log -Level WARN -Message 'A reboot is already pending. Servicing operations may fail until the system restarts.'
    }

    # --- Module 2 -------------------------------------------------------------------------------------------
    Write-LogSection -Title 'Module 2: Catalog query and applicable KB identification'
    $Query = $SearchQuery
    if ([string]::IsNullOrWhiteSpace($Query)) { $Query = Get-CatalogSearchQuery -SystemProfile $SystemProfile }
    $Script:Report.SearchQuery = $Query

    $CatalogResults = @(Invoke-CatalogSearch -Query $Query -SystemProfile $SystemProfile)
    $Update = Select-ApplicableUpdate -CatalogResults $CatalogResults -SystemProfile $SystemProfile

    if (-not $Update) {
        Write-Log -Level WARN -Message 'No applicable cumulative update was found in the catalog for this system.'
        $Script:Report.Status = 'NoUpdateFound'
        $Script:ExitCode = 0
        return
    }

    $Script:Report.SelectedUpdate = $Update | Select-Object -Property KbId, Title, UpdateId, Classification, SizeText, TargetBuild, TargetUbr, @{ Name = 'LastUpdated'; Expression = { $_.LastUpdated.ToString('yyyy-MM-dd') } }
    Write-Log -Level SUCCESS -Message "Selected: $($Update.Title)"
    Write-Log -Message "KB: $($Update.KbId) | Released: $($Update.LastUpdated.ToString('yyyy-MM-dd')) | Size: $($Update.SizeText) | UpdateID: $($Update.UpdateId)"

    # --- Module 3 -------------------------------------------------------------------------------------------
    Write-LogSection -Title 'Module 3: Installed state and pre-flight verification'

    # Version guardrail: a machine already at or beyond the target build revision needs nothing installed.
    if ($Update.TargetBuild -eq $SystemProfile.Build -and $Update.TargetUbr -gt 0 -and $Update.TargetUbr -le $SystemProfile.Ubr -and -not $Force) {
        Write-Log -Level SUCCESS -Message "Installed build $($SystemProfile.FullBuild) is at or beyond the target build $($Update.TargetBuild).$($Update.TargetUbr). The system is current."
        $Script:Report.AlreadyInstalled = $true
        $Script:Report.Status = 'AlreadyCurrent'
        $Script:ExitCode = 0
        return
    }

    $AlreadyInstalled = Test-UpdateInstalled -KbId $Update.KbId
    $Script:Report.AlreadyInstalled = $AlreadyInstalled

    if ($AlreadyInstalled -and -not $Force) {
        Write-Log -Level SUCCESS -Message "$($Update.KbId) is already installed. The system is current - no action required."
        $Script:Report.Status = 'AlreadyCurrent'
        $Script:ExitCode = 0
        return
    }
    if ($AlreadyInstalled) {
        Write-Log -Level WARN -Message "$($Update.KbId) already appears installed but -Force was specified. Continuing."
    }

    if ($ReportOnly) {
        Write-Log -Message "-ReportOnly specified: $($Update.KbId) is applicable but will not be downloaded or installed."
        $Script:Report.Status = 'ReportOnly'
        $Script:ExitCode = 0
        return
    }

    if (-not (Test-StagingFreeSpace)) {
        throw "Insufficient free disk space on the staging volume (minimum $MinimumFreeSpaceGB GB required)."
    }

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Download and install $($Update.KbId)")) {
        Write-Log -Message 'Operation cancelled by ShouldProcess (-WhatIf/-Confirm).'
        $Script:Report.Status = 'Skipped'
        return
    }

    # --- Module 4 -------------------------------------------------------------------------------------------
    Write-LogSection -Title 'Module 4: Payload download'
    $DownloadUrls = @(Get-CatalogDownloadUrl -UpdateId $Update.UpdateId)
    Write-Log -Message "Catalog returned $($DownloadUrls.Count) package file(s) for $($Update.KbId)."

    $Downloads = New-Object System.Collections.Generic.List[object]
    foreach ($DownloadUrl in $DownloadUrls) {
        Write-Log -Message "Resolved download URL: $DownloadUrl"
        $FileName = [System.IO.Path]::GetFileName(([uri]$DownloadUrl).LocalPath)
        if ([string]::IsNullOrWhiteSpace($FileName)) { $FileName = "$($Update.KbId).msu" }
        $MsuPath = Join-Path -Path $Script:PayloadPath -ChildPath $FileName
        $Downloads.Add((Invoke-PayloadDownload -Url $DownloadUrl -Destination $MsuPath))
    }
    $Script:Report.Download = $Downloads.ToArray()

    # --- Module 5 -------------------------------------------------------------------------------------------
    Write-LogSection -Title 'Module 5: Unattended installation'
    $InstallStart = Get-Date
    $Install = Install-UpdatePayload -MsuPaths @($Downloads.Path)

    $Resolved = Resolve-ErrorCode -Code $Install.ExitCode
    $Script:Report.Installation = [pscustomobject]@{
        Method    = $Install.Method
        ExitCode  = $Resolved.ExitCode
        HResult   = $Resolved.HResult
        Meaning   = $Resolved.Meaning
        Packages  = $Install.Packages
        DurationSeconds = [math]::Round(((Get-Date) - $InstallStart).TotalSeconds, 0)
    }

    # 0 = installed, 3010/0xBC2 = installed + reboot required, 0x240006 = already installed.
    if ($Script:InstallSuccessCodes -contains $Install.ExitCode) {
        $InstallSucceeded = $true
        $RebootRequired = ($Install.ExitCode -eq 3010) -or (Test-PendingReboot)
        $Script:Report.RebootRequired = $RebootRequired
        $Script:Report.Status = 'Installed'
        Write-Log -Level SUCCESS -Message "$($Update.KbId) installed successfully via $($Install.Method)."

        if ($RebootRequired) {
            Write-Log -Level WARN -Message 'A restart is required to complete servicing.'
            $Script:ExitCode = 3010
        }
        else {
            $Script:ExitCode = 0
        }
    }
    else {
        # --- Module 6 ---------------------------------------------------------------------------------------
        $Script:Report.Status = 'Failed'
        $Script:Report.Diagnostics = Get-InstallDiagnostics -ExitCode $Install.ExitCode -Since $InstallStart
        $Script:ExitCode = 1
    }
}
catch {
    Write-Log -Level ERROR -Message "Fatal error: $($_.Exception.Message)"
    Write-Log -Level DEBUG -Message $_.ScriptStackTrace
    $Script:Report.Status = 'Error'
    $Script:Report.Diagnostics = [pscustomobject]@{
        Exception  = $_.Exception.Message
        StackTrace = $_.ScriptStackTrace
    }
    $Script:ExitCode = 1
}
finally {
    # --- Module 7 -----------------------------------------------------------------------------------------------
    $Script:Report.Cleanup = Invoke-MaintenanceCleanup -InstallSucceeded $InstallSucceeded
    Write-RunReport

    Write-LogSection -Title "Windows Update Maintenance finished - Status: $($Script:Report.Status) | Exit code: $($Script:ExitCode)"

    if ($AutoReboot -and $Script:Report.RebootRequired) {
        Write-Log -Level WARN -Message "-AutoReboot specified: restarting in $RebootDelaySeconds second(s)."
        & "$env:SystemRoot\System32\shutdown.exe" /r /t $RebootDelaySeconds /c 'Restarting to complete Windows Update servicing.' | Out-Null
    }

    exit $Script:ExitCode
}
