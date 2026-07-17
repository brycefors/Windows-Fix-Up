# --- SCRIPT OVERVIEW ---
# This script builds a fully up-to-date ("slipstreamed") Windows 11 (or Windows 10) installation ISO.
# It downloads the latest official Microsoft ISO, downloads the latest cumulative update(s) from the
# Microsoft Update Catalog, integrates those updates directly into the Windows images inside the ISO,
# and then recompiles a brand-new, bootable ISO that already contains this month's patches.
#
# Building patched media means a fresh install (or in-place upgrade) starts already updated, instead of
# spending an hour downloading and installing the same cumulative update after Setup finishes.
#
# It performs the following actions:
#   1. Obtains the matching official Microsoft ISO (via the community "Fido" helper, which queries
#      Microsoft's own software-download servers) and downloads it - unless you supply one with -IsoPath.
#      RECOMMENDED: download the ISO yourself and pass it with -IsoPath. Microsoft rate-limits and can
#      temporarily block IPs that make repeated ISO requests, which breaks the automatic download; using
#      your own ISO avoids this (the script also reuses any ISO already in the download folder).
#   2. Extracts the ISO to a writable working folder.
#   3. Detects the Windows feature-update (e.g. 24H2) and architecture from the image, then downloads the
#      latest combined Servicing Stack + Cumulative Update (LCU) - and optionally the .NET cumulative
#      update - from the Microsoft Update Catalog. You may instead point at your own .msu/.cab files with
#      -UpdatePath.
#   4. Integrates the update(s) offline with DISM into install.wim (every edition, or one you pick),
#      boot.wim (Windows Setup / WinPE), and optionally winre.wim (recovery).
#   5. Cleans up the component store (/StartComponentCleanup /ResetBase) and re-exports install.wim to
#      shrink it.
#   6. Recompiles a new bootable ISO with oscdimg (from the Windows ADK), preserving both the BIOS and
#      UEFI boot sectors so the new ISO boots on legacy and modern PCs alike.
#
# This is disk- and time-intensive: it needs a lot of free space (the download, the extracted media, the
# mounted image, and the exported image all coexist) and DISM servicing/cleanup can take a long time.
# Nothing on the running machine is changed - all servicing happens against files in the working folder.
# -------------------------------------------------
# How to Run .PS1 Script with PowerShell:
# NOTE: It is recommended to use the "Run-Windows-ISO-Updater.bat" to invoke this script. However, you can run the .PS1 directly if needed.
# 1.  Open PowerShell as an Administrator: Right-click your Start Menu and select "Terminal (Admin)".
# 2.  Enable Script Execution (if needed): Set-ExecutionPolicy Bypass -Force
# 3.  Run the Script: Right-click the saved "Windows-ISO-Updater.ps1" file and select "Run with PowerShell".
# -------------------------------------------------
# Parameters for the script
param(
    [Parameter(HelpMessage = 'Runs the script without any confirmation prompts')]
    [switch]$Unattended,

    [Parameter(HelpMessage = 'Path to an existing Windows ISO to update instead of downloading one from Microsoft')]
    [string]$IsoPath,

    [Parameter(HelpMessage = 'Windows version to download/update: 10 or 11. Defaults to 11')]
    [ValidateSet('10', '11')]
    [string]$WindowsVersion = '11',

    [Parameter(HelpMessage = 'Fido release to request (e.g. 24H2, 23H2) or "Latest". Defaults to Latest')]
    [string]$Release = 'Latest',

    [Parameter(HelpMessage = 'ISO language as named by Microsoft/Fido (e.g. English, "English International"). Defaults to English')]
    [string]$Language = 'English',

    [Parameter(HelpMessage = 'Which edition inside install.wim to service: "All" (default) or an edition name like "Windows 11 Pro"')]
    [string]$Edition = 'All',

    [Parameter(HelpMessage = 'Editions to KEEP in the final ISO, removing the rest to slim it down. Accepts edition names like "Windows 11 Pro" (partial matches allowed) or index numbers, comma-separated. Defaults to keeping all editions')]
    [string[]]$KeepEditions,

    [Parameter(HelpMessage = 'Only list the editions/indexes inside the ISO''s install.wim and exit (does not download updates or build anything). Useful for choosing -Edition/-KeepEditions values')]
    [switch]$ListEditions,

    [Parameter(HelpMessage = 'Folder containing your own .msu/.cab update packages to integrate instead of fetching from the Microsoft Update Catalog')]
    [string]$UpdatePath,

    [Parameter(HelpMessage = 'Also download and integrate the latest .NET cumulative update from the Microsoft Update Catalog')]
    [switch]$IncludeDotNet,

    [Parameter(HelpMessage = 'Also service the recovery image (winre.wim). Off by default; the correct component for WinRE is the Safe OS Dynamic Update, which is fetched when available')]
    [switch]$ServiceWinRE,

    [Parameter(HelpMessage = 'Skip integrating updates entirely and simply extract and recompile the ISO (useful for testing the build pipeline)')]
    [switch]$SkipUpdates,

    [Parameter(HelpMessage = 'Directory to download the ISO/updates into (defaults to the script folder). Needs several GB free')]
    [string]$DownloadPath,

    [Parameter(HelpMessage = 'Working folder used to extract and service the media. Must be on a fast drive with lots of free space. Defaults to <SystemDrive>\WISO-Work')]
    [string]$WorkPath,

    [Parameter(HelpMessage = 'Full path for the recompiled ISO. Defaults to the download folder with an "-Updated" suffix')]
    [string]$OutputIsoPath,

    [Parameter(HelpMessage = 'Full path to oscdimg.exe if the Windows ADK is installed in a non-standard location')]
    [string]$OscdimgPath,

    [Parameter(HelpMessage = 'If oscdimg.exe (Windows ADK Deployment Tools) is not found, download and silently install it from Microsoft')]
    [switch]$InstallAdk,

    [Parameter(HelpMessage = 'Override the URL used to fetch the Fido download helper')]
    [string]$FidoUrl = 'https://github.com/pbatard/Fido/raw/master/Fido.ps1',

    [Parameter(HelpMessage = 'Override the URL used to download the Windows ADK setup bootstrapper (Deployment Tools)')]
    [string]$AdkSetupUrl = 'https://go.microsoft.com/fwlink/?linkid=2289980',

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
$Host.UI.RawUI.WindowTitle = "Windows ISO Updater - Running as Administrator"

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
$LogFile = Join-Path -Path $LogDir -ChildPath "Windows-ISO-Updater_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').log"
Start-Transcript -Path $LogFile | Out-Null

# Rotate logs: keep only the 30 most recent, delete the rest
Get-ChildItem -Path $LogDir -Filter 'Windows-ISO-Updater_*.log' -File |
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

# Returns the free space (GB, rounded to two decimals) on the drive that holds the given path, or $null.
function Get-DriveFreeGB {
    param([string]$Path)
    try {
        $Qualifier = (Split-Path -Path $Path -Qualifier -ErrorAction SilentlyContinue)
        if (-not $Qualifier) { $Qualifier = $env:SystemDrive }
        $Drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$Qualifier'" -ErrorAction Stop
        if ($Drive -and $Drive.FreeSpace) {
            return [math]::Round($Drive.FreeSpace / 1GB, 2)
        }
    }
    catch { }
    return $null
}

# Detects the currently-installed Windows version/architecture so the Fido download request can reuse it.
function Get-InstalledWindowsInfo {
    $Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'x64' }
        'ARM64' { 'arm64' }
        'x86'   { 'x86' }
        default { 'x64' }
    }
    [PSCustomObject]@{ Architecture = $Arch }
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
            Write-HostTimestamp '  Downloading with BITS...'
            Start-BitsTransfer -Source $Url -Destination $Destination -Description 'Windows download' -ErrorAction Stop
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

# Verifies a download URL points at an official Microsoft-owned host over HTTPS, so the script never
# downloads content from somewhere it should not. Microsoft serves ISOs and updates from hosts under
# microsoft.com, windowsupdate.com, and delivery.mp.microsoft.com. Returns $true only for an https:// URL
# whose host is one of those domains or a subdomain of them. Using the parsed Host (not a substring of
# the raw URL) avoids spoofing like "microsoft.com.evil.example".
function Test-MicrosoftDownloadUrl {
    param([string]$Url)
    if (-not $Url) { return $false }
    try { $Uri = [Uri]$Url } catch { return $false }
    if ($Uri.Scheme -ne 'https') { return $false }
    return ($Uri.Host -match '(?i)(^|\.)(microsoft\.com|windowsupdate\.com)$')
}

# Uses the community "Fido" helper (which queries Microsoft's own software-download servers) to resolve
# the official, matching Windows ISO download URL. Downloads Fido to a temp file, runs it with -GetUrl,
# and returns the resulting URL string, or $null on failure. The resolved URL is verified to point at an
# official Microsoft host before being returned. Fido: https://github.com/pbatard/Fido
function Get-WindowsIsoUrl {
    param(
        [Parameter(Mandatory)][string]$Version,       # 10 or 11
        [Parameter(Mandatory)][string]$Release,        # e.g. Latest, 24H2
        [Parameter(Mandatory)][string]$Language,       # e.g. English
        [Parameter(Mandatory)][string]$Architecture    # x64 / arm64 / x86
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

    if (-not (Test-MicrosoftDownloadUrl -Url $Url)) {
        $BadHost = try { ([Uri]$Url).Host } catch { '(unparseable)' }
        Write-HostTimestamp "  The resolved download URL does not point at an official Microsoft host (host: $BadHost). Refusing to download it." -ForegroundColor Red
        return $null
    }
    Write-HostTimestamp "  Verified the ISO download comes from an official Microsoft host: $(([Uri]$Url).Host)" -ForegroundColor Green
    return $Url
}

# Maps a Windows build number to its marketing feature-update name (used to build catalog search queries).
function Get-FeatureUpdateName {
    param([Parameter(Mandatory)][int]$Build)
    switch ($Build) {
        26200  { '25H2'; break }
        26100  { '24H2'; break }
        22631  { '23H2'; break }
        22621  { '22H2'; break }
        22000  { '21H2'; break }
        19045  { '22H2'; break }   # Windows 10
        19044  { '21H2'; break }   # Windows 10
        default { $null }
    }
}

# --- Microsoft Update Catalog helpers ---
# The Microsoft Update Catalog (catalog.update.microsoft.com) has no public API, so these functions use
# the same technique the community relies on: fetch the search results page and parse it, then POST to the
# download dialog to obtain the direct package URL. Every resolved URL is validated to be a Microsoft host
# before it is downloaded.

# Searches the catalog and returns matching updates as PSCustomObjects (Guid, Title, LastUpdated, SizeMB).
function Search-UpdateCatalog {
    param([Parameter(Mandatory)][string]$Query)

    $EncodedQuery = [System.Uri]::EscapeDataString($Query)
    $SearchUrl = "https://www.catalog.update.microsoft.com/Search.aspx?q=$EncodedQuery"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    try {
        $Response = Invoke-WebRequest -Uri $SearchUrl -UseBasicParsing -ErrorAction Stop
    }
    catch {
        Write-HostTimestamp "  Could not query the Microsoft Update Catalog: $($_.Exception.Message)" -ForegroundColor Yellow
        return @()
    }

    $Html = $Response.Content
    $Results = New-Object System.Collections.Generic.List[object]

    # The catalog renders each result as an anchor  <a id='<GUID>_link' ...>Title</a>  (note the SINGLE
    # quotes), and its column values live in separate cells whose ids follow the pattern
    # "<GUID>_C<col>_R<row>" - C1=Title, C3=Classification, C4=Last Updated, C6=Size. We find every result
    # by its "_link" anchor, then read that GUID's date/size/classification cells by id.
    $LinkMatches = [regex]::Matches($Html, "(?s)id=['`"]([0-9a-fA-F-]{36})_link['`"][^>]*>(.*?)</a>")
    foreach ($Link in $LinkMatches) {
        $Guid = $Link.Groups[1].Value
        $Title = [System.Net.WebUtility]::HtmlDecode((([regex]::Replace($Link.Groups[2].Value, '<[^>]+>', ' ')).Trim() -replace '\s+', ' '))
        $EscGuid = [regex]::Escape($Guid)

        # Helper to read the visible text of a specific column cell for this GUID.
        $GetCell = {
            param([int]$Col)
            $M = [regex]::Match($Html, "(?s)id=`"${EscGuid}_C${Col}_R\d+`"[^>]*>(.*?)</td>")
            if ($M.Success) {
                return [System.Net.WebUtility]::HtmlDecode((([regex]::Replace($M.Groups[1].Value, '<[^>]+>', ' ')).Trim() -replace '\s+', ' '))
            }
            return $null
        }

        $Classification = & $GetCell 3
        $DateText = & $GetCell 4
        $SizeText = & $GetCell 6

        $LastUpdated = $null
        if ($DateText -and $DateText -match '(\d{1,2}/\d{1,2}/\d{4})') {
            try { $LastUpdated = [datetime]::Parse($Matches[1]) } catch { }
        }

        $SizeMB = $null
        if ($SizeText -and $SizeText -match '([\d.,]+)\s*(KB|MB|GB)') {
            $Value = [double]($Matches[1] -replace ',', '')
            $SizeMB = switch ($Matches[2]) {
                'KB' { [math]::Round($Value / 1024, 2) }
                'MB' { $Value }
                'GB' { [math]::Round($Value * 1024, 2) }
            }
        }

        $Results.Add([PSCustomObject]@{
            Guid           = $Guid
            Title          = $Title
            Classification = $Classification
            LastUpdated    = $LastUpdated
            SizeMB         = $SizeMB
        })
    }

    return $Results
}

# Resolves the direct download URL(s) for a catalog update GUID by POSTing to the download dialog.
function Get-UpdateCatalogDownloadUrl {
    param([Parameter(Mandatory)][string]$Guid)

    $DialogUrl = 'https://www.catalog.update.microsoft.com/DownloadDialog.aspx'
    $Body = "updateIDs=[{`"size`":0,`"languages`":`"`",`"uidInfo`":`"$Guid`",`"updateID`":`"$Guid`"}]&updateIDsBlockedForImport=&wsusApiPresent=&contentImport=&sqlserverImport=&updateID=$Guid"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    try {
        $Response = Invoke-WebRequest -Uri $DialogUrl -Method Post -Body $Body -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -ErrorAction Stop
    }
    catch {
        Write-HostTimestamp "  Could not resolve the download link for $Guid : $($_.Exception.Message)" -ForegroundColor Yellow
        return @()
    }

    # The dialog echoes the direct file URLs in JavaScript: downloadInformation[0].files[0].url = '...';
    $Urls = [regex]::Matches($Response.Content, "downloadInformation\[\d+\]\.files\[\d+\]\.url\s*=\s*'([^']+)'") |
        ForEach-Object { $_.Groups[1].Value } |
        Where-Object { $_ } |
        Select-Object -Unique

    return @($Urls)
}

# Finds the newest, non-preview cumulative update in the catalog for a given search query, downloads it
# to the download folder, and returns the local .msu path (or $null on failure).
function Get-LatestCatalogPackage {
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$DownloadDir,
        [string]$TitleInclude,   # regex the title MUST match (e.g. cumulative update wording)
        [string]$TitleExclude,   # regex the title must NOT match (e.g. ".net", "dynamic")
        [switch]$AllowPreview
    )

    Write-HostTimestamp "  Searching the Microsoft Update Catalog for: $Query"
    $Results = Search-UpdateCatalog -Query $Query
    if (-not $Results -or $Results.Count -eq 0) {
        Write-HostTimestamp '  No catalog results were returned for that query.' -ForegroundColor Yellow
        return $null
    }
    Write-HostTimestamp "  Found $($Results.Count) catalog result(s); selecting the best match..."

    # Narrow to the packages we actually want, then take the newest by date (largest as a tie-break).
    $Filtered = $Results
    if ($TitleInclude) { $Filtered = $Filtered | Where-Object { $_.Title -match $TitleInclude } }
    if ($TitleExclude) { $Filtered = $Filtered | Where-Object { $_.Title -notmatch $TitleExclude } }
    if (-not $AllowPreview) { $Filtered = $Filtered | Where-Object { $_.Title -notmatch '(?i)preview' } }
    if (-not $Filtered) {
        Write-HostTimestamp '  No catalog results matched the expected update type after filtering.' -ForegroundColor Yellow
        return $null
    }

    $Selected = $Filtered |
        Sort-Object -Property @{ Expression = { $_.LastUpdated }; Descending = $true }, @{ Expression = { $_.SizeMB }; Descending = $true } |
        Select-Object -First 1
    if (-not $Selected) {
        Write-HostTimestamp '  Could not select a suitable update from the catalog results.' -ForegroundColor Yellow
        return $null
    }

    Write-HostTimestamp "  Selected: $($Selected.Title)$(if ($Selected.LastUpdated) { " (released $($Selected.LastUpdated.ToString('yyyy-MM-dd')))" })" -ForegroundColor Green

    # A single catalog entry can resolve to MULTIPLE .msu files. For Windows 11 24H2/25H2, Microsoft uses
    # "checkpoint cumulative updates": the latest LCU download also includes one or more baseline/checkpoint
    # packages that MUST be integrated first. So download every file the dialog returns and order them so
    # the checkpoint/baseline packages come before the main LCU (identified by the KB in the title).
    $Urls = @(Get-UpdateCatalogDownloadUrl -Guid $Selected.Guid)
    $FileUrls = @($Urls | Where-Object { $_ -match '\.(msu|cab)(\?|$)' })
    if (-not $FileUrls) { $FileUrls = $Urls }
    if (-not $FileUrls -or $FileUrls.Count -eq 0) {
        Write-HostTimestamp '  The catalog did not return a download URL for the selected update.' -ForegroundColor Yellow
        return $null
    }

    $PrimaryKb = if ($Selected.Title -match '(?i)KB(\d{6,})') { $Matches[1] } else { $null }

    # Helper: extract the numeric KB from a URL/filename for ordering (checkpoints ascending, LCU last).
    $GetKb = { param($Text) if ($Text -match '(?i)kb(\d{6,})') { [int]$Matches[1] } else { 0 } }

    $Downloaded = New-Object System.Collections.Generic.List[object]
    foreach ($Url in $FileUrls) {
        if (-not (Test-MicrosoftDownloadUrl -Url $Url)) {
            $BadHost = try { ([Uri]$Url).Host } catch { '(unparseable)' }
            Write-HostTimestamp "  Skipping a download URL that is not an official Microsoft host (host: $BadHost)." -ForegroundColor Yellow
            continue
        }

        $FileName = $null
        try { $FileName = [System.IO.Path]::GetFileName(([Uri]$Url).AbsolutePath) } catch { }
        if (-not $FileName) { $FileName = "$($Selected.Guid)_$(& $GetKb $Url).msu" }
        $Destination = Join-Path -Path $DownloadDir -ChildPath $FileName

        if (Test-Path -LiteralPath $Destination) {
            Write-HostTimestamp "  Already downloaded - reusing: $FileName" -ForegroundColor DarkGray
        }
        else {
            Write-HostTimestamp "  Downloading $FileName ..."
            if (-not (Get-FileDownload -Url $Url -Destination $Destination)) {
                Write-HostTimestamp "  Failed to download $FileName." -ForegroundColor Red
                return $null
            }
            Write-HostTimestamp "    Downloaded ($([math]::Round((Get-Item -LiteralPath $Destination).Length / 1MB, 1)) MB)." -ForegroundColor Green
        }

        $Kb = & $GetKb $FileName
        $IsPrimary = ($PrimaryKb -and $FileName -match "(?i)kb$PrimaryKb")
        $Downloaded.Add([PSCustomObject]@{ Path = $Destination; Kb = $Kb; IsPrimary = [bool]$IsPrimary })
    }

    if ($Downloaded.Count -eq 0) {
        Write-HostTimestamp '  No update packages could be downloaded.' -ForegroundColor Red
        return $null
    }

    # Order: non-primary (checkpoints/SSU) first (oldest KB first), then the primary LCU last. If we could
    # not identify the primary KB, fall back to plain KB-ascending order.
    $Ordered = @(
        ($Downloaded | Where-Object { -not $_.IsPrimary } | Sort-Object Kb)
        ($Downloaded | Where-Object { $_.IsPrimary } | Sort-Object Kb)
    )
    if ($Downloaded.Count -gt 1) {
        Write-HostTimestamp "  This update includes $($Downloaded.Count) package(s); they will be integrated in this order:"
        $Ordered | ForEach-Object { Write-HostTimestamp "    - $(Split-Path -Leaf $_.Path)$(if ($_.IsPrimary) { ' (main cumulative update)' })" }
    }

    return @($Ordered | ForEach-Object { $_.Path })
}

# Locates oscdimg.exe (from the Windows ADK Deployment Tools), which is required to recompile the ISO.
# Checks -OscdimgPath, then PATH, then the standard ADK install locations. Returns the full path or $null.
function Find-Oscdimg {
    if ($OscdimgPath -and (Test-Path -LiteralPath $OscdimgPath)) { return (Resolve-Path -LiteralPath $OscdimgPath).Path }

    $OnPath = Get-Command 'oscdimg.exe' -ErrorAction SilentlyContinue
    if ($OnPath) { return $OnPath.Source }

    $Roots = @(
        ${env:ProgramFiles(x86)},
        $env:ProgramFiles
    ) | Where-Object { $_ }
    foreach ($Root in $Roots) {
        $Base = Join-Path $Root 'Windows Kits\10\Assessment and Deployment Kit\Deployment Tools'
        if (Test-Path $Base) {
            $Found = Get-ChildItem -Path $Base -Filter 'oscdimg.exe' -File -Recurse -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($Found) { return $Found.FullName }
        }
    }
    return $null
}

# Downloads the Windows ADK bootstrapper and silently installs ONLY the Deployment Tools feature (which
# contains oscdimg.exe). Returns the oscdimg path on success, or $null.
function Install-AdkDeploymentTools {
    if (-not (Test-MicrosoftDownloadUrl -Url $AdkSetupUrl) -and $AdkSetupUrl -notmatch '(?i)^https://go\.microsoft\.com/') {
        Write-HostTimestamp "  The ADK setup URL is not an official Microsoft URL. Refusing to download it: $AdkSetupUrl" -ForegroundColor Red
        return $null
    }

    $Setup = Join-Path -Path $env:TEMP -ChildPath "adksetup_$(Get-Date -Format 'yyyyMMdd_HHmmss').exe"
    Write-HostTimestamp '  Downloading the Windows ADK setup bootstrapper from Microsoft...'
    if (-not (Get-FileDownload -Url $AdkSetupUrl -Destination $Setup)) {
        Write-HostTimestamp '  Could not download the ADK setup bootstrapper.' -ForegroundColor Red
        return $null
    }

    Write-HostTimestamp '  Installing the ADK Deployment Tools silently (this downloads a few hundred MB and takes a few minutes)...'
    try {
        $Proc = Start-Process -FilePath $Setup -ArgumentList @('/quiet', '/norestart', '/features', 'OptionId.DeploymentTools') -Wait -PassThru -ErrorAction Stop
        if ($Proc.ExitCode -ne 0) {
            Write-HostTimestamp "  ADK setup returned exit code $($Proc.ExitCode)." -ForegroundColor Yellow
        }
    }
    catch {
        Write-HostTimestamp "  ADK installation failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
    finally {
        Remove-Item -LiteralPath $Setup -Force -ErrorAction SilentlyContinue
    }

    return (Find-Oscdimg)
}

# Returns the 8.3 short path for a file, avoiding spaces in paths passed to oscdimg's -bootdata argument.
function Get-ShortPath {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $Fso = New-Object -ComObject Scripting.FileSystemObject
        $Short = $Fso.GetFile($Path).ShortPath
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Fso) | Out-Null
        if ($Short) { return $Short }
    }
    catch { }
    return $Path
}

# Resolves a list of edition tokens (edition names, partial names, or index numbers) to the matching
# install.wim image indexes. Returns the distinct, sorted indexes that matched. Unmatched tokens are
# reported via the [ref]$Unmatched list so the caller can decide whether to fail.
function Resolve-EditionIndexes {
    param(
        [Parameter(Mandatory)][object[]]$Images,
        [Parameter(Mandatory)][string[]]$Tokens,
        [ref]$Unmatched
    )
    $Matched = New-Object System.Collections.Generic.List[int]
    $NoMatch = New-Object System.Collections.Generic.List[string]
    foreach ($Token in $Tokens) {
        $T = "$Token".Trim()
        if (-not $T) { continue }
        $Found = $null
        if ($T -match '^\d+$') {
            $Found = $Images | Where-Object { $_.ImageIndex -eq [int]$T }
        }
        else {
            $Found = $Images | Where-Object { $_.ImageName -eq $T }
            if (-not $Found) { $Found = $Images | Where-Object { $_.ImageName -like "*$T*" } }
        }
        if ($Found) { $Found | ForEach-Object { [void]$Matched.Add([int]$_.ImageIndex) } }
        else { [void]$NoMatch.Add($T) }
    }
    if ($Unmatched) { $Unmatched.Value = $NoMatch }
    return ($Matched | Sort-Object -Unique)
}

# Ensures a mount directory is clean and ready to receive a fresh WIM mount. A previous run that crashed
# or was killed can leave an image still mounted (or a corrupt mount point) there, which makes the next
# Mount-WindowsImage fail with "attempted to mount to a directory that is not empty". This discards any
# image still mounted at the path, clears stale/corrupt mount state, then recreates the empty directory.
function Reset-MountDirectory {
    param([Parameter(Mandatory)][string]$Path)

    $Normalized = $Path.TrimEnd('\')
    try {
        $Mounted = Get-WindowsImage -Mounted -ErrorAction SilentlyContinue
        foreach ($M in $Mounted) {
            if ($M.Path -and ($M.Path.TrimEnd('\') -ieq $Normalized)) {
                Write-HostTimestamp "    A previous run left an image mounted here - discarding it: $Path" -ForegroundColor Yellow
                Dismount-WindowsImage -Path $Path -Discard -ErrorAction SilentlyContinue | Out-Null
            }
        }
    }
    catch { }

    # Clear any stale/corrupt mount points DISM is still tracking.
    try { Clear-WindowsCorruptMountPoint -ErrorAction SilentlyContinue | Out-Null } catch { }

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
    # If a discarded mount is still releasing, a short pause and retry usually clears it.
    if (Test-Path -LiteralPath $Path) {
        Start-Sleep -Seconds 2
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
}

# Applies a set of update packages to a mounted image directory with DISM, reporting per-package results.
# Packages are applied in the order given (checkpoint/SSU baselines first, the main LCU last).
#
# .msu files are applied directly first; if DISM rejects the .msu wrapper (a known failure that surfaces as
# 0x800401e3 "An error occurred applying the Unattend.xml file from the .msu package"), the .msu is expanded
# and its inner .cab payload is applied instead - the servicing-stack (SSU) .cab before the main .cab.
function Add-UpdatesToImage {
    param(
        [Parameter(Mandatory)][string]$MountDir,
        [Parameter(Mandatory)][string[]]$Packages
    )

    foreach ($Pkg in $Packages) {
        $Leaf = Split-Path -Leaf $Pkg
        Write-HostTimestamp "    Applying $Leaf ..."

        $Applied = $false
        try {
            Add-WindowsPackage -Path $MountDir -PackagePath $Pkg -ErrorAction Stop | Out-Null
            $Applied = $true
            Write-HostTimestamp '      Applied.' -ForegroundColor Green
        }
        catch {
            $Msg = $_.Exception.Message
            # 0x800f081e = the package (or a newer one) is already in the image - safe to treat as done.
            if ($Msg -match '0x800f081e') {
                Write-HostTimestamp '      Already present in the image (superseded/not applicable) - skipping.' -ForegroundColor DarkGray
                continue
            }
            Write-HostTimestamp "      Direct apply failed: $Msg" -ForegroundColor Yellow
        }
        if ($Applied) { continue }

        # Fallback for .msu wrapper failures: expand the .msu and apply the inner .cab payload directly.
        if ($Pkg -notlike '*.msu') { continue }
        Write-HostTimestamp '      Retrying by expanding the .msu and applying its inner .cab payload...' -ForegroundColor Yellow

        $ExpandDir = Join-Path -Path $WorkRoot -ChildPath ("expand_" + [System.IO.Path]::GetFileNameWithoutExtension($Pkg))
        try {
            if (Test-Path $ExpandDir) { Remove-Item -LiteralPath $ExpandDir -Recurse -Force -ErrorAction SilentlyContinue }
            New-Item -ItemType Directory -Path $ExpandDir -Force -ErrorAction Stop | Out-Null

            # expand.exe -f:* unpacks every file from the .msu into the target folder.
            & expand.exe "$Pkg" -f:* "$ExpandDir" | Out-Null

            # The applicable payload is the .cab file(s), excluding the WSUSSCAN metadata catalog. Apply any
            # servicing-stack (SSU) cab first, then the remaining cab(s).
            $Cabs = Get-ChildItem -Path $ExpandDir -Filter '*.cab' -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notmatch '(?i)WSUSSCAN' }
            $OrderedCabs = @(
                ($Cabs | Where-Object { $_.Name -match '(?i)SSU|ServicingStack' })
                ($Cabs | Where-Object { $_.Name -notmatch '(?i)SSU|ServicingStack' })
            )

            if (-not $OrderedCabs -or $OrderedCabs.Count -eq 0) {
                Write-HostTimestamp '      No applicable .cab payload was found inside the .msu.' -ForegroundColor Yellow
            }
            foreach ($Cab in $OrderedCabs) {
                Write-HostTimestamp "      Applying inner package $($Cab.Name) ..."
                try {
                    Add-WindowsPackage -Path $MountDir -PackagePath $Cab.FullName -ErrorAction Stop | Out-Null
                    Write-HostTimestamp '        Applied.' -ForegroundColor Green
                }
                catch {
                    if ($_.Exception.Message -match '0x800f081e') {
                        Write-HostTimestamp '        Already present in the image - skipping.' -ForegroundColor DarkGray
                    }
                    else {
                        Write-HostTimestamp "        Could not apply this package: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
            }
        }
        catch {
            Write-HostTimestamp "      Could not expand/apply the .msu: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        finally {
            Remove-Item -LiteralPath $ExpandDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host $LineBreak
Write-HostTimestamp "Windows ISO Updater (slipstream latest updates into a new ISO) on $($env:ComputerName)" -ForegroundColor Cyan
Write-Host $LineBreak

$WinInfo = Get-InstalledWindowsInfo

# --- Resolve working folders ---
# The working folder should live on a fast drive with lots of free space and, ideally, no spaces in the
# path (oscdimg's -bootdata argument dislikes spaces; short paths are used to work around it regardless).
$WorkRoot = if ($WorkPath) { $WorkPath } else { Join-Path -Path $env:SystemDrive -ChildPath 'WISO-Work' }
$ExtractDir = Join-Path -Path $WorkRoot -ChildPath 'ISO'
$MountDir   = Join-Path -Path $WorkRoot -ChildPath 'Mount'
$DlDir = if ($DownloadPath) { $DownloadPath } else { $PSScriptRoot }

foreach ($Dir in @($WorkRoot, $DlDir)) {
    try {
        if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force -ErrorAction Stop | Out-Null }
    }
    catch {
        Write-HostTimestamp "Could not create the folder '$Dir': $($_.Exception.Message). Cannot continue." -ForegroundColor Red
        Stop-Transcript | Out-Null
        exit 1
    }
}

Write-HostTimestamp "Architecture   : $($WinInfo.Architecture)"
Write-HostTimestamp "Target         : Windows $WindowsVersion ($Release, $Language)"
Write-HostTimestamp "Working folder : $WorkRoot"
Write-HostTimestamp "Download folder: $DlDir"
Write-Host $LineBreak

# --- Disk space check ---
# The download (~6 GB), extracted media (~6 GB), the mounted image, and the re-exported image all coexist
# during the build, so the working drive needs plenty of headroom.
$FreeGB = Get-DriveFreeGB -Path $WorkRoot
if ($null -eq $FreeGB) {
    Write-HostTimestamp 'Could not determine free disk space on the working drive. Continuing with caution.' -ForegroundColor Yellow
}
else {
    Write-HostTimestamp "Free space on the working drive: $FreeGB GB"
    $RequiredGB = 40
    if ($FreeGB -lt $RequiredGB) {
        Write-HostTimestamp "CRITICAL: Less than $RequiredGB GB free on the working drive. Building a patched ISO needs a lot of scratch space. Free up space, choose another drive with -WorkPath, and try again." -ForegroundColor Red
        Stop-Transcript | Out-Null
        exit 1
    }
}
Write-Host $LineBreak

# --- Interactive confirmation ---
if (-not $Unattended -and -not $SkipInteractive -and -not $ListEditions) {
    Write-Host "This tool builds an updated Windows installation ISO. It will:"
    if (-not $IsoPath) {
        Write-Host "  - Download the matching official Windows $WindowsVersion ISO from Microsoft (~5-6 GB)"
        Write-Host "      TIP: Microsoft can rate-limit/block repeated ISO downloads. If the download fails," -ForegroundColor Yellow
        Write-Host "           download the ISO yourself and re-run with -IsoPath to avoid this." -ForegroundColor Yellow
    }
    else {
        Write-Host "  - Use the ISO you provided: $IsoPath"
    }
    Write-Host "  - Extract it to $ExtractDir"
    if ($KeepEditions -and $KeepEditions.Count -gt 0) {
        Write-Host "  - Keep ONLY these editions in the final ISO (remove the rest): $($KeepEditions -join ', ')" -ForegroundColor Yellow
    }
    if (-not $SkipUpdates) {
        if ($UpdatePath) {
            Write-Host "  - Integrate the update packages found in: $UpdatePath"
        }
        else {
            Write-Host "  - Download the latest cumulative update(s) from the Microsoft Update Catalog"
        }
        Write-Host "  - Integrate the update(s) into install.wim ($Edition), boot.wim$(if ($ServiceWinRE) { ', and winre.wim' })"
        Write-Host "  - Clean up and re-export the images to shrink them"
    }
    else {
        Write-Host "  - Skip update integration (-SkipUpdates) and just recompile the ISO"
    }
    Write-Host "  - Recompile a new bootable ISO with oscdimg"
    Write-Host ""
    Write-Host "This is disk- and time-intensive and needs a lot of free space. Nothing on this PC is changed." -ForegroundColor Yellow
    Write-Host ""
    $Confirm = Read-Host "Type 'Y' to continue, or anything else to cancel"
    if ($Confirm -notin @('Y', 'y', 'Yes', 'yes')) {
        Write-HostTimestamp 'Operation cancelled by user.' -ForegroundColor Yellow
        Stop-Transcript | Out-Null
        exit 0
    }
    Write-Host $LineBreak
}

# --- Locate oscdimg early so we fail fast if the ISO cannot be recompiled (not needed for -ListEditions) ---
$Oscdimg = $null
if (-not $ListEditions) {
    Invoke-Task -Description 'Locating oscdimg.exe (Windows ADK Deployment Tools)...' -ScriptBlock {
        $script:Oscdimg = Find-Oscdimg
        if ($script:Oscdimg) {
            Write-HostTimestamp "  Found oscdimg: $($script:Oscdimg)" -ForegroundColor Green
        }
        elseif ($InstallAdk) {
            Write-HostTimestamp '  oscdimg was not found. Installing the Windows ADK Deployment Tools...' -ForegroundColor Yellow
            $script:Oscdimg = Install-AdkDeploymentTools
            if ($script:Oscdimg) { Write-HostTimestamp "  Installed. Found oscdimg: $($script:Oscdimg)" -ForegroundColor Green }
        }
    }
    $Oscdimg = $script:Oscdimg
    if (-not $Oscdimg) {
        Write-HostTimestamp 'oscdimg.exe was not found. It is part of the Windows ADK "Deployment Tools" feature and is required to recompile the ISO.' -ForegroundColor Red
        Write-HostTimestamp 'Re-run with -InstallAdk to have this script download and install it automatically, or install the Windows ADK (Deployment Tools) manually from Microsoft and re-run.' -ForegroundColor Yellow
        Stop-Transcript | Out-Null
        exit 1
    }
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
    # Reuse an already-downloaded ISO in the download folder if present, otherwise resolve + download one.
    $ExistingIso = Get-ChildItem -Path $DlDir -Filter '*.iso' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -gt 3GB } |
        Sort-Object -Property Length -Descending |
        Select-Object -First 1
    if ($ExistingIso) {
        $ResolvedIso = $ExistingIso.FullName
        Write-HostTimestamp "An ISO is already downloaded - reusing it: $ResolvedIso ($([math]::Round($ExistingIso.Length / 1GB, 2)) GB)" -ForegroundColor Green
    }
    else {
        Invoke-Task -Description 'Obtaining the Windows ISO download link from Microsoft...' -ScriptBlock {
            $script:IsoUrl = Get-WindowsIsoUrl -Version $WindowsVersion -Release $Release -Language $Language -Architecture $WinInfo.Architecture
        }
        if (-not $script:IsoUrl) {
            Write-HostTimestamp 'Could not obtain a download link. Microsoft may be rate-limiting/blocking your IP for repeated ISO requests.' -ForegroundColor Yellow
            Write-HostTimestamp 'Download the ISO yourself from https://www.microsoft.com/software-download and re-run with -IsoPath "C:\path\to\Windows.iso".' -ForegroundColor Yellow
            Stop-Transcript | Out-Null
            exit 1
        }

        $FileName = $null
        try { $FileName = [System.IO.Path]::GetFileName(([Uri]$script:IsoUrl).AbsolutePath) } catch { }
        if (-not $FileName -or $FileName -notmatch '\.iso$') {
            $FileName = "Windows$WindowsVersion`_$Language`_$($WinInfo.Architecture).iso"
        }
        $ResolvedIso = Join-Path -Path $DlDir -ChildPath $FileName

        Invoke-Task -Description "Downloading the Windows $WindowsVersion ISO to $ResolvedIso ..." -ScriptBlock {
            if (-not (Get-FileDownload -Url $script:IsoUrl -Destination $ResolvedIso)) {
                Write-HostTimestamp 'ISO download failed. Microsoft may be rate-limiting/blocking your IP for repeated ISO requests.' -ForegroundColor Red
                Write-HostTimestamp 'Download the ISO yourself from https://www.microsoft.com/software-download and re-run with -IsoPath "C:\path\to\Windows.iso".' -ForegroundColor Yellow
                Stop-Transcript | Out-Null
                exit 1
            }
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
Write-Host $LineBreak

# --- List editions and exit (-ListEditions) ---
# Mount the ISO (no full extraction needed) just to read the editions inside install.wim/esd, print them,
# then dismount and exit. Handy for picking -Edition / -KeepEditions values before a full build.
if ($ListEditions) {
    $ListMount = $null
    try {
        $ListMount = Mount-DiskImage -ImagePath $ResolvedIso -PassThru -ErrorAction Stop
        Start-Sleep -Seconds 2
        $ListDrive = ($ListMount | Get-Volume -ErrorAction SilentlyContinue).DriveLetter
        if (-not $ListDrive) { $ListDrive = (Get-DiskImage -ImagePath $ResolvedIso | Get-Volume -ErrorAction SilentlyContinue).DriveLetter }
        if (-not $ListDrive) { throw 'Could not determine the drive letter of the mounted ISO.' }

        $ListImg = "$($ListDrive):\sources\install.wim"
        if (-not (Test-Path -LiteralPath $ListImg)) { $ListImg = "$($ListDrive):\sources\install.esd" }
        if (-not (Test-Path -LiteralPath $ListImg)) { throw 'No install.wim or install.esd was found on the ISO.' }

        Write-HostTimestamp "Editions inside $(Split-Path -Leaf $ListImg):" -ForegroundColor Cyan
        Get-WindowsImage -ImagePath $ListImg -ErrorAction Stop | ForEach-Object {
            Write-Host ("    [{0}] {1}" -f $_.ImageIndex, $_.ImageName)
        }
        Write-Host ''
        Write-Host 'Use these with -Edition (which to service) or -KeepEditions (which to keep in the final ISO).'
        Write-Host 'Example: -KeepEditions "Windows 11 Pro","Windows 11 Home"   or   -KeepEditions 6,1'
    }
    catch {
        Write-HostTimestamp "Could not list the editions: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        if ($ListMount) { Dismount-DiskImage -ImagePath $ResolvedIso -ErrorAction SilentlyContinue | Out-Null }
    }
    Write-Host $LineBreak
    Stop-Transcript | Out-Null
    exit 0
}

# --- Extract the ISO to the working folder ---
$MountedImage = $null
try {
    Invoke-Task -Description "Mounting the ISO to copy its contents: $ResolvedIso ..." -ScriptBlock {
        $script:MountedImage = Mount-DiskImage -ImagePath $ResolvedIso -PassThru -ErrorAction Stop
        Start-Sleep -Seconds 2
    }
    $MountedImage = $script:MountedImage

    $DriveLetter = ($MountedImage | Get-Volume -ErrorAction SilentlyContinue).DriveLetter
    if (-not $DriveLetter) {
        $DriveLetter = (Get-DiskImage -ImagePath $ResolvedIso | Get-Volume -ErrorAction SilentlyContinue).DriveLetter
    }
    if (-not $DriveLetter) { throw 'Could not determine the drive letter of the mounted ISO.' }
    Write-HostTimestamp "  ISO mounted at $($DriveLetter):\" -ForegroundColor Green

    if (-not (Test-Path -LiteralPath "$($DriveLetter):\sources\install.wim") -and
        -not (Test-Path -LiteralPath "$($DriveLetter):\sources\install.esd")) {
        throw 'The mounted image has no sources\install.wim or install.esd - this is not a Windows installation ISO.'
    }

    Invoke-Task -Description "Extracting the ISO contents to $ExtractDir ..." -ScriptBlock {
        if (Test-Path $ExtractDir) { Remove-Item -LiteralPath $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $ExtractDir -Force -ErrorAction Stop | Out-Null
        # robocopy mirrors the whole media reliably (long paths, retries). /NP keeps the log readable.
        $RoboArgs = @("$($DriveLetter):\", $ExtractDir, '/E', '/COPY:DAT', '/R:2', '/W:2', '/NFL', '/NDL', '/NP', '/NJH', '/NJS')
        & robocopy.exe @RoboArgs | Out-Null
        # robocopy exit codes 0-7 indicate success; 8+ indicates a real failure.
        if ($LASTEXITCODE -ge 8) { throw "robocopy failed to copy the ISO contents (exit code $LASTEXITCODE)." }
        Write-HostTimestamp '  Extraction complete.' -ForegroundColor Green
    }
}
catch {
    Write-HostTimestamp "Could not extract the ISO: $($_.Exception.Message)" -ForegroundColor Red
    if ($MountedImage) { Dismount-DiskImage -ImagePath $ResolvedIso -ErrorAction SilentlyContinue | Out-Null }
    Stop-Transcript | Out-Null
    exit 1
}
finally {
    if ($MountedImage) {
        Dismount-DiskImage -ImagePath $ResolvedIso -ErrorAction SilentlyContinue | Out-Null
        Write-HostTimestamp '  Dismounted the source ISO.' -ForegroundColor DarkGray
    }
}
Write-Host $LineBreak

# The copied wim files inherit the read-only attribute from the optical media; clear it so DISM can mount
# and commit changes.
Get-ChildItem -Path (Join-Path $ExtractDir 'sources') -Filter '*.wim' -File -ErrorAction SilentlyContinue |
    ForEach-Object { try { Set-ItemProperty -LiteralPath $_.FullName -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue } catch { } }

$InstallWimExtracted = Join-Path $ExtractDir 'sources\install.wim'
$InstallEsdExtracted = Join-Path $ExtractDir 'sources\install.esd'
$BootWim = Join-Path $ExtractDir 'sources\boot.wim'

# If the media ships install.esd (compressed), convert it to an editable install.wim so DISM can service
# it. Servicing is done against a WIM; the ESD is a delivery-only format.
if (-not (Test-Path -LiteralPath $InstallWimExtracted) -and (Test-Path -LiteralPath $InstallEsdExtracted)) {
    Invoke-Task -Description 'The media uses install.esd - converting it to an editable install.wim...' -ScriptBlock {
        $Images = Get-WindowsImage -ImagePath $InstallEsdExtracted -ErrorAction Stop
        foreach ($Img in $Images) {
            Write-HostTimestamp "  Exporting index $($Img.ImageIndex): $($Img.ImageName) ..."
            Export-WindowsImage -SourceImagePath $InstallEsdExtracted -SourceIndex $Img.ImageIndex -DestinationImagePath $InstallWimExtracted -CompressionType Max -ErrorAction Stop | Out-Null
        }
        Remove-Item -LiteralPath $InstallEsdExtracted -Force -ErrorAction SilentlyContinue
        Write-HostTimestamp '  Conversion complete.' -ForegroundColor Green
    }
    Write-Host $LineBreak
}

if (-not (Test-Path -LiteralPath $InstallWimExtracted)) {
    Write-HostTimestamp 'No editable install.wim is present after extraction. Cannot continue.' -ForegroundColor Red
    Stop-Transcript | Out-Null
    exit 1
}

# --- Determine the feature update / architecture from the image (for catalog searches) ---
$ImageInfo = $null
try { $ImageInfo = Get-WindowsImage -ImagePath $InstallWimExtracted -Index 1 -ErrorAction Stop } catch { }
$ImageBuild = 0
if ($ImageInfo -and $ImageInfo.Version -match '^\d+\.\d+\.(\d+)') { $ImageBuild = [int]$Matches[1] }
$FeatureName = if ($ImageBuild) { Get-FeatureUpdateName -Build $ImageBuild } else { $null }
$ImageArch = switch ($ImageInfo.Architecture) { 0 { 'x86' } 9 { 'x64' } 12 { 'arm64' } default { $WinInfo.Architecture } }
$CatalogArch = switch ($ImageArch) { 'x64' { 'x64' } 'arm64' { 'ARM64' } 'x86' { 'x86' } default { 'x64' } }

Write-HostTimestamp "Image build    : $($ImageInfo.Version)$(if ($FeatureName) { " ($FeatureName)" })"
Write-HostTimestamp "Image arch     : $ImageArch"
Write-Host $LineBreak

# --- Gather the update packages to integrate ---
$UpdatePackages = New-Object System.Collections.Generic.List[string]
$SafeOsPackage = $null

if ($SkipUpdates) {
    Write-HostTimestamp 'Skipping update integration (-SkipUpdates was specified).' -ForegroundColor Yellow
    Write-Host $LineBreak
}
elseif ($UpdatePath) {
    $script:UpdateFiles = @()
    Invoke-Task -Description "Collecting update packages from $UpdatePath ..." -ScriptBlock {
        if (-not (Test-Path -LiteralPath $UpdatePath)) { throw "The update folder '$UpdatePath' does not exist." }
        $Found = Get-ChildItem -Path $UpdatePath -Include '*.msu', '*.cab' -File -Recurse -ErrorAction SilentlyContinue
        $script:UpdateFiles = @($Found | ForEach-Object { $_.FullName })
        if (-not $script:UpdateFiles -or $script:UpdateFiles.Count -eq 0) {
            throw "No .msu or .cab packages were found in '$UpdatePath'."
        }
        Write-HostTimestamp "  Found $($script:UpdateFiles.Count) package(s)." -ForegroundColor Green
    }
    foreach ($F in $script:UpdateFiles) { $UpdatePackages.Add($F) }
    Write-Host $LineBreak
}
else {
    if (-not $FeatureName) {
        Write-HostTimestamp 'Could not determine the feature-update name from the image, so the catalog search may be less precise.' -ForegroundColor Yellow
    }

    Invoke-Task -Description 'Downloading the latest cumulative update from the Microsoft Update Catalog...' -ScriptBlock {
        $VerPart = if ($FeatureName) { "Version $FeatureName " } else { '' }
        # The monthly LCU is titled e.g. "2026-07 Cumulative Update for Windows 11 Version 24H2 for
        # x64-based Systems (KB...)" and classified as a Security Update. Restrict the match to real
        # cumulative updates and exclude the .NET / Dynamic Update entries the same query returns.
        $Query = "Cumulative Update for Windows $WindowsVersion ${VerPart}for $CatalogArch-based Systems"
        $Include = '(?i)cumulative update for windows'
        $Exclude = '(?i)\.net|dynamic update'
        $script:Lcu = Get-LatestCatalogPackage -Query $Query -DownloadDir $DlDir -TitleInclude $Include -TitleExclude $Exclude
        if (-not $script:Lcu) {
            # Retry with a looser query (some releases omit the "Version xxHx" token in the title).
            $Query2 = "Cumulative Update for Windows $WindowsVersion for $CatalogArch-based Systems"
            Write-HostTimestamp "  Retrying with a broader query: $Query2" -ForegroundColor Yellow
            $script:Lcu = Get-LatestCatalogPackage -Query $Query2 -DownloadDir $DlDir -TitleInclude $Include -TitleExclude $Exclude
        }
    }
    if ($script:Lcu) { foreach ($P in @($script:Lcu)) { $UpdatePackages.Add($P) } }
    else {
        Write-HostTimestamp 'Could not obtain a cumulative update from the catalog. You can supply one with -UpdatePath, or use -SkipUpdates to just recompile the ISO.' -ForegroundColor Red
        Stop-Transcript | Out-Null
        exit 1
    }
    Write-Host $LineBreak

    if ($IncludeDotNet) {
        Invoke-Task -Description 'Downloading the latest .NET cumulative update from the Microsoft Update Catalog...' -ScriptBlock {
            $VerPart = if ($FeatureName) { "Windows $WindowsVersion Version $FeatureName" } else { "Windows $WindowsVersion" }
            $Query = "Cumulative Update for .NET Framework $VerPart for $CatalogArch"
            $script:DotNet = Get-LatestCatalogPackage -Query $Query -DownloadDir $DlDir -TitleInclude '(?i)\.net framework' -TitleExclude '(?i)dynamic update'
        }
        if ($script:DotNet) { foreach ($P in @($script:DotNet)) { $UpdatePackages.Add($P) } }
        else { Write-HostTimestamp '  No .NET cumulative update was integrated (none found).' -ForegroundColor Yellow }
        Write-Host $LineBreak
    }

    if ($ServiceWinRE) {
        Invoke-Task -Description 'Looking for a Safe OS Dynamic Update for the recovery image (WinRE)...' -ScriptBlock {
            $VerPart = if ($FeatureName) { "Version $FeatureName " } else { '' }
            $script:SafeOs = Get-LatestCatalogPackage -Query "Safe OS Dynamic Update Windows $WindowsVersion $VerPart$CatalogArch" -DownloadDir $DlDir -TitleInclude '(?i)safe os dynamic update'
        }
        if ($script:SafeOs) { $SafeOsPackage = $script:SafeOs }
        else { Write-HostTimestamp '  No Safe OS Dynamic Update was found; the cumulative update will be applied to WinRE instead.' -ForegroundColor Yellow }
        Write-Host $LineBreak
    }
}

# --- Resolve which editions to keep and which to service ---
$InstallImages = @(Get-WindowsImage -ImagePath $InstallWimExtracted -ErrorAction Stop)

# Which editions to KEEP in the final ISO (default: all of them).
$KeepIndexes = @($InstallImages.ImageIndex)
if ($KeepEditions -and $KeepEditions.Count -gt 0) {
    $KeepUnmatched = $null
    $KeepIndexes = @(Resolve-EditionIndexes -Images $InstallImages -Tokens $KeepEditions -Unmatched ([ref]$KeepUnmatched))
    if ($KeepUnmatched -and $KeepUnmatched.Count -gt 0) {
        Write-HostTimestamp "These -KeepEditions values did not match any edition: $($KeepUnmatched -join ', ')" -ForegroundColor Red
        Write-HostTimestamp 'Available editions:' -ForegroundColor Yellow
        $InstallImages | ForEach-Object { Write-Host "    [$($_.ImageIndex)] $($_.ImageName)" }
        Stop-Transcript | Out-Null
        exit 1
    }
    if ($KeepIndexes.Count -eq 0) {
        Write-HostTimestamp '-KeepEditions matched no editions. Cannot continue.' -ForegroundColor Red
        Stop-Transcript | Out-Null
        exit 1
    }
    $KeptNames = $InstallImages | Where-Object { $KeepIndexes -contains $_.ImageIndex } | ForEach-Object { $_.ImageName }
    $DroppedNames = $InstallImages | Where-Object { $KeepIndexes -notcontains $_.ImageIndex } | ForEach-Object { $_.ImageName }
    Write-HostTimestamp "Keeping $($KeepIndexes.Count) of $($InstallImages.Count) editions: $($KeptNames -join ', ')" -ForegroundColor Cyan
    if ($DroppedNames) { Write-HostTimestamp "Removing from the ISO: $($DroppedNames -join ', ')" -ForegroundColor Yellow }
    Write-Host $LineBreak
}
$TrimNeeded = ($KeepIndexes.Count -lt $InstallImages.Count)

# Which of the kept editions to actually service (apply updates to). -Edition narrows this further.
if ($Edition -eq 'All') {
    $ServiceIndexes = $KeepIndexes
}
else {
    $EdUnmatched = $null
    $EdIndexes = @(Resolve-EditionIndexes -Images $InstallImages -Tokens @($Edition) -Unmatched ([ref]$EdUnmatched))
    if ($EdIndexes.Count -eq 0) {
        Write-HostTimestamp "Edition '$Edition' was not found in the image. Available editions:" -ForegroundColor Red
        $InstallImages | ForEach-Object { Write-Host "    [$($_.ImageIndex)] $($_.ImageName)" }
        Stop-Transcript | Out-Null
        exit 1
    }
    # Only service editions we are keeping in the final ISO.
    $ServiceIndexes = @($EdIndexes | Where-Object { $KeepIndexes -contains $_ })
}

# --- Service the images ---
if ($UpdatePackages.Count -gt 0) {
    # Start from a clean mount directory, discarding any stale mount a previous crashed run left behind.
    Reset-MountDirectory -Path $MountDir

    # 1) Service install.wim (each targeted edition).
    foreach ($Index in $ServiceIndexes) {
        $EditionName = ($InstallImages | Where-Object { $_.ImageIndex -eq $Index }).ImageName
        Invoke-Task -Description "Servicing install.wim index $Index ($EditionName)..." -ScriptBlock {
            try {
                Reset-MountDirectory -Path $MountDir
                Write-HostTimestamp '    Mounting the image...'
                Mount-WindowsImage -ImagePath $InstallWimExtracted -Index $Index -Path $MountDir -ErrorAction Stop | Out-Null

                # Optionally service the recovery image (winre.wim) that lives inside this edition.
                if ($ServiceWinRE) {
                    $WinReWim = Join-Path $MountDir 'Windows\System32\Recovery\winre.wim'
                    if (Test-Path -LiteralPath $WinReWim) {
                        $WinReMount = Join-Path $WorkRoot 'WinREMount'
                        Reset-MountDirectory -Path $WinReMount
                        try {
                            Set-ItemProperty -LiteralPath $WinReWim -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
                            Write-HostTimestamp '    Servicing the recovery image (winre.wim)...'
                            Mount-WindowsImage -ImagePath $WinReWim -Index 1 -Path $WinReMount -ErrorAction Stop | Out-Null
                            $WinRePkgs = if ($SafeOsPackage) { @($SafeOsPackage) } else { $UpdatePackages }
                            Add-UpdatesToImage -MountDir $WinReMount -Packages $WinRePkgs
                            Dismount-WindowsImage -Path $WinReMount -Save -ErrorAction Stop | Out-Null
                        }
                        catch {
                            Write-HostTimestamp "      WinRE servicing failed: $($_.Exception.Message)" -ForegroundColor Yellow
                            Dismount-WindowsImage -Path $WinReMount -Discard -ErrorAction SilentlyContinue | Out-Null
                        }
                    }
                }

                Add-UpdatesToImage -MountDir $MountDir -Packages $UpdatePackages

                Write-HostTimestamp '    Cleaning up the component store (/StartComponentCleanup /ResetBase)...'
                # ResetBase permanently removes superseded components, shrinking the image. This is slow.
                & dism.exe /Image:"$MountDir" /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null

                Write-HostTimestamp '    Committing and unmounting...'
                Dismount-WindowsImage -Path $MountDir -Save -ErrorAction Stop | Out-Null
                Write-HostTimestamp "    Index $Index done." -ForegroundColor Green
            }
            catch {
                Write-HostTimestamp "    Servicing index $Index failed: $($_.Exception.Message)" -ForegroundColor Red
                Dismount-WindowsImage -Path $MountDir -Discard -ErrorAction SilentlyContinue | Out-Null
            }
        }
    }

    # 2) Service boot.wim (Windows Setup / WinPE). Index 2 is the Setup environment; index 1 is WinPE.
    if (Test-Path -LiteralPath $BootWim) {
        Set-ItemProperty -LiteralPath $BootWim -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
        $BootImages = Get-WindowsImage -ImagePath $BootWim -ErrorAction SilentlyContinue
        foreach ($BootImg in $BootImages) {
            Invoke-Task -Description "Servicing boot.wim index $($BootImg.ImageIndex) ($($BootImg.ImageName))..." -ScriptBlock {
                try {
                    Reset-MountDirectory -Path $MountDir
                    Mount-WindowsImage -ImagePath $BootWim -Index $BootImg.ImageIndex -Path $MountDir -ErrorAction Stop | Out-Null
                    Add-UpdatesToImage -MountDir $MountDir -Packages $UpdatePackages
                    & dism.exe /Image:"$MountDir" /Cleanup-Image /StartComponentCleanup | Out-Null
                    Dismount-WindowsImage -Path $MountDir -Save -ErrorAction Stop | Out-Null
                    Write-HostTimestamp "    boot.wim index $($BootImg.ImageIndex) done." -ForegroundColor Green
                }
                catch {
                    Write-HostTimestamp "    Servicing boot.wim index $($BootImg.ImageIndex) failed: $($_.Exception.Message)" -ForegroundColor Yellow
                    Dismount-WindowsImage -Path $MountDir -Discard -ErrorAction SilentlyContinue | Out-Null
                }
            }
        }
    }

    # 3) Re-export install.wim below (outside this block) to reclaim the space freed by the cleanup.
    Remove-Item -LiteralPath $MountDir -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Re-export install.wim (shrink after servicing and/or drop editions with -KeepEditions) ---
# Exporting only the kept indexes both reclaims the space freed by the component cleanup AND physically
# removes any editions the user chose not to keep. Runs when updates were applied or when trimming.
if (($UpdatePackages.Count -gt 0) -or $TrimNeeded) {
    $ExportDesc = if ($TrimNeeded) { "Rebuilding install.wim with only the kept edition(s) and shrinking it..." } else { 'Re-exporting install.wim to shrink it...' }
    Invoke-Task -Description $ExportDesc -ScriptBlock {
        $Temp = Join-Path $ExtractDir 'sources\install_new.wim'
        try {
            if (Test-Path -LiteralPath $Temp) { Remove-Item -LiteralPath $Temp -Force -ErrorAction SilentlyContinue }
            # Export the kept indexes in their original order into a fresh WIM (re-indexed 1..N).
            foreach ($Index in ($KeepIndexes | Sort-Object)) {
                $Name = ($InstallImages | Where-Object { $_.ImageIndex -eq $Index }).ImageName
                Write-HostTimestamp "  Exporting [$Index] $Name ..."
                Export-WindowsImage -SourceImagePath $InstallWimExtracted -DestinationImagePath $Temp -CompressionType Max -SourceIndex $Index -ErrorAction Stop | Out-Null
            }
            Remove-Item -LiteralPath $InstallWimExtracted -Force -ErrorAction Stop
            Rename-Item -LiteralPath $Temp -NewName 'install.wim' -ErrorAction Stop
            Write-HostTimestamp '  Re-export complete.' -ForegroundColor Green
        }
        catch {
            Write-HostTimestamp "  Re-export failed: $($_.Exception.Message). The original serviced install.wim will be used as-is." -ForegroundColor Yellow
            Remove-Item -LiteralPath $Temp -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host $LineBreak
}

# --- Recompile the ISO with oscdimg ---
if (-not $OutputIsoPath) {
    $BaseName = [System.IO.Path]::GetFileNameWithoutExtension($ResolvedIso)
    $OutputIsoPath = Join-Path -Path $DlDir -ChildPath "$BaseName-Updated_$(Get-Date -Format 'yyyyMMdd').iso"
}
try {
    $OutDir = Split-Path -Path $OutputIsoPath -Parent
    if ($OutDir -and -not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force -ErrorAction Stop | Out-Null }
}
catch { }

$EtfsBoot = Join-Path $ExtractDir 'boot\etfsboot.com'
$EfiSys   = Join-Path $ExtractDir 'efi\microsoft\boot\efisys.bin'

Invoke-Task -Description "Recompiling the bootable ISO to $OutputIsoPath ..." -ScriptBlock {
    if (Test-Path -LiteralPath $OutputIsoPath) { Remove-Item -LiteralPath $OutputIsoPath -Force -ErrorAction SilentlyContinue }

    # Build the dual (BIOS + UEFI) boot data. Use 8.3 short paths for the boot files so any spaces in the
    # working path do not break oscdimg's -bootdata argument.
    $BootArg = $null
    if ((Test-Path -LiteralPath $EtfsBoot) -and (Test-Path -LiteralPath $EfiSys)) {
        $EtfsShort = Get-ShortPath -Path $EtfsBoot
        $EfiShort  = Get-ShortPath -Path $EfiSys
        $BootArg = "2#p0,e,b$EtfsShort#pEF,e,b$EfiShort"
    }
    elseif (Test-Path -LiteralPath $EfiSys) {
        # UEFI-only media (no BIOS boot sector present).
        $BootArg = "1#pEF,e,b$(Get-ShortPath -Path $EfiSys)"
    }
    else {
        Write-HostTimestamp '  No boot sectors were found in the extracted media; the resulting ISO may not be bootable.' -ForegroundColor Yellow
    }

    $OscdimgArgs = @('-m', '-o', '-u2', '-udfver102')
    if ($BootArg) { $OscdimgArgs += "-bootdata:$BootArg" }
    $OscdimgArgs += @($ExtractDir, $OutputIsoPath)

    Write-HostTimestamp "  Running: `"$Oscdimg`" $($OscdimgArgs -join ' ')"
    $Proc = Start-Process -FilePath $Oscdimg -ArgumentList $OscdimgArgs -Wait -PassThru -NoNewWindow -ErrorAction Stop
    if ($Proc.ExitCode -ne 0) {
        throw "oscdimg returned exit code $($Proc.ExitCode)."
    }
    if (-not (Test-Path -LiteralPath $OutputIsoPath)) {
        throw 'oscdimg reported success but the output ISO was not created.'
    }
    $SizeGB = [math]::Round((Get-Item -LiteralPath $OutputIsoPath).Length / 1GB, 2)
    Write-HostTimestamp "  New ISO created ($SizeGB GB)." -ForegroundColor Green
}
Write-Host $LineBreak

# --- Cleanup the working extraction folder ---
Invoke-Task -Description 'Cleaning up the working extraction folder...' -ScriptBlock {
    try {
        Remove-Item -LiteralPath $ExtractDir -Recurse -Force -ErrorAction Stop
        Write-HostTimestamp '  Removed the extracted media.' -ForegroundColor Green
    }
    catch {
        Write-HostTimestamp "  Could not fully remove $ExtractDir : $($_.Exception.Message). You can delete it manually." -ForegroundColor Yellow
    }
}
Write-Host $LineBreak

Write-HostTimestamp 'Done. Your updated Windows installation ISO is ready:' -ForegroundColor Green
Write-HostTimestamp "  $OutputIsoPath" -ForegroundColor Green
Write-Host ''
Write-Host 'You can write it to a USB drive (e.g. with Rufus) or use it for a clean install or in-place upgrade.'
Write-Host $LineBreak

Write-HostTimestamp 'Windows ISO Updater script finished.' -ForegroundColor Green
if (-not $Unattended -and -not $SkipInteractive) {
    Read-Host -Prompt 'Press enter to exit'
}

# Stop logging
Stop-Transcript
# --- End Logging ---
