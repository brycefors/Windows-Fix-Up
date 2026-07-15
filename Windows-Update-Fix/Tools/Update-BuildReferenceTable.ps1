# =====================================================================================
# Update-BuildReferenceTable.ps1
# -------------------------------------------------------------------------------------
# Maintenance helper for Windows-Update-Fix.ps1. Scrapes Microsoft's public release-health
# pages and generates the $script:KnownBuildReleases hashtable block, picking each serviced
# version's newest NON-PREVIEW cumulative update.
#
# "Preview" = the optional, non-security C/D-week releases (e.g. "2026-06 D"). Those are
# EXCLUDED. The Patch Tuesday "B" release, the initial "A" release, and out-of-band "OOB"
# fixes are kept.
#
# USAGE:
#   .\Update-BuildReferenceTable.ps1                  # every non-preview build per month, past 2 years (default)
#   .\Update-BuildReferenceTable.ps1 -NewestOnly      # newest build per version line only
#   .\Update-BuildReferenceTable.ps1 -OutFile x.txt   # also write it to a file
#   .\Update-BuildReferenceTable.ps1 -MaxAgeYears 3   # widen/narrow the time window (default 2 years)
#   .\Update-BuildReferenceTable.ps1 -IncludeWindows10  # also include Windows 10 (Windows 11 only by default)
#
# By default every month's build for the past -MaxAgeYears (default 2) years is included, so machines on
# any recent build get an exact offline release date/KB without the script ever querying Microsoft.
# Pass -NewestOnly to get only the newest build per version line.
#
# Copy the generated block over the existing $script:KnownBuildReleases table in
# Windows-Update-Fix.ps1 and update the "Last verified" date in that table's comment.
# To patch Windows-Update-Fix.ps1 automatically, use Sync-BuildReferenceTable.ps1 instead.
# =====================================================================================
[CmdletBinding()]
param(
    # Only include builds released within this many years (keeps the table focused on recent releases).
    [double]$MaxAgeYears = 2,
    # Emit only the newest non-preview build per version line instead of every non-preview build per month.
    [switch]$NewestOnly,
    # Include feature updates that have already reached end of servicing (off by default keeps it lean).
    [switch]$IncludeEndOfLife,
    # Also include the Windows 10 page (Windows 11 only by default).
    [switch]$IncludeWindows10,
    # Optional path to also write the generated block to.
    [string]$OutFile,
    [int]$TimeoutSec = 30
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Update-type week letters treated as optional PREVIEW releases and therefore excluded.
# A = initial GA, B = Patch Tuesday (security), C/D = optional non-security previews, OOB = out-of-band.
$PreviewWeeks = @('C', 'D')

# End-of-servicing dates keyed by OS build (major) number. Feature updates past their date are excluded
# unless -IncludeEndOfLife is set. Uses the LATER (Enterprise/Education/IoT/LTSC) date so anything still
# supported for any edition is kept. Keep roughly in sync with $KnownFeatureUpdates in Windows-Update-Fix.ps1.
$FeatureUpdateEol = @{
    28000 = '2029-03-13'  # Windows 11 26H1
    26200 = '2028-10-10'  # Windows 11 25H2
    26100 = '2027-10-12'  # Windows 11 24H2
    22631 = '2026-11-10'  # Windows 11 23H2
    22621 = '2025-10-14'  # Windows 11 22H2
    22000 = '2024-10-08'  # Windows 11 21H2
    19045 = '2025-10-14'  # Windows 10 22H2
    19044 = '2027-01-12'  # Windows 10 21H2 (Enterprise LTSC 2021)
    17763 = '2029-01-09'  # Windows 10 1809 (Server 2019 / LTSC 2019)
    14393 = '2027-01-12'  # Windows 10 1607 (Server 2016)
    10240 = '2025-10-14'  # Windows 10 1507 (LTSB 2015)
}

# Fetches a release-information page and returns non-preview builds as PSCustomObjects: Build (Build.UBR),
# Ubr, Major, Date (yyyy-MM-dd), KB, Version (marketing, e.g. '24H2'). By default only the newest build
# per OS build line is returned; with -AllReleases, every non-preview build within the age window. Builds
# for end-of-life feature updates are excluded unless -IncludeEndOfLife is set.
function Get-BuildTableFromPage {
    param([string]$Url, [int]$TimeoutSec, [bool]$AllReleases, [bool]$IncludeEndOfLife)

    try {
        $Html = (Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop).Content
    }
    catch {
        Write-Warning "Could not fetch $Url : $($_.Exception.Message)"
        return @()
    }

    # Parse only the "release history" section: stop before the "hotpatch calendar", whose rows use a
    # different (YYYY.MM) update-type format that would otherwise pollute the results.
    $HistoryStart = $Html.IndexOf('release history', [StringComparison]::OrdinalIgnoreCase)
    if ($HistoryStart -ge 0) { $Html = $Html.Substring($HistoryStart) }
    $HotpatchStart = $Html.IndexOf('hotpatch calendar', [StringComparison]::OrdinalIgnoreCase)
    if ($HotpatchStart -ge 0) { $Html = $Html.Substring(0, $HotpatchStart) }

    # Flatten the HTML so each table cell becomes space-separated text on one line.
    $Text = ($Html -replace '<[^>]+>', ' ') -replace '\s+', ' '

    # Map OS build number -> marketing version from the "Version 24H2 (OS build 26100)" headers.
    $VersionByBuild = @{}
    foreach ($m in [regex]::Matches($Text, 'Version\s+([0-9A-Za-z]+)\s+\(OS build\s+(\d+)\)')) {
        $VersionByBuild[$m.Groups[2].Value] = $m.Groups[1].Value
    }

    # Each release-history row flattens to: <YYYY-MM> <week> <YYYY-MM-DD> <Build.UBR> <KBxxxxxxx>
    $RowRegex = '(\d{4}-\d{2})\s+([A-Za-z]+)\s+(\d{4}-\d{2}-\d{2})\s+(\d{5,}\.\d+)\s+(KB\d+)'
    $Cutoff = (Get-Date).AddYears(-$MaxAgeYears)

    # Collect every non-preview build within the age window, de-duplicated by exact Build.UBR (a build
    # can appear under both the GA and LTSC labels on the page).
    $ByBuild = @{}
    foreach ($r in [regex]::Matches($Text, $RowRegex)) {
        $Week = $r.Groups[2].Value.ToUpper()
        if ($PreviewWeeks -contains $Week) { continue }   # skip optional preview (C/D) releases

        $Date  = $r.Groups[3].Value
        $Build = $r.Groups[4].Value
        $Kb    = $r.Groups[5].Value
        $Major = ($Build -split '\.')[0]
        $Ubr   = [int]($Build -split '\.')[1]

        # Exclude end-of-life feature updates (unless -IncludeEndOfLife). Unknown lines are kept.
        if (-not $IncludeEndOfLife -and $FeatureUpdateEol.ContainsKey([int]$Major)) {
            $Eol = $null
            try { $Eol = [datetime]::ParseExact($FeatureUpdateEol[[int]$Major], 'yyyy-MM-dd', $null) } catch { $Eol = $null }
            if ($Eol -and (Get-Date) -gt $Eol) { continue }
        }

        # Age filter: skip anything released before the cutoff.
        $Parsed = $null
        try { $Parsed = [datetime]::ParseExact($Date, 'yyyy-MM-dd', $null) } catch { $Parsed = $null }
        if ($Parsed -and $Parsed -lt $Cutoff) { continue }

        if (-not $ByBuild.ContainsKey($Build)) {
            $ByBuild[$Build] = [PSCustomObject]@{
                Build   = $Build
                Ubr     = $Ubr
                Major   = $Major
                Date    = $Date
                KB      = $Kb
                Version = $VersionByBuild[$Major]
            }
        }
    }

    $Entries = @($ByBuild.Values)
    if (-not $AllReleases) {
        # Reduce to just the newest non-preview build per OS build line.
        $Entries = @($Entries | Group-Object Major | ForEach-Object {
            $_.Group | Sort-Object Ubr -Descending | Select-Object -First 1
        })
    }
    return $Entries
}

# Formats a set of build entries into aligned hashtable lines, sorted newest build line first and then
# newest revision first within each line.
function Format-BuildEntries {
    param([object[]]$Entries)
    $Lines = @()
    $Sorted = $Entries | Sort-Object @{Expression = { [int]$_.Major }; Descending = $true }, @{Expression = { $_.Ubr }; Descending = $true }
    foreach ($e in $Sorted) {
        $Key = "'{0}'" -f $e.Build
        $Comment = if ($e.Version) { "  # $($e.Version)" } else { '' }
        $Lines += "    {0} = @{{ Date = '{1}'; KB = '{2}' }}{3}" -f $Key.PadRight(13), $e.Date, $e.KB, $Comment
    }
    return $Lines
}

$Win11 = Get-BuildTableFromPage -Url 'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information' -TimeoutSec $TimeoutSec -AllReleases:(-not $NewestOnly) -IncludeEndOfLife:$IncludeEndOfLife
$Win10 = @()
if ($IncludeWindows10) {
    $Win10 = Get-BuildTableFromPage -Url 'https://learn.microsoft.com/en-us/windows/release-health/release-information' -TimeoutSec $TimeoutSec -AllReleases:(-not $NewestOnly) -IncludeEndOfLife:$IncludeEndOfLife
}

if (-not $Win11 -and -not $Win10) {
    Write-Error 'No build data could be parsed from the Microsoft release pages. Check connectivity and try again.'
    exit 1
}

$Block = @()
$Block += "# Last verified against Microsoft release information: $(Get-Date -Format 'yyyy-MM-dd')"
$Block += '$script:KnownBuildReleases = @{'
$Scope = if (-not $NewestOnly) { "every non-preview build, past $MaxAgeYears year(s)" } else { 'latest non-preview build per serviced version' }
if ($Win11) {
    $Block += "    # --- Windows 11 ($Scope) ---"
    $Block += (Format-BuildEntries -Entries $Win11)
}
if ($Win10) {
    $Block += "    # --- Windows 10 ($Scope) ---"
    $Block += (Format-BuildEntries -Entries $Win10)
}
$Block += '}'

$BlockText = $Block -join [Environment]::NewLine
Write-Output $BlockText

if ($OutFile) {
    $BlockText | Set-Content -Path $OutFile -Encoding UTF8
    Write-Host ""
    Write-Host "Written to $OutFile" -ForegroundColor Green
}
