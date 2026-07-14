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
#   .\Update-BuildReferenceTable.ps1                 # print the block to the console
#   .\Update-BuildReferenceTable.ps1 -OutFile x.txt  # also write it to a file
#   .\Update-BuildReferenceTable.ps1 -MaxAgeYears 3  # include older build lines too
#   .\Update-BuildReferenceTable.ps1 -SkipWindows10  # Windows 11 only
#
# Copy the generated block over the existing $script:KnownBuildReleases table in
# Windows-Update-Fix.ps1 and update the "Last verified" date in that table's comment.
# =====================================================================================
[CmdletBinding()]
param(
    # Only include build lines whose newest non-preview release is within this many years (keeps the
    # table focused on currently/recently serviced versions instead of every historical release).
    [double]$MaxAgeYears = 2,
    # Skip the Windows 10 page (Windows 11 only).
    [switch]$SkipWindows10,
    # Optional path to also write the generated block to.
    [string]$OutFile,
    [int]$TimeoutSec = 30
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Update-type week letters treated as optional PREVIEW releases and therefore excluded.
# A = initial GA, B = Patch Tuesday (security), C/D = optional non-security previews, OOB = out-of-band.
$PreviewWeeks = @('C', 'D')

# Fetches a release-information page and returns the newest non-preview build per OS build line as
# PSCustomObjects: Build (Build.UBR), Ubr, Date (yyyy-MM-dd), KB, Version (marketing, e.g. '24H2').
function Get-BuildTableFromPage {
    param([string]$Url, [int]$TimeoutSec)

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

    $BestByLine = @{}
    foreach ($r in [regex]::Matches($Text, $RowRegex)) {
        $Week = $r.Groups[2].Value.ToUpper()
        if ($PreviewWeeks -contains $Week) { continue }   # skip optional preview (C/D) releases

        $Date  = $r.Groups[3].Value
        $Build = $r.Groups[4].Value
        $Kb    = $r.Groups[5].Value
        $Major = ($Build -split '\.')[0]
        $Ubr   = [int]($Build -split '\.')[1]

        if (-not $BestByLine.ContainsKey($Major) -or $Ubr -gt $BestByLine[$Major].Ubr) {
            $BestByLine[$Major] = [PSCustomObject]@{
                Build   = $Build
                Ubr     = $Ubr
                Date    = $Date
                KB      = $Kb
                Version = $VersionByBuild[$Major]
            }
        }
    }

    # Keep only build lines whose newest non-preview build is recent enough.
    $Result = foreach ($Entry in $BestByLine.Values) {
        $Parsed = $null
        try { $Parsed = [datetime]::ParseExact($Entry.Date, 'yyyy-MM-dd', $null) } catch { $Parsed = $null }
        if (-not $Parsed -or $Parsed -ge $Cutoff) { $Entry }
    }
    return @($Result)
}

# Formats a set of build entries into aligned hashtable lines, sorted newest build line first.
function Format-BuildEntries {
    param([object[]]$Entries)
    $Lines = @()
    foreach ($e in ($Entries | Sort-Object { [int](($_.Build -split '\.')[0]) } -Descending)) {
        $Key = "'{0}'" -f $e.Build
        $Comment = if ($e.Version) { "  # $($e.Version)" } else { '' }
        $Lines += "    {0} = @{{ Date = '{1}'; KB = '{2}' }}{3}" -f $Key.PadRight(13), $e.Date, $e.KB, $Comment
    }
    return $Lines
}

$Win11 = Get-BuildTableFromPage -Url 'https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information' -TimeoutSec $TimeoutSec
$Win10 = @()
if (-not $SkipWindows10) {
    $Win10 = Get-BuildTableFromPage -Url 'https://learn.microsoft.com/en-us/windows/release-health/release-information' -TimeoutSec $TimeoutSec
}

if (-not $Win11 -and -not $Win10) {
    Write-Error 'No build data could be parsed from the Microsoft release pages. Check connectivity and try again.'
    exit 1
}

$Block = @()
$Block += "# Last verified against Microsoft release information: $(Get-Date -Format 'yyyy-MM-dd')"
$Block += '$script:KnownBuildReleases = @{'
if ($Win11) {
    $Block += '    # --- Windows 11 (latest non-preview build per serviced version) ---'
    $Block += (Format-BuildEntries -Entries $Win11)
}
if ($Win10) {
    $Block += '    # --- Windows 10 (latest non-preview build per serviced version) ---'
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
