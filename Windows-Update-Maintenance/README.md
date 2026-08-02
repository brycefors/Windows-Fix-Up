# Windows Update Maintenance Engine

An unattended "Automated Windows Update Maintenance Engine". It detects the local OS build and architecture, finds the newest applicable **Cumulative Update** in the Microsoft Update Catalog, downloads it with BITS, installs it silently, diagnoses any failure, and always cleans up after itself.

> [!IMPORTANT]
> This script installs OS servicing packages directly from the Microsoft Update Catalog, bypassing Windows Update / WSUS approval. Use it on machines where Windows Update is broken, blocked, or intentionally managed out-of-band. Test with `-ReportOnly` first.

## Workflow

```
[1. Detect OS & Build] -> [2. Query Catalog] -> [3. Check Installed Status]
                                                     |
                             (Already Current) ------+------ (Update Needed)
                                     |                              |
                           [7. Maintenance Cleanup]        [4. BITS Download]
                                     |                              |
                                [Exit Code 0]              [5. Install MSU]
                                                                    |
                                                  (Success) --------+-------- (Failure)
                                                       |                          |
                                               [Log & Reboot]           [6. Parse Logs/Events]
                                                       |                          |
                                                       +------------+-------------+
                                                                    |
                                                       [7. Maintenance Cleanup]
```

## How to Run This Script

The easiest way to run this script is with the `Run-Windows-Update-Maintenance.bat` file, which handles administrator elevation and the PowerShell execution policy.

### Quickest Method: Straight from GitHub

Open **Terminal (Admin)** and paste one of these. Nothing has to be downloaded by hand — the script pulls itself from GitHub and runs in memory.

**No parameters (defaults):**

```powershell
irm https://raw.githubusercontent.com/brycefors/Windows-Fix-Up/refs/heads/main/Windows-Update-Maintenance/Windows-Update-Maintenance.ps1 | iex
```

**With parameters** (`iex` cannot take arguments, so wrap the download in a script block):

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/brycefors/Windows-Fix-Up/refs/heads/main/Windows-Update-Maintenance/Windows-Update-Maintenance.ps1))) -ReportOnly
```

**Download then run** — preferred for scheduled tasks, Intune, and RMM, because the file persists for re-runs and the exit code is returned to the caller:

```powershell
$Url  = 'https://raw.githubusercontent.com/brycefors/Windows-Fix-Up/refs/heads/main/Windows-Update-Maintenance/Windows-Update-Maintenance.ps1'
$Path = "$env:ProgramData\UpdateStaging\Windows-Update-Maintenance.ps1"
New-Item -ItemType Directory -Path (Split-Path $Path) -Force | Out-Null
Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing
& $Path -AutoReboot -ComponentCleanup
```

**Single-line command for an RMM / Intune platform script:**

```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol='Tls12'; & ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/brycefors/Windows-Fix-Up/refs/heads/main/Windows-Update-Maintenance/Windows-Update-Maintenance.ps1'))) -AutoReboot; exit $LASTEXITCODE"
```

> [!NOTE]
> Run these from an **elevated** session. If you start an in-memory run unelevated on an interactive desktop, the script writes itself to `%TEMP%\Windows-Update-Maintenance.ps1` and relaunches through UAC. In a non-interactive session (SYSTEM task, RMM) it throws instead of prompting.

> [!TIP]
> Piping any script from the internet straight into `iex` executes whatever that URL returns. Review the source, or pin the URL to a specific commit SHA instead of `refs/heads/main`, before using this in production.

### Recommended Method: Using the Batch File

1.  **Download Files:** Save `Run-Windows-Update-Maintenance.bat` and `Windows-Update-Maintenance.ps1` in the **same folder**.
2.  **Run the Batch File:** Double-click `Run-Windows-Update-Maintenance.bat`.
3.  **Administrator Prompt:** Approve the User Account Control (UAC) prompt.

### Unattended Method (Task Scheduler / Intune / RMM)

Run the `.ps1` directly as SYSTEM or a local Administrator. When the script is not interactive and not elevated it throws instead of prompting for UAC.

```shell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Windows-Update-Maintenance.ps1" -AutoReboot -ComponentCleanup
```

## Command-Line Parameters

| Parameter | Description |
|---|---|
| `-StagingPath` | Staging folder for the downloaded `.msu`, extracted `.cab` files, and logs. Default: `C:\ProgramData\UpdateStaging`. |
| `-LogPath` | Directory for execution logs and JSON reports. Default: `<StagingPath>\Logs`. |
| `-InstallMethod` | `DISM` (default) expands the MSU and injects the CAB with `Add-WindowsPackage` (faster, explicit DISM logging). `WUSA` uses `wusa.exe /quiet /norestart` (stricter applicability checks, slower under SYSTEM). |
| `-DownloadMethod` | `BITS` (default) uses `Start-BitsTransfer` with resumable background transfer. `HTTP` streams the file directly. BITS automatically falls back to HTTP when the service is disabled or the transfer fails. |
| `-SearchQuery` | Overrides the auto-generated Microsoft Update Catalog search term. |
| `-IncludePreview` | Allows optional "Preview" (C/D-week) cumulative updates to be selected. Excluded by default. |
| `-ReportOnly` | Detect and report only. Nothing is downloaded or installed. |
| `-Force` | Install even when the KB already appears to be present or the build revision is already current. |
| `-LogRetentionDays` | Days of logs/reports to retain (default `30`, `0` disables pruning). |
| `-KeepPayload` | Keeps the downloaded `.msu` and extracted `.cab` files instead of purging them during cleanup. |
| `-ComponentCleanup` | After a successful install, runs `Dism.exe /Online /Cleanup-Image /StartComponentCleanup` to trim the WinSxS store. |
| `-AutoReboot` | Restarts the computer when the installed update requires a reboot. |
| `-RebootDelaySeconds` | Delay before the `-AutoReboot` restart (default `60`). |
| `-SkipCbsLogParsing` | Skips the `CBS.log` regex parsing performed on failure (CBS.log can exceed 100 MB). |
| `-MinimumFreeSpaceGB` | Minimum free space required on the staging volume before downloading (default `8`). |
| `-WhatIf` / `-Confirm` | Standard `ShouldProcess` support around the download/install phase. |

## What the Script Does

### Module 1 — System Inspection & Build Detection
Reads `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion` for `CurrentBuildNumber`, `UBR`, `DisplayVersion`/`ReleaseId`, `EditionID`, and `InstallationType`, plus `$env:PROCESSOR_ARCHITECTURE` and the Win32_OperatingSystem product type (workstation vs. server). It also warns when a reboot is already pending, since that commonly blocks servicing.

### Module 2 — Catalog Query & Applicable KB Identification
Builds a strict search term (for example `Cumulative Update for Windows 11 Version 25H2 for x64-based Systems`), queries `catalog.update.microsoft.com/Search.aspx`, and parses the result rows for the title, KB ID, classification, size, release date, and update GUID. Direct scraping is used deliberately so the script has **zero external module dependencies** in unattended environments. `.NET Framework`, Dynamic Update, wrong-architecture, and (by default) Preview entries are filtered out, and the newest remaining build revision wins.

### Module 3 — Installed State & Pre-flight Verification
Applies a version guardrail by comparing the build revision embedded in the catalog title (for example `(26200.8894)`) against the local `CurrentBuild.UBR`, then confirms with `Get-HotFix` and `Get-WindowsPackage -Online`. If the system is already at or beyond the target, the script jumps straight to cleanup and exits `0`. Free disk space on the staging volume is validated before any download.

### Module 4 — BITS Asynchronous File Transfer
Resolves the real `.msu` links from the catalog's `DownloadDialog.aspx` endpoint, rejecting any host that is not a Microsoft CDN and forcing HTTPS. Payloads download to `<StagingPath>\Payload` via `Start-BitsTransfer -Priority Foreground` under a known display name, falling back to a streamed `HttpClient` download if BITS is disabled or blocked by policy. When the catalog returns a prerequisite (checkpoint/SSU) package alongside the cumulative update, both are downloaded in order.

### Module 5 — Unattended MSU Installation
* **DISM (default):** The MSU container is inspected first. Classic CAB-based MSUs (`MSCF` signature) are expanded with `expand.exe -f:*` into `<StagingPath>\Extract`, `WSUSSCAN.cab` is discarded, any servicing stack CAB is applied first, then `Add-WindowsPackage -Online -NoRestart -LogPath <log>` installs the payload.
* **WUSA:** `wusa.exe "<file>.msu" /quiet /norestart`.

Prerequisite packages that report "already installed" or "not applicable" are logged and skipped rather than failing the run.

#### MSUs with no CAB inside

Windows 11 23H2 and later publish cumulative updates in a newer MSU container (`MSWI` signature) that is **not** a cabinet file. `expand.exe` cannot open it, so the classic "expand, then install the CAB" approach finds nothing to install. The script handles this with a three-step chain:

1. **Container check** — the first four bytes of the `.msu` are read. If the signature is not `MSCF`, expansion is skipped entirely and the `.msu` is handed straight to `Add-WindowsPackage -PackagePath <file>.msu`, which DISM supports natively.
2. **PSF-based packages** — if a CAB-based MSU expands to `.mum`/`.manifest`/`.psf` files with no standalone CAB, the expanded folder itself is used as the DISM package path.
3. **WUSA fallback** — if DISM still refuses the payload (and the failure is not simply "not applicable"), the original `.msu` is retried through `wusa.exe /quiet /norestart`, which understands both container formats.

Each step is written to the execution log, so the report shows exactly which path was taken.

### Module 6 — Programmatic Diagnostic Logging & Error Parsing
On a non-success exit code the script:
* Translates the exit code / HRESULT using an embedded `winerror.h` lookup table, falling back to `Win32Exception`.
* Parses the tail of `C:\Windows\Logs\CBS\CBS.log` for `Error`, `Failed`, and `0x8...` matches inside the execution's timestamp window.
* Queries `Microsoft-Windows-WindowsUpdateClient/Operational`, the `System` log (WindowsUpdateClient / Servicing / WUSA providers), and the `Setup` log.
* Captures the component servicing state via `Repair-WindowsImage -Online -CheckHealth`.

### Module 7 — Automated Cleanup & Lifecycle Management
Runs from a `finally` block, so it executes whether the run succeeded, failed, or exited early:
* Purges `.msu` installers and extracted `.cab` files from the staging folder (unless `-KeepPayload`).
* Cancels orphaned or suspended BITS jobs matching the script's display name.
* Prunes logs and JSON reports older than `-LogRetentionDays` (default 30).
* Optionally runs `Dism.exe /Online /Cleanup-Image /StartComponentCleanup` after a successful install.

## Output

| Artifact | Location |
|---|---|
| Execution log | `<LogPath>\WindowsUpdateMaintenance_<timestamp>.log` |
| Structured JSON report | `<LogPath>\Report_<timestamp>.json` |
| DISM installation log | `<LogPath>\DISM_Install_<timestamp>.log` |

The JSON report contains the detected system profile, the search term used, the selected update, download engine and size, installer exit code plus HRESULT translation, matched CBS lines, event log records, the cleanup summary, and the final exit code.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | The system is already current, no applicable update was found, or the update installed with no reboot required. |
| `3010` | The update installed successfully and a restart is required to complete servicing. |
| `1` | The run failed. See the JSON report and execution log for the translated error code and diagnostics. |

## Design Trade-offs

| Decision | Chosen | Why |
|---|---|---|
| Catalog access | Direct scraping | No external module (for example `MSCatalogLTS`) has to be installed on unattended endpoints. The trade-off is sensitivity to catalog HTML changes, which is isolated to `Invoke-CatalogSearch`. |
| Installer engine | DISM `Add-WindowsPackage` (default), WUSA optional | DISM is faster under SYSTEM and produces an explicit servicing log; WUSA is available via `-InstallMethod WUSA` when its stricter applicability validation is preferred. |
| Download pipeline | BITS with HTTP fallback | BITS respects network throttling and resumes over intermittent links; the fallback keeps the script working where BITS is disabled by policy. |
| Diagnostics | Event logs + optional CBS parsing | Event logs give clean structured HRESULTs; CBS parsing is limited to the log tail and the execution time window so a 100 MB+ file does not stall the run. |
| Cleanup | Immediate purge in `finally` | Payloads are only deleted after the servicing stack has committed the package, so a pending reboot is unaffected while multi-hundred-megabyte files never accumulate. |
