# Windows Update Error Analysis

> [!NOTE]
> This is a diagnostic companion to the main [Windows Fix-Up](../README.md) toolkit and to [Windows Update Fix](../Windows-Update-Fix/README.md). Where those tools *change* the system, this one is built to **diagnose first**: it parses the local Windows Update and Servicing (CBS) logs, decodes the failure codes, and produces a clean, actionable report plus a **remediation script you can review before running**.

`Get-WindowsUpdateErrorAnalysis.ps1` reads Windows Update failures from the System event log (and, optionally, the CBS servicing log), extracts the HRESULT / Win32 error codes, looks up their technical meaning in an embedded offline database, and outputs step-by-step remediation guidance.

## Table of Contents

- [Why This Tool](#why-this-tool)
- [Build & Patch Currency](#build--patch-currency)
- [How It Works](#how-it-works)
- [How to Run This Script](#how-to-run-this-script)
  - [Recommended Method: Using the Batch File](#recommended-method-using-the-batch-file)
  - [Running with Parameters](#running-with-parameters)
- [Command-Line Parameters](#command-line-parameters)
- [Error Lookup Database](#error-lookup-database)
- [Auto-Remediation: The Trade-Off](#auto-remediation-the-trade-off)
- [Requirements](#requirements)

## Why This Tool

Windows Update errors are rarely unique to a single KB. Over **85% of update failures stem from standard WinSxS component-store corruption or `SoftwareDistribution` cache deadlocks**. This script therefore operates primarily as an **interactive diagnostic engine**: it parses the logs, prints a clean report, and generates a single reviewable remediation script (`Invoke-RepairWU.ps1`) that an administrator can inspect before executing — rather than blindly applying changes.

## Build & Patch Currency

Before the error report, the script prints a **Build & Patch Currency** section showing the OS build (`Build.UBR`) and the date of the most recent installed quality update. This is an **offline heuristic** — it does not look up the latest available build online. If no quality update has installed within `-StaleBuildDays` (default **45**), it warns that the machine **is not on a recent build and patching may be impaired**, which is a very common context for the servicing errors this tool decodes.

## How It Works

```
[Windows Log Sources]
   ├─> Get-WinEvent (System log, provider Microsoft-Windows-WindowsUpdateClient, Event IDs 20 / 25 / 31)
   └─> C:\Windows\Logs\CBS\CBS.log  (matched with -IncludeCbsLogs)
        │
        ▼
[Log Parsing & Deduplication]  →  Timestamp, KB ID, raw HRESULT / Win32 hex code
        │
        ▼
[Offline Embedded Error Lookup Table]  →  Name, Technical Cause, Native Remediation
        │   (falls back to Win32Exception / net helpmsg for unlisted codes)
        ▼
[Output Pipeline]
   ├─> Colour-coded console report
   ├─> JSON export (-ExportJsonPath)
   ├─> Generated Invoke-RepairWU.ps1 (review before running)
   └─> Optional native auto-remediation (-AutoRemediate)
```

## How to Run This Script

### Recommended Method: Using the Batch File

1.  **Download Files:** Make sure both `Run-Windows-Update-Error-Analysis.bat` and `Get-WindowsUpdateErrorAnalysis.ps1` are saved in the **same folder**. (If the `.ps1` is missing, the batch file will download it automatically.)
2.  **Run the Batch File:** Double-click `Run-Windows-Update-Error-Analysis.bat`.
3.  **Administrator Prompt:** Accept the User Account Control (UAC) prompt.
4.  **Review the Report:** The script prints the decoded failures and writes an `Invoke-RepairWU.ps1` you can review before applying any fix.

### Running with Parameters

Run the batch file (or the `.ps1` directly) from an elevated Command Prompt or PowerShell terminal:

```shell
.\Run-Windows-Update-Error-Analysis.bat -Days 60 -IncludeCbsLogs -ExportJsonPath C:\Temp\wu-analysis.json
```

Or invoke the script directly:

```powershell
.\Get-WindowsUpdateErrorAnalysis.ps1 -Days 30 -PassThru
```

## Command-Line Parameters

| Parameter | Description |
|---|---|
| `-Days <int>` | Look-back period in days for both the event log and the CBS log. Default: `30`. |
| `-ActiveThresholdDays <int>` | A failure whose most recent occurrence is within this many days is flagged **Active**; older codes are flagged **Resolved?** (recency only — it cannot confirm a fix). Default: `7`. |
| `-StaleBuildDays <int>` | If no quality update has installed within this many days, the report warns that the build is not recent and patching may be impaired. Default: `45`. |
| `-ExportJsonPath <path>` | Exports the structured analysis to the given JSON file. |
| `-IncludeCbsLogs` | Also parse `C:\Windows\Logs\CBS\CBS.log` (matches lines containing `Failed`, `Error`, or `STORE_ERROR` with an HRESULT). Slower on large logs. |
| `-AutoRemediate` | Executes only the deterministic, **safe** native repairs for the detected errors, then runs `DISM /RestoreHealth` and `sfc /scannow`. Honors `-WhatIf` / `-Confirm`. |
| `-PassThru` | Returns the structured analysis objects to the pipeline. |

## Error Lookup Database

The script embeds an offline mapping for the most common Windows Servicing HRESULTs. Codes not in the table fall back to the OS description (`System.ComponentModel.Win32Exception` / `net helpmsg`).

| Hex Error | Error Name | Technical Cause | Remediation |
|---|---|---|---|
| `0x80070002` | `ERROR_FILE_NOT_FOUND` | Missing update file or corrupted WU cache. | Stop `wuauserv` & `bits`, rename `SoftwareDistribution`, restart services. |
| `0x80070005` | `ERROR_ACCESS_DENIED` | File-system/registry permission blockade. | Reset servicing permissions (`subinacl`). *Manual review.* |
| `0x800705b4` | `ERROR_TIMEOUT` | WU service timed out waiting on a child process / Defender scan. | Restart `wuauserv`, set startup to Automatic. |
| `0x800f081f` | `CBS_E_SOURCE_MISSING` | SxS payload missing from the WinSxS store. | `DISM /Online /Cleanup-Image /RestoreHealth`. |
| `0x800f0922` | `CBS_E_INSTALL_FAILED` | Low System Reserved space, Secure Boot, or VPN block. | Verify partition space (>100 MB) & BitLocker. *Manual review.* |
| `0x800f0988` | `PSFX_E_MATCHING_BINARY_MISSING` | Reset-base/WinSxS cleanup removed a delta dependency. | Reset-base DISM repair or install latest SSU. *Manual review.* |
| `0x80240020` | `WU_E_NO_INTERACTIVE_USER` | Non-interactive session needed interactive auth. | Trigger a scan from SYSTEM context (`UsoClient StartScan`). |
| `0x80248007` | `WU_E_DS_NODRIVER` | Driver payload missing from the WU datastore. | Delete `DataStore.edb` under `SoftwareDistribution`. |
| `0x80073D02` | `ERROR_DEPLOYMENT_BLOCKED_BY_IN_USE_PACKAGE` | AppX/UWP package in use (running app) or corrupted Store cache. | Close the app to release locks, run `wsreset.exe`, then re-register the Store manifest. *Manual review.* |

## Auto-Remediation: The Trade-Off

`-AutoRemediate` is **opt-in** and only runs the fixes classified as *safe* in the report.

- **For:** Instantly applies deterministic fixes (service reset, `SoftwareDistribution` rename, `DISM /RestoreHealth`, `sfc /scannow`) for known state-corruption errors without manual intervention.
- **Against:** Running DISM or flushing `SoftwareDistribution` during an active background patch cycle can break in-flight deployments, trigger reboot locks, or cause transient false negatives.

> [!TIP]
> When in doubt, skip `-AutoRemediate`. Review the generated `Invoke-RepairWU.ps1` and run it yourself when no update is actively in progress. Commands classified as *manual review* are written into that script as commented-out guidance, never as automatic actions.

## Requirements

- **PowerShell 5.1** (Windows PowerShell) or **PowerShell 7.x+** (Core).
- **Administrator elevation** — the script throws a terminating error if not elevated (it does not self-elevate).
- **Windows 10 / Server 2016** or newer.
