# Windows Update Fix

> [!NOTE]
> This is a specialized companion to the main [Windows Fix-Up](../README.md) script. Where that tool takes the broad "shotgun" approach to Windows repair, this one is focused on a single, very common problem: a **Windows Update experience that is broken by leftover or misconfigured Local Group Policy**. It is still a blunt instrument — it resets policy to "Not Configured" rather than isolating a root cause — so exercise caution in production or enterprise environments where Group Policy is intentionally configured.

This PowerShell script repairs Windows Update by clearing the Local Group Policy store, removing the Windows Update policy registry keys that "tattoo" the system, resetting the update cache, re-registering the update components, and verifying that all required services are healthy. It can also inspect the update history and **automatically decide whether — and how aggressively — to act**.

## How to Run This Script

The easiest and recommended way to run this script is by using the `Run-Windows-Update-Fix.bat` file. It automatically handles administrator elevation and PowerShell execution policies, and will even download the latest `Windows-Update-Fix.ps1` from GitHub if it is missing.

### Recommended Method: Using the Batch File

1.  **Download Files:** Make sure both `Run-Windows-Update-Fix.bat` and `Windows-Update-Fix.ps1` are saved in the **same folder**. (If the `.ps1` is missing, the batch file will download it automatically.)
2.  **Run the Batch File:** Double-click the `Run-Windows-Update-Fix.bat` file.
3.  **Administrator Prompt:** A User Account Control (UAC) window will appear asking for administrative privileges. Click **Yes**.
4.  **Follow Prompts:** The script opens in a new window, shows the last update and any recent failures, and asks for confirmation before making changes.

### Running with Parameters (from Command Line)

To use command-line parameters (like `-Remediate` or `-Unattended`), run the batch file from a Command Prompt or PowerShell terminal.

1.  Open Command Prompt or PowerShell.
2.  Navigate to the directory where you saved the files (e.g., `cd C:\Users\YourUser\Downloads`).
3.  Run the batch file with your desired parameters. For example:
    ```shell
    .\Run-Windows-Update-Fix.bat -Remediate
    ```

You can also run the PowerShell script directly (it will self-elevate):

```powershell
Set-ExecutionPolicy Bypass -Force
.\Windows-Update-Fix.ps1 -Remediate
```

## Command-Line Parameters

The script supports the following optional parameters:

| Parameter | Description |
|---|---|
| `-Unattended` | Runs the script without any user prompts. It will not ask for confirmation to start. |
| `-AutoReboot` | Automatically restarts the computer after a 60-second countdown once the fix completes. |
| `-Remediate` | **Adaptive mode.** Assesses Windows Update health from the update history and automatically scales the repair to how broken things are (see [Adaptive Remediation](#adaptive-remediation-recommended) below). Runs hands-off with no prompts. |
| `-FixIfStale` | Only runs the fix if updates look stale or unresolved failures exist (uses `-StaleDays`). If Windows Update looks healthy, the script exits without making changes. |
| `-StaleDays <n>` | Number of days used by `-Remediate` / `-FixIfStale` to consider updates stale. Default is `45`. |
| `-FailureFixThreshold <n>` | Maximum number of unresolved standard update failures tolerated when a recent patch has succeeded (below this, they are treated as likely false positives). Default is `5`. |
| `-ResetAllPolicies` | **Aggressive.** Also removes the broader Software Policies registry hive, not just the Windows Update keys. Automatically enabled by `-Remediate` when a system is classified as *severe*. |
| `-IncludeGroupPolicyUsers` | Also clears the per-user Local Group Policy store (`C:\Windows\System32\GroupPolicyUsers`). Off by default to avoid wiping intentional per-user policy. |
| `-RepairComponentStore` | Also runs `DISM /RestoreHealth` and `SFC /scannow` to repair the component store (slow). Automatically enabled by `-Remediate` when a system is classified as *severe*. |
| `-SkipOnlineBuildDate` | Skips the online lookup of the current build's exact release date and KB article. By default the script queries Microsoft's public release-information page (best-effort; falls back silently if offline or unmatched) to report, e.g., `Build 26200.8737 released: 2026-06-23 via KB5095093`. |
| `-TriggerUpdateScan` | Triggers a fresh Windows Update detection scan after the fix. Automatically enabled by `-Remediate`. |
| `-SkipInteractive` | Skips the interactive confirmation prompt while still showing output. |

## Adaptive Remediation (Recommended)

Running with `-Remediate` makes the script inspect the Windows Update history (ignoring driver and Microsoft Defender / antivirus definition updates) and choose an action based on how healthy things look:

| Severity | Trigger | Action |
|---|---|---|
| **Healthy** | A genuine patch was installed within `-StaleDays`, the installed build was released within `-StaleDays`, and there are no action-worthy failures. | Does nothing and exits. |
| **Mild** | Updates are stale (no recent patch *or* the installed build was released more than `-StaleDays` days ago), or there are unresolved failures while stale. | Baseline repair: clear Local Group Policy, remove the Windows Update policy keys, reset the cache/BITS queue, re-register the DLLs, verify services, and run `gpupdate /force`. |
| **Severe** | Never patched / no patch and no build newer than **2 × `-StaleDays`**, or more than `-FailureFixThreshold` unresolved failures. | Everything in *Mild*, **plus** `-ResetAllPolicies` and `-RepairComponentStore` (DISM/SFC). |

In every remediation case a fresh Windows Update scan is triggered afterward, and the whole process runs hands-off (no prompts). Remediation also honors the false-positive logic: a small number of unresolved failures alongside a recent successful patch are reported but ignored.

Staleness is judged from **two** independent signals: the date of the last successful patch in the update history, and the Microsoft release date of the currently-installed build revision (resolved online, unless `-SkipOnlineBuildDate` is set). The build-date signal catches machines whose update history has been cleared or truncated but which are nonetheless running an old build. If the online lookup is unavailable (offline or unmatched), the script silently falls back to the update-history signal alone.

> **Note on empty update history:** On modern Windows 11, cumulative updates are often installed through the Unified Update Platform and do **not** appear in the legacy Windows Update history (`Microsoft.Update.Session` can report zero entries). When the history is empty, the script does not blindly assume the machine is unpatched — it falls back to the installed build's release date. A recent build keeps the machine classified as *healthy*; only an old build (or an unavailable build date) is treated as stale.

## What the Script Does

When it proceeds with a repair, the script performs the following actions in sequence:

1.  **Stop Update Services**
    *   Stops `wuauserv`, `UsoSvc`, `BITS`, `DoSvc`, `CryptSvc`, and `msiserver` so files and registry keys are not locked during cleanup.

2.  **Clear the Local Group Policy Store**
    *   Removes the contents of `C:\Windows\System32\GroupPolicy` (and `GroupPolicyUsers` when `-IncludeGroupPolicyUsers` is used).

3.  **Remove Windows Update Policy Registry Keys**
    *   Deletes the `HKLM` Windows Update policy keys (including the `WOW6432Node` variant) that block or misconfigure updates. With `-ResetAllPolicies`, the broader Software Policies hive is removed as well.

4.  **Reset the Windows Update Cache**
    *   Clears the BITS transfer queue (`qmgr*.dat`) and renames `SoftwareDistribution` and `catroot2` to timestamped `.old_*` backups so Windows rebuilds them cleanly (falling back to clearing their contents if a rename is blocked).

5.  **Re-register Windows Update Components**
    *   Re-registers the set of DLLs Windows Update depends on via `regsvr32 /s`.

6.  **Verify and Enable Required Services**
    *   Ensures the services below are not disabled and are set to their healthy default startup type, starting the ones that must be running:

    | Service | Startup Type | Display Name |
    |---|---|---|
    | `BITS` | Manual | Background Intelligent Transfer Service |
    | `wuauserv` | Manual | Windows Update |
    | `UsoSvc` | Automatic | Update Orchestrator Service |
    | `WaaSMedicSvc` | Manual | Windows Update Medic Service |
    | `CryptSvc` | Automatic | Cryptographic Services |
    | `msiserver` | Manual | Windows Installer |
    | `TrustedInstaller` | Manual | Windows Modules Installer |
    | `DoSvc` | Automatic | Delivery Optimization |
    | `AppIDSvc` | Manual | Application Identity |
    | `gpsvc` | Automatic | Group Policy Client |

7.  **Force a Group Policy Refresh**
    *   Runs `gpupdate /force` so the machine rebuilds a clean policy set.

8.  **Repair the Component Store (Optional)**
    *   With `-RepairComponentStore` (or *severe* remediation), runs `DISM /Online /Cleanup-Image /RestoreHealth` followed by `SFC /scannow`.

9.  **Trigger an Update Scan (Optional)**
    *   With `-TriggerUpdateScan` (or any remediation), requests a fresh detection scan via `UsoClient StartScan` (with a COM fallback for older builds).

## Logging

Every run writes a timestamped transcript to the script's folder, named `Windows-Update-Fix_yyyy-MM-dd_HH-mm-ss.log`, so you can review exactly what was changed.

## Important Notes

> [!WARNING]
> This script resets any settings applied through **Local Group Policy** back to "Not Configured." On a machine that is joined to a domain or managed with intentional local policy, those settings will be reapplied on the next policy refresh (or may need to be reconfigured). Do not run this blindly on managed endpoints.

- A **restart is recommended** after the fix to fully apply the Group Policy and service changes.
- Requires **PowerShell 5.0+** and **Windows 10 / Server 2016** or newer.
- The `SoftwareDistribution.old_*` and `catroot2.old_*` backup folders are safe to delete once Windows Update is confirmed working.
