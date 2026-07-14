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

### Remote / One-Line Deployment

To run the tool on a machine without cloning the repo (handy for RMM tools, remote sessions, or a quick fix), use this block to download `Windows-Update-Fix.ps1` into the temp folder and run it in adaptive remediation mode:

```powershell
# Fetch Windows-Update-Fix.ps1 to the temp folder and run it in adaptive remediation mode
$Url  = 'https://raw.githubusercontent.com/brycefors/Windows-Fix-Up/refs/heads/main/Windows-Update-Fix/Windows-Update-Fix.ps1'
$Dest = Join-Path $env:TEMP 'Windows-Update-Fix.ps1'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
powershell.exe -ExecutionPolicy Bypass -File $Dest -Remediate
```

Compact one-liner (handy for RMM command fields):

```powershell
$d="$env:TEMP\Windows-Update-Fix.ps1";[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;irm 'https://raw.githubusercontent.com/brycefors/Windows-Fix-Up/refs/heads/main/Windows-Update-Fix/Windows-Update-Fix.ps1' -OutFile $d;powershell -ExecutionPolicy Bypass -File $d -Remediate
```

> [!NOTE]
> The script self-elevates, so a UAC prompt will appear unless it is launched from an already-elevated context (e.g. an RMM agent running as `SYSTEM`). `-Remediate` assesses Windows Update health and scales the repair automatically, and honors the 7-day cooldown — add `-IgnoreCooldown` to bypass it. For a machine you know needs fixing regardless of history, swap in `-ForceRemediate Mild` or `-ForceRemediate Severe`.

### Running Across Machines with `Invoke-Command`

If PowerShell Remoting (WinRM) is enabled on the targets (`Enable-PSRemoting -Force`) and you have admin credentials, you can download-and-run the script on one or many machines at once. Remoting sessions are already elevated, so there is no UAC prompt.

```powershell
$Computers = 'PC01', 'PC02', 'PC03'
$Cred = Get-Credential   # an admin account on the targets

Invoke-Command -ComputerName $Computers -Credential $Cred -ScriptBlock {
    $Url  = 'https://raw.githubusercontent.com/brycefors/Windows-Fix-Up/refs/heads/main/Windows-Update-Fix/Windows-Update-Fix.ps1'
    $Dest = Join-Path $env:TEMP 'Windows-Update-Fix.ps1'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
    & $Dest -Remediate -Unattended
}
```

- Call the script inline with `& $Dest` (not a nested `powershell.exe`) so output and errors flow back to you; results are tagged with `PSComputerName` per machine.
- Include `-Unattended` so it never waits for a prompt — there is no interactive console on the remote side.
- To pass flags from your side, build an array locally and splat it with `$using:`:

  ```powershell
  $Flags = @('-ForceRemediate', 'Severe', '-Unattended')
  Invoke-Command -ComputerName $Computers -Credential $Cred -ScriptBlock {
      $Url  = 'https://raw.githubusercontent.com/brycefors/Windows-Fix-Up/refs/heads/main/Windows-Update-Fix/Windows-Update-Fix.ps1'
      $Dest = Join-Path $env:TEMP 'Windows-Update-Fix.ps1'
      [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
      Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
      & $Dest @using:Flags
  }
  ```

> [!NOTE]
> Targets need outbound internet to reach both GitHub and Windows Update; if they cannot reach GitHub, copy the script over a session instead (`$s = New-PSSession ...; Copy-Item .\Windows-Update-Fix.ps1 -ToSession $s -Destination "$env:TEMP\"; Invoke-Command -Session $s { & "$env:TEMP\Windows-Update-Fix.ps1" -Remediate -Unattended }`). Adding `-AutoReboot` will reboot the machine and drop the session, so only use it when that is intended.

## Command-Line Parameters

The script supports the following optional parameters:

| Parameter | Description |
|---|---|
| `-Unattended` | Runs the script without any user prompts. It will not ask for confirmation to start. |
| `-AutoReboot` | Restarts the computer after a 60-second countdown once the fix completes. **The script only reboots when this flag is set** — without it, the fix finishes and just reminds you to restart manually. During an interactive run the countdown can be cancelled by pressing any key. |
| `-ScheduleReboot` | Only takes effect together with `-InstallUpdates`. If the installed updates require a restart to finish, the script **schedules** a reboot for the next occurrence of `-ScheduleRebootTime` (default **2:00 AM**) instead of rebooting immediately, and **broadcasts an on-screen notice to every logged-on user** telling them the exact date/time. It takes precedence over `-AutoReboot` when an update-required restart is pending. The scheduled reboot can be cancelled any time with `shutdown /a`. Does nothing if no update actually requires a restart. |
| `-ScheduleRebootTime <HH:mm>` | Local time of day (24-hour `HH:mm`) for the reboot scheduled by `-ScheduleReboot`. Defaults to `02:00`. If the time has already passed today, the reboot is scheduled for the same time tomorrow. |
| `-Remediate` | **Adaptive mode.** Assesses Windows Update health from the update history and automatically scales the repair to how broken things are (see [Adaptive Remediation](#adaptive-remediation-recommended) below). Runs hands-off with no prompts. |
| `-ForceRemediate <Mild\|Severe>` | **Forced mode.** Skips the health assessment entirely and applies the specified repair level directly. `Mild` runs the baseline repair; `Severe` additionally enables `-ResetAllPolicies` and `-RepairComponentStore`. Also runs hands-off with no prompts and triggers an update scan. Useful when the update history is empty or unreliable. Ignored if `-Remediate` is also passed. |
| `-CooldownDays <n>` | Minimum number of days that must pass before `-Remediate` or `-ForceRemediate` can run again on the same machine. The timestamp is stored in a `.last_remediation` file alongside the script. Default is `7`. Set to `0` to disable. Stamps older than `2 × CooldownDays` are automatically removed. |
| `-IgnoreCooldown` | Bypasses the cooldown check for a single run without changing the default. |
| `-FixIfStale` | Only runs the fix if updates look stale or unresolved failures exist (uses `-StaleDays`). If Windows Update looks healthy, the script exits without making changes. |
| `-StaleDays <n>` | Number of days used by `-Remediate` / `-FixIfStale` to consider updates stale. Default is `45`. |
| `-FailureFixThreshold <n>` | Maximum number of unresolved standard update failures tolerated when a recent patch has succeeded (below this, they are treated as likely false positives). Default is `5`. |
| `-ResetAllPolicies` | **Aggressive.** Also removes the broader Software Policies registry hive, not just the Windows Update keys. Automatically enabled by `-Remediate` when a system is classified as *severe*. |
| `-IncludeGroupPolicyUsers` | Also clears the per-user Local Group Policy store (`C:\Windows\System32\GroupPolicyUsers`). Off by default to avoid wiping intentional per-user policy. |
| `-RepairComponentStore` | Also runs `DISM /RestoreHealth` and `SFC /scannow` to repair the component store (slow). Automatically enabled by `-Remediate` when a system is classified as *severe*. |
| `-SkipOnlineBuildDate` | Skips the online lookup of the current build's exact release date and KB article. By default the script queries Microsoft's public release-information page (best-effort) to report, e.g., `Build 26200.8737 released: 2026-06-23 via KB5095093`. If the online lookup times out or is unreachable, it falls back to a small **hardcoded build reference table** in the script (see [Build Date Lookup](#build-date-lookup)); if neither is available it falls back silently. |
| `-TriggerUpdateScan` | Triggers a fresh Windows Update detection scan after the fix. Automatically enabled by `-Remediate`. When used **without** `-InstallUpdates`, it also performs a quick read-only detection and prints what the scan found, so you can confirm the scan is actually picking up updates. See [Checking What a Scan Detects](#checking-what-a-scan-detects). |
| `-InstallUpdates` | After the fix, searches for available updates via the WUA COM API, downloads and installs them, then reports per-update results (succeeded / failed / reboot required). See [Installing Updates](#installing-updates) for details. |
| `-InstallViaScheduledTask` | Runs the `-InstallUpdates` step through a local scheduled task running as `NT AUTHORITY\SYSTEM`, working around the WUA access-denied (`0x80070005`) error that occurs when downloading/installing updates over a remote (WinRM / PowerShell Remoting) session. This is **applied automatically** when the script detects it is running in a remote session, so you rarely need to set it by hand. See [Installing Updates Remotely](#installing-updates-remotely). |
| `-LogPath <path>` | Directory to write log files to. Defaults to the script folder. The directory is created automatically if it does not exist. If the path is invalid or cannot be created, the script falls back to the script folder. |
| `-SkipInteractive` | Skips the interactive confirmation prompt while still showing output. |

## Adaptive Remediation (Recommended)

Running with `-Remediate` makes the script inspect the Windows Update history (ignoring driver and Microsoft Defender / antivirus definition updates) and choose an action based on how healthy things look:

| Severity | Trigger | Action |
|---|---|---|
| **Healthy** | A genuine patch was installed within `-StaleDays`, the installed build was released within `-StaleDays`, and there are no action-worthy failures. | Does nothing and exits. |
| **Mild** | Updates are stale (no recent patch *or* the installed build was released more than `-StaleDays` days ago), or there are unresolved failures while stale. | Baseline repair: clear Local Group Policy, remove the Windows Update policy keys, reset the cache/BITS queue, re-register the DLLs, verify services, and run `gpupdate /force`. |
| **Severe** | Never patched / no patch and no build newer than **2 × `-StaleDays`**, or more than `-FailureFixThreshold` unresolved failures. | Everything in *Mild*, **plus** `-ResetAllPolicies` and `-RepairComponentStore` (DISM/SFC). |

If you want to skip the health assessment and force a specific level regardless of what the history shows, use `-ForceRemediate Mild` or `-ForceRemediate Severe` instead. This is useful when the update history is empty (common on modern Windows 11) or when you simply know the machine needs fixing.

```shell
# Baseline repair, no health check
.\Run-Windows-Update-Fix.bat -ForceRemediate Mild

# Full repair (ResetAllPolicies + DISM/SFC), no health check
.\Run-Windows-Update-Fix.bat -ForceRemediate Severe
```

In every remediation case a fresh Windows Update scan is triggered afterward, and the whole process runs hands-off (no prompts). Remediation also honors the false-positive logic: a small number of unresolved failures alongside a recent successful patch are reported but ignored.

Staleness is judged from **two** independent signals: the date of the last successful patch in the update history, and the Microsoft release date of the currently-installed build revision (resolved online, unless `-SkipOnlineBuildDate` is set). The build-date signal catches machines whose update history has been cleared or truncated but which are nonetheless running an old build. If the online lookup is unavailable (offline or timed out), the script first consults the [hardcoded build reference](#build-date-lookup) baked into the script, and only falls back to the update-history signal alone if the build is not listed there.

## Build Date Lookup

When reporting the current build's release date/KB (and for the build-based staleness signal), the script first tries Microsoft's public release-information page. Because that page can be slow or unreachable, the script also ships with a small **hardcoded fallback table** (`$KnownBuildReleases`) near the top of `Windows-Update-Fix.ps1`, keyed by `Build.UBR` (e.g. `26100.8737`). If the online lookup times out or fails, this table supplies the release date and KB instead; it is also used to fill in whichever single value (date or KB) the online lookup could not resolve.

The table is easy to keep current. To update it:

1.  Open the Microsoft release information page ([Windows 11](https://learn.microsoft.com/windows/release-health/windows11-release-information) / [Windows 10](https://learn.microsoft.com/windows/release-health/release-information)).
2.  In the *release history* section, find the newest row for the version(s) you care about and note its **Build** (`Build.UBR`), **Availability date**, and **KB article**.
3.  Add or replace the matching entry in `$KnownBuildReleases`, using an ISO `yyyy-MM-dd` date. Old entries are harmless — they are only ever used as a fallback — so you only need to keep the latest few builds.

### "Am I on an old build?" comparison

Because the table lists the **latest known build per version line** (e.g. `26100.8737` for 24H2), the script also uses it as a date-independent way to tell whether a newer build already exists. When it prints the build banner, it compares the installed `Build.UBR` against the newest entry in the table for the **same major build number**:

- **Installed UBR is lower** → reports `Newer build available … this PC is behind the latest known build.`
- **Installed UBR matches** → reports it is up to date with the latest build the script knows about.
- **Installed UBR is higher** → the machine is newer than the table (a reminder to refresh the table).

This comparison is **informational** and does not by itself trigger remediation — that decision still comes from the date-based staleness signals described under [Adaptive Remediation](#adaptive-remediation-recommended). Because it only ever reports "behind" when the installed build is genuinely lower than a build Microsoft has already shipped, a stale table can never produce a false "behind" result (only a missed one), so it is safe to rely on. Keeping the table current simply makes the comparison more accurate.

### Feature update end-of-life note

Separately from the monthly-build comparison above, the script reports the installed **feature update's support lifecycle** (end of servicing, a.k.a. end of life). This uses a small `$KnownFeatureUpdates` table (also near the top of the script) that lists each feature update's end-of-servicing date, per product and edition:

- The check is **strictly per product** — a Windows 11 machine uses only the Windows 11 dates, a Windows 10 machine only the Windows 10 dates.
- The date is chosen by **edition**: Enterprise, Education, and IoT Enterprise editions get the longer servicing window; all others use the Home/Pro date.
- Nothing is printed while the feature update is comfortably in support (more than 6 months of servicing left).

It prints one of two lines when relevant:

```
END OF LIFE: 22H2 reached end of servicing on 2024-10-08 (Home/Pro) - it no longer receives security updates. Upgrade to a supported feature update.
```
```
END OF LIFE APPROACHING: 24H2 reaches end of servicing on 2026-10-13 (Home/Pro) - about 92 day(s) left. Plan to update before then.
```

This is **informational only** — the script never downloads, installs, or remediates based on it. To keep it accurate, update the end-of-servicing dates in `$KnownFeatureUpdates` from the *servicing channels* table on the Microsoft release information page whenever a feature update ships or Microsoft revises a date.

## Remediation Cooldown

To prevent `-Remediate` and `-ForceRemediate` from running too frequently in automated scenarios (e.g., a scheduled task or RMM deployment), the script enforces a cooldown period between repairs.

When a repair commits, it writes the current timestamp to a `.last_remediation` file stored alongside the script. On the next run, if the elapsed time is less than `-CooldownDays` (default: `7`), the script exits immediately with a message rather than running the repair again.

| Situation | Behavior |
|---|---|
| File does not exist | No cooldown — proceeds normally. |
| File is newer than `-CooldownDays` | Exits with `"Cooldown active"` message. |
| File is older than `-CooldownDays` but newer than `2 ×` | Proceeds; file is overwritten with a new stamp when repair commits. |
| File is older than `2 × CooldownDays` | File is deleted proactively; repair proceeds and writes a fresh stamp. |
| `-Remediate` exits as **Healthy** (no repair run) | Stamp file is not updated. |
| Interactive / manual run (no `-Remediate` or `-ForceRemediate`) | Stamp file is not touched at all. |

To reset the cooldown manually, delete the `.last_remediation` file or use `-IgnoreCooldown`:

```shell
# Bypass for a single run
.\Run-Windows-Update-Fix.bat -Remediate -IgnoreCooldown

# Disable the cooldown entirely
.\Run-Windows-Update-Fix.bat -Remediate -CooldownDays 0

# Use a longer cooldown for monthly maintenance
.\Run-Windows-Update-Fix.bat -Remediate -CooldownDays 30
```

> **Note on empty update history:** On modern Windows 11, cumulative updates are often installed through the Unified Update Platform and do **not** appear in the legacy Windows Update history (`Microsoft.Update.Session` can report zero entries). When the history is empty, the script does not blindly assume the machine is unpatched — it falls back to the installed build's release date. A recent build keeps the machine classified as *healthy*; only an old build (or an unavailable build date) is treated as stale.

## Disk Space Check

Before doing any work, the script checks the free space on the system drive, because Windows Update needs room to download and stage updates:

| Free space | Behavior |
|---|---|
| **Under 1 GB** | Refuses to run — logs a critical message and exits, since updates cannot function reliably. |
| **Under 5 GB** | Runs a light, safe proactive cleanup to free space, then continues (only aborts if it is *still* under 1 GB afterward). |
| **Under 20 GB** | Warns that feature updates may need more room, but continues. |

The light cleanup is non-destructive to user data. It removes:
- Leftover `SoftwareDistribution.old_*` / `catroot2.old_*` backups from previous runs
- The Windows Update download cache (`SoftwareDistribution\Download`, which Windows re-downloads as needed)
- User and Windows Temp folders
- Delivery Optimization peer cache (can be several GB)
- Windows Error Reporting archives (`WER\ReportArchive` / `ReportQueue`)
- CBS/DISM log files (`C:\Windows\Logs\CBS`)
- Crash dump files (`Minidump\*` and `MEMORY.DMP`)
- Windows Update internal logs (`SoftwareDistribution\DataStore\Logs`)

## What the Script Does

When it proceeds with a repair, the script performs the following actions in sequence:

1.  **Stop Update Services**
    *   Temporarily sets `WaaSMedicSvc`, `UsoSvc`, `wuauserv`, `BITS`, `DoSvc`, `CryptSvc`, and `msiserver` to **Disabled** and then stops them, so Windows cannot trigger-start them again and re-lock files or registry keys mid-cleanup. The Windows Update Medic Service (`WaaSMedicSvc`) in particular is known to silently revive the other update services during a repair. For each service it **confirms the disabled state actually took effect** (via the live service start mode, falling back to the registry `Start` value) and **retries stopping until the service stays down**. A final verification pass checks that every targeted service is both stopped and disabled before any files are renamed, and reports any that could not be — so a locked-file outcome is never silent. Step 7 restores every service to its healthy startup type at the end of the run.

2.  **Clear the Local Group Policy Store**
    *   Removes the contents of `C:\Windows\System32\GroupPolicy` (and `GroupPolicyUsers` when `-IncludeGroupPolicyUsers` is used).

3.  **Remove Windows Update Policy Registry Keys**
    *   Deletes the `HKLM` Windows Update policy keys (including the `WOW6432Node` variant) that block or misconfigure updates. With `-ResetAllPolicies`, the broader Software Policies hive is removed as well.

4.  **Clear Stale Reboot-Pending Flags**
    *   Removes the `RebootRequired`, `RebootPending`, and `RebootInProgress` registry keys left over from previous (or phantom) update cycles. These flags silently block new update installations without requiring an actual reboot to clear them.

5.  **Reset the Windows Update Cache**
    *   Removes any leftover `.old_*` backups from previous runs, then clears the BITS transfer queue (`qmgr*.dat`) and renames `SoftwareDistribution` and `catroot2` to timestamped `.old_*` backups so Windows rebuilds them cleanly (falling back to clearing their contents if a rename is blocked).

6.  **Re-register Windows Update Components**
    *   Re-registers the set of DLLs Windows Update depends on via `regsvr32 /s`.

7.  **Verify and Enable Required Services**
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

8.  **Re-enable Windows Update Scheduled Tasks**
    *   Re-enables the scheduled tasks that drive automatic scanning and installation. If these are disabled, Windows Update will never auto-scan or install regardless of service state:

    | Task | Path |
    |---|---|
    | `Scheduled Start` | `\Microsoft\Windows\WindowsUpdate\` |
    | `ScanForUpdates` | `\Microsoft\Windows\InstallService\` |
    | `ScanForUpdatesAsUser` | `\Microsoft\Windows\InstallService\` |

9.  **Force a Group Policy Refresh**
    *   Runs `gpupdate /force` so the machine rebuilds a clean policy set.

10. **Reset WinHTTP Proxy**
    *   Checks whether a WinHTTP proxy is configured. If one is found, it is reset to Direct Access (no proxy). A stale proxy left over from a domain join, VPN, or MDM enrolment is a common silent cause of Windows Update connectivity failures. If the machine requires a proxy, it can be re-configured afterward with `netsh winhttp set proxy <proxy:port>`.

11. **Check Hosts File for Blocked Windows Update Domains**
    *   Scans `C:\Windows\System32\drivers\etc\hosts` for entries matching Windows Update domains (`windowsupdate.com`, `update.microsoft.com`, `download.microsoft.com`, etc.). Some "privacy" tools and malware redirect these to `0.0.0.0` or `127.0.0.1`, silently preventing updates. The script reports any matches in red with instructions to remove them manually.

12. **Repair the Component Store (Optional)**
    *   With `-RepairComponentStore` (or *severe* remediation), runs `DISM /Online /Cleanup-Image /RestoreHealth` followed by `SFC /scannow`.

13. **Trigger an Update Scan (Optional)**
    *   With `-TriggerUpdateScan` (or any remediation), requests a fresh detection scan via `UsoClient StartScan` (with a COM fallback for older builds).

## Checking What a Scan Detects

`UsoClient StartScan` is **fire-and-forget** — it kicks off a scan but returns no result, so on its own it can't tell you whether the scan actually found anything. To close that gap, when you use `-TriggerUpdateScan` **without** `-InstallUpdates`, the script follows the scan with a **read-only detection** and prints what it found:

```
Checking what the scan detects (read-only - nothing is downloaded or installed)...
  Detection found 2 applicable update(s): 1 quality/feature, 1 driver/definition.
    - 2026-07 Cumulative Update for Windows 11 Version 24H2 (KB50xxxxx)
    - Intel - Display - 31.0.101.x [driver/definition]
  Last successful detection recorded by Windows: 2026-07-13 09:00:00 (UTC).
```

Key points:

- It is a **search only** — nothing is downloaded or installed. (This is why it runs even without `-InstallUpdates`.)
- Search is **allowed over a remote session**, so this works over WinRM too (only `Download()`/`Install()` are blocked remotely — see [Installing Updates Remotely](#installing-updates-remotely)).
- It splits results into **quality/feature** updates and **driver/definition** updates so you can see what kind of updates are pending.
- The **last successful detection timestamp** is read from the registry (`…\WindowsUpdate\Auto Update\Results\Detect\LastSuccessTime`) to confirm a scan completed.
- **UUP caveat:** on modern Windows 11, cumulative updates delivered via the Unified Update Platform are **not visible** to the WUA COM API, so `0 applicable updates` here does not always mean nothing is pending — confirm in **Settings > Windows Update**.

When you *do* pass `-InstallUpdates`, this read-only step is skipped because the install path already enumerates and reports every update.

## Installing Updates

Pass `-InstallUpdates` to have the script search, download, and install available updates immediately after the fix completes, rather than just requesting a background scan.

```shell
.\Run-Windows-Update-Fix.bat -InstallUpdates
.\Run-Windows-Update-Fix.bat -Remediate -InstallUpdates
```

The script uses the built-in **WUA COM API** (`Microsoft.Update.Session`) — no external modules required. It excludes driver and antivirus/definition updates (same filter used by the health assessment), then **downloads and installs each update individually** so it can report progress and results per update.

Every step is wrapped in its own error handling, so hitting the update API **never aborts the run**: a search hiccup, a failed download, or a failed install for one update is caught, reported, and the script moves on to the next update (and then continues with the rest of the fix). Each update produces a download line (only if it still needs downloading) and an install result line:

| Result | Meaning |
|---|---|
| `Succeeded` | Downloaded / installed successfully. |
| `SucceededWithErrors` | Installed but with non-fatal errors. |
| `Failed` | Download or installation failed — HRESULT shown in parentheses. |
| `Aborted` | Installation was aborted. |
| `Download Failed` | The update could not be downloaded — HRESULT shown; install is skipped for that update. |

The EULA is auto-accepted per update where required, and updates Windows has already staged skip the download step. A final summary line reports the total succeeded / failed counts.

If a restart is needed to complete one or more updates, the script reports this. The existing `-AutoReboot` flag will then handle the countdown and reboot. Alternatively, pass `-ScheduleReboot` to defer the restart to a quiet time — by default **2:00 AM**, or whatever you set with `-ScheduleRebootTime`:

```shell
# Install updates, then schedule the required restart for 2:00 AM (default)
.\Run-Windows-Update-Fix.bat -InstallUpdates -ScheduleReboot

# Install updates, then schedule the required restart for 3:30 AM
.\Run-Windows-Update-Fix.bat -InstallUpdates -ScheduleReboot -ScheduleRebootTime 03:30
```

`-ScheduleReboot` only acts when the installed updates actually require a restart, and it takes precedence over `-AutoReboot` in that case. The scheduled reboot can be cancelled at any time before it fires with `shutdown /a`.

When the reboot is scheduled, the script **notifies everyone who is signed in** so no one is caught off guard. It broadcasts a formatted message box to all sessions with `msg.exe *`, for example:

```
============================================================
            SCHEDULED WINDOWS UPDATE RESTART
============================================================

  This computer will automatically RESTART to finish
  installing Windows updates at:

      Monday, July 13, 2026 at 2:00 AM

  Please SAVE YOUR WORK and close your applications before
  then so you do not lose anything.

============================================================
```

The scheduled time is also included in the native Windows shutdown warning. `msg.exe` ships with Windows **Pro/Enterprise/Education** editions but not **Home**; on Home editions the broadcast is skipped and users still get the built-in shutdown warning.

> [!NOTE]
> On **modern Windows 11**, cumulative updates are delivered through the **Unified Update Platform (UUP)** and are **not exposed by the WUA COM API**. If no updates are found here, use **Settings > Windows Update** or run `UsoClient.exe StartInstall` to trigger those. `-TriggerUpdateScan` (or `-Remediate`) is a better fit for fully automated modern-Windows pipelines where you just want to kick off a scan and let Windows handle the rest.

### Installing Updates Remotely

The Windows Update Agent **blocks `Download()` and `Install()` calls made over a remote session** (WinRM / PowerShell Remoting) by design, returning access denied (`0x80070005`). No amount of elevation fixes this — the restriction is on the *remote logon type*, not on permissions.

To work around it, the script runs the update step inside a **local scheduled task executing as `NT AUTHORITY\SYSTEM`**. Because the task is a local logon, WUA allows the download/install. The script:

1. Serializes its update logic into a small worker script under `C:\ProgramData\Windows-Update-Fix\`.
2. Registers and starts a one-shot SYSTEM task (highest privileges, 3-hour limit).
3. Streams the worker's per-update output back into the current (remote) transcript as it runs.
4. Detects whether a restart is required and cleans up the task afterward. The worker log is kept under `C:\ProgramData\Windows-Update-Fix\` for troubleshooting.

This happens **automatically** whenever the script detects a remote session, so `Invoke-Command … { … -InstallUpdates }` just works:

```powershell
Invoke-Command -ComputerName $Computers -Credential $Cred -ScriptBlock {
    $Url  = 'https://raw.githubusercontent.com/brycefors/Windows-Fix-Up/refs/heads/main/Windows-Update-Fix/Windows-Update-Fix.ps1'
    $Dest = Join-Path $env:TEMP 'Windows-Update-Fix.ps1'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
    & $Dest -InstallUpdates -Unattended
}
```

You can also force the scheduled-task path on a local run with `-InstallViaScheduledTask` (useful for testing, or when running under a service account that hits the same restriction). Scheduled reboots (`-ScheduleReboot`) still work from a remote session because `shutdown.exe` is not subject to the WUA remote block.

> [!NOTE]
> The scheduled-task workaround requires the remote account to be a local administrator (needed to register a SYSTEM task) and the **Task Scheduler** service to be running. If the task cannot be created, the script reports the error and suggests running locally or using Settings > Windows Update.

## Logging

Every run writes a timestamped transcript named `Windows-Update-Fix_yyyy-MM-dd_HH-mm-ss.log`. By default logs are written to the script's folder; use `-LogPath` to redirect them elsewhere:

```shell
.\Run-Windows-Update-Fix.bat -Remediate -LogPath "C:\Logs\WindowsUpdateFix"
```

The directory is created automatically if it does not exist. If it is invalid or cannot be created, the script warns and falls back to the script folder.

To prevent log accumulation, the **30 most recent** log files are kept and any older ones are automatically deleted at the start of each run.

## Important Notes

> [!WARNING]
> This script resets any settings applied through **Local Group Policy** back to "Not Configured." On a machine that is joined to a domain or managed with intentional local policy, those settings will be reapplied on the next policy refresh (or may need to be reconfigured). Do not run this blindly on managed endpoints.

- A **restart is recommended** after the fix to fully apply the Group Policy and service changes. The script never reboots on its own — it only restarts when you pass `-AutoReboot` (which runs a 60-second countdown you can cancel with a keypress during an interactive run). Otherwise it just reminds you to restart manually.
- Requires **PowerShell 5.0+** and **Windows 10 / Server 2016** or newer.
- The `SoftwareDistribution.old_*` and `catroot2.old_*` backup folders are safe to delete once Windows Update is confirmed working. The script also removes any leftover backups automatically on its next run.

> [!NOTE]
> Deleting `SoftwareDistribution` content can fail with **"Could not find a part of the path"** because the update cache routinely nests folders past the legacy 260-character (`MAX_PATH`) limit, which `Remove-Item` cannot handle. To work around this, the script deletes these trees with a robust helper that escalates automatically: a normal recursive delete first, then a **robocopy mirror-from-empty purge** (which walks long/deep trees natively), and finally `rd /s /q` via the **`\\?\` long-path prefix**. If a tree still cannot be fully removed (usually an open file handle), the script says so and a reboot will release the remaining locks.
