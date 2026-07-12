# Windows Clean-Up

> [!NOTE]
> This is a specialized companion to the main [Windows Fix-Up](../README.md) script. Where that tool takes the broad "shotgun" approach to Windows repair, this one is focused on a single job: **reclaiming disk space on the system drive**. It uses four escalating cleanup levels and can automatically scale how aggressively it cleans based on how little free space is left.

This PowerShell script frees up disk space by clearing temp folders and caches, running Windows Disk Cleanup, cleaning the component store (WinSxS), removing leftover Windows upgrade folders, and — as a last resort — removing the hibernation file, pruning restore points, and clearing event logs. It can also measure free space and **automatically decide whether — and how aggressively — to clean**.

## How to Run This Script

The easiest and recommended way to run this script is by using the `Run-Windows-Clean-Up.bat` file. It automatically handles administrator elevation and PowerShell execution policies, and will even download the latest `Windows-Clean-Up.ps1` from GitHub if it is missing.

### Recommended Method: Using the Batch File

1.  **Download Files:** Make sure both `Run-Windows-Clean-Up.bat` and `Windows-Clean-Up.ps1` are saved in the **same folder**. (If the `.ps1` is missing, the batch file will download it automatically.)
2.  **Run the Batch File:** Double-click the `Run-Windows-Clean-Up.bat` file.
3.  **Administrator Prompt:** A User Account Control (UAC) window will appear asking for administrative privileges. Click **Yes**.
4.  **Follow Prompts:** The script opens in a new window, shows the current free space, recommends a cleanup level, and lets you confirm or pick a different level before making changes.

### Running with Parameters (from Command Line)

To use command-line parameters (like `-Remediate` or `-ForceLevel`), run the batch file from a Command Prompt or PowerShell terminal.

1.  Open Command Prompt or PowerShell.
2.  Navigate to the directory where you saved the files (e.g., `cd C:\Users\YourUser\Downloads`).
3.  Run the batch file with your desired parameters. For example:
    ```shell
    .\Run-Windows-Clean-Up.bat -Remediate
    ```

You can also run the PowerShell script directly (it will self-elevate):

```powershell
Set-ExecutionPolicy Bypass -Force
.\Windows-Clean-Up.ps1 -Remediate
```

## Command-Line Parameters

The script supports the following optional parameters:

| Parameter | Description |
|---|---|
| `-Unattended` | Runs the script without any user prompts. If no level is specified, it picks one automatically from the free-space thresholds (falling back to *Light*). |
| `-AutoReboot` | Restarts the computer after a 60-second countdown **only when a restart is actually warranted** (e.g. the Aggressive level disabled hibernation, or Windows reports a pending reboot). If nothing needs a restart, the reboot is skipped. During an interactive run the countdown can be cancelled with any keypress. |
| `-Audit` | **Read-only.** Deletes nothing and makes no changes; instead reports what *would* be cleaned at the chosen level and estimates how much space would be freed. See [Audit Mode](#audit-mode). |
| `-Remediate` | **Adaptive mode.** Measures free space on the system drive and automatically scales the cleanup to how full the drive is (see [Adaptive Remediation](#adaptive-remediation-recommended) below). Runs hands-off with no prompts. |
| `-ForceLevel <Light\|Medium\|Severe\|Aggressive>` | **Forced mode.** Skips the free-space assessment entirely and applies the specified level directly. Runs hands-off with no prompts. Ignored if `-Remediate` is also passed. |
| `-LightThresholdGB <n>` | Free space (GB) at or below which a **Light** cleanup is triggered in adaptive mode. Default is `30`. |
| `-MediumThresholdGB <n>` | Free space (GB) at or below which a **Medium** cleanup is triggered. Default is `20`. |
| `-SevereThresholdGB <n>` | Free space (GB) at or below which a **Severe** cleanup is triggered. Default is `10`. |
| `-AggressiveThresholdGB <n>` | Free space (GB) at or below which an **Aggressive** cleanup is triggered. Default is `5`. |
| `-SkipRecycleBin` | Do not empty the Recycle Bin during cleanup. |
| `-CleanupOrphanedInstaller` | **Experimental.** Removes orphaned `.msi`/`.msp` packages from `C:\Windows\Installer` that are no longer referenced by any installed product or applied patch. Runs regardless of the selected level. See [Experimental Cleanups](#experimental-cleanups). |
| `-CleanupOldProfiles` | **Experimental.** Deletes local user profiles that have not been signed into for more than `-ProfileAgeDays` days. Runs regardless of the selected level. See [Experimental Cleanups](#experimental-cleanups). |
| `-ProfileAgeDays <n>` | Number of days a local profile must be unused before `-CleanupOldProfiles` removes it. Default is `90`. |
| `-MinCachedProfiles <n>` | `-CleanupOldProfiles` only runs when there are **more than** this many cached local profiles under `C:\Users`. Default is `5`. |
| `-CooldownDays <n>` | Minimum number of days that must pass before `-Remediate` or `-ForceLevel` can run again on the same machine. The timestamp is stored in a `.last_cleanup` file alongside the script. Default is `7`. Set to `0` to disable. |
| `-IgnoreCooldown` | Bypasses the cooldown check for a single run without changing the default. |
| `-LogPath <path>` | Directory to write log files to. Defaults to the script folder. The directory is created automatically if it does not exist. |
| `-SkipInteractive` | Skips the interactive confirmation/level-selection prompt while still showing output. |

> [!NOTE]
> The thresholds must descend (`Light > Medium > Severe > Aggressive`). If they do not, the script reports the error and exits without cleaning.

## Cleanup Levels

The cleanup is organized into four escalating levels. **Each level includes everything the levels below it do**, so a higher level always reclaims more space.

| Level | Name | What it adds |
|---|---|---|
| **1** | **Light** | Empties system and per-user Temp folders, the Windows Update download cache and DataStore logs, leftover `SoftwareDistribution.old_*` / `catroot2.old_*` backups, the Delivery Optimization cache, Windows Error Reporting archives, crash dumps (`Minidump`, `MEMORY.DMP`, per-user `CrashDumps`), thumbnail/icon caches, and (unless `-SkipRecycleBin`) the Recycle Bin. Safe and non-destructive to user data. |
| **2** | **Medium** | Everything in *Light*, **plus** Windows Disk Cleanup (`cleanmgr` for all categories except Downloads), CBS/DISM log files, Windows setup (Panther) logs, the Prefetch cache, the font cache, and the Configuration Manager (SCCM) client cache (`ccmcache`) if present. |
| **3** | **Severe** | Everything in *Medium*, **plus** the DISM component-store cleanup (`DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase`) and removal of leftover Windows upgrade folders (`Windows.old`, `$Windows.~BT`, `$Windows.~WS`, `$WinREAgent`, `$GetCurrent`). |
| **4** | **Aggressive** | Everything in *Severe*, **plus** pruning old System Restore points (keeping the most recent), removing the hibernation file (`hiberfil.sys`) via `powercfg /hibernate off`, and clearing all Windows event logs. Last-resort reclamation for a nearly-full disk. |

## Adaptive Remediation (Recommended)

Running with `-Remediate` makes the script measure free space on the system drive and choose a level automatically:

| Free space | Level applied |
|---|---|
| **Above `-LightThresholdGB` (30 GB)** | Nothing — the disk has enough room, so the script exits without cleaning. |
| **At or under `-LightThresholdGB` (30 GB)** | **Light** cleanup. |
| **At or under `-MediumThresholdGB` (20 GB)** | **Medium** cleanup. |
| **At or under `-SevereThresholdGB` (10 GB)** | **Severe** cleanup. |
| **At or under `-AggressiveThresholdGB` (5 GB)** | **Aggressive** cleanup. |

The default thresholds (30 / 20 / 10 / 5 GB) can each be overridden with the `-*ThresholdGB` parameters:

```shell
# Adaptive cleanup using the default thresholds
.\Run-Windows-Clean-Up.bat -Remediate

# Adaptive cleanup with custom thresholds (light at 50 GB, aggressive at 8 GB)
.\Run-Windows-Clean-Up.bat -Remediate -LightThresholdGB 50 -MediumThresholdGB 30 -SevereThresholdGB 15 -AggressiveThresholdGB 8
```

If you want to skip the assessment and force a specific level regardless of free space, use `-ForceLevel`:

```shell
# Just the safe, quick cleanup
.\Run-Windows-Clean-Up.bat -ForceLevel Light

# The full treatment (WinSxS, upgrade folders, hibernation, restore points, event logs)
.\Run-Windows-Clean-Up.bat -ForceLevel Aggressive
```

Both `-Remediate` and `-ForceLevel` run hands-off with no prompts.

## Remediation Cooldown

To prevent `-Remediate` and `-ForceLevel` from running too frequently in automated scenarios (e.g., a scheduled task or RMM deployment), the script enforces a cooldown period between runs.

When a cleanup commits, it writes the current timestamp to a `.last_cleanup` file stored alongside the script. On the next run, if the elapsed time is less than `-CooldownDays` (default: `7`), the script exits immediately with a message rather than cleaning again. Use `-IgnoreCooldown` to bypass it for a single run, or `-CooldownDays 0` to disable it entirely.

```shell
# Bypass for a single run
.\Run-Windows-Clean-Up.bat -Remediate -IgnoreCooldown

# Disable the cooldown entirely
.\Run-Windows-Clean-Up.bat -Remediate -CooldownDays 0
```

> Interactive (manual) runs — those without `-Remediate` or `-ForceLevel` — do not read or write the cooldown file.

## Audit Mode

Pass `-Audit` to run the tool in **read-only** mode. It performs no deletions and makes no system changes — every cleanup step instead measures what it *would* remove and reports a per-item estimate prefixed with `[AUDIT]`, followed by a grand total of the space that could be freed at the selected level.

```shell
# Audit the level that -Remediate would pick for this disk
.\Run-Windows-Clean-Up.bat -Audit -Remediate

# Audit exactly what the Aggressive level would remove
.\Run-Windows-Clean-Up.bat -Audit -ForceLevel Aggressive
```

`-Audit` combines with any level selection (interactive, `-ForceLevel`, `-Remediate`, or `-Unattended`) and with the experimental flags (`-CleanupOrphanedInstaller`, `-CleanupOldProfiles`) so you can preview those too. Because it changes nothing, audit runs **ignore the cooldown** (they neither read nor write the `.last_cleanup` stamp) and never reboot.

> [!NOTE]
> A few steps cannot be estimated precisely and are reported but excluded from the total: Windows Disk Cleanup (`cleanmgr`) and the DISM component-store cleanup (for which the script instead runs the read-only `DISM /AnalyzeComponentStore` and prints its reclaimable figure), and System Restore point pruning (reported as a count).

## Experimental Cleanups

These opt-in flags perform deeper, riskier cleanups. They are **not tied to a cleanup level** — when the flag is set, the action runs regardless of whether you chose Light, Medium, Severe, or Aggressive (and regardless of what `-Remediate` selects).

> [!WARNING]
> These are **experimental**. They can, in edge cases, remove data that is still needed. Review what they do before using them on an important machine.

### `-CleanupOrphanedInstaller`

Windows keeps a cached copy of every product's and patch's installer package in `C:\Windows\Installer` so software can later be repaired or uninstalled. Over time, packages for software that no longer exists become orphaned and waste space.

The script asks the **Windows Installer** (`WindowsInstaller.Installer` COM API) for every `LocalPackage` still referenced by an installed product (`ProductsEx`) or applied patch (`PatchesEx`), then deletes only the `.msi`/`.msp` files in `C:\Windows\Installer` that are **not** in that referenced set. As a safety guard, if the referenced-package list cannot be built (or comes back empty), it skips deletion entirely rather than risk removing needed packages.

```shell
.\Run-Windows-Clean-Up.bat -CleanupOrphanedInstaller
```

### `-CleanupOldProfiles`

Deletes local user profiles that have not been signed into for more than `-ProfileAgeDays` days (default `90`). It uses `Win32_UserProfile` so both the profile folder **and** its registry references are removed cleanly.

To avoid touching machines that only have a handful of accounts, this cleanup **only runs when there are more than `-MinCachedProfiles` (default `5`) cached local profiles** under `C:\Users`. Below that count it is skipped entirely.

Whether a profile is deleted is decided by a **file-activity check**, which is treated as the definitive signal. The script samples a subset of high-signal locations inside the user folder (`Desktop`, `Documents`, `Downloads`, `Pictures`, `AppData\Roaming`, `AppData\Local`); if any contain files modified more recently than the age cutoff, the profile is considered active and **kept** — otherwise it is **removed**. `Win32_UserProfile.LastUseTime` is only informational here: a profile it reports as recently used is still removed when no recent file activity proves it, since that timestamp can be bumped by background/system activity. (`NTUSER.DAT` is deliberately not sampled, for the same reason.)

The following profiles are **always skipped**: special/system profiles, profiles currently loaded (a user is signed in), the account running the script, and any profile located outside `%SystemDrive%\Users`.

```shell
# Remove profiles unused for 90+ days (default), only if there are more than 5 cached profiles
.\Run-Windows-Clean-Up.bat -CleanupOldProfiles

# Use a stricter 180-day threshold and only run when more than 10 profiles are cached
.\Run-Windows-Clean-Up.bat -CleanupOldProfiles -ProfileAgeDays 180 -MinCachedProfiles 10
```

> [!WARNING]
> Removing a profile **permanently deletes that user's local data** (desktop, documents, app data). There is no undo.

## Restart Behavior

The tool **never restarts on its own** — a reboot only ever happens when you pass `-AutoReboot`. Internally the script tracks whether a restart is *recommended*: this becomes true when a step makes a change a restart would finalize (currently the **Aggressive** level disabling hibernation) or when Windows itself reports a pending reboot (CBS `RebootPending`, Windows Update `RebootRequired`, or queued `PendingFileRenameOperations`).

That "recommended" state is a **gate on `-AutoReboot`, not a trigger by itself** — so `-AutoReboot` won't needlessly reboot after a routine cleanup. The two combine as follows:

| `-AutoReboot` | Restart recommended? | Result |
|---|---|---|
| Not passed | Yes (e.g. Aggressive) | Prints "A restart is recommended…" — **no reboot** |
| Not passed | No | Prints "No restart is required" — no reboot |
| Passed | Yes | 60-second countdown, then restarts (see below) |
| Passed | No | Prints "…nothing here requires a restart - skipping the reboot" — **no reboot** |

So reaching the Aggressive level does **not** reboot by itself; you must also pass `-AutoReboot` for the restart to happen automatically.

During an **interactive** run (a real console, not `-Unattended`), the countdown can be cancelled by pressing any key. Unattended/automated runs count down and restart without waiting for input. Audit runs (`-Audit`) never restart.

## Logging

```shell
.\Run-Windows-Clean-Up.bat -Remediate -LogPath "C:\Logs\WindowsCleanUp"
```

The directory is created automatically if it does not exist. To prevent log accumulation, the **30 most recent** log files are kept and any older ones are automatically deleted at the start of each run.

## Important Notes

> [!WARNING]
> The **Aggressive** level is destructive to recovery options. It **prunes System Restore points** (keeping only the most recent), **removes the hibernation file** (which also disables Fast Startup — re-enable with `powercfg /hibernate on`), and **clears all Windows event logs**. Only use it when the disk is critically full and you understand the trade-offs.

- The **Severe** level's `DISM ... /ResetBase` makes currently-installed updates permanent — they can no longer be uninstalled — in exchange for reclaiming the most component-store space.
- A **restart** is only strictly required after the *Aggressive* level (for the hibernation change) but is generally harmless. The tool never reboots on its own — see [Restart Behavior](#restart-behavior) for how `-AutoReboot` interacts with this.
- Requires **PowerShell 5.0+** and **Windows 10 / Server 2016** or newer.
