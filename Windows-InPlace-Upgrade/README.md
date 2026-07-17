# Windows In-Place Upgrade

> [!NOTE]
> This is a specialized companion to the main [Windows Fix-Up](../README.md) and [Windows Update Fix](../Windows-Update-Fix/README.md) scripts. When the lighter policy/cache/component-store repairs are not enough — updates that simply refuse to install (`0x800f081f`, `0x80073712`, `0x800f0988`, stuck at a percentage), or deep servicing-stack corruption — an **in-place upgrade (repair install)** is the most reliable fix. It re-lays the entire operating system while keeping your apps, settings, and files, and rebuilds the servicing stack from scratch.

This PowerShell script automates the whole process: it detects your installed Windows version, **automatically obtains the matching official Microsoft ISO** (via the community [Fido](https://github.com/pbatard/Fido) helper, which queries Microsoft's own download servers), downloads it, mounts it, and launches Windows Setup in in-place-upgrade mode.

## Table of Contents

- [Important Notes](#important-notes)
- [How to Run This Script](#how-to-run-this-script)
  - [Recommended Method: Using the Batch File](#recommended-method-using-the-batch-file)
  - [Running with Parameters (from Command Line)](#running-with-parameters-from-command-line)
  - [Remote / One-Line Deployment](#remote--one-line-deployment)
- [Command-Line Parameters](#command-line-parameters)
- [What the Script Does](#what-the-script-does)
- [How the ISO Is Downloaded](#how-the-iso-is-downloaded)
- [Keep Modes](#keep-modes)
- [Disk Space Requirements](#disk-space-requirements)
- [Logging](#logging)

## Important Notes

> [!WARNING]
> An in-place upgrade **re-installs Windows**. Although it is designed to preserve your apps and files, any OS-level change carries risk. **Back up important data first.** The process takes 20–90 minutes and **restarts the computer several times** — do not power the machine off while it is running.

- Requires **PowerShell 5.0+** and **Windows 10 / Server 2016** or newer.
- Needs an internet connection to download the ISO (unless you supply your own with `-IsoPath`) and roughly **20 GB of free disk space** to stage the upgrade (plus ~6 GB for the ISO).
- The script downloads and runs the third-party **Fido** helper to resolve the official Microsoft ISO link. If you prefer not to run external code, download an ISO yourself and pass it with `-IsoPath`.
- After a successful upgrade you can reclaim 10–30 GB by removing the leftover `Windows.old` / `$Windows.~BT` folders — the main [Windows Fix-Up](../README.md) script does this with `-CleanupUpgradeFolders`.

## How to Run This Script

The easiest and recommended way to run this script is by using the `Run-Windows-InPlace-Upgrade.bat` file. It automatically handles administrator elevation and PowerShell execution policies, and will download the latest `Windows-InPlace-Upgrade.ps1` from GitHub if it is missing.

### Recommended Method: Using the Batch File

1.  **Download Files:** Make sure both `Run-Windows-InPlace-Upgrade.bat` and `Windows-InPlace-Upgrade.ps1` are saved in the **same folder**. (If the `.ps1` is missing, the batch file will download it automatically.)
2.  **Run the Batch File:** Double-click the `Run-Windows-InPlace-Upgrade.bat` file.
3.  **Administrator Prompt:** A User Account Control (UAC) window will appear asking for administrative privileges. Click **Yes**.
4.  **Follow Prompts:** The script opens in a new window, shows your current build and the upgrade target, and asks for confirmation before downloading the ISO and starting Setup.

### Running with Parameters (from Command Line)

To use command-line parameters (like `-Unattended` or `-IsoPath`), run the batch file from a Command Prompt or PowerShell terminal.

1.  Open Command Prompt or PowerShell.
2.  Navigate to the directory where you saved the files (e.g., `cd C:\Users\YourUser\Downloads`).
3.  Run the batch file with your desired parameters. For example:
    ```shell
    .\Run-Windows-InPlace-Upgrade.bat -Unattended
    ```

You can also run the PowerShell script directly (it will self-elevate):

```powershell
Set-ExecutionPolicy Bypass -Force
.\Windows-InPlace-Upgrade.ps1
```

### Remote / One-Line Deployment

To run the tool without cloning the repo (handy for a quick fix on someone else's machine), use this block to download `Windows-InPlace-Upgrade.ps1` into the temp folder and run it. Because the ISO is large, download it into a folder with plenty of space using `-DownloadPath`:

```powershell
# Fetch Windows-InPlace-Upgrade.ps1 to the temp folder and run an in-place upgrade to Windows 11
$Url  = 'https://raw.githubusercontent.com/brycefors/Windows-Fix-Up/refs/heads/main/Windows-InPlace-Upgrade/Windows-InPlace-Upgrade.ps1'
$Dest = Join-Path $env:TEMP 'Windows-InPlace-Upgrade.ps1'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
powershell.exe -ExecutionPolicy Bypass -File $Dest -DownloadPath 'C:\ISO'
```

Fully unattended (no prompts, Setup runs silently). **This will restart the machine on its own** — only use it when that is acceptable:

```powershell
$Url  = 'https://raw.githubusercontent.com/brycefors/Windows-Fix-Up/refs/heads/main/Windows-InPlace-Upgrade/Windows-InPlace-Upgrade.ps1'
$Dest = Join-Path $env:TEMP 'Windows-InPlace-Upgrade.ps1'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
powershell.exe -ExecutionPolicy Bypass -File $Dest -Unattended -DownloadPath 'C:\ISO'
```

Compact one-liner (handy for RMM command fields):

```powershell
$d="$env:TEMP\Windows-InPlace-Upgrade.ps1";[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;irm 'https://raw.githubusercontent.com/brycefors/Windows-Fix-Up/refs/heads/main/Windows-InPlace-Upgrade/Windows-InPlace-Upgrade.ps1' -OutFile $d;powershell -ExecutionPolicy Bypass -File $d -Unattended -DownloadPath 'C:\ISO'
```

Download the ISO now, upgrade later (e.g. stage the ISO overnight, then run the upgrade during a maintenance window):

```powershell
# Step 1 - just download the ISO
$d="$env:TEMP\Windows-InPlace-Upgrade.ps1";irm 'https://raw.githubusercontent.com/brycefors/Windows-Fix-Up/refs/heads/main/Windows-InPlace-Upgrade/Windows-InPlace-Upgrade.ps1' -OutFile $d;powershell -ExecutionPolicy Bypass -File $d -DownloadOnly -DownloadPath 'C:\ISO'

# Step 2 - run the upgrade later using the already-downloaded ISO (no re-download)
powershell -ExecutionPolicy Bypass -File $d -DownloadPath 'C:\ISO'
```

> [!NOTE]
> The script self-elevates, so a UAC prompt will appear unless it is launched from an already-elevated context. If a matching ISO (larger than 3 GB) already exists in the download folder, it is reused instead of downloading again. To use your own ISO and skip the download entirely, add `-IsoPath 'C:\path\to\Windows.iso'`.

## Command-Line Parameters

| Parameter | Description |
|---|---|
| `-Unattended` | Runs with no confirmation prompts and launches Setup silently (`/quiet`). |
| `-IsoPath` | Path to an existing Windows ISO to use instead of downloading one from Microsoft. |
| `-WindowsVersion` | Windows version to upgrade to: `10` or `11`. Defaults to `11`. |
| `-Release` | Fido release to request (e.g. `24H2`, `23H2`) or `Latest`. Defaults to `Latest`. |
| `-Language` | ISO language as named by Microsoft/Fido (e.g. `English`, `"English International"`). Defaults to `English`. |
| `-KeepMode` | What Setup keeps: `KeepAll` (apps + data, default) or `KeepNothing` (clean install). |
| `-DownloadPath` | Directory to download the ISO into (defaults to the script folder). |
| `-DownloadOnly` | Only obtain/download the ISO; do not launch the upgrade. |
| `-NoReboot` | Prevents Setup from restarting automatically at the end (`/noreboot`). |
| `-NoDynamicUpdate` | Turns off Dynamic Update so Setup does not pull the latest fixes online before upgrading. |
| `-CleanupIso` | Deletes the downloaded ISO after Setup has started. |
| `-FidoUrl` | Override the URL used to fetch the Fido download helper. |
| `-LogPath` | Directory to write log files to (defaults to the script folder). |
| `-SkipInteractive` | Skips the interactive confirmation prompt (still shows output). |

## What the Script Does

1.  **System detection** — Reads the installed Windows version, edition, architecture, and build so the correct ISO is requested and shown in the preflight summary.
2.  **Disk space check** — Confirms there is enough free space (~20 GB for the upgrade, ~8 GB for download-only) before doing anything.
3.  **ISO acquisition** — If a valid Windows ISO (larger than 3 GB) is already present in the download folder, it is **reused instead of downloading again**. Otherwise the script downloads the [Fido](https://github.com/pbatard/Fido) helper, uses it to resolve the official Microsoft ISO download URL, then downloads the ISO (resumable via BITS, with an `Invoke-WebRequest` fallback). Skipped entirely when you supply `-IsoPath`.
4.  **Mount & launch** — Mounts the ISO, locates `setup.exe`, and launches Windows Setup in in-place-upgrade mode with the chosen keep-mode and Dynamic Update enabled.
5.  **Cleanup** — Dismounts the ISO when appropriate, and optionally deletes the downloaded ISO (`-CleanupIso`).

## How the ISO Is Downloaded

There is no single stable direct-download URL for Windows ISOs — Microsoft generates them per session on its download page. This script uses **[Fido](https://github.com/pbatard/Fido)**, a well-known open-source PowerShell helper by Pete Batard (also the author of Rufus), to query Microsoft's own software-download servers and return the genuine, matching ISO link. The ISO is then downloaded directly from Microsoft.

If you would rather not run an external helper, download an ISO manually (e.g. from the [Microsoft software-download site](https://www.microsoft.com/software-download)) and point the script at it:

```powershell
.\Windows-InPlace-Upgrade.ps1 -IsoPath "C:\ISOs\Win11_24H2_English_x64.iso"
```

## Keep Modes

| Mode | Setup behavior |
|---|---|
| `KeepAll` *(default)* | Keeps your apps, settings, and personal files. This is the true "repair install." |
| `KeepNothing` | Clean install — nothing is kept. **Use with caution.** |

## Disk Space Requirements

- **Download-only / supplied ISO:** at least **8 GB** free.
- **Full in-place upgrade:** at least **20 GB** free (25 GB+ recommended). The script refuses to run below the minimum and warns when space is tight.

## Logging

Every run is transcribed to a timestamped `Windows-InPlace-Upgrade_YYYY-MM-DD_HH-mm-ss.log` file in the script folder (or `-LogPath`). The 30 most recent logs are kept; older ones are pruned automatically. If Setup itself fails, its detailed logs live in `C:\$WINDOWS.~BT\Sources\Panther\setupact.log`.
