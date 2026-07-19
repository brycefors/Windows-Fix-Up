# Windows ISO Updater

> [!NOTE]
> This is a specialized companion to the main [Windows Fix-Up](../README.md), [Windows Update Fix](../Windows-Update-Fix/README.md), and [Windows In-Place Upgrade](../Windows-InPlace-Upgrade/README.md) scripts. Instead of repairing an installed system, it builds **fresh, fully-patched installation media**: it downloads the latest official Microsoft ISO, integrates ("slipstreams") the latest cumulative update directly into the Windows images, and recompiles a brand-new bootable ISO that is already up to date.

This PowerShell script automates the whole process. A clean install or in-place upgrade started from the resulting ISO begins already patched, instead of spending a long time downloading and installing the same cumulative update after Setup finishes.

## Table of Contents

- [Important Notes](#important-notes)
- [Requirements](#requirements)
- [How to Run This Script](#how-to-run-this-script)
  - [Recommended Method: Using the Batch File](#recommended-method-using-the-batch-file)
  - [Running with Parameters (from Command Line)](#running-with-parameters-from-command-line)
- [Command-Line Parameters](#command-line-parameters)
- [What the Script Does](#what-the-script-does)
- [How Files Are Downloaded](#how-files-are-downloaded)
- [Disk Space Requirements](#disk-space-requirements)
- [Logging](#logging)

## Important Notes

> [!WARNING]
> This is a **disk- and time-intensive** operation. The downloaded ISO, the extracted media, the mounted image, and the re-exported image all coexist during the build, and offline DISM servicing plus component-store cleanup can take a long time. Nothing on the machine running the script is changed — all servicing happens against files in the working folder.

> [!TIP]
> **It is recommended to download the ISO yourself and pass it with `-IsoPath`.** The automatic download relies on the community Fido helper, which queries Microsoft's software-download servers on your behalf. Microsoft rate-limits and can temporarily block IP addresses that make repeated ISO requests, which causes the automatic download to fail. Downloading the ISO once from [microsoft.com/software-download](https://www.microsoft.com/software-download) (or with the Media Creation Tool) and reusing it with `-IsoPath` avoids this entirely — and the script also reuses any ISO already sitting in the download folder.

- The Microsoft Update Catalog has **no public API**, so the script parses its search pages to find the latest cumulative update. If Microsoft changes the catalog layout the lookup may need adjustment; you can always supply your own `.msu`/`.cab` packages with `-UpdatePath`.- Recompiling the ISO requires **`oscdimg.exe`**, part of the **Windows ADK "Deployment Tools"** feature. If it is not installed, pass `-InstallAdk` to have the script download and install it from Microsoft, or install the ADK manually first.
- Every download URL (ISO, updates, ADK) is validated to point at an **official Microsoft host over HTTPS** before anything is downloaded.

> [!IMPORTANT]
> The working and download folders **must be on a local, fixed disk**. Cloud-synced folders (Google Drive, OneDrive, Dropbox, etc.) turn files into on-demand placeholders and sync them in the background, which makes DISM unable to read the `.msu`/`.wim` reliably — this shows up as *"An error occurred applying the Unattend.xml file from the .msu package"*. By default the script works and downloads under `<SystemDrive>\WISO-Work`; if you run it from a cloud-synced folder, keep `-WorkPath`/`-DownloadPath` pointed at a local disk (and preferably pass your ISO with `-IsoPath` from a local copy).

## Requirements

- **PowerShell 5.0+** and **Windows 10 / Server 2016** or newer, run **as Administrator**.
- An internet connection (unless you supply both the ISO with `-IsoPath` and updates with `-UpdatePath`).
- The **Windows ADK Deployment Tools** (`oscdimg.exe`) — installed automatically with `-InstallAdk`.
- Plenty of free disk space on a **local** working drive — see [Disk Space Requirements](#disk-space-requirements).

## How to Run This Script

The easiest and recommended way to run this script is by using the `Run-Windows-ISO-Updater.bat` file. It automatically handles administrator elevation and PowerShell execution policies, and will download the latest `Windows-ISO-Updater.ps1` from GitHub if it is missing.

### Recommended Method: Using the Batch File

1.  **Download Files:** Make sure both `Run-Windows-ISO-Updater.bat` and `Windows-ISO-Updater.ps1` are saved in the **same folder**. (If the `.ps1` is missing, the batch file will download it automatically.)
2.  **Run the Batch File:** Double-click the `Run-Windows-ISO-Updater.bat` file.
3.  **Administrator Prompt:** A User Account Control (UAC) window will appear asking for administrative privileges. Click **Yes**.
4.  **Follow Prompts:** The script opens in a new window, summarizes what it will do, and asks for confirmation before downloading and building.

### Running with Parameters (from Command Line)

To use command-line parameters, run the batch file from a Command Prompt or PowerShell terminal.

1.  Open Command Prompt or PowerShell.
2.  Navigate to the directory where you saved the files (e.g., `cd C:\Users\YourUser\Downloads`).
3.  Run the batch file with your desired parameters. For example:
    ```shell
    .\Run-Windows-ISO-Updater.bat -Unattended -InstallAdk -Edition "Windows 11 Pro"
    ```

### Removing Editions (Slimming the ISO)

A Windows ISO's `install.wim` usually contains many editions (Home, Home N, Pro, Education, etc.). **By default the script keeps only the highest edition present** (e.g. Enterprise over Pro, or Pro over Home) and removes the rest — this speeds up servicing and produces a smaller ISO. Use `-KeepAllEditions` to keep every edition, or `-KeepEditions` to choose exactly which ones to keep.

```shell
:: See what editions are inside the ISO first (downloads/uses the ISO, then just lists and exits)
.\Run-Windows-ISO-Updater.bat -ListEditions

:: Keep EVERY edition instead of just the highest one
.\Run-Windows-ISO-Updater.bat -KeepAllEditions

:: Build an updated ISO containing ONLY Windows 11 Pro and Home (by name)
.\Run-Windows-ISO-Updater.bat -KeepEditions "Windows 11 Pro","Windows 11 Home"

:: Same idea, selecting by index number instead of name
.\Run-Windows-ISO-Updater.bat -KeepEditions 6,1
```

`-KeepEditions` accepts edition names (partial matches allowed) or index numbers, and overrides the highest-edition default. Only the kept editions are serviced and re-exported, so the removed editions are gone from the final `install.wim`. It works with `-SkipUpdates` too, if you only want to trim editions without integrating updates.

## Command-Line Parameters

The script supports the following optional parameters:

| Parameter | Description |
|---|---|
| `-Unattended` | Runs the script without any confirmation prompts. |
| `-IsoPath` | Path to an existing Windows ISO to update instead of downloading one from Microsoft. |
| `-WindowsVersion` | Windows version to download/update: `10` or `11`. Defaults to `11`. |
| `-Release` | Fido release to request (e.g. `24H2`, `23H2`) or `Latest`. Defaults to `Latest`. |
| `-Language` | ISO language as named by Microsoft/Fido (e.g. `English`, `"English International"`). Defaults to `English`. |
| `-Edition` | Which edition inside `install.wim` to service: `All` (default) or an edition name like `"Windows 11 Pro"`. |
| `-KeepEditions` | Editions to **keep** in the final ISO, removing the rest to slim it down. Accepts edition names (partial matches allowed) or index numbers, comma-separated. Overrides the default of keeping only the highest edition. |
| `-KeepAllEditions` | Keep **every** edition in the final ISO. By default only the highest edition present (e.g. Enterprise over Pro, or Pro over Home) is kept. |
| `-ListEditions` | List the editions/indexes inside the ISO's `install.wim` and exit, without downloading updates or building anything. Useful for choosing `-Edition`/`-KeepEditions` values. |
| `-UpdatePath` | Folder containing your own `.msu`/`.cab` update packages to integrate instead of fetching from the Microsoft Update Catalog. |
| `-SkipDotNet` | Skip the **.NET cumulative update**. The .NET update is downloaded and integrated **by default**; use this switch to leave it out. |
| `-ServiceWinRE` | Also service the recovery image (`winre.wim`). Off by default; the Safe OS Dynamic Update is used when available. |
| `-SkipUpdates` | Skip update integration entirely and just extract and recompile the ISO. |
| `-DownloadPath` | Directory to download the ISO/updates into. Defaults to the script folder. |
| `-WorkPath` | Working folder used to extract and service the media. Defaults to `<SystemDrive>\WISO-Work`. |
| `-OutputIsoPath` | Full path for the recompiled ISO. Defaults to the download folder with an `-Updated` suffix. |
| `-OscdimgPath` | Full path to `oscdimg.exe` if the Windows ADK is installed in a non-standard location. |
| `-InstallAdk` | If `oscdimg.exe` is not found, download and silently install the ADK Deployment Tools from Microsoft. |
| `-FidoUrl` | Override the URL used to fetch the Fido download helper. |
| `-AdkSetupUrl` | Override the URL used to download the Windows ADK setup bootstrapper. |
| `-LogPath` | Directory to write log files to. Defaults to the script folder. |
| `-SkipInteractive` | Skips the interactive confirmation prompt (still shows output). |

## What the Script Does

1.  **Locate `oscdimg.exe`** — Fails fast (or installs the ADK with `-InstallAdk`) so the build cannot get most of the way through and then be unable to recompile the ISO.
2.  **Obtain the ISO** — Downloads the matching official Microsoft ISO via the community [Fido](https://github.com/pbatard/Fido) helper, or reuses an ISO already in the download folder, or uses `-IsoPath`.
3.  **Extract the ISO** — Mounts the ISO and mirrors its contents into the working folder with `robocopy`, then dismounts. If the media ships `install.esd`, it is converted to an editable `install.wim`.
4.  **Find the updates** — Detects the feature update (e.g. `24H2`) and architecture from the image, then downloads the latest combined Servicing Stack + Cumulative Update (and, by default, the .NET cumulative update — disable with `-SkipDotNet`) from the Microsoft Update Catalog. `-UpdatePath` uses your own packages instead.
5.  **Integrate the updates** — Uses offline DISM to apply the package(s) to `install.wim` (by default only the highest edition present — override with `-KeepAllEditions` or `-KeepEditions`/`-Edition`), to `boot.wim` (Windows Setup / WinPE), and optionally to `winre.wim`.
6.  **Clean up and shrink** — Runs `DISM /Cleanup-Image /StartComponentCleanup /ResetBase` and re-exports `install.wim` to reclaim space.
7.  **Recompile the ISO** — Uses `oscdimg` to build a new bootable ISO, preserving both the **BIOS (`etfsboot.com`)** and **UEFI (`efisys.bin`)** boot sectors so the media boots on legacy and modern PCs alike.
8.  **Clean up** — Removes the extracted working files, leaving the finished ISO.

## How Files Are Downloaded

- The **ISO** link is resolved by the third-party **Fido** helper, which queries Microsoft's own software-download servers. If you prefer not to run external code, supply your own ISO with `-IsoPath`.
- The **updates** are located by parsing the Microsoft Update Catalog search results and its download dialog (the same technique community tools use), then downloaded directly from Microsoft's update servers.
- Downloads prefer **BITS** (resumable) and fall back to `Invoke-WebRequest`. Every resolved URL is verified to point at an official Microsoft host (`microsoft.com`, `windowsupdate.com`) over HTTPS before it is downloaded.

## Disk Space Requirements

Because the download, the extracted media, the mounted image, and the re-exported image all coexist, the working drive should have at least **40 GB free**. The script checks this up front and stops if the working drive is too small — choose a larger drive with `-WorkPath` if needed.

## Logging

Each run writes a timestamped transcript to the script folder (or `-LogPath`) named `Windows-ISO-Updater_<date>_<time>.log`. The 30 most recent logs are kept and older ones are pruned automatically.
