# Windows Fix-Up Script

> [!NOTE]
> This script was born out of the necessity for one IT professional to find a lazy-yet-effective way to fix the recurring computer problems of friends and family. Think of this as the 'shotgun' approach to Windows repair. It is not designed to isolate a root cause, it is a blunt instrument intended simply to force Windows back into a working state. While it's generally safe and has saved countless hours of phone support, please exercise caution when running it in a production or enterprise environment.

This PowerShell script automates a sequence of common Windows repair and maintenance tasks. It is designed to be a comprehensive "fix-it" tool for resolving system instability, update failures, application problems, and file system corruption.

## How to Run This Script

The easiest and recommended way to run this script is by using the `Run-Windows-Fix-Up.bat` file. It automatically handles administrator elevation and PowerShell execution policies.

### Recommended Method: Using the Batch File

1.  **Download Files:** Make sure both `Run-Windows-Fix-Up.bat` and `Windows-Fix-Up.ps1` are saved in the **same folder**.
2.  **Run the Batch File:** Double-click the `Run-Windows-Fix-Up.bat` file.
3.  **Administrator Prompt:** A User Account Control (UAC) window will appear asking for administrative privileges. Click **Yes**.
4.  **Follow Prompts:** The script will open in a new window and guide you through the rest of the process.

### Running with Parameters (from Command Line)

To use command-line parameters (like `-Unattended` or `-AutoReboot`), you must run the batch file from a Command Prompt or PowerShell terminal.

1.  Open Command Prompt or PowerShell.
2.  Navigate to the directory where you saved the files (e.g., `cd C:\Users\YourUser\Downloads`).
3.  Run the batch file with your desired parameters. For example:
    ```shell
    .\Run-Windows-Fix-Up.bat -Unattended -AutoReboot -DisableBrandBloat
    ```

## Command-Line Parameters

The script supports the following optional parameters for automation:

| Parameter | Description |
|---|---|
| `-Unattended` | Runs the script without any user prompts. It will not ask for confirmation to start. |
| `-AutoReboot` | When used with `-Unattended`, this will automatically configure the script to restart the computer upon completion. If used without `-Unattended`, it pre-answers 'Y' to the automatic restart question. |
| `-ResetWMI` | Forces a rebuild of the WMI repository without attempting to salvage it first. This can be useful if you suspect deep-rooted WMI corruption. |
| `-DisableHibernation` | Disables hibernation and fast startup by running `powercfg.exe /hibernate off`. See [Why Disable Hibernation and Fast Startup?](#why-disable-hibernation-and-fast-startup) for more details. |
| `-DisableBrandBloat` | Disables startup services from common computer manufacturers (e.g., HP, Dell, ASUS, Lenovo, Acer) to reduce background processes. |
| `-ResetNetwork` | Resets the network stack (Winsock, TCP/IP), flushes the DNS cache, and renews the IP address. |
| `-RunDiskCleanup` | Runs the Windows Disk Cleanup utility, clearing all categories except for the `Downloads` folder. |
| `-RunDiskOptimization` | Performs a disk optimization on the C: drive. It will run a re-trim on an SSD or a defragmentation on an HDD. |
| `-ResetWindowsUpdate` | Resets the components of Windows Update by stopping services and renaming the `SoftwareDistribution` and `catroot2` folders. |
| `-InstallWindowsUpdates` | Installs all available Windows Updates using the `PSWindowsUpdate` module. |
| `-UpdateAllWinGet` | Uses the Windows Package Manager (`winget`) to upgrade all installed applications that support it. |
| `-CleanupNetworking` | Performs a deep cleanup of networking devices (`netcfg -d`). This removes all network adapters and requires a reboot to reinstall them. **Forces a reboot.** |
| `-SkipInteractive` | Skips the interactive selection menu. Useful if you want to run with specific parameters (or defaults) without navigating the menu, but still want to see the output. |
| `-All` | **CAUTION:** Enables all available optional parameters. |

## What the Script Does

The script performs the following actions in sequence to repair and optimize your Windows installation.

1.  **WMI Repository Verification and Repair**
    *   Checks the health of the Windows Management Instrumentation (WMI) repository. If it is found to be inconsistent, the script first attempts to salvage it. If salvaging is unsuccessful or the `-ResetWMI` parameter is used, it proceeds to rebuild the repository to resolve issues with system management tools and services.

2.  **Disable Manufacturer Bloatware (Optional)**
    *   If the `-DisableBrandBloat` parameter is used, the script will find, stop, and disable common services from manufacturers like HP, Dell, ASUS, Lenovo, and Acer. This helps reduce unnecessary background processes.

3.  **Network Stack Reset (Optional)**
    *   If the `-ResetNetwork` parameter is used, this step resets the network configuration to resolve common connectivity issues:
        *   Resets the Winsock Catalog (`netsh winsock reset`).
        *   Resets the TCP/IP stack (`netsh int ip reset`).
        *   Flushes the DNS resolver cache (`ipconfig /flushdns`).
        *   Releases and renews the IP address configuration (`ipconfig /release` & `ipconfig /renew`).

4.  **System File Checker (SFC) - First Pass**
    *   Runs `sfc /scannow` to scan for and repair corrupted or missing Windows system files.

5.  **DISM Component Store Cleanup & Repair**
    *   **Cleanup (`/StartComponentCleanup /ResetBase`):** Cleans up and compresses the component store (WinSxS folder) to save disk space.
    *   **Health Check (`/CheckHealth` & `/ScanHealth`):** Scans the Windows component store for corruption.
    *   **Restore Health (`/RestoreHealth`):** Performs repair operations automatically, using Windows Update if necessary, to fix any detected corruption.

6.  **System File Checker (SFC) - Second Pass**
    *   Runs `sfc /scannow` again to address any issues that may have been uncovered or made fixable by the DISM repairs.

7.  **Disk Cleanup (Optional)**
    *   If the `-RunDiskCleanup` parameter is used, this step automates the Windows Disk Cleanup utility (`cleanmgr.exe`) to remove temporary files, system logs, old update files, and other unnecessary data. **The Downloads folder is explicitly excluded.**
    *   The script includes a monitor to prevent the Disk Cleanup process from getting stuck, which can happen. If it detects no activity for 30 seconds, it will forcefully close the process.

8.  **Print Spooler Reset** 
    *   Stops the Print Spooler service, clears out any stuck print jobs from the `C:\Windows\System32\spool\PRINTERS` directory, and then restarts the service. This can resolve issues where printers are offline or jobs won't print.

9. **Microsoft Store Reset & Update**
    *   Clears the Microsoft Store cache non-interactively (`wsreset.exe -i`) to resolve problems with apps not downloading or launching.
    *   Triggers a scan for pending Microsoft Store app updates.

10. **Re-register Windows Apps**
    *   Attempts to re-register all built-in and installed Microsoft Store (AppX) packages for all users. This can fix issues with modern apps that fail to start or function correctly.

11. **Install Windows Updates**
    *   **Module Installation (Optional):** If `-ResetWindowsUpdate` or `-InstallWindowsUpdates` is used, the script installs or updates the `PSWindowsUpdate` PowerShell module, which allows for advanced management of Windows Updates. It also ensures the required `NuGet` package provider is present.
    *   **Windows Update Reset (Optional):** If the `-ResetWindowsUpdate` parameter is used, the script uses the `Reset-WUComponents` command from the `PSWindowsUpdate` module to stop Windows Update services, rename the `SoftwareDistribution` and `catroot2` folders, and re-register necessary DLLs. This resolves many common update failures.
    *   **Update Installation (Optional):** If the `-InstallWindowsUpdates` parameter is used, the script uses the `PSWindowsUpdate` module to check for, download, and install all available updates from Microsoft Update, including for other Microsoft products.

12. **Upgrade Applications with Winget (Optional)**
    *   If the `-UpdateAllWinGet` parameter is used, the Windows Package Manager (`winget`) is available, and the script is not running as the SYSTEM account, it will attempt to upgrade all installed applications silently. It runs twice to handle dependencies or failed initial attempts.

13. **Disable Hibernation (Optional)**
    *   If the `-DisableHibernation` parameter is used, this step will turn off hibernation, delete the `hiberfil.sys` file, and disable Windows Fast Startup.

14. **Disk Check (CHKDSK)**
    *   Schedules a comprehensive disk check (`chkdsk /f /r /x`) to run on the system drive during the next system restart. This finds and repairs file system errors and scans for bad sectors.

15. **Disk Optimization (Optional)**
    *   This step only runs if the `-RunDiskOptimization` parameter is used.
    *   Checks the media type of the system drive.
    *   If it's an SSD, it performs a re-trim operation (`Optimize-Volume -ReTrim`).
    *   If it's an HDD, it performs a defragmentation (`Optimize-Volume -Defrag`).

16. **Windows Search Index Reset**
    *   Stops and temporarily disables the Windows Search service, deletes the index database files (`Windows.db`) to clear out corruption, and then re-enables and restarts the service to allow it to rebuild the index from scratch in the background.

17. **Cleanup Networking Devices (Optional)**
    *   If the `-CleanupNetworking` parameter is used, this runs `netcfg -d` to perform a hard reset on all networking components. This removes all network adapters (virtual and physical) and their settings. Windows will attempt to reinstall them upon the next reboot. **This forces an automatic reboot.**

18. **Final Restart**
    *   If you agreed to the automatic restart at the beginning or used the `-AutoReboot` parameter, the script will initiate a 60-second countdown before rebooting. Otherwise, it will remind you to restart manually.

## Additional Information
### Does This Script Work?

Yes...though this won't fix every possible error, it addresses the most common Windows issues to improve overall performance. You may need to run the script twice to ensure all fixes apply correctly. If issues persist, wait 24 hours before running it again. Windows requires time to complete specific background tasks and maintenance cycles before certain repairs take effect.

### Will This Script Break My Computer?

Unlikely. The script is designed to repair Windows components, which involves resetting services and purging cache files. However, the default execution path is safe. Any functions identified as potentially aggressive or risky are strictly opt-in and must be explicitly triggered via command-line arguments.

### This Didn't Fix My Issue

If the script didn't work, try these next steps:

* Research your specific symptoms online, as your issue may be unique to your environment.
* Some manufacturers require manual driver or firmware updates that scripts cannot handle.
* This script addresses software only. If the underlying hardware is failing, troubleshooting will require physical diagnostics.
* As a worst-case scenario, reinstall Windows to see if the issue is strictly software-related.

### Will This Remove Viruses?

This process may repair the built-in Windows Defender service. However, if you suspect an active malware infection, do not rely on this fix alone. Verify that Windows Defender is currently running, then scan your system with a reputable second-opinion scanner such as the [ESET Online Scanner](https://download.eset.com/com/eset/tools/online_scanner/latest/esetonlinescanner.exe) or [Malwarebytes Free Scanner](https://www.malwarebytes.com/solutions/virus-scanner) to ensure nothing was missed.

### Why Disable Hibernation and Fast Startup?

> [!NOTE]
> This action is only performed if you use the `-DisableHibernation` switch. It is not enabled by default because some users, particularly on laptops, rely on hibernation to save their session and conserve battery. Disabling it can also sometimes interfere with power management features on certain hardware.

Windows Fast Startup doesn't fully shut down the system. Instead, it hibernates the core operating system to speed up the next boot. While fast, this can cause issues with drivers, software updates, and dual-booting environments because the system never gets a completely fresh start. Disabling it provides several benefits:

*   **Ensures a True "Fresh Start":** Forces a full shutdown, which can resolve persistent driver and software glitches that survive a normal reboot.
*   **Improves Update Reliability:** A full shutdown allows system files to be properly replaced during updates, preventing common failures.
*   **Fixes Driver State Issues:** Because drivers are fully re-initialized on a cold boot, this can resolve odd hardware behavior. Note that on the first restart after disabling hibernation, display settings (like resolution or multi-monitor arrangement) may temporarily change before correcting themselves.
*   **Frees Up Disk Space:** Deletes the `hiberfil.sys` file, reclaiming several gigabytes of space on your system drive.
*   **Aids Dual-Booting:** Prevents file system corruption issues when accessing the Windows partition from another operating system (like Linux).

## Troubleshooting

### DISM /RestoreHealth Failed
If the standard restore fails due to connectivity or corruption issues with Windows Update, you will need to switch to a local source. By pointing DISM to a clean Windows ISO, you provide a verified set of files to repair the system image manually.

#### Phase 1: Preparation
Before running the command, you must have a valid source file (`install.wim` or `install.esd`) that matches your installed Windows version exactly.

1. Check your Windows Version:
    * Open Command Prompt or PowerShell.
    * Type `winver` and press Enter.
    * Note your Version (e.g., 23H2) and OS Build (e.g., 22631.xxxx). Your local source must be the same version or newer.

2. Get the Source (ISO):
    * If you don't have a Windows ISO, download one using the [Microsoft Media Creation Tool](https://www.microsoft.com/software-download/).
    * Mount the ISO: Right-click the ISO file and select Mount. This will create a virtual DVD drive (e.g., Drive `E:`).
3. Locate the Install File:
    * Open the mounted drive in File Explorer.
    * Go to the `sources` folder.
    * Look for a large file named `install.wim` OR `install.esd`.
    * *Note: `install.esd` is more common in consumer downloads; `install.wim` is common in enterprise/business media.*

4. Find the Correct Index Number:
    * A single ISO often contains multiple editions (Home, Pro, Education). You must tell DISM which one to use.
    * Open Command Prompt as Administrator.
    * Run the following command (replace `E:` with your mounted ISO drive letter):
        ```cmd
        dism /Get-WimInfo /WimFile:E:\sources\install.wim
        ```
        *(If you have an `.esd` file, change `install.wim` to `install.esd` in the command above.)*
    * Look at the output. Find the Index number for the Edition you are running (e.g., if you are running Windows 11 Pro, and "Windows 11 Pro" is Index 6, remember Index 6).

#### Phase 2: The Repair Command
Choose the syntax below that matches the file type you found (`.wim` or `.esd`).

##### Option A: If using `install.wim`

- Run this command in an Admin Command Prompt. Replace `E:` with your ISO drive letter and `1` with the Index number you found in Phase 1.
    ```cmd
    DISM /Online /Cleanup-Image /RestoreHealth /Source:WIM:E:\sources\install.wim:1 /LimitAccess
    ```
##### Option B: If using `install.esd`

- Run this command in an Admin Command Prompt. Replace `E:` with your ISO drive letter and `1` with the Index number you found in Phase 1.
    ```cmd
    DISM /Online /Cleanup-Image /RestoreHealth /Source:ESD:E:\sources\install.esd:1 /LimitAccess
    ```

**Key Parameters Explained:**
* `/Source`: Specifies the location of the known good files.
* `WIM:` / `ESD:`: Tells DISM exactly what file format to read.
* `:1` (The number at the end): The Index number of your Windows Edition.
* `/LimitAccess`: Crucial. It prevents DISM from trying to contact Windows Update, ensuring it only uses the local file you provided.

#### Phase 3: Verification
1. Wait for completion: The process usually pauses at 62.3% or 84.9%. This is normal. Let it finish.
2. Run SFC: Once DISM finishes successfully, run the System File Checker to apply the final repairs:
    ```cmd
    sfc /scannow
    ```
#### Troubleshooting DISM Errors
Error 0x800f081f: "The source files could not be found."
* Cause 1: You pointed to the wrong Index. (e.g., You have Windows Pro installed, but you pointed DISM to the Index for Windows Home).
* Cause 2: The ISO version is too old. If your installed Windows has recent updates (e.g., Build 19045) but your ISO is old (e.g., Build 19041), the repair will fail because the ISO doesn't have the newer files your system expects.
* Fix: Ensure you download the absolute latest ISO using the Media Creation Tool, which will include the latest major updates.