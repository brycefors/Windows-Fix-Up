@echo off
setlocal

:: Check for administrative privileges
NET SESSION >NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO Requesting administrative privileges...
    :: Relaunch the script with admin rights, passing along any arguments.
    IF [%1]==[] (
        powershell -Command "Start-Process -FilePath '%~dpnx0' -Verb RunAs"
    ) ELSE (
        powershell -Command "Start-Process -FilePath '%~dpnx0' -Verb RunAs -ArgumentList '%*'"
    )
    EXIT /B
)

:: If we reach here, the script is running with administrative privileges.
ECHO Running with administrative privileges.

:: This batch file is a simple wrapper to execute the Windows-Update-Maintenance.ps1 PowerShell script.
:: It ensures that the script is run with an execution policy that allows it to execute,
:: and it passes along any arguments provided to this batch file.

:: Get the directory where this batch file is located.
set "SCRIPT_DIR=%~dp0"

:: Construct the full path to the PowerShell script.
set "PS_SCRIPT=%SCRIPT_DIR%Windows-Update-Maintenance.ps1"

:: Check if the script exists. If not, download it.
IF NOT EXIST "%PS_SCRIPT%" (
    ECHO Windows-Update-Maintenance.ps1 not found. Downloading from GitHub...
    powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/brycefors/Windows-Fix-Up/refs/heads/main/Windows-Update-Maintenance/Windows-Update-Maintenance.ps1' -OutFile '%PS_SCRIPT%'"
    IF NOT EXIST "%PS_SCRIPT%" (
        ECHO Failed to download Windows-Update-Maintenance.ps1.
        PAUSE
        EXIT /B 1
    )
    ECHO Download complete.
)

:: Execute the PowerShell script.
:: -ExecutionPolicy Bypass: Allows the script to run without changing the system-wide policy.
:: -File: Specifies the script to run.
:: %*: Passes all arguments from this batch file to the PowerShell script.
powershell.exe -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*

:: Surface the PowerShell exit code to the caller (0 = current/success, 3010 = reboot required, 1 = failure).
EXIT /B %ERRORLEVEL%
