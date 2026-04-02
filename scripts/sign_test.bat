@echo off
REM =========================================================================
REM  Test Signing Script for Development
REM  Run as Administrator
REM =========================================================================

echo.
echo ====================================================
echo   VMX Hypervisor Toolbox - Test Signing Setup
echo ====================================================
echo.

REM Add WDK tools to PATH
set BASEDIR=C:\WinDDK\7600.16385.1
set PATH=%BASEDIR%\bin\x86\amd64;%BASEDIR%\bin\x86;%BASEDIR%\bin;%PATH%

REM Check admin
net session >nul 2>&1
if errorlevel 1 (
    echo [!] This script requires Administrator privileges.
    echo     Right-click and "Run as Administrator".
    exit /b 1
)

REM Locate the driver
set DRIVER_PATH=%~dp0..\driver\objchk_win7_amd64\amd64\VMXToolboxDrv.sys
if not exist "%DRIVER_PATH%" (
    echo [!] Driver not found: %DRIVER_PATH%
    echo     Run do_build.bat first.
    exit /b 1
)

REM Enable test signing mode
echo [*] Enabling test signing mode...
bcdedit /set testsigning on
if errorlevel 1 (
    echo [!] Failed to enable test signing.
    echo     If Secure Boot is enabled, disable it in BIOS first.
    exit /b 1
)

echo [+] Test signing enabled.
echo [*] A reboot is required for this to take effect.
echo.

REM Create test certificate
echo [*] Creating test certificate...
makecert -r -pe -ss PrivateCertStore -n "CN=VMXToolbox Test" "%~dp0VMXToolboxTest.cer"
if errorlevel 1 (
    echo [!] makecert failed.
    exit /b 1
)
echo [+] Test certificate created.

REM Sign the driver (use /a to auto-select best certificate)
echo [*] Signing VMXToolboxDrv.sys...
signtool sign /a /s PrivateCertStore /n "VMXToolbox Test" /t http://timestamp.digicert.com "%DRIVER_PATH%"
if errorlevel 1 (
    echo [!] signtool sign failed, trying without timestamp...
    signtool sign /a /s PrivateCertStore /n "VMXToolbox Test" "%DRIVER_PATH%"
    if errorlevel 1 (
        echo [!] Signing failed.
        exit /b 1
    )
)
echo [+] Driver signed successfully.

REM Verify signature
echo [*] Verifying signature...
signtool verify /pa "%DRIVER_PATH%"

echo.
echo ====================================================
echo   Driver Loading Instructions
echo ====================================================
echo.
echo   1. Reboot (if test signing was just enabled)
echo   2. Load driver:
echo      sc create VMXToolboxDrv type=kernel binPath="%DRIVER_PATH%"
echo      sc start VMXToolboxDrv
echo   3. Run VMXToolbox.exe to control the driver
echo   4. To unload:
echo      sc stop VMXToolboxDrv
echo      sc delete VMXToolboxDrv
echo.
