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

REM Check admin
net session >nul 2>&1
if errorlevel 1 (
    echo [!] This script requires Administrator privileges.
    echo     Right-click and "Run as Administrator".
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

REM Check if makecert is available for self-signed cert
where makecert >nul 2>&1
if errorlevel 0 (
    echo [*] Creating test certificate...

    makecert -r -pe -ss PrivateCertStore -n "CN=VMXToolbox Test" VMXToolboxTest.cer
    if errorlevel 1 (
        echo [!] makecert failed. You can sign the driver manually.
    ) else (
        echo [+] Test certificate created: VMXToolboxTest.cer
        echo [*] To sign the driver:
        echo     signtool sign /s PrivateCertStore /n "VMXToolbox Test" /t http://timestamp.digicert.com VMXToolboxDrv.sys
    )
) else (
    echo [*] makecert not found. Use signtool from WDK to sign manually.
)

echo.
echo ====================================================
echo   Driver Loading Instructions
echo ====================================================
echo.
echo   1. Reboot (if test signing was just enabled)
echo   2. Copy VMXToolboxDrv.sys to a known location
echo   3. Load driver:
echo      sc create VMXToolboxDrv type=kernel binPath="C:\path\to\VMXToolboxDrv.sys"
echo      sc start VMXToolboxDrv
echo   4. Run VMXToolbox.exe to control the driver
echo   5. To unload:
echo      sc stop VMXToolboxDrv
echo      sc delete VMXToolboxDrv
echo.
