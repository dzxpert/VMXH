@echo off
setlocal EnableDelayedExpansion
REM =========================================================================
REM  VMX Hypervisor Toolbox — Test Signing Setup (v2)
REM
REM  Run as Administrator.  This script:
REM    1. Verifies admin / build / driver / tool availability.
REM    2. Detects Secure Boot state — if ON, refuses early and tells you
REM       exactly what to do (disable in UEFI + BitLocker caveat).
REM    3. Detects BitLocker on the system drive and warns BEFORE touching
REM       BCD, because changing boot policy can trigger a recovery-key
REM       prompt on next boot.
REM    4. Enables test signing mode (bcdedit /set testsigning on).
REM    5. Creates a self-signed test certificate (MakeCert + CertMgr).
REM    6. Signs the driver with SignTool and verifies the signature.
REM    7. Prints load / unload instructions.
REM =========================================================================

echo.
echo ==========================================================
echo   VMX Hypervisor Toolbox - Test Signing Setup (v2)
echo ==========================================================
echo.

REM ---------------------------------------------------------------
REM  Add WDK tools to PATH (adjust BASEDIR if your WDK lives elsewhere).
REM ---------------------------------------------------------------
set BASEDIR=C:\WinDDK\7600.16385.1
set PATH=%BASEDIR%\bin\x86\amd64;%BASEDIR%\bin\x86;%BASEDIR%\bin;%PATH%

REM ---------------------------------------------------------------
REM  [1/7] Admin check
REM ---------------------------------------------------------------
echo [1/7] Checking administrator privileges...
net session >nul 2>&1
if errorlevel 1 (
    echo [!] This script requires Administrator privileges.
    echo     Right-click the script and choose "Run as administrator".
    goto :fail
)
echo     OK
echo.

REM ---------------------------------------------------------------
REM  [2/7] Driver existence check
REM ---------------------------------------------------------------
echo [2/7] Locating driver binary...
set DRIVER_PATH=%~dp0..\driver\objchk_win7_amd64\amd64\VMXToolboxDrv.sys
if not exist "%DRIVER_PATH%" (
    echo [!] Driver not found:
    echo         %DRIVER_PATH%
    echo     Build it first with do_build.bat / do_build_svm.bat.
    goto :fail
)
echo     Found: %DRIVER_PATH%
echo.

REM ---------------------------------------------------------------
REM  [3/7] WDK tool availability
REM ---------------------------------------------------------------
echo [3/7] Checking required WDK tools...
where makecert >nul 2>&1
if errorlevel 1 (
    echo [!] makecert.exe not found in PATH.
    echo     Expected under: %BASEDIR%\bin\x86 or the Windows SDK.
    echo     Install Windows SDK ^(for signtool/makecert^) or adjust BASEDIR.
    goto :fail
)
where signtool >nul 2>&1
if errorlevel 1 (
    echo [!] signtool.exe not found in PATH.
    echo     Install Windows SDK or adjust BASEDIR.
    goto :fail
)
echo     makecert and signtool OK
echo.

REM ---------------------------------------------------------------
REM  [4/7] Secure Boot detection — HARD STOP if enabled.
REM
REM        On UEFI + Secure Boot systems, Windows refuses to enable
REM        test signing no matter what privilege you have.  The ONLY
REM        ways forward are:
REM          (a) disable Secure Boot in UEFI firmware, OR
REM          (b) enrol your cert into the UEFI db (advanced, not
REM              automated by this script).
REM        We detect Secure Boot by reading the official WMI property
REM        via PowerShell, which is the Microsoft-sanctioned method.
REM ---------------------------------------------------------------
echo [4/7] Checking Secure Boot state...

set SECUREBOOT_STATE=UNKNOWN

REM PowerShell Confirm-SecureBootUEFI:
REM   returns True  -> Secure Boot ON
REM   returns False -> Secure Boot OFF
REM   throws        -> legacy BIOS (no Secure Boot concept)
for /f "usebackq tokens=*" %%R in (`powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { if ((Confirm-SecureBootUEFI) -eq $true) { 'ON' } else { 'OFF' } } catch { 'LEGACY' }"`) do (
    set SECUREBOOT_STATE=%%R
)

if /i "!SECUREBOOT_STATE!"=="ON" (
    echo [!] Secure Boot is ENABLED.
    echo.
    echo     Windows will refuse to turn on test signing while Secure
    echo     Boot is active.  You must disable it first:
    echo.
    echo     1. Reboot into UEFI firmware ^(Shift+Restart -^> Troubleshoot
    echo        -^> Advanced options -^> UEFI Firmware Settings^).
    echo     2. Disable "Secure Boot" ^(may be under Boot, Security,
    echo        or Authentication tab depending on vendor^).
    echo     3. Save and reboot back into Windows.
    echo     4. Re-run this script.
    echo.
    echo     WARNING: if the system drive uses BitLocker, suspend it
    echo     with   manage-bde -protectors -disable C:   BEFORE
    echo     entering UEFI, otherwise you will be prompted for the
    echo     48-digit recovery key on next boot.
    echo.
    goto :fail
)
if /i "!SECUREBOOT_STATE!"=="LEGACY" (
    echo     Legacy BIOS detected ^(Secure Boot not applicable^)
) else (
    echo     Secure Boot OFF — good to go
)
echo.

REM ---------------------------------------------------------------
REM  [5/7] BitLocker pre-flight — warn if system drive is protected.
REM        Changing boot policy (bcdedit) on a BitLocker-protected
REM        system drive can trigger a recovery-key prompt on next
REM        reboot.  We warn but do not hard-stop — user may have the
REM        key handy.
REM ---------------------------------------------------------------
echo [5/7] Checking BitLocker state on system drive...
for /f "usebackq tokens=*" %%R in (`powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus } catch { 'Unknown' }"`) do (
    set BL_STATE=%%R
)
if /i "!BL_STATE!"=="On" (
    echo [!] BitLocker protection is ON on %SystemDrive%.
    echo     Enabling test signing changes boot-loader policy, which
    echo     MAY prompt for the recovery key on next boot.
    echo.
    echo     Recommended before rebooting:
    echo         manage-bde -protectors -disable %SystemDrive%
    echo     This suspends protection for one reboot; resumes
    echo     automatically afterwards.
    echo.
    choice /c YN /n /m "Continue anyway? [Y/N]: "
    if errorlevel 2 (
        echo     Aborted by user.
        goto :fail
    )
    echo.
)
if /i "!BL_STATE!"=="Off" echo     BitLocker OFF
echo.

REM ---------------------------------------------------------------
REM  [6/7] Enable test signing
REM ---------------------------------------------------------------
echo [6/7] Enabling test signing mode...
bcdedit /set testsigning on
if errorlevel 1 (
    echo [!] bcdedit /set testsigning on failed.
    echo     If Secure Boot was re-enabled or a Group Policy forbids
    echo     test signing, this command will be rejected.  See
    echo     step [4] for the Secure Boot case.
    goto :fail
)
echo     Test signing ENABLED ^(effective after reboot^)
echo.

REM ---------------------------------------------------------------
REM  [7/7] Certificate + driver signing
REM ---------------------------------------------------------------
echo [7/7] Creating test certificate and signing driver...
makecert -r -pe -ss PrivateCertStore -n "CN=VMXToolbox Test" "%~dp0VMXToolboxTest.cer"
if errorlevel 1 (
    echo [!] makecert failed.  Is the Windows SDK properly installed?
    goto :fail
)
echo     Certificate created: %~dp0VMXToolboxTest.cer

echo     Signing driver...
signtool sign /a /v /s PrivateCertStore /n "VMXToolbox Test" ^
    /t http://timestamp.digicert.com "%DRIVER_PATH%"
if errorlevel 1 (
    echo [!] signtool with timestamp failed, retrying without timestamp...
    signtool sign /a /v /s PrivateCertStore /n "VMXToolbox Test" "%DRIVER_PATH%"
    if errorlevel 1 (
        echo [!] Signing failed.
        goto :fail
    )
)
echo     Signed OK.

echo     Verifying signature...
signtool verify /pa /v "%DRIVER_PATH%"
if errorlevel 1 (
    echo [!] signtool verify reported an issue ^(may be benign under test
    echo     signing — re-verify after reboot with /pa^).
)

echo.
echo ==========================================================
echo   SUCCESS — Driver signed, test signing enabled
echo ==========================================================
echo.
echo   NEXT STEPS:
echo.
echo     1. REBOOT the machine so test signing mode takes effect.
echo        ^(Watch for BitLocker recovery-key prompt if you ignored
echo         the warning in step [5].^)
echo.
echo     2. After reboot, load the driver:
echo           sc create VMXToolboxDrv type= kernel binPath= "%DRIVER_PATH%"
echo           sc start VMXToolboxDrv
echo.
echo     3. Run VMXToolbox.exe to control the driver.
echo.
echo     4. To unload:
echo           sc stop VMXToolboxDrv
echo           sc delete VMXToolboxDrv
echo.
echo     5. To TURN OFF test signing afterwards:
echo           bcdedit /set testsigning off
echo           ^(then reboot^)
echo.
endlocal
exit /b 0


:fail
echo.
echo ==========================================================
echo   FAILED — see messages above
echo ==========================================================
echo.
endlocal
exit /b 1
