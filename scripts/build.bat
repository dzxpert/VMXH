@echo off
REM =========================================================================
REM  VMX Hypervisor Toolbox - Build Script
REM  Requires: WDK 10, Visual Studio 2022, MASM (ml64)
REM =========================================================================

setlocal

REM ---- Configuration ----
set PROJECT_ROOT=%~dp0..
set DRIVER_DIR=%PROJECT_ROOT%\driver
set CLIENT_DIR=%PROJECT_ROOT%\client
set COMMON_DIR=%PROJECT_ROOT%\common
set OUTPUT_DIR=%PROJECT_ROOT%\build

REM Create output directory
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo.
echo ====================================================
echo   VMX Hypervisor Toolbox - Build
echo ====================================================
echo.

REM ---- Check for VS environment ----
where cl >nul 2>&1
if errorlevel 1 (
    echo [!] Visual Studio environment not found.
    echo     Run this script from a "x64 Native Tools Command Prompt"
    echo     or from a WDK build environment.
    exit /b 1
)

REM =========================================================================
REM  Build User-Mode Client (VMXToolbox.exe)
REM =========================================================================

echo [*] Building user-mode client (VMXToolbox.exe)...

cl /nologo /W4 /O2 /Fe"%OUTPUT_DIR%\VMXToolbox.exe" ^
    /I"%COMMON_DIR%" ^
    "%CLIENT_DIR%\main.c" ^
    "%CLIENT_DIR%\driver_comm.c" ^
    /link /SUBSYSTEM:CONSOLE

if errorlevel 1 (
    echo [!] Client build failed!
    exit /b 1
)

echo [+] VMXToolbox.exe built successfully.
echo.

REM =========================================================================
REM  Build Kernel Driver (VMXToolboxDrv.sys)
REM =========================================================================

echo [*] Building kernel driver (VMXToolboxDrv.sys)...
echo.
echo     NOTE: The kernel driver requires WDK build tools.
echo     For a proper driver build, use Visual Studio with WDK project
echo     or the 'msbuild' command with a proper .vcxproj.
echo.
echo     Driver source files:
echo       - driver\vmxdrv.c        (Entry point)
echo       - driver\vmx_init.c      (VMX initialization)
echo       - driver\vmx_exit.c      (VM-Exit dispatcher)
echo       - driver\vmx_asm.asm     (Assembly routines)
echo       - driver\ept.c           (EPT management)
echo       - driver\msr.c           (MSR handling)
echo       - driver\process.c       (Process tracking)
echo       - driver\anti_anti_debug.c (Anti-anti-debug engine)
echo       - driver\log.c           (Logging)
echo.
echo     To build with WDK:
echo     1. Create a WDK driver project in Visual Studio
echo     2. Add all source files from driver\ directory
echo     3. Set target to x64 Release
echo     4. Build solution
echo.

echo ====================================================
echo   Build Complete
echo ====================================================
echo   Output: %OUTPUT_DIR%\VMXToolbox.exe
echo ====================================================

endlocal
