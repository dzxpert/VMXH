@echo off
REM =========================================================================
REM  Direct WDK 7600 build - minimal environment, no OACR
REM =========================================================================

set BASEDIR=C:\WinDDK\7600.16385.1

set DDKBUILDENV=chk
set BUILD_ALT_DIR=chk_win7_amd64
set DDK_TARGET_OS=Win7
set _ddkspec=win7
set _RunOacr=FALSE
set BUILD_OACR=

set NTMAKEENV=%BASEDIR%\bin
set BUILD_MAKE_PROGRAM=nmake.exe
set BUILD_DEFAULT=-ei -nmake -i -nosqm
set BUILD_DEFAULT_TARGETS=-amd64
set BUILD_MULTIPROCESSOR=1
set NO_BINPLACE=TRUE
set NO_BROWSER_FILE=TRUE
set NEW_CRTS=1
set USE_OBJECT_ROOT=1
set LANGUAGE_NEUTRAL=0
set RCNOFONTMAP=1
set LINK_LIB_IGNORE=4198

set AMD64=1
set _BUILDARCH=AMD64
set PROCESSOR_ARCHITECTURE=AMD64
set _FreeBuild=false
set _AMD64bit=true

set CRT_INC_PATH=%BASEDIR%\inc\crt
set SDK_INC_PATH=%BASEDIR%\inc\api
set DDK_INC_PATH=%BASEDIR%\inc\ddk
set WDM_INC_PATH=%BASEDIR%\inc\ddk
set OAK_INC_PATH=%BASEDIR%\inc\api
set IFSKIT_INC_PATH=%BASEDIR%\inc\ddk
set HALKIT_INC_PATH=%BASEDIR%\inc\ddk
set DRIVER_INC_PATH=%BASEDIR%\inc\ddk
set ATL_INC_PATH=%BASEDIR%\inc
set ATL_INC_ROOT=%BASEDIR%\inc
set MFC_INC_PATH=%BASEDIR%\inc\mfc42

set SDK_LIB_DEST=%BASEDIR%\lib\win7
set DDK_LIB_DEST=%BASEDIR%\lib\win7
set IFSKIT_LIB_DEST=%BASEDIR%\lib\win7

set SDK_LIB_PATH=%BASEDIR%\lib\win7\*
set DDK_LIB_PATH=%BASEDIR%\lib\win7\*
set HALKIT_LIB_PATH=%BASEDIR%\lib\win7\*
set IFSKIT_LIB_PATH=%BASEDIR%\lib\win7\*

set CRT_LIB_PATH=%BASEDIR%\lib\Crt\*
set ATL_LIB_PATH=%BASEDIR%\lib\atl\*
set MFC_LIB_PATH=%BASEDIR%\lib\mfc\*

set Include=%BASEDIR%\inc\api;%BASEDIR%\inc\crt;%BASEDIR%\inc\ddk
set Lib=%BASEDIR%\lib\win7\amd64

set WPP_CONFIG_PATH=%BASEDIR%\bin\wppconfig
set PROJECT_ROOT=%BASEDIR%\src
set PUBLIC_ROOT=%BASEDIR%
set PUBLISH_CMD=@echo.

set PATH=%BASEDIR%\bin\x86\amd64;%BASEDIR%\bin\x86;%BASEDIR%\bin;%SystemRoot%\system32;%SystemRoot%

cd /d %~dp0..
%BASEDIR%\bin\x86\build.exe -cZg
cd /d %~dp0
