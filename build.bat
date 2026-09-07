@echo off
REM modlink - local build with the MSVC toolchain.
REM
REM Needs "Visual Studio Build Tools" (free). Run this from a
REM "x64 Native Tools Command Prompt for VS", or let the line below find it.

setlocal enabledelayedexpansion
cd /d "%~dp0"

where cl.exe >nul 2>&1
if errorlevel 1 (
    for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSPATH=%%i
    if not defined VSPATH (
        echo   ERROR: MSVC not found. Install "Visual Studio Build Tools" with the
        echo          "Desktop development with C++" workload.
        exit /b 1
    )
    call "!VSPATH!\VC\Auxiliary\Build\vcvars64.bat" >nul
)

if not exist res\3proxy.exe (
    echo   fetching 3proxy...
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\fetch-3proxy.ps1
    if errorlevel 1 exit /b 1
)

if not exist build mkdir build

echo   compiling resources...
rc.exe /nologo /fo build\modlink.res /i res res\modlink.rc
if errorlevel 1 exit /b 1

echo   compiling...
REM /utf-8 matters: the sources carry Cyrillic inside L"" literals.
cl.exe /nologo /W3 /O2 /MT /utf-8 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS ^
   /Isrc /Fobuild\ /Fdbuild\ ^
   src\main.c src\util.c src\json.c src\config.c src\proxy3.c ^
   src\net.c src\hilink.c src\reconn.c src\ui_theme.c src\ui_main.c ^
   build\modlink.res ^
   /link /SUBSYSTEM:WINDOWS /OUT:build\modlink.exe ^
   user32.lib gdi32.lib comctl32.lib shell32.lib ole32.lib ^
   winhttp.lib ws2_32.lib dwmapi.lib uxtheme.lib advapi32.lib

if errorlevel 1 (
    echo.
    echo   BUILD FAILED
    exit /b 1
)

echo   compiling tapprobe...
REM Diagnostic probe for the agent side; console subsystem, no resources.
cl.exe /nologo /W3 /O2 /MT /utf-8 /D_CRT_SECURE_NO_WARNINGS ^
   /Fobuild\ /Fdbuild\ probe\tapprobe.c ^
   /link /SUBSYSTEM:CONSOLE /OUT:build\tapprobe.exe advapi32.lib

if errorlevel 1 (
    echo.
    echo   BUILD FAILED ^(tapprobe^)
    exit /b 1
)

echo.
echo   OK: build\modlink.exe
echo   OK: build\tapprobe.exe
dir /b build\modlink.exe build\tapprobe.exe
