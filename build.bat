@echo off
REM ProxyVeth - local build with the MSVC toolchain.
REM
REM Needs "Visual Studio Build Tools" (free, "Desktop development with C++").
REM Run from an "x64 Native Tools Command Prompt for VS", or let the block below
REM locate vcvars. The only extra dependency is the WebView2 SDK *header*
REM (WebView2.h) - the loader is built into the vendored webview.h, so no .lib or
REM .dll ships with us. Point %WEBVIEW2_INCLUDE% at the folder holding WebView2.h,
REM or have nuget on PATH and this script fetches it.

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

REM ---- 3proxy binary to embed ----
if not exist res\3proxy.exe (
    echo   fetching 3proxy...
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\fetch-3proxy.ps1
    if errorlevel 1 exit /b 1
)

REM ---- WebView2 SDK header ----
if not defined WEBVIEW2_INCLUDE (
    if exist packages\Microsoft.Web.WebView2\build\native\include\WebView2.h (
        set "WEBVIEW2_INCLUDE=%CD%\packages\Microsoft.Web.WebView2\build\native\include"
    ) else (
        where nuget >nul 2>&1
        if errorlevel 1 (
            echo   ERROR: WebView2.h not found and nuget is not on PATH.
            echo          Set WEBVIEW2_INCLUDE to the folder that contains WebView2.h.
            exit /b 1
        )
        echo   fetching WebView2 SDK header via nuget...
        nuget install Microsoft.Web.WebView2 -OutputDirectory packages -ExcludeVersion
        if errorlevel 1 exit /b 1
        set "WEBVIEW2_INCLUDE=%CD%\packages\Microsoft.Web.WebView2\build\native\include"
    )
)
if not exist "%WEBVIEW2_INCLUDE%\WebView2.h" (
    echo   ERROR: WebView2.h not found at "%WEBVIEW2_INCLUDE%".
    exit /b 1
)

if not exist build mkdir build

REM The resource script embeds res\ui.html; keep it in step with the source UI.
copy /Y app\ui.html res\ui.html >nul

echo   compiling resources...
rc.exe /nologo /fo build\proxyveth.res /i res res\proxyveth.rc
if errorlevel 1 exit /b 1

echo   compiling...
REM /utf-8: Cyrillic lives in the C sources and in ui.html.
REM /EHsc: the C++ host (webview) uses exceptions and the STL.
cl.exe /nologo /W3 /O2 /MT /EHsc /utf-8 /DUNICODE /D_UNICODE ^
   /D_CRT_SECURE_NO_WARNINGS /D_WINSOCK_DEPRECATED_NO_WARNINGS ^
   /Isrc /Ithird_party\webview /I"%WEBVIEW2_INCLUDE%" /Fobuild\ /Fdbuild\ ^
   app\host.cc ^
   src\util.c src\json.c src\config.c src\proxy3.c src\net.c ^
   src\hilink.c src\reconn.c src\bridge.c ^
   build\proxyveth.res ^
   /link /SUBSYSTEM:WINDOWS /OUT:build\proxyveth.exe ^
   user32.lib gdi32.lib ole32.lib oleaut32.lib shlwapi.lib version.lib ^
   advapi32.lib shell32.lib winhttp.lib ws2_32.lib

if errorlevel 1 (
    echo.
    echo   BUILD FAILED
    exit /b 1
)

echo.
echo   OK: build\proxyveth.exe
dir /b build\*.exe
