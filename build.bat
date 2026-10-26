@echo off
setlocal enabledelayedexpansion
rem ============================================================
rem  Warden build script (MSVC, x64)
rem  Run from "x64 Native Tools Command Prompt for VS 2022"
rem  or let .github/workflows/build.yml do it on CI.
rem ============================================================

where cl >nul 2>nul
if errorlevel 1 (
    echo [!] cl.exe not found. Open the "x64 Native Tools Command Prompt"
    echo     for VS 2022 and run this script again.
    exit /b 1
)

if not exist bin mkdir bin
if not exist obj\exe mkdir obj\exe
if not exist obj\dll mkdir obj\dll

rem  src\sdk\corprof.h + corhdr.h are vendored Windows SDK 10 headers.
rem  /I makes them take precedence over the machine's SDK copy (the
rem  NETFXSDK 4.8.1 corprof.h has include-contract quirks), so the
rem  profiler compiles identically on every VS/SDK install.
set CFLAGS=/nologo /W3 /MT /O2 /Zi /FS /EHsc /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS /Isrc\sdk /Isrc\sdk /Isrc\common
set COMMON=src\common\sha256.c src\common\util.c src\common\log.c

echo [*] Building Warden.dll (monitor + CLR profiler)...
cl %CFLAGS% /c %COMMON% src\monitor\dllmain.c src\monitor\monitor.c ^
    src\monitor\scanner.c src\monitor\integrity.c src\monitor\hooks.c ^
    src\monitor\profiler.cpp /Foobj\dll\
if errorlevel 1 goto :fail

link /nologo /DLL /DEF:src\warden.def /OUT:bin\Warden.dll /MACHINE:X64 ^
    /PDB:bin\Warden.pdb /DEBUG:FULL obj\dll\*.obj kernel32.lib
if errorlevel 1 goto :fail

echo [*] Building Warden.exe (launcher)...
cl %CFLAGS% /c %COMMON% src\launcher\main.c src\launcher\inject.c ^
    src\launcher\report.c /Foobj\exe\
if errorlevel 1 goto :fail

link /nologo /OUT:bin\Warden.exe /MACHINE:X64 /SUBSYSTEM:CONSOLE ^
    /PDB:bin\Warden.pdb /DEBUG:FULL obj\exe\*.obj kernel32.lib
if errorlevel 1 goto :fail

echo [*] Building LoadSim.exe (benign test target)...
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if exist "%CSC%" (
    "%CSC%" /nologo /target:exe /platform:x64 /optimize /out:bin\LoadSim.exe simulator\LoadSim.cs
    if errorlevel 1 goto :fail
) else (
    echo [i] csc.exe not found - skipping LoadSim (optional)
)

echo.
echo [+] Build complete:
dir /b bin
echo.
echo Try:  bin\Warden.exe bin\LoadSim.exe
exit /b 0

:fail
echo [!] build failed
exit /b 1
