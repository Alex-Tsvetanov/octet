@echo off
rem Builds and tests octet on Windows from a plain prompt. Needs Visual Studio Build Tools,
rem Ninja, CMake, and OpenSSL installed through vcpkg (vcpkg install openssl:x64-windows)
rem with VCPKG_ROOT pointing at that vcpkg checkout.
setlocal
rem vcvars64.bat points VCPKG_ROOT at the copy bundled with Visual Studio, which has no
rem packages installed. Keep the one the user set.
set "OCTET_VCPKG_ROOT=%VCPKG_ROOT%"
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath`) do set "VSDIR=%%i"
if not defined VSDIR (echo Visual Studio not found & exit /b 1)
rem vcvars64.bat from Visual Studio 18 prints "vswhere.exe is not recognized" on stderr from
rem one of its own extension scripts. It is harmless; its exit code is still checked.
call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1 || exit /b 1
set "VCPKG_ROOT=%OCTET_VCPKG_ROOT%"
cd /d "%~dp0.."
cmake --preset windows-release %OCTET_CONFIGURE% || exit /b 1
cmake --build --preset windows-release || exit /b 1
ctest --preset windows-release %* || exit /b 1
