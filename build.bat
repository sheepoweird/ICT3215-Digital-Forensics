@echo off
rem Builds dist\EnvStego-portable.zip: both token firmwares + the frozen app.
rem Needs Python 3.12 (py -3.12). If it is missing, the script offers to
rem download Python 3.12.10 from python.org and install it for all users
rem (one administrator prompt). The first run downloads PlatformIO's ESP32
rem toolchains (about 1 GB). Only the zip is left in dist\: unzip it to test.
setlocal
cd /d "%~dp0"

rem A double-click in Explorer runs  cmd /c ""<this script>" "  and the window
rem closes as soon as the script ends. In that case wait for a key first, so
rem the messages can be read. Runs from a terminal or PowerShell never wait.
set "PAUSE_AT_END="
setlocal EnableDelayedExpansion
set "CMDLINE=!cmdcmdline:"=#!"
if "!CMDLINE:~-3!"=="# #" (endlocal & set "PAUSE_AT_END=1") else endlocal

rem 3.12.10 is the last 3.12 release with Windows installers on python.org.
set "PY_VERSION=3.12.10"

rem Reuse .venv only if it still runs Python 3.12. A .venv copied from another
rem PC points at that PC's Python and cannot start, so it is rebuilt.
if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe -c "import sys; sys.exit(sys.version_info[:2] != (3, 12))" >nul 2>&1 && goto :install
    echo The existing .venv is broken or not Python 3.12 - rebuilding it ...
    rmdir /s /q .venv || goto :fail
)

where py >nul 2>&1 || goto :offer_install
py -3.12 -c "" >nul 2>&1 || goto :offer_install

:create_venv
echo Creating the build environment in .venv ...
py -3.12 -m venv .venv || goto :fail

:install
.venv\Scripts\python -m pip install --quiet --upgrade pip || goto :fail
.venv\Scripts\python -m pip install --quiet -r Python\requirements.txt -r packaging\requirements-build.txt || goto :fail
.venv\Scripts\python packaging\build.py || goto :fail

echo.
echo Done: dist\EnvStego-portable.zip
set "EXIT_CODE=0"
goto :end

rem ---------------------------------------------------------------------------
rem Python 3.12 is missing: offer to download and install it from python.org.
rem ---------------------------------------------------------------------------
:offer_install
echo.
set "HAVE_LAUNCHER="
where py >nul 2>&1 && set "HAVE_LAUNCHER=1"
if defined HAVE_LAUNCHER (
    echo Python 3.12 is needed to build, but it is not installed. Installed versions:
    py --list
) else (
    echo Python 3.12 is needed to build, but Python is not installed.
)
echo Newer versions such as 3.13 are not used, because some dependencies are
echo only tested on 3.12.

set "PY_ARCH=%PROCESSOR_ARCHITECTURE%"
if defined PROCESSOR_ARCHITEW6432 set "PY_ARCH=%PROCESSOR_ARCHITEW6432%"
set "PY_FILE="
if /i "%PY_ARCH%"=="AMD64" set "PY_FILE=python-%PY_VERSION%-amd64.exe"
if /i "%PY_ARCH%"=="ARM64" set "PY_FILE=python-%PY_VERSION%-arm64.exe"
if not defined PY_FILE goto :unsupported_arch

set "CURL=%SystemRoot%\System32\curl.exe"
set "POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%CURL%" goto :no_tools
if not exist "%POWERSHELL%" goto :no_tools

set "PY_URL=https://www.python.org/ftp/python/%PY_VERSION%/%PY_FILE%"
set "PY_INSTALLER=%TEMP%\%PY_FILE%"
set "PY_LOG=%TEMP%\python-%PY_VERSION%-install.log"

echo.
echo build.bat can download Python %PY_VERSION% (about 27 MB) from python.org and
echo install it for all users. Windows will ask for administrator permission
echo once. Other Python versions and your default "python" are left as they are.
echo.
choice /c YN /m "Download and install Python %PY_VERSION% now"
if not "%errorlevel%"=="1" goto :declined

echo.
echo Downloading %PY_URL% ...
if exist "%PY_INSTALLER%" del /f /q "%PY_INSTALLER%"
"%CURL%" -fL --retry 2 --progress-bar -o "%PY_INSTALLER%" "%PY_URL%" || goto :download_failed

rem Only run the installer if Windows trusts its signature and it was signed
rem by the Python Software Foundation.
echo Checking the installer's digital signature ...
"%POWERSHELL%" -NoProfile -NonInteractive -Command "$s = Get-AuthenticodeSignature -LiteralPath $env:PY_INSTALLER; if ($s.Status -eq 'Valid' -and $s.SignerCertificate.Subject -like '*O=Python Software Foundation,*') { exit 0 }; exit 1" || goto :bad_signature

rem Leave an existing py launcher alone: it may be newer than 3.12's and the
rem installer must not try to downgrade it.
if defined HAVE_LAUNCHER (
    set "PY_LAUNCHER_OPTS=Include_launcher=0"
) else (
    set "PY_LAUNCHER_OPTS=Include_launcher=1 InstallLauncherAllUsers=1"
)
echo Installing Python %PY_VERSION% for all users. Approve the administrator prompt.
echo This takes a minute or two ...
start "" /wait "%PY_INSTALLER%" /quiet /log "%PY_LOG%" InstallAllUsers=1 PrependPath=0 Include_test=0 %PY_LAUNCHER_OPTS%
set "PY_RC=%errorlevel%"
del /f /q "%PY_INSTALLER%" >nul 2>&1
if "%PY_RC%"=="1602" goto :install_cancelled
if "%PY_RC%"=="1223" goto :install_cancelled
if not "%PY_RC%"=="0" if not "%PY_RC%"=="3010" goto :install_failed

py -3.12 -c "" >nul 2>&1 || goto :install_not_found
echo Python %PY_VERSION% is installed.
if "%PY_RC%"=="3010" echo Windows wants a restart to finish the install, but the build can continue.
echo.
goto :create_venv

:unsupported_arch
echo.
echo Automatic install is only available for 64-bit Windows (x64 or ARM64).
echo This PC reports "%PY_ARCH%".
goto :manual_steps

:no_tools
echo.
echo Automatic install needs curl.exe and PowerShell, which come with
echo Windows 10 (version 1803 or later) and Windows 11. They were not found.
goto :manual_steps

:declined
echo.
echo Python 3.12 was not installed.
goto :manual_steps

:download_failed
del /f /q "%PY_INSTALLER%" >nul 2>&1
echo.
echo The download failed. Check the internet connection and try again.
goto :manual_steps

:bad_signature
del /f /q "%PY_INSTALLER%" >nul 2>&1
echo.
echo The downloaded file is not signed by the Python Software Foundation,
echo so it was deleted without being run.
goto :manual_steps

:install_cancelled
echo.
echo The administrator prompt was cancelled, so Python was not installed.
echo Installing for all users needs administrator rights: run build.bat again
echo and choose Yes at the prompt, or ask someone with an administrator
echo account to enter their password there.
goto :fail

:install_failed
echo.
echo The Python installer failed with exit code %PY_RC%.
echo Its log is at: %PY_LOG%
goto :manual_steps

:install_not_found
echo.
echo The installer finished, but "py -3.12" still does not work.
echo Close this window and run build.bat again. If that does not help, restart
echo the PC first.
goto :fail

:manual_steps
echo.
echo To install it yourself, download Python %PY_VERSION% from
echo https://www.python.org/downloads/ and keep "Install the py launcher" ticked.
echo The Microsoft Store Python does not include it. Then run build.bat again.
goto :fail

:fail
echo.
echo Build failed.
set "EXIT_CODE=1"

:end
if defined PAUSE_AT_END (
    echo.
    pause
)
exit /b %EXIT_CODE%
