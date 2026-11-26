@echo off
rem Builds dist\EnvStego-portable.zip: both token firmwares + the frozen app.
rem Needs Python 3.12 (py -3.12). The first run downloads PlatformIO's ESP32
rem toolchains (about 1 GB). Only the zip is left in dist\: unzip it to test.
setlocal
cd /d "%~dp0"

rem Reuse .venv only if it still runs Python 3.12. A .venv copied from another
rem PC points at that PC's Python and cannot start, so it is rebuilt.
if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe -c "import sys; sys.exit(sys.version_info[:2] != (3, 12))" >nul 2>&1 && goto :install
    echo The existing .venv is broken or not Python 3.12 - rebuilding it ...
    rmdir /s /q .venv || goto :fail
)

where py >nul 2>&1 || goto :no_launcher
py -3.12 -c "" >nul 2>&1 || goto :no_python
echo Creating the build environment in .venv ...
py -3.12 -m venv .venv || goto :fail

:install
.venv\Scripts\python -m pip install --quiet --upgrade pip || goto :fail
.venv\Scripts\python -m pip install --quiet -r Python\requirements.txt -r packaging\requirements-build.txt || goto :fail
.venv\Scripts\python packaging\build.py || goto :fail

echo.
echo Done: dist\EnvStego-portable.zip
exit /b 0

:no_launcher
echo.
echo The Python launcher "py" was not found.
echo Install Python 3.12 from https://www.python.org/downloads/ and keep
echo "Install the py launcher" ticked. The Microsoft Store Python does not include it.
goto :fail

:no_python
echo.
echo Python 3.12 was not found. These versions are installed:
py --list
echo.
echo Install Python 3.12 from https://www.python.org/downloads/ - newer versions
echo such as 3.13 are not used, because some dependencies are only tested on 3.12.
goto :fail

:fail
echo.
echo Build failed.
exit /b 1
