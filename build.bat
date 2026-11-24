@echo off
rem Builds dist\EnvStego-portable.zip: both token firmwares + the frozen app.
rem Needs Python 3.12 (py -3.12). The first run downloads PlatformIO's ESP32
rem toolchains (about 1 GB). Only the zip is left in dist\: unzip it to test.
setlocal
cd /d "%~dp0"

if not exist .venv\Scripts\python.exe (
    echo Creating the build environment in .venv ...
    py -3.12 -m venv .venv || goto :fail
)
.venv\Scripts\python -m pip install --quiet --upgrade pip || goto :fail
.venv\Scripts\python -m pip install --quiet -r Python\requirements.txt -r packaging\requirements-build.txt || goto :fail
.venv\Scripts\python packaging\build.py || goto :fail

echo.
echo Done: dist\EnvStego-portable.zip
exit /b 0

:fail
echo.
echo Build failed.
exit /b 1
