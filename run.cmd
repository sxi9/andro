@echo off
rem Android Sentinel launcher (Windows). Finds the venv the installer made,
rem installs any requirements a `git pull` added, then starts the dashboard.
rem   run.cmd            phone on USB debugging
rem   run.cmd --demo     simulated device
rem   run.cmd -s IP:PORT wireless debugging
setlocal
set "DIR=%~dp0"
set "PY=%DIR%.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=%LOCALAPPDATA%\android-sentinel\.venv\Scripts\python.exe"
if not exist "%PY%" (
  echo No virtualenv found. Run the installer first:
  echo   powershell -ExecutionPolicy Bypass -File "%DIR%install.ps1"
  exit /b 1
)
rem requirements.txt newer than the last install stamp -> install (quiet)
set "STAMP=%PY%.reqs-stamp"
set "NEED=1"
if exist "%STAMP%" (
  for /f %%A in ('powershell -NoProfile -Command "if ((Get-Item -LiteralPath '%DIR%requirements.txt').LastWriteTimeUtc -le (Get-Item -LiteralPath '%STAMP%').LastWriteTimeUtc) { 0 } else { 1 }"') do set "NEED=%%A"
)
if "%NEED%"=="1" (
  echo ==^> installing/updating dependencies
  "%PY%" -m pip install --quiet -r "%DIR%requirements.txt" && type nul > "%STAMP%"
)
cd /d "%DIR%"
"%PY%" -m sentinel %*
