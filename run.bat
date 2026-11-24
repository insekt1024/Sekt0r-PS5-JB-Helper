@echo off
rem PS5 Jailbreak Helper launcher
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python 3.9+ is required. Install it from https://www.python.org/downloads/
  echo During install, check "Add python.exe to PATH".
  pause
  exit /b 1
)
python ps5_jb_helper.py
if errorlevel 1 pause