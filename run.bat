@echo off
rem SEKT0R AUTO JAILBREAK TOOLKIT launcher
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python 3.9+ is required. Install it from https://www.python.org/downloads/
  echo During install, check "Add python.exe to PATH".
  pause
  exit /b 1
)
where PySide6 >nul 2>nul
if errorlevel 1 (
  echo The PySide6 GUI requires the PySide6 package (pip install ps5-jb-helper).
  echo Falling back to the standard-library tkinter UI:
  python ps5_jb_helper_main.py
  pause
  exit /b %ERRORLEVEL%
)
python ps5_jb_helper/gui/__main__.py
if errorlevel 1 pause