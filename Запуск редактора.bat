@echo off
cd /d "%~dp0"
where pythonw >nul 2>&1
if errorlevel 1 (
  echo Python not found. Install Python 3 from python.org and tick "Add python.exe to PATH".
  pause
  exit /b 1
)
rem runs without a console window; quits by itself a minute after FIFA 19 closes
start "" pythonw le.py
