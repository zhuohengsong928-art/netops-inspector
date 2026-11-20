@echo off
chcp 65001 >nul
cd /d %~dp0
where python >nul 2>nul
if %errorlevel% neq 0 (
  echo [ERROR] Python not found. Please install Python 3 and tick "Add Python to PATH".
  pause
  exit /b 1
)
python netops.py targets.txt
echo.
pause
