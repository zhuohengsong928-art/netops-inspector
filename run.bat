@echo off
chcp 65001 >nul
cd /d %~dp0
where python >nul 2>nul
if %errorlevel% equ 0 goto run_python
where py >nul 2>nul
if %errorlevel% equ 0 goto run_py
echo [ERROR] Python not found. Please install Python 3 and tick "Add Python to PATH".
pause
exit /b 1
:run_python
python netops.py targets.txt
goto done
:run_py
py -3 netops.py targets.txt
:done
echo.
pause
