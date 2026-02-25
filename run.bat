@echo off
SETLOCAL EnableDelayedExpansion

echo ✦ God's Hands v3.0 Launcher ✦
echo Searching for compatible Python environment...

:: Check for Python 3.13 (Preferred)
C:\Users\augus\AppData\Local\Programs\Python\Python313\python.exe --version >nul 2>&1
if !errorlevel! == 0 (
    echo [OK] Found Python 3.13. Launching...
    C:\Users\augus\AppData\Local\Programs\Python\Python313\python.exe app.py
    pause
    exit /b
)

:: Check for Python 3.10 (Fallback)
C:\Users\augus\AppData\Local\Programs\Python\Python310\python.exe --version >nul 2>&1
if !errorlevel! == 0 (
    echo [OK] Found Python 3.10. Launching...
    C:\Users\augus\AppData\Local\Programs\Python\Python310\python.exe app.py
    pause
    exit /b
)

echo [ERROR] No compatible Python (3.13 or 3.10) found.
echo Python 3.14 is currently incompatible with pywebview dependencies.
pause
