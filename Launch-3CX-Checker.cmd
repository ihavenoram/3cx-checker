@echo off
REM Launches the 3CX Desk-Phone Connectivity Checker with WinForms-safe STA.
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp03CX-Checker.ps1"
if errorlevel 1 (
    echo.
    echo The checker exited with an error. Review the message above.
    pause
)
