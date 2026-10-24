@echo off
rem 3CX Desk-Phone Checker - launcher for Generate-3cxReport.ps1
setlocal
set "PSEXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "L_ARGS= %* "
set "L_PAUSE=1"
set "L_ASK=1"
echo.%L_ARGS%| find /i " /nopause " >nul && set "L_PAUSE="
echo.%L_ARGS%| find /i " /noelevate " >nul && set "L_ASK="
echo.%L_ARGS%| find /i " /elevated " >nul && set "L_ASK="
set "L_ARGS=%L_ARGS: /noelevate=%"
set "L_ARGS=%L_ARGS: /elevated=%"
set "L_ARGS=%L_ARGS: /nopause=%"
:run
start "" "%PSEXE%" -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0Generate-3cxReport.ps1"%L_ARGS%
endlocal
