@echo off
cd /d "%~dp0"
"%CD%\busybox.exe" bash "%CD%\%~n0.sh"
pause
