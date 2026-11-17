@echo off
REM DNS Kalkan (c) 2026 Wesar
REM Python'u Microsoft Store kisayolu yerine dogrudan kendi klasorunden baslatir.
set "PYW="
for /d %%D in ("%LOCALAPPDATA%\Python\pythoncore-3*") do if exist "%%D\pythonw.exe" set "PYW=%%D\pythonw.exe"
if not defined PYW for /f "delims=" %%P in ('where pythonw 2^>nul ^| findstr /v /i "WindowsApps"') do if not defined PYW set "PYW=%%P"
if not defined PYW set "PYW=pythonw"
start "" "%PYW%" "%~dp0dns_kalkan.py"
