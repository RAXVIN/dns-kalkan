@echo off
REM DNS Kalkan kurtarma (c) 2026 Wesar
REM Uygulama acilmiyorsa ve bir sorun oldugunu dusunuyorsan bunu cift tikla.
REM Windows proxy ayarlarini DNS Kalkan'dan onceki haline dondurur.
set "PY="
for /d %%D in ("%LOCALAPPDATA%\Python\pythoncore-3*") do if exist "%%D\python.exe" set "PY=%%D\python.exe"
if not defined PY for /f "delims=" %%P in ('where python 2^>nul ^| findstr /v /i "WindowsApps"') do if not defined PY set "PY=%%P"
if not defined PY set "PY=python"
taskkill /f /im pythonw.exe /fi "WINDOWTITLE eq DNS Kalkan*" >nul 2>&1
"%PY%" "%~dp0dns_kalkan.py" --restore
powershell -NoProfile -Command "$k='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; if ((Get-ItemProperty $k).AutoConfigURL -like '*127.0.0.1:8881*') { Remove-ItemProperty $k AutoConfigURL; 'Kalan DNS Kalkan proxy ayari kaldirildi.' }; Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name DNSKalkanKurtarma -ErrorAction SilentlyContinue"
echo.
echo Bitti. Simdiki proxy ayari:
powershell -NoProfile -Command "Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Format-List AutoConfigURL,ProxyEnable,ProxyServer"
pause
