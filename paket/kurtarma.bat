@echo off
REM DNS Kalkan kurtarma (c) 2026 RAXVIN
REM Bir sorun olursa bunu cift tikla: Windows proxy ayarlarini DNS Kalkan'dan onceki haline dondurur.
taskkill /f /im "DNS Kalkan.exe" >nul 2>&1
"%~dp0DNS Kalkan.exe" --restore
powershell -NoProfile -Command "$k='HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'; if ((Get-ItemProperty $k).AutoConfigURL -like '*127.0.0.1:8881*') { Remove-ItemProperty $k AutoConfigURL }; Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name DNSKalkanKurtarma -ErrorAction SilentlyContinue"
echo.
echo Tamam. Windows proxy ayarlari eski haline getirildi.
echo Simdiki ayar:
powershell -NoProfile -Command "Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Format-List AutoConfigURL,ProxyEnable,ProxyServer"
pause
