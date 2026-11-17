@echo off
REM Discord'u DNS Kalkan tuneliyle baslatir (c) Wesar
REM DNS Kalkan ACIK olmali. Uygulamadaki "Discord'u tunelle baslat" dugmesi de ayni isi yapar.
taskkill /f /im Discord.exe >nul 2>&1
timeout /t 2 /nobreak >nul
set HTTPS_PROXY=http://127.0.0.1:8881
set HTTP_PROXY=http://127.0.0.1:8881
set ALL_PROXY=http://127.0.0.1:8881
set NO_PROXY=localhost,127.0.0.1
start "" "%LOCALAPPDATA%\Discord\Update.exe" --processStart Discord.exe --process-start-args "--proxy-server=http://127.0.0.1:8881"
