@echo off
REM HSIP bootstrap: start daemon, gateway and tray in background

cd /d "%~dp0"

REM Daemon: HSIP shield + /status API
start "" "%~dp0hsip-cli.exe" daemon

REM HTTP/HTTPS gateway on 127.0.0.1:8080
start "" "%~dp0hsip-gateway.exe"

REM Tray icon (green/red square)
start "" "%~dp0hsip-tray.exe"

exit /b 0
