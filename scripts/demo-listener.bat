@echo off
setlocal
REM Use local config if present
set HSIP_CONFIG=%~dp0..\examples\hsip.toml
echo [hsip] using config: %HSIP_CONFIG%
start "" cmd /c "%~dp0..\..\target\release\hsip-cli.exe listen --addr 127.0.0.1:9000"
start "" cmd /c "%~dp0..\..\target\release\hsip-cli.exe consent-listen --addr 127.0.0.1:40406"
