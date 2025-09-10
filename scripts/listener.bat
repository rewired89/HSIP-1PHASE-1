@echo off
REM listener: hello + consent on fixed ports
start "" cmd /c "target\debug\hsip-cli.exe listen --addr 127.0.0.1:9000"
start "" cmd /c "target\debug\hsip-cli.exe consent-listen --addr 127.0.0.1:40406"
