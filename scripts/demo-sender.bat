@echo off
setlocal
set HSIP_CONFIG=%~dp0..\examples\hsip.toml
echo [hsip] using config: %HSIP_CONFIG%
if not exist sample.txt (echo hello world>sample.txt)
"%~dp0..\..\target\release\hsip-cli.exe" send --to 127.0.0.1:9000
"%~dp0..\..\target\release\hsip-cli.exe" consent-request --file sample.txt --purpose demo --expires-ms 60000 --out req.json
"%~dp0..\..\target\release\hsip-cli.exe" consent-send-request --to 127.0.0.1:40406 --file req.json --wait-reply --wait-timeout-ms 3000
