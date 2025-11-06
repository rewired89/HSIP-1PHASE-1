@echo off
cd /d "%~dp0"
echo.
echo HSIP Quickstart
echo ---------------
echo 1) Show help:
echo    hsip-cli.exe --help
echo.
echo 2) Initialize identity (if needed):
echo    hsip-cli.exe init
echo.
echo 3) Try local demos:
echo    hsip-cli.exe hello-listen --addr 0.0.0.0:40404
echo    hsip-cli.exe hello-send --to 127.0.0.1:40404
echo.
echo 4) Consent demo (two terminals):
echo    hsip-cli.exe consent-listen --addr 127.0.0.1:9100
echo    hsip-cli.exe consent-request --file demo.txt --purpose demo --expires-ms 60000 --out req.json
echo    hsip-cli.exe consent-send-request --to 127.0.0.1:9100 --file req.json --wait-reply
echo.
echo 5) Session demo (two terminals):
echo    hsip-cli.exe session-listen --addr 127.0.0.1:50505
echo    hsip-cli.exe session-send --to 127.0.0.1:50505 --packets 5
echo.
cmd /k
