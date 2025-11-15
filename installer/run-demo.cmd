@echo off
set HSIP_IDENTITY_ADDR=127.0.0.1:9200
set HSIP_LOCAL_JWT_KEY_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
start "" "%ProgramFiles%\Nyx Systems\HSIP\hsip-cli.exe" identity-serve
timeout /t 1 >nul
start "" http://127.0.0.1:9200/demo
