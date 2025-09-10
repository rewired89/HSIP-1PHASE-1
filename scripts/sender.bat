@echo off
REM sender: hello send + consent roundtrip
target\debug\hsip-cli.exe send --to 127.0.0.1:9000
if not exist sample.txt (echo hello world>sample.txt)
target\debug\hsip-cli.exe consent-request --file sample.txt --purpose demo --expires-ms 60000 --out req.json
target\debug\hsip-cli.exe consent-send-request --to 127.0.0.1:40406 --file req.json --wait-reply --wait-timeout-ms 3000
