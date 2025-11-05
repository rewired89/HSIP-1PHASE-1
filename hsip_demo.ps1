<# HSIP End-to-End Demo (Windows / PowerShell)
 - Opens separate terminals for: HELLO listen, Session listen, Ping listen, Consent listen
 - Then runs sender-side actions in this window.
 - Requirements: repo built, `cargo` on PATH.
#>

function New-Term {
    param([string]$Title, [string]$Cmd)
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Write-Host '>>> $Title' -ForegroundColor Cyan; $Cmd"
}

# 1) One-time identity (safe to re-run)
Write-Host "`n[1/8] Identity init" -ForegroundColor Cyan
cargo run -p hsip-cli -- init | Out-Host
cargo run -p hsip-cli -- whoami | Out-Host

# 2) Start listeners in separate terminals
Write-Host "`n[2/8] Spawning listeners (new windows)" -ForegroundColor Cyan

# HELLO listener
New-Term -Title "HELLO Listener :40404" -Cmd 'cargo run -p hsip-cli -- hello-listen --addr 0.0.0.0:40404'

# Session listener
New-Term -Title "SESSION Listener :50505" -Cmd 'cargo run -p hsip-cli -- session-listen --addr 127.0.0.1:50505'

# Ping listener
New-Term -Title "PING Listener :51515" -Cmd 'cargo run -p hsip-cli -- ping-listen --addr 127.0.0.1:51515'

# Consent listener (explicit policy allow 30s)
New-Term -Title "CONSENT Listener :9100 (allow/30s)" -Cmd 'cargo run -p hsip-cli -- consent-listen --addr 127.0.0.1:9100 --decision allow --ttl-ms 30000'

Start-Sleep -Seconds 2

# 3) HELLO send
Write-Host "`n[3/8] HELLO send → 40404" -ForegroundColor Cyan
cargo run -p hsip-cli -- hello-send --to 127.0.0.1:40404 | Out-Host

# 4) Encrypted session demo (sealed DATA)
Write-Host "`n[4/8] SESSION send 5 packets → 50505" -ForegroundColor Cyan
cargo run -p hsip-cli -- session-send --to 127.0.0.1:50505 --packets 5 | Out-Host

# 5) Privacy Ping (sealed RTT echo)
Write-Host "`n[5/8] PING x3 → 51515" -ForegroundColor Cyan
cargo run -p hsip-cli -- ping --to 127.0.0.1:51515 --count 3 | Out-Host

# 6) Consent (build request + sealed CONTROL wait-reply)
Write-Host "`n[6/8] CONSENT request + wait-reply → 9100" -ForegroundColor Cyan
'hello' | Out-File -Encoding ascii -FilePath demo.txt
cargo run -p hsip-cli -- consent-request --file demo.txt --purpose demo --expires-ms 60000 --out req.json | Out-Host
cargo run -p hsip-cli -- consent-send-request --to 127.0.0.1:9100 --file req.json --wait-reply | Out-Host

# 7) Reputation enforcement toggle (new window; stop previous consent listener first if running)
Write-Host "`n[7/8] (Optional) Reputation enforcement demo (opens new window)" -ForegroundColor Yellow
New-Term -Title "CONSENT Listener :9100 (rep enforce)" -Cmd '$env:HSIP_ENFORCE_REP="1"; $env:HSIP_REP_THRESHOLD="-6"; cargo run -p hsip-cli -- consent-listen --addr 127.0.0.1:9100'

Start-Sleep -Seconds 2
Write-Host "Re-sending consent request to reputation-enforced listener" -ForegroundColor Yellow
cargo run -p hsip-cli -- consent-send-request --to 127.0.0.1:9100 --file req.json --wait-reply | Out-Host

# 8) Session blob save/load (operator-visible metadata)
Write-Host "`n[8/8] Session blob save/load" -ForegroundColor Cyan
$metaPath = "$env:USERPROFILE\.hsip\state\last_session.json"
if (Test-Path $metaPath) {
    cargo run -p hsip-cli -- session-save --name demo --file $metaPath | Out-Host
    cargo run -p hsip-cli -- session-load --name demo --out recovered.json | Out-Host
    Get-Content .\recovered.json | Out-Host
} else {
    Write-Host "No last_session.json yet (run session-send/listen first)" -ForegroundColor DarkYellow
}

Write-Host "`nDemo complete. Close listener windows with Ctrl+C when done." -ForegroundColor Green
