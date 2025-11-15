#Requires -Version 5.1
#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

# ---- Logging (creates installer\update-hsip.log) ----
$logFile = Join-Path $PSScriptRoot "update-hsip.log"
Start-Transcript -Path $logFile -Append | Out-Null

Write-Host "== HSIP Update Script =="

# ---- Paths ----
$build = "C:\Users\melas\HSIP-fresh\target\release"
$root  = "C:\Program Files\Nyx Systems\HSIP"
Write-Host "Build dir: $build"
Write-Host "Dest  dir: $root"

# ---- Sanity check: show available build EXEs ----
Write-Host "Scanning build dir for hsip*.exe..."
Get-ChildItem -Path $build -Filter "hsip*.exe" -ErrorAction SilentlyContinue | ForEach-Object {
  Write-Host "  found: $($_.Name)"
}

# ---- Stop tasks/processes ----
$taskNames = @("HSIP Daemon","HSIP Tray")
foreach ($t in $taskNames) {
  try {
    Write-Host "Stopping scheduled task: $t"
    Stop-ScheduledTask -TaskName $t -ErrorAction Stop
  } catch {
    Write-Host "  (skip) $t not found or already stopped"
  }
}

Write-Host "Stopping processes: hsip-tray, hsip-cli (if running)"
Get-Process hsip-tray, hsip-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Start-Sleep -Milliseconds 400

# ---- Ensure destination exists ----
Write-Host "Ensuring destination folder exists: $root"
New-Item -ItemType Directory -Path $root -Force | Out-Null

# ---- Copy binaries ----
$files = @("hsip-cli.exe","hsip-tray.exe")
foreach ($f in $files) {
  $src = Join-Path $build $f
  $dst = Join-Path $root  $f
  if (Test-Path $src) {
    Write-Host "Copying $f -> $dst"
    Copy-Item $src $dst -Force
  } else {
    Write-Host "WARN: Missing $src"
  }
}

Write-Host "Done. Log: $logFile"
Stop-Transcript | Out-Null
Read-Host "Press Enter to close this window"
