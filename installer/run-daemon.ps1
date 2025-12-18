$ErrorActionPreference = "SilentlyContinue"
$root = Split-Path $MyInvocation.MyCommand.Path
$exe  = Join-Path $root "hsip-cli.exe"
$log  = Join-Path $root "daemon.log"
$err  = Join-Path $root "daemon.err"

# Rotate simple log
if (Test-Path $log) { Move-Item $log "$log.bak" -Force -ErrorAction SilentlyContinue }

# Configure process to run hidden (no window)
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName  = $exe
$psi.Arguments = 'daemon --status-addr 127.0.0.1:8787'
$psi.WorkingDirectory = $root
$psi.UseShellExecute  = $false
$psi.CreateNoWindow   = $true              # CRITICAL: Don't create a window
$psi.WindowStyle      = 'Hidden'           # Hide the window
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$proc = [System.Diagnostics.Process]::Start($psi)
"[$(Get-Date -Format o)] spawned PID=$($proc.Id)" | Out-File -FilePath $log -Append -Encoding utf8

Start-Job -ScriptBlock {
  param($p,$outp,$errp)
  $p.BeginOutputReadLine()
  $p.BeginErrorReadLine()
} -ArgumentList $proc,$log,$err | Out-Null
