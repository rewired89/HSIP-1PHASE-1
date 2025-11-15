$root = Split-Path $MyInvocation.MyCommand.Path
Start-Process -FilePath (Join-Path $root "hsip-tray.exe") `
  -WorkingDirectory $root `
  -WindowStyle Hidden
