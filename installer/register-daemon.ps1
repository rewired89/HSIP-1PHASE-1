$root = Split-Path $MyInvocation.MyCommand.Path
$action    = New-ScheduledTaskAction -Execute "powershell.exe" `
              -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$root\run-daemon.ps1`""
$trigger   = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -Hidden:$true
Unregister-ScheduledTask -TaskName "HSIP Daemon" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask  -TaskName "HSIP Daemon" -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask     -TaskName "HSIP Daemon"
