# fix-gradle.ps1
# Purpose: ensure gradle-wrapper.jar exists (wrapper script fails without it)

$wrapperDir = Join-Path $PSScriptRoot "gradle\wrapper"
$jarPath    = Join-Path $wrapperDir "gradle-wrapper.jar"

New-Item -ItemType Directory -Force -Path $wrapperDir | Out-Null

if (Test-Path $jarPath) {
  Write-Host "OK: gradle-wrapper.jar already exists at $jarPath"
  exit 0
}

Write-Host "Downloading gradle-wrapper.jar..."
Start-BitsTransfer `
  -Source "https://raw.githubusercontent.com/gradle/gradle/v8.9/gradle/wrapper/gradle-wrapper.jar" `
  -Destination $jarPath

Write-Host "Done: $jarPath"
Write-Host "Next: run .\gradlew.bat :app:assembleDebug"
