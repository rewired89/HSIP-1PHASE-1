$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Resolve-Path (Join-Path $root "..")
$bin  = Join-Path $repo "target\release\hsip-cli.exe"
if (!(Test-Path $bin)) { throw "Build first: cargo build -p hsip-cli --release" }

$stage = Join-Path $repo "dist\hsip-windows-x86_64"
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
New-Item $stage -ItemType Directory | Out-Null
New-Item (Join-Path $stage "scripts") -ItemType Directory | Out-Null
New-Item (Join-Path $stage "examples") -ItemType Directory | Out-Null

Copy-Item $bin $stage
Copy-Item (Join-Path $repo "scripts\demo-*.bat") (Join-Path $stage "scripts")
Copy-Item (Join-Path $repo "examples\hsip.toml") (Join-Path $stage "examples")

# tiny README for the zip
@"
Quickstart
----------
1) Run scripts\demo-listener.bat
2) Run scripts\demo-sender.bat
"@ | Set-Content (Join-Path $stage "README.txt")

$zip = Join-Path $repo "dist\hsip-windows-x86_64.zip"
If (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip
Write-Host "Created $zip"
