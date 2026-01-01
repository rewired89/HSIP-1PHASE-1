@echo off
setlocal EnableDelayedExpansion

:: HSIP Demo Launcher
:: Requires HSIP_LOCAL_JWT_KEY_HEX to be set in environment or generates one

set HSIP_IDENTITY_ADDR=127.0.0.1:9200

:: Check if JWT key is already configured
if not defined HSIP_LOCAL_JWT_KEY_HEX (
    echo [HSIP] No JWT key found. Generating a secure random key...

    :: Generate 32 random bytes as hex using PowerShell
    for /f "delims=" %%i in ('powershell -Command "[System.BitConverter]::ToString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).Replace('-','')"') do set HSIP_LOCAL_JWT_KEY_HEX=%%i

    if not defined HSIP_LOCAL_JWT_KEY_HEX (
        echo [ERROR] Failed to generate JWT key. Please set HSIP_LOCAL_JWT_KEY_HEX manually.
        echo Example: set HSIP_LOCAL_JWT_KEY_HEX=^<64 hex characters^>
        pause
        exit /b 1
    )

    echo [HSIP] Generated temporary JWT key for this session.
    echo [HSIP] For persistent config, add HSIP_LOCAL_JWT_KEY_HEX to your environment.
)

:: Launch identity server
start "" "%ProgramFiles%\Nyx Systems\HSIP\hsip-cli.exe" identity-serve
timeout /t 1 >nul

:: Open demo page
start "" http://127.0.0.1:9200/demo
