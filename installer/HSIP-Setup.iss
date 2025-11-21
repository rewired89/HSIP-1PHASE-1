; ============================================================
; HSIP Windows Installer - MVP (daemon + tray shield)
; ============================================================

[Setup]
AppId={{8C8B8C3E-1D9E-4E7A-9C0C-4D6C32E2F4AA}
AppName=HSIP
AppVersion=0.2.0-mvp
AppPublisher=Nyx Systems LLC
DefaultDirName={autopf}\Nyx Systems\HSIP
DefaultGroupName=HSIP
DisableProgramGroupPage=yes
OutputDir=.
OutputBaseFilename=HSIP-Setup
Compression=lzma
SolidCompression=yes
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Core daemon + tray UI (built with `cargo build --release`)
Source: "..\target\release\hsip-cli.exe";  DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\hsip-tray.exe"; DestDir: "{app}"; Flags: ignoreversion
; User-facing readme (how HSIP works, shield meaning, etc.)
Source: "README-USER.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Start menu shortcut: HSIP Shield (tray)
Name: "{group}\HSIP Shield"; \
    Filename: "{app}\hsip-tray.exe"; \
    WorkingDir: "{app}"

; Start menu shortcut: HSIP CLI in a terminal (for power users)
Name: "{group}\HSIP CLI (Terminal)"; \
    Filename: "{cmd}"; \
    Parameters: "/k ""cd /d {app} && hsip-cli.exe"""; \
    WorkingDir: "{app}"

[Registry]
; Auto-start HSIP daemon on user login
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: "HSIP Daemon"; \
    ValueData: """{app}\hsip-cli.exe"" daemon"; \
    Flags: uninsdeletevalue

; Auto-start HSIP tray (shield icon) on user login
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: "HSIP Tray"; \
    ValueData: """{app}\hsip-tray.exe"""; \
    Flags: uninsdeletevalue

[Run]
; After install, immediately start daemon + tray so user sees shield
Filename: "{app}\hsip-cli.exe"; \
    Parameters: "daemon"; \
    WorkingDir: "{app}"; \
    Flags: nowait postinstall skipifsilent; \
    Description: "Start HSIP daemon"

Filename: "{app}\hsip-tray.exe"; \
    WorkingDir: "{app}"; \
    Flags: nowait postinstall skipifsilent; \
    Description: "Start HSIP tray shield"

[UninstallDelete]
; Remove installation directory on uninstall
Type: filesandordirs; Name: "{app}"
