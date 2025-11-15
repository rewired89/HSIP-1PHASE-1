; ============================================================
; HSIP Windows Installer - Minimal clean build (no tray, no VBS)
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
Source: "..\target\release\hsip-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "README-USER.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Tech users: open HSIP CLI in a terminal
Name: "{group}\HSIP CLI (Terminal)"; \
    Filename: "{cmd}"; \
    Parameters: "/k ""cd /d {app} && hsip-cli.exe"""; \
    WorkingDir: "{app}"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
