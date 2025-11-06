#define MyAppName "HSIP CLI"
#define MyAppVersion "0.2.0-mvp"
#define MyAppPublisher "Nyx Systems LLC"

[Setup]
AppId={{F3B1D0D5-5C1C-47E8-9A9A-12A7F0D9B3C0}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={pf}\HSIP
DefaultGroupName=HSIP
DisableDirPage=auto
DisableProgramGroupPage=auto
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
SetupIconFile=hsip.ico
OutputBaseFilename=HSIP-CLI-Setup
WizardStyle=modern

[Files]
; this path is RELATIVE to this .iss file location (installer\...)
; go up one level to repo root, then to target\release
Source: "..\target\release\hsip-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "HSIP Quickstart.cmd"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\HSIP Quickstart"; Filename: "{app}\HSIP Quickstart.cmd"
Name: "{group}\HSIP CLI (Command Only)"; Filename: "{cmd}"; Parameters: "/k ""cd /d {app} && hsip-cli.exe --help"""
Name: "{commondesktop}\HSIP Quickstart"; Filename: "{app}\HSIP Quickstart.cmd"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
Filename: "{app}\HSIP Quickstart.cmd"; Description: "Open HSIP Quickstart"; Flags: nowait postinstall skipifsilent
