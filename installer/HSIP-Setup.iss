; ============================================================
; HSIP Windows Installer (silent tray startup, clean version)
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

[Tasks]
Name: "startup"; Description: "Start HSIP automatically when I log in"; Flags: unchecked

[Files]
Source: "..\target\release\hsip-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "README-USER.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "start-hsip-tray.vbs"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Start HSIP protection (hidden tray)
Name: "{group}\Start HSIP (Background)"; \
    Filename: "wscript.exe"; \
    Parameters: """{app}\start-hsip-tray.vbs"""; \
    WorkingDir: "{app}"

; Tech version (opens terminal)
Name: "{group}\HSIP CLI (Terminal)"; \
    Filename: "{cmd}"; \
    Parameters: "/k ""cd /d {app} && hsip-cli.exe"""; \
    WorkingDir: "{app}"

; Optional Auto-Start
Name: "{userstartup}\HSIP Background"; \
    Filename: "wscript.exe"; \
    Parameters: """{app}\start-hsip-tray.vbs"""; \
    WorkingDir: "{app}"; \
    Tasks: startup

[Run]
; Start HSIP silently after install
Filename: "wscript.exe"; \
    Parameters: """{app}\start-hsip-tray.vbs"""; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
