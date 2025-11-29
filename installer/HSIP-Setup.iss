; ============================================================
; HSIP Windows Installer - MVP (daemon + gateway + tray)
; ============================================================

[Setup]
AppId={{8C8B8C3E-1D9E-4B16-8C34-44B1D3E7A9C1}
AppName=HSIP
AppVersion=0.2.0-mvp
AppPublisher=Nyx Systems LLC
DefaultDirName={pf}\HSIP
DefaultGroupName=HSIP
DisableProgramGroupPage=yes
OutputDir=.
OutputBaseFilename=HSIP-Setup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

; ============================
; Files: CLI + Gateway + Tray
; ============================

[Files]
Source: "..\target\release\hsip-cli.exe";      DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\hsip-gateway.exe";  DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\hsip-tray.exe";     DestDir: "{app}"; Flags: ignoreversion
Source: "README-USER.txt";                     DestDir: "{app}"; Flags: ignoreversion

; ============================
; Shortcuts (Start Menu)
; ============================

[Icons]
Name: "{group}\HSIP Shield"; \
      Filename: "{app}\hsip-tray.exe"; \
      WorkingDir: "{app}"

Name: "{group}\HSIP CLI (Terminal)"; \
      Filename: "{cmd}"; \
      Parameters: "/k ""cd /d {app} && hsip-cli.exe"""; \
      WorkingDir: "{app}"

Name: "{group}\Uninstall HSIP"; \
      Filename: "{uninstallexe}"

; ============================
; Auto-start al login
; ============================

[Registry]
; Daemon
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
      ValueType: string; ValueName: "HSIP Daemon"; \
      ValueData: """{app}\hsip-cli.exe"" daemon"; \
      Flags: uninsdeletevalue

; Gateway
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
      ValueType: string; ValueName: "HSIP Gateway"; \
      ValueData: """{app}\hsip-gateway.exe"" --listen 127.0.0.1:8080"; \
      Flags: uninsdeletevalue

; Tray
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
      ValueType: string; ValueName: "HSIP Tray"; \
      ValueData: """{app}\hsip-tray.exe"""; \
      Flags: uninsdeletevalue

; ============================
; Post-install (background)
; ============================

[Run]
Filename: "{app}\hsip-cli.exe"; \
      Parameters: "daemon"; \
      WorkingDir: "{app}"; \
      Flags: nowait postinstall skipifsilent runhidden

Filename: "{app}\hsip-gateway.exe"; \
      Parameters: "--listen 127.0.0.1:8080"; \
      WorkingDir: "{app}"; \
      Flags: nowait postinstall skipifsilent runhidden

Filename: "{app}\hsip-tray.exe"; \
      WorkingDir: "{app}"; \
      Flags: nowait postinstall skipifsilent runhidden

; ============================
; Uninstall clean-up
; ============================

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
