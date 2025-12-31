; ============================================================
; HSIP Windows Installer - One-Click Installation
; Build with: Inno Setup Compiler 6.0+
; ============================================================

#define MyAppName "HSIP"
#define MyAppVersion "0.2.0"
#define MyAppPublisher "Nyx Systems LLC"
#define MyAppURL "https://github.com/rewired89/HSIP"

[Setup]
AppId={{8C8B8C3E-1D9E-4B16-8C34-44B1D3E7A9C1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=.
OutputBaseFilename=HSIP-Setup
Compression=lzma2/max
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
WizardStyle=modern
UninstallDisplayIcon={app}\hsip-cli.exe
; No prompts - just install
DisableWelcomePage=no
DisableDirPage=yes
DisableReadyPage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

; ============================
; Files to install
; ============================

[Files]
Source: "..\target\release\hsip-cli.exe";   DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\hsip-tray.exe";  DestDir: "{app}"; Flags: ignoreversion
Source: "README-USER.txt";                  DestDir: "{app}"; Flags: ignoreversion

; ============================
; Start Menu shortcuts
; ============================

[Icons]
Name: "{group}\HSIP Status"; Filename: "{app}\hsip-tray.exe"; WorkingDir: "{app}"
Name: "{group}\Uninstall HSIP"; Filename: "{uninstallexe}"

; ============================
; Auto-start on Windows login (Registry)
; ============================

[Registry]
; Daemon - runs hidden
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
      ValueType: string; ValueName: "HSIP Daemon"; \
      ValueData: "cmd /c start /min """" ""{app}\hsip-cli.exe"" daemon"; \
      Flags: uninsdeletevalue

; Tray icon - shows status
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
      ValueType: string; ValueName: "HSIP Tray"; \
      ValueData: """{app}\hsip-tray.exe"""; \
      Flags: uninsdeletevalue

; ============================
; Start immediately after install (HIDDEN - no windows!)
; ============================

[Run]
; Start daemon hidden
Filename: "cmd"; \
      Parameters: "/c start /min """" ""{app}\hsip-cli.exe"" daemon"; \
      WorkingDir: "{app}"; \
      Flags: nowait runhidden

; Start tray (visible in system tray only)
Filename: "{app}\hsip-tray.exe"; \
      WorkingDir: "{app}"; \
      Flags: nowait runhidden

; ============================
; Kill processes before uninstall
; ============================

[UninstallRun]
Filename: "taskkill"; Parameters: "/F /IM hsip-cli.exe"; Flags: runhidden
Filename: "taskkill"; Parameters: "/F /IM hsip-tray.exe"; Flags: runhidden

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
Type: dirifempty; Name: "{userappdata}\.hsip"
