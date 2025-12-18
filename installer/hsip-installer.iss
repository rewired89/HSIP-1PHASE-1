; HSIP Windows Installer - Inno Setup Script
; Creates a professional installer with Green/Yellow/Red tray notifications
; Build with Inno Setup Compiler 6.0+

#define MyAppName "HSIP"
#define MyAppVersion "0.2.0"
#define MyAppPublisher "Nyx Systems LLC"
#define MyAppURL "https://hsip.io"
#define MyAppExeName "hsip-cli.exe"
#define MyAppTrayName "hsip-tray.exe"

[Setup]
; Basic application info
AppId={{HSIP-ENCRYPTION-DAEMON}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=..\LICENSE
OutputDir=output
OutputBaseFilename=HSIP-Setup-{#MyAppVersion}
SetupIconFile=hsip.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
UninstallDisplayIcon={app}\{#MyAppExeName}

; Visual customization
WizardImageFile=compiler:WizModernImage-IS.bmp
WizardSmallImageFile=compiler:WizModernSmallImage-IS.bmp

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "autostart"; Description: "Start HSIP automatically when Windows starts"; GroupDescription: "Startup Options:"; Flags: checkedonce

[Files]
; Main executables
Source: "..\target\release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\{#MyAppTrayName}"; DestDir: "{app}"; Flags: ignoreversion

; PowerShell scripts
Source: "register-daemon.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "register-tray.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "run-daemon.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "run-tray.ps1"; DestDir: "{app}"; Flags: ignoreversion

; Documentation
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "..\ENCRYPTION_VERIFICATION_REPORT.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\HOW_TO_VERIFY_ENCRYPTION.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "BUILD_INSTRUCTIONS.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\HSIP Status"; Filename: "{app}\{#MyAppTrayName}"
Name: "{group}\HSIP Documentation"; Filename: "{app}\README.md"
Name: "{group}\Verify Encryption"; Filename: "{app}\HOW_TO_VERIFY_ENCRYPTION.md"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"

[Run]
; Register auto-start tasks if user selected the option
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\register-daemon.ps1"""; StatusMsg: "Registering HSIP daemon..."; Flags: runhidden; Tasks: autostart
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\register-tray.ps1"""; StatusMsg: "Registering HSIP tray icon..."; Flags: runhidden; Tasks: autostart

; Show success message
Filename: "{app}\README.md"; Description: "View Documentation"; Flags: postinstall shellexec skipifsilent unchecked

[UninstallRun]
; Stop and unregister scheduled tasks
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Unregister-ScheduledTask -TaskName 'HSIP Daemon' -Confirm:$false -ErrorAction SilentlyContinue"""; Flags: runhidden
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Unregister-ScheduledTask -TaskName 'HSIP Tray' -Confirm:$false -ErrorAction SilentlyContinue"""; Flags: runhidden
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Stop-Process -Name '{#MyAppExeName}' -Force -ErrorAction SilentlyContinue"""; Flags: runhidden
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Stop-Process -Name '{#MyAppTrayName}' -Force -ErrorAction SilentlyContinue"""; Flags: runhidden

[Code]
procedure InitializeWizard();
var
  WelcomeLabel: TLabel;
begin
  // Custom welcome message
  WelcomeLabel := TLabel.Create(WizardForm);
  WelcomeLabel.Parent := WizardForm.WelcomePage;
  WelcomeLabel.Caption :=
    'This wizard will install HSIP - High-Speed Internet Protection.' + #13#10 + #13#10 +
    'HSIP provides:' + #13#10 +
    '  • ChaCha20-Poly1305 encryption (same as Signal)' + #13#10 +
    '  • Visual status with colored tray icons' + #13#10 +
    '  • Automatic threat blocking' + #13#10 +
    '  • Independent verification (IETF RFC 8439)' + #13#10 + #13#10 +
    'Look for the tray icon after installation:' + #13#10 +
    '  🟢 GREEN  = Protected' + #13#10 +
    '  🟡 YELLOW = Blocking threats' + #13#10 +
    '  🔴 RED    = Offline or error';
  WelcomeLabel.Left := WizardForm.WelcomeLabel2.Left;
  WelcomeLabel.Top := WizardForm.WelcomeLabel2.Top + WizardForm.WelcomeLabel2.Height + 20;
  WelcomeLabel.Width := WizardForm.WelcomeLabel2.Width;
  WelcomeLabel.AutoSize := False;
  WelcomeLabel.WordWrap := True;
  WelcomeLabel.Height := 200;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Create .hsip directory for config and logs
    CreateDir(ExpandConstant('{userappdata}\.hsip'));
  end;
end;

function InitializeUninstall(): Boolean;
begin
  Result := True;
  if MsgBox('This will remove HSIP and stop all protection services. Continue?',
            mbConfirmation, MB_YESNO) = IDNO then
    Result := False;
end;
