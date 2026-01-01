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
Source: "..\target\release\hsip-cli.exe";     DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\hsip-tray.exe";    DestDir: "{app}"; Flags: ignoreversion
Source: "..\target\release\hsip-gateway.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "README-USER.txt";                    DestDir: "{app}"; Flags: ignoreversion

; ============================
; Start Menu shortcuts
; ============================

[Icons]
Name: "{group}\HSIP Status"; Filename: "{app}\hsip-tray.exe"; WorkingDir: "{app}"
Name: "{group}\Uninstall HSIP"; Filename: "{uninstallexe}"

; ============================
; Auto-start on Windows login (Registry) - using PowerShell hidden
; ============================

[Registry]
; Daemon - runs truly hidden via PowerShell
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
      ValueType: string; ValueName: "HSIP Daemon"; \
      ValueData: "powershell -WindowStyle Hidden -Command ""Start-Process -FilePath '{app}\hsip-cli.exe' -ArgumentList 'daemon' -WindowStyle Hidden"""; \
      Flags: uninsdeletevalue

; Gateway - runs truly hidden via PowerShell
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
      ValueType: string; ValueName: "HSIP Gateway"; \
      ValueData: "powershell -WindowStyle Hidden -Command ""Start-Process -FilePath '{app}\hsip-gateway.exe' -WindowStyle Hidden"""; \
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
; Start gateway first (must be running before proxy is configured)
Filename: "powershell"; \
      Parameters: "-WindowStyle Hidden -Command ""Start-Process -FilePath '{app}\hsip-gateway.exe' -WindowStyle Hidden"""; \
      Flags: nowait runhidden shellexec

; Start daemon truly hidden via PowerShell
Filename: "powershell"; \
      Parameters: "-WindowStyle Hidden -Command ""Start-Process -FilePath '{app}\hsip-cli.exe' -ArgumentList 'daemon' -WindowStyle Hidden"""; \
      Flags: nowait runhidden shellexec

; Start tray (visible in system tray only)
Filename: "{app}\hsip-tray.exe"; \
      WorkingDir: "{app}"; \
      Flags: nowait runhidden

; ============================
; Kill processes before uninstall
; ============================

[UninstallRun]
Filename: "taskkill"; Parameters: "/F /IM hsip-gateway.exe"; Flags: runhidden
Filename: "taskkill"; Parameters: "/F /IM hsip-cli.exe"; Flags: runhidden
Filename: "taskkill"; Parameters: "/F /IM hsip-tray.exe"; Flags: runhidden

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
Type: dirifempty; Name: "{userappdata}\.hsip"

; ============================
; Pascal Script for Proxy Configuration
; ============================

[Code]
const
  INTERNET_SETTINGS = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings';
  HSIP_BACKUP = 'Software\HSIP\ProxyBackup';

// Save original proxy settings before we modify them
procedure BackupProxySettings();
var
  ProxyEnable: Cardinal;
  ProxyServer: String;
begin
  // Read current proxy settings
  if RegQueryDWordValue(HKEY_CURRENT_USER, INTERNET_SETTINGS, 'ProxyEnable', ProxyEnable) then
  begin
    RegWriteDWordValue(HKEY_CURRENT_USER, HSIP_BACKUP, 'OriginalProxyEnable', ProxyEnable);
  end
  else
  begin
    // No proxy was enabled, save 0
    RegWriteDWordValue(HKEY_CURRENT_USER, HSIP_BACKUP, 'OriginalProxyEnable', 0);
  end;

  if RegQueryStringValue(HKEY_CURRENT_USER, INTERNET_SETTINGS, 'ProxyServer', ProxyServer) then
  begin
    RegWriteStringValue(HKEY_CURRENT_USER, HSIP_BACKUP, 'OriginalProxyServer', ProxyServer);
  end
  else
  begin
    RegWriteStringValue(HKEY_CURRENT_USER, HSIP_BACKUP, 'OriginalProxyServer', '');
  end;

  // Mark that we have a backup
  RegWriteDWordValue(HKEY_CURRENT_USER, HSIP_BACKUP, 'BackupExists', 1);
end;

// Configure system to use HSIP gateway as proxy
procedure EnableHSIPProxy();
begin
  // Set proxy server to HSIP gateway
  RegWriteStringValue(HKEY_CURRENT_USER, INTERNET_SETTINGS, 'ProxyServer', '127.0.0.1:8080');
  // Enable proxy
  RegWriteDWordValue(HKEY_CURRENT_USER, INTERNET_SETTINGS, 'ProxyEnable', 1);
end;

// Restore original proxy settings
procedure RestoreProxySettings();
var
  BackupExists: Cardinal;
  OriginalProxyEnable: Cardinal;
  OriginalProxyServer: String;
begin
  // Check if we have a backup
  if RegQueryDWordValue(HKEY_CURRENT_USER, HSIP_BACKUP, 'BackupExists', BackupExists) then
  begin
    if BackupExists = 1 then
    begin
      // Restore ProxyEnable
      if RegQueryDWordValue(HKEY_CURRENT_USER, HSIP_BACKUP, 'OriginalProxyEnable', OriginalProxyEnable) then
      begin
        RegWriteDWordValue(HKEY_CURRENT_USER, INTERNET_SETTINGS, 'ProxyEnable', OriginalProxyEnable);
      end
      else
      begin
        // Default: disable proxy
        RegWriteDWordValue(HKEY_CURRENT_USER, INTERNET_SETTINGS, 'ProxyEnable', 0);
      end;

      // Restore ProxyServer
      if RegQueryStringValue(HKEY_CURRENT_USER, HSIP_BACKUP, 'OriginalProxyServer', OriginalProxyServer) then
      begin
        if OriginalProxyServer <> '' then
          RegWriteStringValue(HKEY_CURRENT_USER, INTERNET_SETTINGS, 'ProxyServer', OriginalProxyServer)
        else
          RegDeleteValue(HKEY_CURRENT_USER, INTERNET_SETTINGS, 'ProxyServer');
      end;

      // Clean up backup
      RegDeleteKeyIncludingSubkeys(HKEY_CURRENT_USER, 'Software\HSIP');
    end;
  end
  else
  begin
    // No backup found, just disable proxy to be safe
    RegWriteDWordValue(HKEY_CURRENT_USER, INTERNET_SETTINGS, 'ProxyEnable', 0);
  end;
end;

// Called after installation completes
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Backup original settings first
    BackupProxySettings();
    // Then enable HSIP proxy
    EnableHSIPProxy();
  end;
end;

// Called during uninstall
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    // Restore original proxy settings
    RestoreProxySettings();
  end;
end;
