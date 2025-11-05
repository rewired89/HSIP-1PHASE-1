[Setup]
AppName=HSIP CLI
AppVersion=0.2.0-mvp
DefaultDirName={pf}\HSIP
DefaultGroupName=HSIP
DisableDirPage=no
DisableProgramGroupPage=no
OutputBaseFilename=HSIP-CLI-Setup
Compression=lzma
SolidCompression=yes

[Files]
Source: "target\release\hsip-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "installer\HSIP Quickstart.cmd"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\HSIP Quickstart"; Filename: "{app}\HSIP Quickstart.cmd"; WorkingDir: "{app}"
Name: "{group}\HSIP CLI (Help)"; Filename: "{app}\hsip-cli.exe"; Parameters: "--help"; WorkingDir: "{app}"

[Tasks]
Name: "addpath"; Description: "Add HSIP to PATH"; GroupDescription: "Additional tasks:"; Flags: unchecked

[Registry]
; Add PATH (Current User) when selected
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path";
ValueData: "{olddata};{app}"; Tasks: addpath; Check: NeedsAddPath('{app}')

[Code]
function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', OrigPath) then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Param) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;
