; nodewatch master (nodewatch-server) - Windows installer (Inno Setup 6).
;
;   iscc /DVersion=0.2.0 /DSource=C:\...\nodewatch-server-0.2.0-windows-x64.exe server.iss
;
; Installs nodewatch-server.exe to %ProgramFiles%\nodewatch-server, registers
; and starts the "nodewatch master" Windows service (`nodewatch-server
; install`, see server/nodewatch_server/winservice.py), then shows the
; setup code and opens the setup page. Uninstalling removes the service and
; keeps %ProgramData%\nodewatch-server - the database, CA and licence.
;
; Unattended: nodewatch-server-setup-0.2.0-windows-x64.exe /VERYSILENT

#ifndef Version
  #define Version "0.0.0"
#endif
#ifndef Source
  #define Source "..\..\dist\nodewatch-server-" + Version + "-windows-x64.exe"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist"
#endif

[Setup]
AppId={{9C6016C0-A071-4E9B-BF7D-9F69CF5DF60B}
AppName=nodewatch master
AppVersion={#Version}
AppVerName=nodewatch master {#Version}
AppPublisher=nodewatch
DefaultDirName={autopf}\nodewatch-server
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=nodewatch-server-setup-{#Version}-windows-x64
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=nodewatch master
UninstallDisplayIcon={app}\nodewatch-server.exe
VersionInfoVersion={#Version}
VersionInfoProductName=nodewatch master
SetupLogging=yes

[Files]
Source: "{#Source}"; DestDir: "{app}"; DestName: "nodewatch-server.exe"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\nodewatch dashboard"; Filename: "https://localhost:8443/"

[Run]
Filename: "https://localhost:8443/"; Description: "Open the nodewatch setup page"; \
  Flags: postinstall shellexec nowait skipifsilent

[UninstallRun]
Filename: "{app}\nodewatch-server.exe"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; \
  RunOnceId: "RemoveMasterService"

[Code]
const
  DataDir = '{commonappdata}\nodewatch-server';

{ Stop the service so its executable can be replaced on upgrade. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  RC: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop nodewatch-server', '', SW_HIDE, ewWaitUntilTerminated, RC);
  Sleep(5000);
  Result := '';
end;

{ "setup_code": "ABCD1234" out of config.json. }
function JsonString(Json, Key: String): String;
var
  P: Integer;
begin
  Result := '';
  P := Pos('"' + Key + '": "', Json);
  if P = 0 then
    Exit;
  Result := Copy(Json, P + Length(Key) + 5, Length(Json));
  P := Pos('"', Result);
  if P > 0 then
    Result := Copy(Result, 1, P - 1);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  RC, I: Integer;
  Config: AnsiString;
  Ready: Boolean;
begin
  if CurStep <> ssPostInstall then
    Exit;
  WizardForm.StatusLabel.Caption := 'Starting the nodewatch master service...';
  if not Exec(ExpandConstant('{app}\nodewatch-server.exe'), 'install', '', SW_HIDE, ewWaitUntilTerminated, RC)
     or (RC <> 0) then
  begin
    if not WizardSilent then
      MsgBox('The nodewatch master service could not be installed (exit code ' + IntToStr(RC) + ').' + #13#10 +
             'See ' + ExpandConstant(DataDir) + '\server.log', mbError, MB_OK);
    Exit;
  end;

  { First start initialises the database; config.json appears early on. }
  Ready := False;
  for I := 1 to 60 do
  begin
    if LoadStringFromFile(ExpandConstant(DataDir + '\config.json'), Config) then
    begin
      Ready := True;
      Break;
    end;
    Sleep(1000);
  end;

  if Ready and (Pos('"setup_complete": true', String(Config)) > 0) then
    WizardForm.FinishedLabel.Caption :=
      'The nodewatch master is running. Open the dashboard at https://localhost:8443/' + #13#10#13#10 +
      'Your browser will warn about the certificate until you trust the master''s own CA ' +
      '(download it from https://localhost:8443/ca.crt).'
  else if Ready then
    WizardForm.FinishedLabel.Caption :=
      'The nodewatch master is running.' + #13#10#13#10 +
      'Finish setup at https://localhost:8443/setup with this setup code:' + #13#10#13#10 +
      '    ' + JsonString(String(Config), 'setup_code') + #13#10#13#10 +
      'You will need your licence key. Your browser will warn about the certificate - the master ' +
      'makes its own; continue past the warning for this first visit.'
  else
    WizardForm.FinishedLabel.Caption :=
      'The nodewatch master service is starting. The setup code will be in ' +
      ExpandConstant(DataDir) + '\server.log';
end;
