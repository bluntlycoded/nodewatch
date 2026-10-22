; nodewatch Agent - Windows installer (Inno Setup 6).
;
;   iscc /DVersion=0.5.0 /DSource=C:\...\nodewatch-agent-0.5.0-windows-x64.exe agent.iss
;
; Installs nodewatch-agent.exe to %ProgramFiles%\nodewatch - the install
; root the agent itself expects (agent/nwconfig.py), and the same place the
; PowerShell installer used - adds a Start menu entry for its window, and
; optionally joins a master straight away.
;
; Unattended rollout (GPO, Intune, SCCM):
;   nodewatch-agent-setup-0.5.0-windows-x64.exe /VERYSILENT /CODE=NWJ1-... /SITE="Lab 1"
;
; The join code is passed to the agent in a temporary file, never on a
; command line where other processes could read it.

#ifndef Version
  #define Version "0.0.0"
#endif
#ifndef Source
  #define Source "..\..\dist\nodewatch-agent-" + Version + "-windows-x64.exe"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist"
#endif

[Setup]
AppId={{B0916CB1-3D0D-4C67-B4BD-230B7C78C208}
AppName=nodewatch Agent
AppVersion={#Version}
AppVerName=nodewatch Agent {#Version}
AppPublisher=nodewatch
DefaultDirName={autopf}\nodewatch
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=nodewatch-agent-setup-{#Version}-windows-x64
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=nodewatch Agent
UninstallDisplayIcon={app}\nodewatch-agent.exe
VersionInfoVersion={#Version}
VersionInfoProductName=nodewatch Agent
SetupLogging=yes

[Files]
Source: "{#Source}"; DestDir: "{app}"; DestName: "nodewatch-agent.exe"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\nodewatch Agent"; Filename: "{app}\nodewatch-agent.exe"; Parameters: "gui"

[Run]
Filename: "{app}\nodewatch-agent.exe"; Parameters: "gui"; Description: "Open nodewatch Agent"; \
  Flags: postinstall nowait skipifsilent runasoriginaluser

[UninstallRun]
; Removes the scheduled task. Configuration and the node's state directory
; are kept, so reinstalling resumes as the same node.
Filename: "{app}\nodewatch-agent.exe"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; \
  RunOnceId: "RemoveAgentTask"

[Code]
var
  JoinPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  JoinPage := CreateInputQueryPage(wpWelcome,
    'Join a nodewatch master',
    'Paste the join code from your master''s Add node page.',
    'You can leave this empty and join later from the nodewatch Agent window.');
  JoinPage.Add('Join code:', False);
  JoinPage.Add('Site (optional):', False);
  JoinPage.Values[0] := ExpandConstant('{param:CODE|}');
  JoinPage.Values[1] := ExpandConstant('{param:SITE|}');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Code: String;
begin
  Result := True;
  if CurPageID = JoinPage.ID then
  begin
    Code := Trim(JoinPage.Values[0]);
    if (Code <> '') and (Pos('NWJ1-', Code) <> 1) then
    begin
      MsgBox('That is not a nodewatch join code. It starts with NWJ1-.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

{ Stop a running agent so its executable can be replaced on upgrade. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  RC: Integer;
begin
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN nodewatch-agent', '', SW_HIDE, ewWaitUntilTerminated, RC);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM nodewatch-agent.exe', '', SW_HIDE, ewWaitUntilTerminated, RC);
  Result := '';
end;

{ The agent writes {"ok": true|false, "message": "..."}; pull out the message. }
function ResultMessage(Json: String): String;
var
  P: Integer;
begin
  Result := Json;
  P := Pos('"message": "', Json);
  if P > 0 then
  begin
    Result := Copy(Json, P + 12, Length(Json));
    P := Pos('"', Result);
    if P > 0 then
      Result := Copy(Result, 1, P - 1);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code, Site, CodeFile, ResultFile, Params: String;
  Output: AnsiString;
  RC: Integer;
begin
  if CurStep <> ssPostInstall then
    Exit;
  Code := Trim(JoinPage.Values[0]);
  Site := Trim(JoinPage.Values[1]);
  if Code = '' then
  begin
    { An upgrade of an already-joined node: start it again. }
    if FileExists(ExpandConstant('{app}\agent.json')) then
      Exec(ExpandConstant('{sys}\schtasks.exe'), '/Run /TN nodewatch-agent', '', SW_HIDE, ewWaitUntilTerminated, RC);
    Exit;
  end;

  CodeFile := ExpandConstant('{tmp}\join-code.txt');
  ResultFile := ExpandConstant('{tmp}\join-result.json');
  SaveStringToFile(CodeFile, Code, False);
  Params := 'join --code-file "' + CodeFile + '" --result-file "' + ResultFile + '"';
  if Site <> '' then
    Params := Params + ' --site "' + Site + '"';

  WizardForm.StatusLabel.Caption := 'Joining the nodewatch master...';
  Exec(ExpandConstant('{app}\nodewatch-agent.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, RC);
  DeleteFile(CodeFile);

  if not LoadStringFromFile(ResultFile, Output) then
    Output := '{"message": "the agent did not report a result"}';
  Log('join result: ' + String(Output));
  if not WizardSilent then
  begin
    if RC = 0 then
      MsgBox('Joined: ' + ResultMessage(String(Output)), mbInformation, MB_OK)
    else
      MsgBox('The agent is installed, but joining failed:' + #13#10#13#10 + ResultMessage(String(Output)) +
             #13#10#13#10 + 'Get a new join code and use the nodewatch Agent window to try again.', mbError, MB_OK);
  end;
end;
