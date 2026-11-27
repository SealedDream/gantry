; Gantry Terminal for Windows: Inno Setup 6 installer (unsigned by the owner's decision; SmartScreen asks once).
; Built by package-windows.ps1, which passes Source (the staged Release output), Version, License, OutputDir and
; OutputBaseFilename. Default: per user, no admin rights, to %LOCALAPPDATA%\Programs\Gantry. "Install for all users"
; (the privileges dialog, or /ALLUSERS) installs to Program Files and only then asks for admin rights.
; Upgrades: a per-user NSIS install (Settings > Apps entry "BastionNative") is uninstalled silently first; the user's
; library, settings and vault in %APPDATA%\Gantry are never touched unless the user asks on uninstall.
; Scripts: Gantry-<v>-windows-x64-setup.exe /VERYSILENT /CURRENTUSER [/TASKS="desktopicon,addtopath"]
; Silent uninstall: unins000.exe /VERYSILENT [/REMOVEDATA]

#ifndef Source
  #error pass /DSource=<staged Release output folder>
#endif
#ifndef Version
  #define Version "0.1.0"
#endif
#ifndef License
  #define License "..\..\..\LICENSE"
#endif
#if !FileExists(License)
  #error the Apache-2.0 LICENSE is missing (pass /DLicense=<path>)
#endif
#ifndef OutputBaseFilename
  #define OutputBaseFilename "Gantry-" + Version + "-windows-x64-setup"
#endif
#ifndef OutputDir
  #define OutputDir "dist"
#endif

#define AppName "Gantry Terminal"
#define AppDir "Gantry"
#define AppExe "Gantry.exe"
#define NsisKey "Software\Microsoft\Windows\CurrentVersion\Uninstall\BastionNative"

[Setup]
; Never change AppId: upgrades and the Settings > Apps entry depend on it. New for the Gantry rename (owner
; 2026-11-23); the Bastion AppId {44841522-0501-4A29-AF1F-AEA91E15F3DA} was never released.
AppId={{6BE06FEF-6E7A-4A54-B5EF-F8A42FFE6D73}
AppName={#AppName}
AppVersion={#Version}
AppVerName={#AppName} {#Version}
AppPublisher=Gantry contributors
AppPublisherURL=https://github.com/SealedDream/gantry
AppSupportURL=https://github.com/SealedDream/gantry/issues
AppUpdatesURL=https://github.com/SealedDream/gantry/releases
AppCopyright=Gantry contributors
VersionInfoVersion={#Version}.0
VersionInfoDescription={#AppName} setup
DefaultDirName={autopf}\{#AppDir}
DefaultGroupName={#AppName}
AllowNoIcons=yes
DisableWelcomePage=no
DisableDirPage=no
DisableProgramGroupPage=no
DisableReadyPage=no
UsePreviousAppDir=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
LicenseFile={#License}
SetupIconFile=..\Assets\Bastion.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
WizardStyle=modern
WizardImageFile=images\wizard-100.bmp,images\wizard-125.bmp,images\wizard-150.bmp,images\wizard-200.bmp
WizardSmallImageFile=images\wizard-small-100.bmp,images\wizard-small-125.bmp,images\wizard-small-150.bmp,images\wizard-small-200.bmp
WizardImageStretch=no
Compression=lzma2/max
SolidCompression=yes
CloseApplications=yes
RestartApplications=no
ChangesEnvironment=yes
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBaseFilename}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
FinishedLabel=Setup has installed [name] on your computer.

[Tasks]
Name: "startmenu"; Description: "Start menu entry"; GroupDescription: "Shortcuts:"
Name: "desktopicon"; Description: "Desktop icon"; GroupDescription: "Shortcuts:"; Flags: unchecked
Name: "addtopath"; Description: "Add the bastion command line tool to PATH"; GroupDescription: "Command line:"; Flags: unchecked

[InstallDelete]
; Replace the previous version's runtime files; the user's data lives in %APPDATA%\Gantry, never here.
Type: filesandordirs; Name: "{app}\runtimes"

[Files]
Source: "{#Source}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"; Comment: "Remote connections: SSH, RDP, VNC, web"; Tasks: startmenu
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Comment: "Remote connections: SSH, RDP, VNC, web"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[Code]
var
  RemoveData: Boolean;

function EnvKeyRoot: Integer;
begin
  if IsAdminInstallMode then Result := HKEY_LOCAL_MACHINE else Result := HKEY_CURRENT_USER;
end;

function EnvKeyPath: String;
begin
  if IsAdminInstallMode then Result := 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  else Result := 'Environment';
end;

function CliDir: String;
begin
  Result := ExpandConstant('{app}\cli');
end;

{ Position of Dir in a ;-separated Path, matched whole and without case; 0 when absent. }
function PathIndex(const Path, Dir: String): Integer;
begin
  Result := Pos(';' + Uppercase(RemoveBackslashUnlessRoot(Dir)) + ';', ';' + Uppercase(Path) + ';');
end;

procedure AddCliToPath;
var
  Path: String;
begin
  if not RegQueryStringValue(EnvKeyRoot, EnvKeyPath, 'Path', Path) then Path := '';
  if PathIndex(Path, CliDir) > 0 then Exit;
  if (Path <> '') and (Path[Length(Path)] <> ';') then Path := Path + ';';
  RegWriteExpandStringValue(EnvKeyRoot, EnvKeyPath, 'Path', Path + CliDir);
end;

procedure RemoveCliFromPath;
var
  Path, Padded, Needle: String;
  P: Integer;
begin
  if not RegQueryStringValue(EnvKeyRoot, EnvKeyPath, 'Path', Path) then Exit;
  Padded := ';' + Path + ';';
  Needle := ';' + RemoveBackslashUnlessRoot(CliDir) + ';';
  P := Pos(Uppercase(Needle), Uppercase(Padded));
  if P = 0 then Exit;
  Delete(Padded, P, Length(Needle) - 1);
  Path := Copy(Padded, 2, Length(Padded) - 2);
  RegWriteExpandStringValue(EnvKeyRoot, EnvKeyPath, 'Path', Path);
end;

{ An older per-user NSIS install (Bastion Native). Uninstall it silently, keeping the user's data, and wait for its
  entry to go: the NSIS uninstaller copies itself to %TEMP% and returns at once. }
function RemoveNsisInstall: String;
var
  Cmd, Dir: String;
  Code, Waited: Integer;
begin
  Result := '';
  if not RegQueryStringValue(HKEY_CURRENT_USER, '{#NsisKey}', 'InstallLocation', Dir) then Exit;
  Cmd := AddBackslash(RemoveQuotes(Dir)) + 'Uninstall.exe';
  if not FileExists(Cmd) then begin
    RegDeleteKeyIncludingSubkeys(HKEY_CURRENT_USER, '{#NsisKey}');
    Exit;
  end;
  { SEC-REVIEW-01: the path comes from HKCU, which any user-level process can write. An elevated setup never runs it;
    it drops the stale entry and leaves the old per-user files for that user to remove. }
  if IsAdmin then begin
    Log('Elevated setup: not running the per-user NSIS uninstaller in ' + Dir + '; removing its entry only');
    RegDeleteKeyIncludingSubkeys(HKEY_CURRENT_USER, '{#NsisKey}');
    Exit;
  end;
  Log('Removing the NSIS install in ' + Dir);
  if not Exec(Cmd, '/S _?=' + RemoveBackslashUnlessRoot(Dir), '', SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then begin
    Result := 'Could not remove the previous Bastion Native install (' + Dir + '). Uninstall it in Settings > Apps, then run setup again.';
    Exit;
  end;
  { With _?= the uninstaller runs in place and leaves itself behind; remove what is left. }
  Waited := 0;
  while RegKeyExists(HKEY_CURRENT_USER, '{#NsisKey}') and (Waited < 30000) do begin
    Sleep(250);
    Waited := Waited + 250;
  end;
  DeleteFile(Cmd);
  RemoveDir(Dir);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := RemoveNsisInstall;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addtopath') then AddCliToPath;
end;

function InitializeUninstall: Boolean;
var
  I: Integer;
begin
  RemoveData := False;
  { The second uninstall phase gets the original switches in its command tail; match the whole switch. }
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), '/REMOVEDATA') = 0 then RemoveData := True;
  if Pos(' /REMOVEDATA ', ' ' + Uppercase(GetCmdTail) + ' ') > 0 then RemoveData := True;
  Log('Command tail: ' + GetCmdTail);
  if not RemoveData and not UninstallSilent then
    RemoveData := MsgBox('Also remove your Gantry library, settings and saved credentials (' +
      ExpandConstant('{userappdata}\Gantry') + ')?' + #13#10#13#10 + 'Choose No to keep them for a later install.',
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then RemoveCliFromPath;
  if CurUninstallStep = usPostUninstall then begin
    { Only what setup put there goes; a folder the user chose may hold other files. }
    RemoveDir(ExpandConstant('{app}'));
    Log('Remove user data: ' + IntToStr(Ord(RemoveData)));
    if RemoveData and not DelTree(ExpandConstant('{userappdata}\Gantry'), True, True, True) then
      Log('Could not remove ' + ExpandConstant('{userappdata}\Gantry'));
  end;
end;
