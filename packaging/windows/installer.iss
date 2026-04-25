; Inno Setup script for Intifybrowser
; Produces a single Intifybrowser-Setup.exe that any Windows user can
; double-click to install.  No admin rights required (per-user install).
;
; Build:
;   "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer.iss
; or run:
;   packaging\windows\build-installer.ps1

#define AppName    "Intifybrowser"
#define AppVersion "0.1.0"
#define AppPublisher "Nav420"
#define AppURL     "https://github.com/Nav420/intifybrowser"
#define GuiExe     "ifb-gui.exe"
#define CliExe     "ifb.exe"
#define BinDir     "..\..\launcher\target\release"

[Setup]
AppId={{B9F3A2C4-7D8E-4F5A-9B6C-2E1D0A3B4C5D}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases

; Install to %LOCALAPPDATA%\Programs\Intifybrowser by default (no admin needed)
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}

; Allow the user to choose per-user or per-machine if they want
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

; Output
OutputDir=output
OutputBaseFilename=Intifybrowser-Setup

; Compression
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes

; Appearance
WizardStyle=modern
DisableWelcomePage=no
DisableDirPage=no
DisableReadyPage=no

; 64-bit only
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Use the GUI exe icon in Add/Remove Programs
UninstallDisplayIcon={app}\{#GuiExe}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; \
  Description: "Create a &desktop shortcut"; \
  GroupDescription: "Additional shortcuts:"

[Files]
; GUI launcher (the main app a normal user opens)
Source: "{#BinDir}\{#GuiExe}"; DestDir: "{app}"; Flags: ignoreversion

; CLI launcher (for power users)
Source: "{#BinDir}\{#CliExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Start Menu
Name: "{group}\{#AppName}"; \
  Filename: "{app}\{#GuiExe}"; \
  Comment: "Open an encrypted browser vault"

Name: "{group}\Uninstall {#AppName}"; \
  Filename: "{uninstallexe}"

; Desktop shortcut (opt-in)
Name: "{commondesktop}\{#AppName}"; \
  Filename: "{app}\{#GuiExe}"; \
  Comment: "Open an encrypted browser vault"; \
  Tasks: desktopicon

[Registry]
; Add install dir to user PATH so `ifb` works from any terminal
Root: HKCU; \
  Subkey: "Environment"; \
  ValueType: expandsz; \
  ValueName: "Path"; \
  ValueData: "{olddata};{app}"; \
  Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
; Offer to launch the app at the end of setup
Filename: "{app}\{#GuiExe}"; \
  Description: "Launch {#AppName}"; \
  Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up any leftover temp files the app may have created
Type: filesandordirs; Name: "{localappdata}\Temp\ifb-*"

[Code]
// Check whether the given path is already in the user PATH variable.
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;

// Remove the install dir from PATH on uninstall.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Path: string;
  AppDir: string;
  P: Integer;
begin
  if CurUninstallStep <> usPostUninstall then exit;
  AppDir := ExpandConstant('{app}');
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Path)
  then exit;
  P := Pos(';' + AppDir, Path);
  if P > 0 then
  begin
    Delete(Path, P, Length(';' + AppDir));
    RegWriteExpandStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Path);
  end;
end;
