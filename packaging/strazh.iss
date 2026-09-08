; Установщик «Стража».
;
; Обычная установка копирует файлы. Этой программе такого мало: у неё есть
; фоновая часть, запускаемая системой, и изменения в реестре, брандмауэре и
; групповой политике. Поэтому установщик заводит задание наблюдения, а
; удаление сначала снимает всё, что программа внесла в систему, и только
; потом стирает файлы. Удаление, оставляющее после себя перехваты запуска и
; политику, было бы хуже, чем отсутствие установщика.
;
; Собирается командой:
;   ISCC /DAppVersion=1.2.0 packaging\strazh.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

#define AppName "Страж"
#define AppPublisher "Aleck59"
#define AppURL "https://github.com/Aleck59/unwant_zapret"
#define AppExe "Strazh.exe"
#define CliExe "strazh-cli.exe"

[Setup]
; Опознаватель приложения менять нельзя: по нему Windows понимает, что
; следующая установка — обновление этой же программы, а не вторая копия.
AppId={{8F3C6A21-4B7E-4C0A-9E2D-5A1F7C9B3D64}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
AppCopyright={#AppPublisher}, 2026
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}

DefaultDirName={autopf}\Strazh
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\dist\installer
OutputBaseFilename=strazh-setup-v{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern

; Программа правит общую ветку реестра и групповую политику — без прав
; администратора установка бессмысленна, и честнее спросить их сразу.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
MinVersion=10.0

; Windows не даст заменить файл работающей программы. Просим закрыть её сами,
; чтобы обновление не заканчивалось требованием перезагрузки.
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
UninstallDisplayName={#AppName} {#AppVersion}

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
ru.TaskAutostart=Наблюдать с запуска системы (рекомендуется)
ru.TaskApply=Включить защиту сразу после установки
ru.TaskDesktop=Значок на рабочем столе
ru.LaunchApp=Открыть «Страж»
ru.StoppingWatch=Останавливаю наблюдение…
ru.RevertingChanges=Снимаю изменения, внесённые в систему…
ru.DataKept=Настройки, свой каталог и карантин остались в %ProgramData%\Strazh. Удалите эту папку вручную, если они больше не нужны.
en.TaskAutostart=Watch from system start (recommended)
en.TaskApply=Turn protection on right after install
en.TaskDesktop=Desktop shortcut
en.LaunchApp=Open Strazh
en.StoppingWatch=Stopping the watcher...
en.RevertingChanges=Reverting the changes made to the system...
en.DataKept=Settings, your own catalogue and the quarantine remain in %ProgramData%\Strazh. Remove that folder by hand if you no longer need them.

[Tasks]
Name: "autostart"; Description: "{cm:TaskAutostart}"; GroupDescription: "{#AppName}"
Name: "applynow"; Description: "{cm:TaskApply}"; GroupDescription: "{#AppName}"
Name: "desktopicon"; Description: "{cm:TaskDesktop}"; GroupDescription: "{#AppName}"; Flags: unchecked

[Files]
Source: "..\dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\{#CliExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\strazh-deny.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; DestName: "README.md"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
; Порядок важен: сначала заводим наблюдение, потом применяем правила. Иначе
; между применением и запуском наблюдателя остаётся щель.
Filename: "{app}\{#CliExe}"; Parameters: "autostart on"; StatusMsg: "{cm:TaskAutostart}"; Flags: runhidden waituntilterminated; Tasks: autostart
Filename: "{app}\{#CliExe}"; Parameters: "apply"; StatusMsg: "{cm:TaskApply}"; Flags: runhidden waituntilterminated; Tasks: applynow
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchApp}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Выполняется до удаления файлов — иначе снимать изменения было бы нечем.
; Порядок этих двух строк не важен: наблюдение к этому моменту уже снято
; кодом ниже, а откат и удаление задания друг от друга не зависят.
Filename: "{app}\{#CliExe}"; Parameters: "revert"; StatusMsg: "{cm:RevertingChanges}"; Flags: runhidden waituntilterminated; RunOnceId: "StrazhRevert"
Filename: "{app}\{#CliExe}"; Parameters: "autostart off"; StatusMsg: "{cm:StoppingWatch}"; Flags: runhidden waituntilterminated; RunOnceId: "StrazhAutostartOff"

[Code]
procedure StopRunning();
var
  ResultCode: Integer;
begin
  { Работающее наблюдение держит свои файлы, и Windows не даст их заменить.
    Останавливаем задание и закрываем окно до того, как трогать файлы. }
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN Strazh',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM Strazh.exe',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM strazh-cli.exe',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    StopRunning();
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  { Задание могло уже запустить наблюдение, и оно держит свои файлы.
    Снимаем его до удаления — иначе удаление упрётся в занятый файл. }
  if CurUninstallStep = usUninstall then
    StopRunning();

  if CurUninstallStep = usPostUninstall then
    { Данные не удаляем: в карантине лежат чужие файлы, которые человек мог
      захотеть вернуть, а в каталоге — его собственные правила.

      SuppressibleMsgBox, а не MsgBox: при тихом удалении (/VERYSILENT)
      обычное окно ждало бы нажатия, которого некому сделать, и удаление
      висело бы вечно. }
    SuppressibleMsgBox(ExpandConstant('{cm:DataKept}'), mbInformation, MB_OK, IDOK);
end;
