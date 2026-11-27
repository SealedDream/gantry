@echo off
rem Bastion update swap (MainWindow.Updates.cs, Codex W06). Run from a copy in %TEMP%, never from the install folder.
rem   update-apply.cmd <pid> <staging> <install> <root> <failure-marker>
rem Waits for <pid> to exit, backs the installation up under <root>\backup, copies <staging> over <install> and starts
rem the new Gantry.exe. When any copy fails (robocopy exit 8 or more: locked file, access denied, disk full) the backup
rem is copied back, <failure-marker> says why, and the previous version starts again. <root> (download, staging and
rem backup) is never deleted here: the next Bastion that starts successfully removes it.
setlocal
set "PID=%~1"
set "STAGING=%~2"
set "INSTALL=%~3"
set "ROOT=%~4"
set "MARKER=%~5"
if "%MARKER%"=="" exit /b 2

:wait
tasklist /FI "PID eq %PID%" /NH | find "%PID%" >nul && (timeout /t 1 /nobreak >nul & goto wait)

rem No echo inside ( ) blocks: a path such as "Program Files (x86)" would end the block early.
robocopy "%INSTALL%" "%ROOT%\backup" /E /R:2 /W:1 /NFL /NDL /NJH /NJS >nul
if errorlevel 8 goto nobackup

robocopy "%STAGING%" "%INSTALL%" /E /R:5 /W:1 /NFL /NDL /NJH /NJS >nul
if errorlevel 8 goto rollback
goto relaunch

:nobackup
> "%MARKER%" echo The update was not installed: the current installation could not be backed up first. The download is kept in %ROOT%.
goto relaunch

:rollback
rem Restore exactly the backed-up files; anything the partial copy added stays harmlessly unused.
robocopy "%ROOT%\backup" "%INSTALL%" /E /R:5 /W:1 /NFL /NDL /NJH /NJS >nul
if errorlevel 8 goto norestore
> "%MARKER%" echo The update was not installed: a file in %INSTALL% could not be replaced, in use or access denied. The previous version was restored; the download is kept in %ROOT%.
goto relaunch

:norestore
> "%MARKER%" echo The update failed and the previous version could not be fully restored. Copy %ROOT%\backup over %INSTALL% to repair it.

:relaunch
start "" "%INSTALL%\Gantry.exe"
(goto) 2>nul & del "%~f0"
