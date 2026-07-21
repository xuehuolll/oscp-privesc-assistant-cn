@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "VERSION=1.8.8-cn-cmd"
set "MODE=summary"
set "OUTFILE="
set "REPORT_MODE=0"
set "HIGH=0"
set "MED=0"
set "INFO=0"
set "FIND_N=0"
set "CRED_HITS=0"
set "SVC_UQ_INFO=0"
set "PATH_WR_N=0"
set "MED_PRINT=0"
set "IDX=0"
set "MAX_MED=8"
set "HELP_ONLY=0"
set "ARG_ERR=0"
set "WORK=%TEMP%\opassist_win_%RANDOM%%RANDOM%"
mkdir "%WORK%" >nul 2>&1
set "FINDINGS=%WORK%\findings.txt"
set "KEYS=%WORK%\keys.txt"
set "RAW_PRIV=%WORK%\priv.txt"
set "RAW_GRP=%WORK%\groups.txt"
set "RAW_SVC=%WORK%\services.txt"
set "RAW_TASK=%WORK%\tasks.txt"
set "RAW_NET=%WORK%\netstat.txt"
set "RAW_ENV=%WORK%\basic.txt"
type nul > "%FINDINGS%" 2>nul
type nul > "%KEYS%" 2>nul
call :parse_args %*
if "!HELP_ONLY!"=="1" (call :show_help & call :cleanup & exit /b 0)
if "!ARG_ERR!"=="1" (call :show_help & call :cleanup & exit /b 1)
if defined OUTFILE (
  call :main > "%WORK%\out.txt" 2>&1
  type "%WORK%\out.txt"
  copy /y "%WORK%\out.txt" "!OUTFILE!" >nul 2>&1
) else (
  call :main
)
call :cleanup
endlocal
exit /b 0

:parse_args
if "%~1"=="" exit /b 0
if /i "%~1"=="-h" set "HELP_ONLY=1" & exit /b 0
if /i "%~1"=="/h" set "HELP_ONLY=1" & exit /b 0
if /i "%~1"=="--help" set "HELP_ONLY=1" & exit /b 0
if /i "%~1"=="/?" set "HELP_ONLY=1" & exit /b 0
if /i "%~1"=="-help" set "HELP_ONLY=1" & exit /b 0
if /i "%~1"=="--quick" set "MODE=summary" & shift & goto parse_args
if /i "%~1"=="-quick" set "MODE=summary" & shift & goto parse_args
if /i "%~1"=="--full" set "MODE=full" & shift & goto parse_args
if /i "%~1"=="-full" set "MODE=full" & shift & goto parse_args
if /i "%~1"=="/full" set "MODE=full" & shift & goto parse_args
if /i "%~1"=="full" set "MODE=full" & shift & goto parse_args
if /i "%~1"=="--no-color" shift & goto parse_args
if /i "%~1"=="--report" set "REPORT_MODE=1" & shift & goto parse_args
if /i "%~1"=="-report" set "REPORT_MODE=1" & shift & goto parse_args
if /i "%~1"=="-o" set "OUTFILE=%~2" & shift & shift & goto parse_args
if /i "%~1"=="--out" set "OUTFILE=%~2" & shift & shift & goto parse_args
if /i "%~1"=="/o" set "OUTFILE=%~2" & shift & shift & goto parse_args
echo Unknown arg: %~1
set "ARG_ERR=1"
exit /b 0

:show_help
echo Usage: opassist-win-cn.bat [--full^|--quick] [-o FILE] [--report] [-h]
echo Pure CMD OSCP Windows privesc enum. No PowerShell. No auto exploit.
exit /b 0

:main
call :banner
echo [*] identity/privs ...
call :collect_basic
call :check_admin_group
call :check_privs
call :check_aie
call :check_autologon
call :check_unattend
call :check_sam_backups
echo [*] services ...
call :check_services
echo [*] scheduled tasks ...
call :check_tasks
echo [*] path/creds/ports ...
call :check_path
call :check_creds
call :check_ports
call :check_profile
call :check_autorun
call :check_domain
echo [*] summary ...
call :print_summary
call :print_basic
if /i "!MODE!"=="full" call :print_full
echo.
echo ========== RESULT ==========
echo HIGH: !HIGH!  MED: !MED!  INFO: !INFO!
echo Enum-only. No PowerShell required. Use --full for raw dumps.
exit /b 0

:banner
echo ============================================================
echo  OSCP Privesc Assistant - Windows CMD v!VERSION!
echo  Mode=!MODE! Host=!COMPUTERNAME! User=!USERDOMAIN!\!USERNAME!
echo ============================================================
echo.
exit /b 0

:collect_basic
(
  echo TIME=%DATE% %TIME%
  echo HOST=%COMPUTERNAME%
  echo USER=%USERDOMAIN%\%USERNAME%
  echo USERPROFILE=%USERPROFILE%
  whoami 2>nul
  whoami /user 2>nul
  ver 2>nul
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName 2>nul
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuild 2>nul
) > "%RAW_ENV%" 2>nul
if /i "!MODE!"=="full" systeminfo 2>nul | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)" /C:"Domain" >> "%RAW_ENV%" 2>nul
whoami /priv > "%RAW_PRIV%" 2>nul
whoami /groups > "%RAW_GRP%" 2>nul
exit /b 0

:add_finding
set "SEV=%~1"
set "FKEY=%~2"
set "FTITLE=%~3"
set "FREASON=%~4"
set "FNEXT=%~5"
if not defined FKEY set "FKEY=!SEV!:!FTITLE!"
findstr /X /C:"!FKEY!" "%KEYS%" >nul 2>&1 && exit /b 0
>>"%KEYS%" echo !FKEY!
set /a FIND_N+=1
if /i "!SEV!"=="HIGH" set /a HIGH+=1
if /i "!SEV!"=="MED" set /a MED+=1
if /i "!SEV!"=="INFO" set /a INFO+=1
>>"%FINDINGS%" echo BEGIN
>>"%FINDINGS%" echo SEV=!SEV!
>>"%FINDINGS%" echo TITLE=!FTITLE!
>>"%FINDINGS%" echo REASON=!FREASON!
>>"%FINDINGS%" echo NEXT=!FNEXT!
>>"%FINDINGS%" echo END
exit /b 0

:can_write_dir
set "WRITABLE=0"
set "TDIR=%~1"
if not defined TDIR exit /b 1
if "!TDIR:~-1!"=="\" set "TDIR=!TDIR:~0,-1!"
echo !TDIR! | findstr /R /C:"^\\\\" >nul 2>&1 && exit /b 1
if not exist "!TDIR!\" exit /b 1
set "TF=!TDIR!\opassist_!RANDOM!.tmp"
(echo.> "!TF!") 2>nul
if exist "!TF!" (
  del /f /q "!TF!" >nul 2>&1
  set "WRITABLE=1"
  exit /b 0
)
exit /b 1

:is_priv_account
set "ISPRIV=0"
set "ACC=%~1"
if not defined ACC exit /b 1
echo !ACC! | findstr /I /C:"LocalSystem" /C:"Local Service" /C:"Network Service" /C:"NT AUTHORITY" /C:"SYSTEM" /C:"Administrator" >nul 2>&1 && set "ISPRIV=1"
exit /b 0

:extract_exe
set "EXEPATH="
set "EXEDIR="
if not defined RAWPATH exit /b 1
set "RP=!RAWPATH!"
for /f "tokens=* delims= " %%T in ("!RP!") do set "RP=%%T"
if "!RP:~0,1!"==^"^" (
  for /f tokens^=2^ delims^=^" %%A in ("!RP!") do set "EXEPATH=%%A"
) else (
  echo !RP! | findstr /I "\.exe" >nul 2>&1 || exit /b 1
  set "BUILD="
  for %%T in (!RP!) do (
    if not defined EXEPATH (
      if defined BUILD (set "BUILD=!BUILD! %%T") else (set "BUILD=%%T")
      echo !BUILD! | findstr /I /E /C:".exe" >nul 2>&1 && set "EXEPATH=!BUILD!"
    )
  )
  if not defined EXEPATH for /f "tokens=1 delims= " %%A in ("!RP!") do set "EXEPATH=%%A"
)
if not defined EXEPATH exit /b 1
for %%D in ("!EXEPATH!") do set "EXEDIR=%%~dpD"
if defined EXEDIR if "!EXEDIR:~-1!"=="\" set "EXEDIR=!EXEDIR:~0,-1!"
exit /b 0

:is_unquoted
set "ISUQ=0"
set "UP=%~1"
if not defined UP exit /b 1
if "!UP:~0,1!"==^"^" exit /b 1
echo !UP! | findstr /I "\.exe" >nul 2>&1 || exit /b 1
echo !UP! | findstr /C:" " >nul 2>&1 && set "ISUQ=1"
exit /b 0

:check_admin_group
findstr /I /C:"S-1-5-32-544" /C:"Administrators" "%RAW_GRP%" >nul 2>&1
if not errorlevel 1 call :add_finding "HIGH" "admin_group" "User may be local Administrators" "Remote shell may still be UAC-filtered." "whoami /groups|whoami /priv|net localgroup administrators"
exit /b 0

:check_privs
findstr /I /C:"SeImpersonatePrivilege" "%RAW_PRIV%" | findstr /I "Enabled" >nul 2>&1
if not errorlevel 1 call :add_finding "HIGH" "priv_imp" "SeImpersonatePrivilege Enabled" "High-value. Confirm build/context before potato techniques." "whoami /priv|systeminfo|tasklist /v"
findstr /I /C:"SeAssignPrimaryTokenPrivilege" "%RAW_PRIV%" | findstr /I "Enabled" >nul 2>&1
if not errorlevel 1 call :add_finding "HIGH" "priv_apt" "SeAssignPrimaryTokenPrivilege Enabled" "High-value token privilege." "whoami /priv"
findstr /I /C:"SeBackupPrivilege" "%RAW_PRIV%" | findstr /I "Enabled" >nul 2>&1
if not errorlevel 1 call :add_finding "HIGH" "priv_bak" "SeBackupPrivilege Enabled" "May read sensitive files. reg save writes disk - manual only." "whoami /priv|dir C:\Windows\Repair 2>nul|dir C:\Windows\System32\config\RegBack 2>nul"
findstr /I /C:"SeRestorePrivilege" "%RAW_PRIV%" | findstr /I "Enabled" >nul 2>&1
if not errorlevel 1 call :add_finding "HIGH" "priv_res" "SeRestorePrivilege Enabled" "Manual verify only." "whoami /priv"
findstr /I /C:"SeDebugPrivilege" "%RAW_PRIV%" | findstr /I "Enabled" >nul 2>&1
if not errorlevel 1 call :add_finding "HIGH" "priv_dbg" "SeDebugPrivilege Enabled" "May debug privileged processes." "whoami /priv|tasklist /v"
findstr /I /C:"SeTakeOwnershipPrivilege" "%RAW_PRIV%" | findstr /I "Enabled" >nul 2>&1
if not errorlevel 1 call :add_finding "MED" "priv_own" "SeTakeOwnershipPrivilege Enabled" "Sometimes useful for ACL paths." "whoami /priv"
findstr /I /C:"SeLoadDriverPrivilege" "%RAW_PRIV%" | findstr /I "Enabled" >nul 2>&1
if not errorlevel 1 call :add_finding "MED" "priv_drv" "SeLoadDriverPrivilege Enabled" "Rarely first OSCP path." "whoami /priv"
exit /b 0

:check_aie
set "AIE_HKCU=0" & set "AIE_HKLM=0"
reg query "HKCU\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul | findstr /I "0x1" >nul 2>&1 && set "AIE_HKCU=1"
reg query "HKLM\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul | findstr /I "0x1" >nul 2>&1 && set "AIE_HKLM=1"
if "!AIE_HKCU!"=="1" if "!AIE_HKLM!"=="1" call :add_finding "HIGH" "aie" "AlwaysInstallElevated HKCU+HKLM" "Classic misconfig." "reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated|reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated"
exit /b 0

:check_autologon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>nul | findstr /I "DefaultPassword" >nul 2>&1
if not errorlevel 1 call :add_finding "HIGH" "autologon" "Winlogon DefaultPassword present" "Cleartext autologon creds." "reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon|cmdkey /list|net user"
exit /b 0

:check_unattend
for %%P in (
  "C:\Windows\Panther\Unattend.xml"
  "C:\Windows\Panther\Unattended.xml"
  "C:\Windows\System32\Sysprep\Unattend.xml"
  "C:\Windows\System32\Sysprep\Panther\Unattend.xml"
  "C:\Windows\System32\Sysprep\sysprep.xml"
  "C:\sysprep\sysprep.xml"
  "C:\sysprep\Unattend.xml"
) do if exist "%%~P" call :add_finding "HIGH" "unattend_%%~nxP" "Unattend/Sysprep found: %%~P" "Often has admin passwords." "dir %%~P|findstr /ni /i password administrator username domain %%~P"
exit /b 0

:check_sam_backups
for %%P in (
  "C:\Windows\Repair\SAM"
  "C:\Windows\Repair\SYSTEM"
  "C:\Windows\System32\config\RegBack\SAM"
  "C:\Windows\System32\config\RegBack\SYSTEM"
  "C:\Windows\System32\config\RegBack\SECURITY"
) do if exist "%%~P" call :add_finding "HIGH" "sam_%%~nxP" "SAM/SYSTEM backup candidate: %%~P" "If readable, offline hashes possible." "dir %%~P|icacls %%~P"
exit /b 0

:check_services
where wmic >nul 2>&1 && (
  wmic service get Name,PathName,StartName,State,StartMode /format:list > "%RAW_SVC%" 2>nul
  call :svc_from_wmic
) || call :svc_from_sc
exit /b 0

:svc_from_wmic
set "SNAME=" & set "SPATH=" & set "SUSER="
for /f "usebackq delims=" %%L in ("%RAW_SVC%") do (
  set "SL=%%L"
  if defined SL (
    if /i "!SL:~0,5!"=="Name=" (
      if defined SNAME if defined SPATH call :analyze_svc
      set "SNAME=!SL:~5!" & set "SPATH=" & set "SUSER="
    )
    if /i "!SL:~0,9!"=="PathName=" set "SPATH=!SL:~9!"
    if /i "!SL:~0,10!"=="StartName=" set "SUSER=!SL:~10!"
  ) else (
    if defined SNAME if defined SPATH call :analyze_svc
    set "SNAME=" & set "SPATH=" & set "SUSER="
  )
)
if defined SNAME if defined SPATH call :analyze_svc
exit /b 0

:svc_from_sc
sc query state= all > "%WORK%\sc_all.txt" 2>nul
for /f "tokens=2 delims=:" %%S in ('findstr /I "SERVICE_NAME" "%WORK%\sc_all.txt" 2^>nul') do (
  set "SNAME=%%S"
  for /f "tokens=* delims= " %%T in ("!SNAME!") do set "SNAME=%%T"
  set "SPATH=" & set "SUSER="
  for /f "tokens=1,* delims=:" %%K in ('sc qc "!SNAME!" 2^>nul') do (
    set "SK=%%K" & set "SV=%%L"
    for /f "tokens=* delims= " %%X in ("!SK!") do set "SK=%%X"
    for /f "tokens=* delims= " %%X in ("!SV!") do set "SV=%%X"
    if /i "!SK!"=="BINARY_PATH_NAME" set "SPATH=!SV!"
    if /i "!SK!"=="SERVICE_START_NAME" set "SUSER=!SV!"
  )
  if defined SPATH call :analyze_svc
)
exit /b 0

:analyze_svc
if not defined SNAME exit /b 0
if not defined SPATH exit /b 0
set "RAWPATH=!SPATH!"
call :is_unquoted "!SPATH!"
set "THIS_UQ=!ISUQ!"
call :is_priv_account "!SUSER!"
set "THIS_PRIV=!ISPRIV!"
call :extract_exe
if not defined EXEPATH exit /b 0
set "IS_SYS=0"
echo !EXEPATH! | findstr /I /C:"\\Windows\\System32\\" /C:"\\Windows\\SysWOW64\\" /C:"\\Windows\\WinSxS\\" >nul 2>&1 && set "IS_SYS=1"
if "!IS_SYS!"=="1" if not "!THIS_UQ!"=="1" exit /b 0
if exist "!EXEPATH!" if defined EXEDIR if "!IS_SYS!"=="0" (
  call :can_write_dir "!EXEDIR!"
  if "!WRITABLE!"=="1" (
    if "!THIS_PRIV!"=="1" (
      call :add_finding "HIGH" "svcdir_!SNAME!" "Writable priv service dir: !EXEDIR!" "Service !SNAME! as !SUSER!." "sc qc !SNAME!|sc sdshow !SNAME!|icacls !EXEDIR!"
    ) else (
      call :add_finding "MED" "svcdirL_!SNAME!" "Writable service dir low account: !EXEDIR!" "Service !SNAME! as !SUSER!." "sc qc !SNAME!|icacls !EXEDIR!"
    )
  )
)
if "!THIS_UQ!"=="1" (
  set "UQ_HIT=0" & set "UQ_WHERE="
  call :uq_writable "!EXEPATH!"
  if "!UQ_HIT!"=="1" (
    if "!THIS_PRIV!"=="1" (
      call :add_finding "HIGH" "svcuq_!SNAME!" "Unquoted path + writable prefix: !SNAME!" "Path=!SPATH! Writable=!UQ_WHERE!" "sc qc !SNAME!|icacls !UQ_WHERE!"
    ) else (
      call :add_finding "MED" "svcuqL_!SNAME!" "Unquoted+writable prefix low: !SNAME!" "Path=!SPATH! Writable=!UQ_WHERE!" "sc qc !SNAME!|icacls !UQ_WHERE!"
    )
  )
)
exit /b 0

:uq_writable
set "UQ_HIT=0" & set "UQ_WHERE="
set "DRIVE=%~d1" & set "PONLY=%~p1"
call :can_write_dir "!DRIVE!"
if "!WRITABLE!"=="1" (set "UQ_HIT=1" & set "UQ_WHERE=!DRIVE!" & exit /b 0)
set "ACC=!DRIVE!"
set "PONLY=!PONLY:\= !"
for %%P in (!PONLY!) do (
  if not "%%~P"=="" (
    set "ACC=!ACC!\%%~P"
    if exist "!ACC!\" (
      call :can_write_dir "!ACC!"
      if "!WRITABLE!"=="1" (set "UQ_HIT=1" & set "UQ_WHERE=!ACC!" & exit /b 0)
    )
  )
)
exit /b 0

:check_tasks
schtasks /query /fo LIST /v > "%WORK%\tasks_raw.txt" 2>nul
if errorlevel 1 schtasks /query /fo LIST > "%WORK%\tasks_raw.txt" 2>nul
if not exist "%WORK%\tasks_raw.txt" exit /b 0
findstr /I /C:"TaskName:" /C:"Run As User:" /C:"Task To Run:" /C:"SYSTEM" /C:"Administrator" /C:"LOCAL SERVICE" /C:"NETWORK SERVICE" /C:"NT AUTHORITY" /C:"LocalSystem" "%WORK%\tasks_raw.txt" > "%RAW_TASK%" 2>nul
if /i "!MODE!"=="full" copy /y "%WORK%\tasks_raw.txt" "%RAW_TASK%" >nul 2>&1
set "T_NAME=" & set "T_RUNAS=" & set "T_TORUN="
for /f "usebackq delims=" %%L in ("%RAW_TASK%") do (
  set "LINE=%%L"
  if defined LINE (
    echo !LINE! | findstr /I /B /C:"TaskName:" >nul 2>&1 && (
      if defined T_NAME call :flush_task
      for /f "tokens=1,* delims=:" %%A in ("!LINE!") do (set "T_NAME=%%B" & for /f "tokens=* delims= " %%X in ("!T_NAME!") do set "T_NAME=%%X")
      set "T_RUNAS=" & set "T_TORUN="
    )
    echo !LINE! | findstr /I /B /C:"Run As User:" >nul 2>&1 && (
      for /f "tokens=1,* delims=:" %%A in ("!LINE!") do (set "T_RUNAS=%%B" & for /f "tokens=* delims= " %%X in ("!T_RUNAS!") do set "T_RUNAS=%%X")
    )
    echo !LINE! | findstr /I /B /C:"Task To Run:" >nul 2>&1 && (
      for /f "tokens=1,* delims=:" %%A in ("!LINE!") do (set "T_TORUN=%%B" & for /f "tokens=* delims= " %%X in ("!T_TORUN!") do set "T_TORUN=%%X")
    )
  ) else (
    if defined T_NAME call :flush_task
  )
)
if defined T_NAME call :flush_task
exit /b 0

:flush_task
if not defined T_TORUN goto flush_task_clear
echo !T_TORUN! | findstr /I /C:"N/A" /C:"COM handler" >nul 2>&1 && goto flush_task_clear
set "TASK_PRIV=0"
echo !T_RUNAS! | findstr /I /C:"SYSTEM" /C:"Administrator" /C:"LOCAL SERVICE" /C:"NETWORK SERVICE" /C:"LocalSystem" /C:"NT AUTHORITY" >nul 2>&1 && set "TASK_PRIV=1"
if "!TASK_PRIV!"=="0" goto flush_task_clear
set "RAWPATH=!T_TORUN!"
call :extract_exe
if not defined EXEPATH (
  echo !T_TORUN! | findstr /I /C:"powershell" /C:"cmd.exe" /C:"wscript" /C:"cscript" /C:".bat" /C:".cmd" /C:".ps1" /C:".vbs" >nul 2>&1
  if not errorlevel 1 call :add_finding "MED" "tasksc_!T_NAME!" "Priv task script/interpreter: !T_NAME!" "RunAs=!T_RUNAS! Cmd=!T_TORUN!" "schtasks /query /tn !T_NAME! /fo LIST /v"
  goto flush_task_clear
)
if exist "!EXEPATH!" if defined EXEDIR (
  call :can_write_dir "!EXEDIR!"
  if "!WRITABLE!"=="1" call :add_finding "HIGH" "taskdir_!T_NAME!" "Writable priv task dir: !EXEDIR!" "Task !T_NAME! as !T_RUNAS!" "schtasks /query /tn !T_NAME! /fo LIST /v|icacls !EXEDIR!"
) else (
  echo !EXEPATH! | findstr /I /C:"\\Users\\" /C:"\\Temp\\" /C:"\\ProgramData\\" /C:"\\inetpub\\" >nul 2>&1
  if not errorlevel 1 call :add_finding "MED" "taskns_!T_NAME!" "Priv task nonstd path: !EXEPATH!" "Task !T_NAME! RunAs=!T_RUNAS!" "schtasks /query /tn !T_NAME! /fo LIST /v"
)
:flush_task_clear
set "T_NAME=" & set "T_RUNAS=" & set "T_TORUN="
exit /b 0

:check_path
set "PATH_WR_N=0"
for %%D in ("%PATH:;=" "%") do (
  set "PD=%%~D"
  if defined PD (
    echo !PD! | findstr /R /C:"^\\\\" >nul 2>&1
    if errorlevel 1 if exist "!PD!\" (
      call :can_write_dir "!PD!"
      if "!WRITABLE!"=="1" (
        set /a PATH_WR_N+=1
        if !PATH_WR_N! LEQ 4 call :add_finding "MED" "path_!PATH_WR_N!" "Writable PATH dir: !PD!" "Only if priv process uses relative cmds." "icacls !PD!"
      )
    )
  )
)
if !PATH_WR_N! GTR 4 call :add_finding "INFO" "path_more" "More writable PATH dirs" "About !PATH_WR_N! entries." "echo %PATH%"
exit /b 0

:check_creds
if defined APPDATA if exist "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" (
  findstr /I /C:"password" /C:"passwd" /C:"pwd" /C:"credential" /C:"cmdkey" /C:"runas" /C:"net use" "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" >nul 2>&1
  if not errorlevel 1 call :add_finding "HIGH" "ps_hist" "PS history has credential keywords" "ConsoleHost_history.txt" "findstr /ni /i password passwd pwd credential cmdkey %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
)
if /i "!MODE!"=="full" for /d %%U in ("C:\Users\*") do if exist "%%U\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" (
  findstr /I /C:"password" /C:"passwd" /C:"pwd" /C:"credential" "%%U\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" >nul 2>&1
  if not errorlevel 1 call :add_finding "HIGH" "ps_hist_%%~nxU" "Other user PS history keywords: %%~nxU" "history" "findstr /ni /i password passwd pwd %%U\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
)
cmdkey /list > "%WORK%\cmdkey.txt" 2>nul
findstr /I /C:"Target:" "%WORK%\cmdkey.txt" >nul 2>&1
if not errorlevel 1 call :add_finding "MED" "cmdkey" "Saved credentials via cmdkey" "Check targets manually." "cmdkey /list"
for %%F in (
  "%APPDATA%\FileZilla\sitemanager.xml"
  "%APPDATA%\WinSCP.ini"
  "%APPDATA%\mRemoteNG\confCons.xml"
  "%LOCALAPPDATA%\mRemoteNG\confCons.xml"
  "%USERPROFILE%\.aws\credentials"
) do if exist "%%~F" call :add_finding "MED" "client_%%~nxF" "Client cred config: %%~F" "May hold host/user/pass." "dir %%~F|findstr /ni /i password pass user host %%~F"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" >nul 2>&1
if not errorlevel 1 call :add_finding "MED" "putty" "PuTTY sessions present" "HostName/UserName/key path." "reg query HKCU\Software\SimonTatham\PuTTY\Sessions /s"
if exist "C:\inetpub\wwwroot\web.config" (
  findstr /I /C:"connectionString" /C:"password" /C:"pwd=" /C:"Data Source" "C:\inetpub\wwwroot\web.config" >nul 2>&1
  if not errorlevel 1 call :add_finding "HIGH" "iis_root" "IIS web.config DB/cred keywords" "C:\inetpub\wwwroot\web.config" "findstr /ni /i connectionString password pwd= C:\inetpub\wwwroot\web.config"
)
set "CRED_HITS=0"
for %%F in (
  "C:\inetpub\wwwroot\web.config"
  "C:\xampp\phpMyAdmin\config.inc.php"
  "C:\xampp\mysql\bin\my.ini"
) do if exist "%%~F" call :probe_cred "%%~F"
if exist "C:\inetpub\" for /f "delims=" %%F in ('dir /s /b "C:\inetpub\web.config" 2^>nul') do (
  call :probe_cred "%%F"
  if !CRED_HITS! GEQ 6 goto creds_done
)
:creds_done
exit /b 0

:probe_cred
set "CF=%~1"
if not exist "!CF!" exit /b 0
findstr /I /C:"password=" /C:"password =" /C:"passwd=" /C:"pwd=" /C:"connectionString" /C:"PRIVATE KEY" /C:"secret=" /C:"token=" /C:"Data Source=" /C:"Initial Catalog" "!CF!" >nul 2>&1
if errorlevel 1 exit /b 0
set /a CRED_HITS+=1
if !CRED_HITS! LEQ 8 call :add_finding "MED" "cred_!CRED_HITS!" "Config strong credential pattern: !CF!" "password=/pwd=/connectionString hit." "dir !CF!|findstr /ni /i password passwd pwd connectionString !CF!"
exit /b 0

:check_ports
netstat -ano > "%RAW_NET%" 2>nul
findstr /C:"127.0.0.1:3306" /C:"127.0.0.1:5432" /C:"127.0.0.1:6379" /C:"127.0.0.1:27017" /C:"127.0.0.1:1433" /C:"127.0.0.1:8080" /C:"127.0.0.1:8000" /C:"127.0.0.1:9200" "%RAW_NET%" >nul 2>&1
if not errorlevel 1 call :add_finding "MED" "local_ports" "Interesting localhost listeners" "Pair with web/app config creds." "netstat -ano|findstr LISTENING|findstr 127.0.0.1"
exit /b 0

:check_profile
echo !USERDOMAIN!\!USERNAME! | findstr /I /C:"IIS APPPOOL" /C:"IUSR" >nul 2>&1
if not errorlevel 1 (call :add_finding "MED" "prof_iis" "Looks like IIS app pool user" "Check inetpub and web.config." "whoami|dir C:\inetpub" & exit /b 0)
echo !USERNAME! | findstr /I /C:"mssql" /C:"sqlserver" /C:"sqlsvc" >nul 2>&1
if not errorlevel 1 (call :add_finding "MED" "prof_sql" "Looks like SQL service account" "Check SQL dirs and connection strings." "sc query state= all" & exit /b 0)
echo !USERNAME! | findstr /I /X /C:"Administrator" /C:"Admin" /C:"User" /C:"Users" /C:"Guest" /C:"DefaultAccount" >nul 2>&1
if errorlevel 1 call :add_finding "INFO" "prof_gen" "Possible app/service account: !USERNAME!" "Check profile/APPDATA configs." "dir /a %USERPROFILE%|dir /a %APPDATA%"
exit /b 0

:check_autorun
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" > "%WORK%\run_hklm.txt" 2>nul
findstr /I /C:"\\Users\\" /C:"\\Temp\\" /C:"\\ProgramData\\" /C:"\\AppData\\" "%WORK%\run_hklm.txt" >nul 2>&1
if not errorlevel 1 call :add_finding "MED" "run_hklm" "HKLM Run uses Users/Temp/ProgramData path" "Check writability." "reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
if exist "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\" (
  dir /b "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\" 2>nul | findstr /R "." >nul 2>&1
  if not errorlevel 1 (
    call :can_write_dir "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    if "!WRITABLE!"=="1" call :add_finding "HIGH" "startup_wr" "Common Startup writable" "May affect other logons." "dir /a C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
  )
)
exit /b 0

:check_domain
if defined USERDOMAIN if /i not "!USERDOMAIN!"=="!COMPUTERNAME!" call :add_finding "INFO" "domain" "Likely domain: !USERDOMAIN!" "No auto AD enum." "whoami /fqdn|net user /domain"
exit /b 0

:print_summary
echo.
echo ========== PRIORITY FINDINGS ==========
echo Privesc-first summary. Use --full for raw dumps.
echo.
if "!HIGH!"=="0" if "!MED!"=="0" (
  echo No clear high-value leads.
  echo Check: creds, Autologon, Unattend, tokens, writable priv svc/task, AIE, SAM backups.
  echo.
  if /i not "!MODE!"=="full" exit /b 0
)
set "IDX=0" & set "MED_PRINT=0"
call :emit_sev HIGH
call :emit_sev MED
if /i "!MODE!"=="full" call :emit_sev INFO
if !MED! GTR !MAX_MED! if /i not "!MODE!"=="full" echo [tip] MED capped at !MAX_MED!; use --full.
exit /b 0

:emit_sev
set "WANT=%~1"
set "CUR_SEV=" & set "CUR_TITLE=" & set "CUR_REASON=" & set "CUR_NEXT="
for /f "usebackq delims=" %%L in ("%FINDINGS%") do (
  set "FL=%%L"
  if "!FL!"=="BEGIN" (
    set "CUR_SEV=" & set "CUR_TITLE=" & set "CUR_REASON=" & set "CUR_NEXT="
  ) else if "!FL!"=="END" (
    set "DO=0"
    if /i "!CUR_SEV!"=="!WANT!" set "DO=1"
    if "!DO!"=="1" if /i "!WANT!"=="MED" if /i not "!MODE!"=="full" (
      set /a MED_PRINT+=1
      if !MED_PRINT! GTR !MAX_MED! set "DO=0"
    )
    if "!DO!"=="1" (
      set /a IDX+=1
      echo [!IDX!]
      if /i "!CUR_SEV!"=="HIGH" echo [HIGH] !CUR_TITLE!
      if /i "!CUR_SEV!"=="MED" echo [MED] !CUR_TITLE!
      if /i "!CUR_SEV!"=="INFO" echo [INFO] !CUR_TITLE!
      if defined CUR_REASON echo     reason: !CUR_REASON!
      if defined CUR_NEXT (
        echo     next:
        call :print_next "!CUR_NEXT!"
      )
      if "!REPORT_MODE!"=="1" (
        echo     [Report Finding] !CUR_TITLE!
        echo     [Evidence] !CUR_REASON!
      )
      echo.
    )
  ) else (
    if "!FL:~0,4!"=="SEV=" set "CUR_SEV=!FL:~4!"
    if "!FL:~0,6!"=="TITLE=" set "CUR_TITLE=!FL:~6!"
    if "!FL:~0,7!"=="REASON=" set "CUR_REASON=!FL:~7!"
    if "!FL:~0,5!"=="NEXT=" set "CUR_NEXT=!FL:~5!"
  )
)
exit /b 0

:print_next
set "NX=%~1"
if not defined NX exit /b 0
for /f "tokens=1* delims=|" %%A in ("!NX!") do (
  echo       %%A
  if not "%%B"=="" call :print_next "%%B"
)
exit /b 0

:print_basic
echo.
echo ========== BASIC ENV ==========
if exist "%RAW_ENV%" type "%RAW_ENV%"
echo.
echo --- privs ---
findstr /I "Privilege Enabled Disabled Se" "%RAW_PRIV%" 2>nul
echo.
echo --- admin groups ---
findstr /I /C:"Administrators" /C:"S-1-5-32-544" /C:"BUILTIN" /C:"Label" "%RAW_GRP%" 2>nul
exit /b 0

:print_full
echo.
echo ========== FULL ==========
type "%RAW_PRIV%" 2>nul
echo.
reg query "HKCU\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul
reg query "HKLM\Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated 2>nul
echo.
if exist "%RAW_SVC%" type "%RAW_SVC%"
echo.
if exist "%WORK%\tasks_raw.txt" type "%WORK%\tasks_raw.txt"
echo.
net user 2>nul
echo.
net localgroup administrators 2>nul
echo.
findstr /I "LISTENING" "%RAW_NET%" 2>nul
echo.
cmdkey /list 2>nul
echo.
echo LIMITS: sc sdshow for service DACL; powershell needed for CLM/Defender; write probe uses temp file.
exit /b 0

:cleanup
if defined WORK if exist "%WORK%\" rd /s /q "%WORK%" >nul 2>&1
exit /b 0
