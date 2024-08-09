@REM This file was made by OrdinaryDude2634 at Github and uploaded to Github
echo off
cd /d "%~dp0"
CLS




@REM Check if the script is running as an administrator
net session >nul 2>&1
if %errorlevel% == 0 (
    echo [32mThe script is running as an administrator[0m
) else (
    echo [31mPlease run this script as an administrator[0m
    pause
    exit /b
)


@REM Change the name of the currently running file for camouflage
set "camouflageName=Windows_KMS_Activation.bat"
if /i "%~nx0" neq "%camouflageName%" (
    setlocal enabledelayedexpansion
    echo [33mChanging the name of the currently running file to !camouflageName! for camouflage[0m
    set "renameCommand=Rename-Item -Path ''%~f0'' -NewName ''%~dp0!camouflageName!''; Start-Process -FilePath ''%~dp0!camouflageName!'' -Verb RunAs"
    powershell -Command ^
        "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command ""!renameCommand!""' -Verb RunAs"
    endlocal
    exit /b
)


title Kraken Bypasser
echo [1;32mKraken Bypasser[0m
echo [33mThis tool is designed to [4mtry[0;33m to hide [95mTZ[33m from pc checks[0m
pause

@REM Delete browser's history, cache and cookies
:browser_consent
set /p delete_browser_consent=[34mDo you want to delete any browser's history, cache and cookies? (Y/N): [0m
set "delete_browser_consent=%delete_browser_consent:~0,1%"
if /i "%delete_browser_consent%" == "Y" (
    @REM Delete Chrome history, cache and cookies
    set /p delete_chrome_consent="[34mDo you want to delete Chrome's history, cache and cookies? (Y/N): [0m"
    set "delete_chrome_consent=%delete_chrome_consent:~0,1%"
    if /i "%delete_chrome_consent%" == "Y" (
        taskkill /f /im "chrome.exe" /t >nul
        echo [33mDeleting Chrome history[0m
        del /q "%LOCALAPPDATA%\Google\Chrome\User Data\Default\History"
        echo [95mChrome history deleted[0m
        echo [33mDeleting Chrome cache[0m
        del /q "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache"
        echo [95mChrome cache deleted[0m
        echo [33mDeleting Chrome cookies[0m
        del /q "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies"
        echo [95mChrome cookies deleted[0m
    )

    @REM Delete Opera history, cache and cookies
    set /p delete_opera_consent="[34mDo you want to delete Opera's history, cache and cookies? (Y/N): [0m"
    set "delete_opera_consent=%delete_opera_consent:~0,1%"
    if /i "%delete_opera_consent%" == "Y" (
        taskkill /f /im "opera.exe" /t >nul
        echo [33mDeleting Opera history[0m
        del /q "%APPDATA%\Opera Software\Opera GX Stable\History"
        echo [95mOpera history deleted[0m
        echo [33mDeleting Opera cache[0m
        del /q "%APPDATA%\Opera Software\Opera GX Stable\Cache"
        echo [95mOpera cache deleted[0m
        echo [33mDeleting Opera cookies[0m
        del /q "%APPDATA%\Opera Software\Opera GX Stable\Cookies"
        echo [95mOpera cookies deleted[0m
    )

    @REM Delete Edge history, cache and cookies
    set /p delete_edge_consent="[34mDo you want to delete Edge's history, cache and cookies? (Y/N): [0m"
    set "delete_edge_consent=%delete_edge_consent:~0,1%"
    if /i "%delete_edge_consent%" == "Y" (
        taskkill /f /im "edge.exe" /t >nul
        echo [33mDeleting Edge history[0m
        del /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History"
        echo [95mEdge history deleted[0m
        echo [33mDeleting Edge cache[0m
        del /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache"
        echo [95mEdge cache deleted[0m
        echo [33mDeleting Edge cookies[0m
        del /q "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies"
        echo [95mEdge cookies deleted[0m
    )
) else if /i "%delete_browser_consent%"=="N" (
    @REM Do nothing
) else (
    echo [31mInvalid input, please enter Y or N[0m
    goto browser_consent
)

@REM Delete TZ
if not exist chrome.exe (
    cls
    echo [95mTZ[33m was not found to delete ^(looking for "chrome.exe"^)[0m
) else (
    cls
    echo [33mDeleting [95mTZ[0m
    del chrome.exe
    echo [95mTZ deleted[0m
)


@REM Delete %temp%
echo [33mDeleting %%temp%%[0m
del /q "%TEMP%" >nul 2>&1
for /d %%x in ("%TEMP%\*") do (
    rmdir /s /q "%%x" >nul 2>&1
)
echo [95m%%temp%% deleted[0m


@REM Delete Recents folder
echo [33mDeleting Recents folder[0m
del /q "%APPDATA%\Microsoft\Windows\Recent" >nul 2>&1
del /q "%USERPROFILE%\Recent" >nul 2>&1
echo [95mRecents folder deleted[0m


@REM Delete Minidump folder
echo [33mDeleting minidump folder[0m
del /q "C:\Windows\Minidump"
echo [95mMinidump folder deleted[0m


@REM Delete Windows logs folder
echo [33mDeleting Windows logs folder[0m
del /q "C:\Windows\Logs"
echo [95mWindows logs folder deleted[0m


@REM Delete the jump list
echo [33mDeleting the jump list[0m
del /q "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*"
del /q "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*"
echo [95mJump list deleted[0m


@REM Delete Prefetch folder
echo [33mDeleting Prefetch folder[0m
del /q "C:\Windows\Prefetch\*" >nul 2>&1
echo [95mPrefetch folder deleted[0m


@REM Delete Recents registry
echo [33mDeleting Recents registery[0m
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /f /va >nul
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" /f /va >nul
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\exe" /f /va >nul
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /f /va >nul
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU" /f /va >nul
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f /va >nul
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched" /f /va >nul
@REM Set the permissions and revert them after deletion
set "mostRecentApplicationCommand=$regKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(''SOFTWARE\Microsoft\DirectInput\MostRecentApplication'',[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions); $acl = $regKey.GetAccessControl(); $rule=New-Object System.Security.AccessControl.RegistryAccessRule(''Administrators'', ''FullControl'', ''ContainerInherit, ObjectInherit'', ''None'', ''Allow''); $acl.SetAccessRule($rule); $regKey.SetAccessControl($acl)"
set "mostRecentApplicationResetCommand=$regKey=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(''SOFTWARE\Microsoft\DirectInput\MostRecentApplication'',[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions); $acl=$regKey.GetAccessControl(); $ruleToRemove=$acl.Access|Where-Object{ $_.RegistryRights -eq [System.Security.AccessControl.RegistryRights]::FullControl -and $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and $_.IdentityReference.Value -eq ''BUILTIN\Administrators'' -and $_.IsInherited -eq $false -and $_.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None }; if($ruleToRemove){$acl.RemoveAccessRule($ruleToRemove); $regKey.SetAccessControl($acl)}"
powershell -Command ^
    "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command ""%mostRecentApplicationCommand%""' -Verb RunAs -Wait"
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\DirectInput\MostRecentApplication" /f /va >nul
powershell -Command ^
    "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command ""%mostRecentApplicationResetCommand%""' -Verb RunAs"
reg delete "HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" /f /va >nul
@REM Set the permissions and revert them after deletion
setlocal enabledelayedexpansion
for /f "tokens=*" %%i in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s /f "*" /k 2^>nul') do (
    set "key=%%i"
    set "lastFour=!key:~-4!"
    if "!lastFour!"=="1001" (
        set "keyNoPrefix=!key:HKEY_LOCAL_MACHINE\=!"
        set "command=$regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(''!keyNoPrefix!'',[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions); $acl = $regKey.GetAccessControl(); $rule=New-Object System.Security.AccessControl.RegistryAccessRule(''Administrators'', ''FullControl'', ''ContainerInherit, ObjectInherit'', ''None'', ''Allow''); $acl.SetAccessRule($rule); $regKey.SetAccessControl($acl)"
        set "resetCommand=$regKey=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(''!keyNoPrefix!'',[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions); $acl=$regKey.GetAccessControl(); $ruleToRemove=$acl.Access|Where-Object{ $_.RegistryRights -eq [System.Security.AccessControl.RegistryRights]::FullControl -and $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and $_.IdentityReference.Value -eq ''BUILTIN\Administrators'' -and $_.IsInherited -eq $false -and $_.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None }; if($ruleToRemove){$acl.RemoveAccessRule($ruleToRemove); $regKey.SetAccessControl($acl)}"
        powershell -Command ^
            "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command ""!command!""' -Verb RunAs -Wait"
        reg delete !key! /f /va >nul
        powershell -Command ^
            "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command ""!resetCommand!""' -Verb RunAs"
    )
)
endlocal
echo [95mRecents registery deleted[0m


@REM Kill smartscreen.exe
echo [33mKilling smartscreen.exe[0m
:smartscreenLoop
tasklist /fi "imagename eq smartscreen.exe" 2>NUL | find /i "smartscreen.exe" >NUL
if not errorlevel 1 (
    taskkill /f /im smartscreen.exe >nul
    timeout /t 1 /nobreak >nul
    goto smartscreenLoop
)
echo [95msmartscreen.exe killed[0m


@REM Restart some of the svchost.exe processes
echo [33mRestarting svchost.exe processes[0m
for /F "tokens=2 delims=," %%i in ('tasklist /FI "IMAGENAME eq svchost.exe" /FO CSV /NH') do (
    setlocal enabledelayedexpansion
    set "pid=%%~i"
    set "pid=!pid:~1,-1!"
    taskkill /pid !pid! /f >nul 2>&1
    endlocal
)
start /b "svchost" "C:\Windows\System32\svchost.exe"
echo [95msvchost.exe processes restarted[0m


@REM Restart explorer.exe
echo [33mRestarting the explorer.exe process[0m
taskkill /f /im explorer.exe >nul
start explorer.exe
echo [95mexplorer.exe restarted[0m


@REM Restart the needed services
setlocal enabledelayedexpansion
set "services=sysmain WSearch PcaSvc DPS DiagTrack"
set "command=$service = Get-Service -Name ''%%S''; if ($service.Status -eq ''Running'') { Restart-Service -Name ''%%S'' -Force }"
for %%S in (%services%) do (
    echo [33mRestarting %%S
    powershell -Command ^
        "Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command ""$service = Get-Service -Name ''%%S''; if ($service.Status -eq ''Running'') { Restart-Service -Name ''%%S'' -Force }""' -Verb RunAs -Wait"
)
endlocal


echo [32mCleaning process done, try to make up a reason to why all your logs are empty to the person pc checking you
pause
@REM This file was made by OrdinaryDude2634 at Github and uploaded to Github
