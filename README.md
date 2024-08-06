## How does it work?
It works by deleting some log files and restarting processes to make the pc check harder, however do note it does not guarantee bypassing as i might have missed some things or the person checking might simply conclude you are guilty because of being too suspicious(e.g. having cleared logs)

Here's a list of what it does in order
* Delete Chrome history, cache and cookies
* Delete TZ *(looks for any file named "chrome.exe" in the same directory)*
* Delete %temp%
* Delete Recents folder
* * %APPDATA%\Microsoft\Windows\Recent
* * %USERPROFILE%\Recent
* Delete Minidump folder
* * C:\Windows\Minidump
* Delete Windows logs folder
* * C:\Windows\Logs
* Delete the jump list
* * %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations
* * %APPDATA%\Microsoft\Windows\Recent\CustomDestinations
* Delete Prefetch folder
* * C:\Windows\Prefetch
* Delete Recents registery
* * HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
* * HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store
* * HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\exe
* * HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
* * HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU
* * HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
* * HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched
* * HKEY_CURRENT_USER\SOFTWARE\Microsoft\DirectInput\MostRecentApplication
* * HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
* * HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings *(any subkey inside it that ends with "1001")*
* Kill smartscreen.exe
* Restart some of the svchost.exe processes *(tries to restart all of them but some are critical processes and cannot be restarted)*
* Restart explorer.exe process
* Restart the needed services
* * sysmain
* * WSearch
* * PcaSvc
* * DPS
* * DiagTrack

## Why only TZ?
Because i only had access to that to test and develop on and it's decently legit for pvp and such

I do realize TZX is known to be better for legit pvp but as i said, i did not have access to it
