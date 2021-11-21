## Fast script download

Run PowerShell as administrator and paste this to download, configure and run script:

```
mkdir "$ENV:TEMP\UltraDebloater"
mkdir "$ENV:TEMP\UltraDebloater\actions"
cd "$ENV:TEMP\UltraDebloater"
Invoke-RestMethod -Uri "https://github.com/jszczerbinsky/WindowsUItraDebloat/archive/refs/heads/main.zip" -OutFile "downloaded.zip"
Expand-Archive -Path ".\downloaded.zip" -DestinationPath "."
cd "WindowsUItraDebloat-main"
notepad.exe config.ps1
Set-ExecutionPolicy -Scope CurrentUser Unrestricted
.\UltraDebloat.ps1
cd ..\..
rm -r "$ENV:TEMP\UltraDebloater"
```
