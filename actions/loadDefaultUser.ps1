Write-Host "Loading default user registry branch"
	
	Reg Load HKLM\DefaultUser C:\Users\Default\NTUSER.DAT | Out-Null