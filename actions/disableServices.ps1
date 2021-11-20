. ".\..\config.ps1"

foreach($s in $servicesToDiable)
{
	Get-Service -Name $s -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled | Out-Null
	Stop-Service -Name $s -ErrorAction SilentlyContinue | Out-Null
}