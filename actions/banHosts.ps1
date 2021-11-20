. ".\..\config.ps1"

$content = Get-Content "$ENV:SYSTEMROOT\System32\drivers\etc\hosts"

if( -not ($content | Select-String "Banned hosts"))
{
	Add-Content -Path  "$ENV:SYSTEMROOT\System32\drivers\etc\hosts" "`n`n============== Banned hosts ==============`n"
	
	foreach($h in $hostsToBan)
	{
		if( -not ($content | Select-String $h))
		{
			Add-Content -Path  "$ENV:SYSTEMROOT\System32\drivers\etc\hosts" "	127.0.0.1	$h"
		}
	}
}