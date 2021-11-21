$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Run script"
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","Don't run script"
$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

$result = $host.ui.PromptForChoice("", "
	This script will make changes on Your system. Make sure it is properly configured and 
	run it only if You know, what You are doing. Do You want to run it?`n`n", 
	$options, 1)
	
switch ($result)
{
  0{
    . ".\config.ps1"

	cd actions
	. ".\loadDefaultUser.ps1"

	if($removeApps)
	{
		Write-Host "Removing apps"
		. ".\removeApps.ps1"
	}
	if($disableFeatures)
	{
		Write-Host "Removing features"
		. ".\disableFeatures.ps1"
	}
	if($protectPrivacy)
	{
		Write-Host "Protecting privacy"
		. ".\protectPrivacy.ps1"
	}
	if($banHosts)
	{
		Write-Host "Banning hosts"
		. ".\banHosts.ps1"
	}
	if($disableServices)
	{
		Write-Host "Disabling services"
		. ".\disableServices.ps1"
	}

	. ".\unloadDefaultUser.ps1"
	Write-Host "Done"
	cd ..
  }
  1
  {
    return
  }
}
