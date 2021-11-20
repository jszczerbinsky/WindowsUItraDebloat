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