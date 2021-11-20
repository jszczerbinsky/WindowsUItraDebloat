. ".\..\config.ps1"

foreach($app in $appsToRemove)
{
	Write-Host "Removing $app"
	Get-AppxPackage -AllUsers $app | Remove-AppxPackage | Out-Null
	Get-AppxProvisionedPackage -Online | Where{ $_.DisplayName -eq $app } | Remove-AppxProvisionedPackage -Online
}


if($removeAppsFromRegistry -eq 1)
{
	
	Write-Host "Removing random apps registry keys"
	foreach ($key in $appKeysToRemove)
	{
		Remove-Item $key -Recurse -ErrorAction SilentlyContinue
	}
}

if($blockContentDelivery -eq 1)
{
	Write-Host "Disabling content delivery"
	
	Set-ItemProperty -Path  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2
	Set-ItemProperty -Path  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1
	
	Stop-Process -Name explorer -Force
	Remove-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore" -Recurse -Force -ErrorAction SilentlyContinue
	Start-Process Explorer.exe -Wait
	
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "FeatureManagementEnabled" -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled" -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0
	
	if($applyChangesToDefaultUser -eq 1)
	{
		Remove-Item "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore" -Recurse -Force -ErrorAction SilentlyContinue
		
		Set-ItemProperty -Path "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value 0
		Set-ItemProperty -Path "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "FeatureManagementEnabled" -Value 0
		Set-ItemProperty -Path "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Value 0
		Set-ItemProperty -Path "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value 0
		Set-ItemProperty -Path "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Value 0
		Set-ItemProperty -Path "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value 0
		Set-ItemProperty -Path "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Value 0
		Set-ItemProperty -Path "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Value 0
		Set-ItemProperty -Path "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0
		Set-ItemProperty -Path "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0
		Set-ItemProperty -Path "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0
		Set-ItemProperty -Path "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled" -Value 0
		Set-ItemProperty -Path "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0
	}
}