. ".\..\config.ps1"

if($disalbeTelemetry -eq 1)
{
	New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "CommercialIdPolicy" -Value 0 -Type DWORD  -Force -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0

	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	
	New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force -ErrorAction SilentlyContinue | Out-Null																																																							
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value 0 -Type DWORD  -Force -ErrorAction SilentlyContinue | Out-Null																									
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Value 1 -Type DWORD  -Force -ErrorAction SilentlyContinue | Out-Null														
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableExperimentation" -Value 0 -Type DWORD  -Force -ErrorAction SilentlyContinue | Out-Null
	
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWORD -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CorporateSQM" -Type DWORD -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Type DWORD -Value 1  -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWORD -Value 1  -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWORD -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type DWORD -Value 1  -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\Software\Policies\Microsoft\InternetManagement" -Name "RestrictCommunication"  -Type DWORD -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing"  -Type DWORD -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -Type DWORD -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWORD -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Type DWORD -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWORD -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWORD -Value 1  -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendGenericDriverNotFoundToWER"  -Type DWORD -Value 1  -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableSendRequestAdditionalSoftwareToWER"  -Type DWORD -Value 1  -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "AllowRemoteRPC"  -Type DWORD -Value 1  -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWORD  -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Type DWORD  -Value 1 -Force -ErrorAction SilentlyContinue  | Out-Null
	New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Type DWORD  -Value 1 -Force -ErrorAction SilentlyContinue  | Out-Null
	New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" -Name "Start" -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" -Name "Start" -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting"  -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" -Name "UserAuthPolicy" -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" -Name "BluetoothPolicy" -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
	
	Get-ScheduledTask | Where {$_.State -eq "Ready"} | Where {$_.TaskName -Like "*Telemetry*"} | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
}
if($disableWindowsFeedback -eq 1)
{
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWORD -Force -ErrorAction SilentlyContinue | Out-Null
	
	New-Item "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWORD -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-ItemProperty "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name 'PeriodInNanoSeconds' -Force -ErrorAction SilentlyContinue  | Out-Null
	
	if($applyChangesToDefaultUser -eq 1)
	{
		New-Item "HKLM:\DefaultUser\SOFTWARE\Microsoft\Siuf\Rules" -Force -ErrorAction SilentlyContinue | Out-Null
		New-ItemProperty "HKLM:\DefaultUser\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWORD -Force -ErrorAction SilentlyContinue | Out-Null
		Remove-ItemProperty "HKLM:\DefaultUser\SOFTWARE\Microsoft\Siuf\Rules" -Name 'PeriodInNanoSeconds' -Force -ErrorAction SilentlyContinue  | Out-Null
	}
	
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}
if($disableCortana -eq 1)
{
	New-Item "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -Type DWORD  -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language"  -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" -Name "Enabled" -Value 0 -Type DWORD  -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -Type DWORD  -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -Type DWORD -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -Type DWORD  -Force -ErrorAction SilentlyContinue | Out-Null
	
	if($applyChangesToDefaultUser -eq 1)
	{
		New-Item "HKLM:\DefaultUser\SOFTWARE\Microsoft\Personalization\Settings" -Force -ErrorAction SilentlyContinue | Out-Null
		New-ItemProperty "HKLM:\DefaultUser\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -Type DWORD  -Force -ErrorAction SilentlyContinue | Out-Null
		New-Item "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language"  -Force -ErrorAction SilentlyContinue | Out-Null
		New-ItemProperty "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" -Name "Enabled" -Value 0 -Type DWORD  -Force -ErrorAction SilentlyContinue | Out-Null
		New-ItemProperty "HKLM:\DefaultUser\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 -Type DWORD  -Force -ErrorAction SilentlyContinue | Out-Null
		New-ItemProperty "HKLM:\DefaultUser\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 -Type DWORD -Force -ErrorAction SilentlyContinue | Out-Null
		New-Item "HKLM:\DefaultUser\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force -ErrorAction SilentlyContinue | Out-Null
		New-ItemProperty "HKLM:\DefaultUser\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -Type DWORD  -Force -ErrorAction SilentlyContinue | Out-Null
	}
}
if($disableInkingAndTypingPersonalization -eq 1)
{
	New-Item "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enable" -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
	
	if($applyChangesToDefaultUser -eq 1)
	{
		New-Item "HKLM:\DefaultUser\SOFTWARE\Microsoft\Input\TIPC" -Force -ErrorAction SilentlyContinue | Out-Null
		New-ItemProperty "HKLM:\DefaultUser\SOFTWARE\Microsoft\Input\TIPC" -Name "Enable" -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
	}
 
}
if($disableBackgroundApps -eq 1)
{
	if(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")
    {
		Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | %{
			New-ItemProperty $_.PSPath -Name "Disabled" -Type DWORD  -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			New-ItemProperty $_.PSPath -Name "DisabledByUser" -Type DWORD  -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
		}
	}
	
	if(($applyChangesToDefaultUser -eq 1) -and (Test-Path "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"))
    {
		Get-ChildItem "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | %{
			New-ItemProperty $_.PSPath -Name "Disabled" -Type DWORD  -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
			New-ItemProperty $_.PSPath -Name "DisabledByUser" -Type DWORD  -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
		}
	}
}
if($disableAdID -eq 1)
{
	New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null  
	
	if($applyChangesToDefaultUser -eq 1)
	{
		New-Item "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force -ErrorAction SilentlyContinue | Out-Null
		New-ItemProperty "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
		New-Item "HKLM:\DefaultUser\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Force -ErrorAction SilentlyContinue | Out-Null
		New-ItemProperty "HKLM:\DefaultUser\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name Enabled -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null  
	}
 
}
if($disableSmartScreenFilter -eq 1)
{
	New-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null      
    New-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name AllowTelemetry  -Type DWORD -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null  
    New-ItemProperty "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name AllowTelemetry  -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null 

	if($applyChangesToDefaultUser -eq 1)
	{
		New-ItemProperty "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null      
		New-ItemProperty "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name AllowTelemetry  -Type DWORD -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null  
		New-ItemProperty "HKLM:\DefaultUser\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name AllowTelemetry  -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null  	
	}
}
if($disableP2PdeliveryOptimizationOutsideLAN -eq 1)
{
	New-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name SystemSettingsDownloadMode -Type DWORD  -Value 0 -Force -ErrorAction SilentlyContinue  | Out-Null
	
	if($applyChangesToDefaultUser -eq 1)
	{
		New-ItemProperty "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name SystemSettingsDownloadMode -Type DWORD  -Value 0 -Force -ErrorAction SilentlyContinue  | Out-Null
	}
}
if($disableWifiSense -eq 1)
{
	New-ItemProperty "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" -Name "WiFiSenseCredShared" -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" -Name "WiFiSenseOpen" -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null
}
if($disableCollectingActivity -eq 1)
{
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null
}
if($disableLocationTelemetry -eq 1)
{
	New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny"  -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null
}
if($blockPersonalizedContent -eq 1)
{
	New-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1  -Force -ErrorAction SilentlyContinue | Out-Null
	if($applyChangesToDefaultUser -eq 1)
	{
		New-ItemProperty "HKLM:\DefaultUser\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1  -Force -ErrorAction SilentlyContinue | Out-Null
	}
}
if($blockErrorReporting -eq 1)
{
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}
if($blockDiagnosticTracker -eq 1)
{
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled
}
if($blockRemoteAssistance -eq 1)
{
	New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null
}
if($blockStorageSense -eq 1)
{
	Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\DefaultUser\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled
}
if($blockAutomaticMapsUpdate -eq 1)
{
	New-ItemProperty "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Value 0  -Force -ErrorAction SilentlyContinue | Out-Null
}
if($disableOneDriveSync -eq 1)
{
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWORD -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null	
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableLibrariesDefaultSaveToOneDrive" -Type DWORD -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
	New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -Type DWORD -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
}