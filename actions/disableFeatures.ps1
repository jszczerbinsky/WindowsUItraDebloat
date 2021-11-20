. ".\..\config.ps1"

foreach($feature in $featuresToDisable)
{
	Get-WindowsOptionalFeature -FeatureName $feature -Online | Where { $_.State -eq "Enabled" } | Disable-WindowsOptionalFeature -Online -NoRestart | Out-Null
}