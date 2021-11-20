Write-Host "Unloading default user registry branch"

[gc]::Collect()
Reg Unload HKLM\DefaultUser | Out-Null
$done = $?

if (!$done) {
  Write-Warning "Failed to unload default user registry branch, do it manually"
}