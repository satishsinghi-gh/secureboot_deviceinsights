# ================== CONFIG ==================
 
$RegPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
 
$ValueName = "AvailableUpdates"
 
$HexValue  = 0x5944
 
# ============================================
 
# Ensure registry path exists
 
if (-not (Test-Path $RegPath)) {
 
    New-Item -Path $RegPath -Force | Out-Null
 
}
 
# Set DWORD value
 
New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType DWord -Value $HexValue -Force | Out-Null
