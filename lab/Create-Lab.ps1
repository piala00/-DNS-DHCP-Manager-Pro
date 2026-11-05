#requires -RunAsAdministrator
param(
 [string]$LabRoot = 'C:\DNS-DHCP-Lab',
 [string]$SwitchName = 'DNS-DHCP-LAB-ISOLATED',
 [string]$ServerIso = '',
 [string]$ClientIso = ''
)
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop
New-Item -ItemType Directory -Force -Path $LabRoot | Out-Null
if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
 New-VMSwitch -Name $SwitchName -SwitchType Private | Out-Null
}
$machines = @(
 @{Name='LAB-DC01';Memory=4GB;Disk=80GB;Iso=$ServerIso},
 @{Name='LAB-CLIENT01';Memory=4GB;Disk=64GB;Iso=$ClientIso}
)
foreach ($m in $machines) {
 if (Get-VM -Name $m.Name -ErrorAction SilentlyContinue) {
  Write-Host "Existing VM: $($m.Name) - no changes made"
  continue
 }
 $disk = Join-Path $LabRoot "$($m.Name).vhdx"
 New-VM -Name $m.Name -Generation 2 -MemoryStartupBytes $m.Memory -NewVHDPath $disk -NewVHDSizeBytes $m.Disk -SwitchName $SwitchName -Path $LabRoot | Out-Null
 Set-VMProcessor -VMName $m.Name -Count 2
 if ($m.Iso) {
  if (-not (Test-Path $m.Iso)) { throw "ISO not found: $($m.Iso)" }
  Add-VMDvdDrive -VMName $m.Name -Path $m.Iso
  $dvd = Get-VMDvdDrive -VMName $m.Name
  Set-VMFirmware -VMName $m.Name -FirstBootDevice $dvd
 }
 Write-Host "Created $($m.Name); install Windows manually from ISO, then use guest scripts."
}
Write-Host "Lab created with PRIVATE virtual switch; no external network connection."
