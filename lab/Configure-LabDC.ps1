#requires -RunAsAdministrator
# LAB ONLY: run inside LAB-DC01 after Windows Server installation.
# Creates a test domain controller. NEVER run on a production server.
param(
 [string]$DomainName = 'lab.example.test',
 [string]$NetbiosName = 'LAB',
 [string]$ServerIP = '10.77.0.10',
 [int]$PrefixLength = 24,
 [string]$DhcpStart = '10.77.0.100',
 [string]$DhcpEnd = '10.77.0.200',
 [switch]$ConfigureNetwork,
 [switch]$InstallRoles,
 [switch]$PromoteForest,
 [switch]$ConfigureDhcp
)
$ErrorActionPreference='Stop'
if ($env:COMPUTERNAME -ne 'LAB-DC01') { throw 'Safety guard: this script must run on LAB-DC01.' }
if ($ConfigureNetwork) {
 $adapters = @(Get-NetAdapter | Where-Object Status -eq 'Up')
 if ($adapters.Count -ne 1) { throw 'Expected exactly one connected network adapter in the isolated VM.' }
 $nic = $adapters[0]
 Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object PrefixOrigin -ne 'WellKnown' | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
 New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $ServerIP -PrefixLength $PrefixLength -ErrorAction Stop
 Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $ServerIP
}
if ($InstallRoles) {
 Install-WindowsFeature AD-Domain-Services,DNS,DHCP -IncludeManagementTools -ErrorAction Stop | Format-List
}
if ($PromoteForest) {
 if (-not (Get-WindowsFeature AD-Domain-Services).Installed) { throw 'Install AD DS role first.' }
 $pwd = Read-Host 'Enter DSRM password' -AsSecureString
 Install-ADDSForest -DomainName $DomainName -DomainNetbiosName $NetbiosName -InstallDNS -SafeModeAdministratorPassword $pwd -Force -NoRebootOnCompletion:$false
}
if ($ConfigureDhcp) {
 Import-Module DhcpServer -ErrorAction Stop
 if (-not (Get-ADDomain -ErrorAction SilentlyContinue)) { throw 'Domain must exist before DHCP authorization.' }
 if (-not (Get-DhcpServerv4Scope -ScopeId '10.77.0.0' -ErrorAction SilentlyContinue)) {
  Add-DhcpServerv4Scope -Name 'LAB isolated scope' -StartRange $DhcpStart -EndRange $DhcpEnd -SubnetMask '255.255.255.0' -State Active
 }
 Set-DhcpServerv4OptionValue -ScopeId '10.77.0.0' -DnsServer $ServerIP -DnsDomain $DomainName
 Add-DhcpServerInDC -DnsName "$env:COMPUTERNAME.$DomainName" -IPAddress $ServerIP -ErrorAction Stop
}
Write-Host 'Requested stage finished; inspect event logs and run verification.'
