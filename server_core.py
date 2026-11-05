"""Backend testable for Windows Server role inspection and guarded configuration."""
import ipaddress
import json
import re
import subprocess

ROLE_NAMES = ("AD-Domain-Services", "DNS", "DHCP")

def validate_ipv4(value):
    address = ipaddress.ip_address(value)
    if not isinstance(address, ipaddress.IPv4Address) or address.is_multicast or address.is_unspecified or address.is_loopback:
        raise ValueError("Adresse IPv4 invalide")
    return str(address)

def validate_domain(value):
    value = value.strip().lower()
    if len(value) > 253 or "." not in value or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
        for part in value.split(".")
    ):
        raise ValueError("Nom de domaine DNS invalide")
    return value

def validate_scope(network, start, end, exclusions=()):
    subnet = ipaddress.IPv4Network(network, strict=True)
    first, last = ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
    if first not in subnet or last not in subnet or first > last:
        raise ValueError("Plage DHCP hors du sous-réseau")
    if first in (subnet.network_address, subnet.broadcast_address) or last in (subnet.network_address, subnet.broadcast_address):
        raise ValueError("Plage DHCP contient une adresse réservée")
    for excluded in exclusions:
        addr = ipaddress.IPv4Address(excluded)
        if first <= addr <= last:
            raise ValueError("La plage DHCP inclut une adresse exclue")
    return {"network": str(subnet), "start": str(first), "end": str(last)}

def run_ps(script, timeout=60, runner=None):
    runner = runner or subprocess.run
    p = runner(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
               capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(p.stderr.strip() or "PowerShell a échoué")
    return p.stdout.strip()

def inspect(kind, runner=None):
    scripts = {
        "network": r"""$ErrorActionPreference='Stop'
Get-NetIPConfiguration | Where-Object IPv4Address | Select-Object InterfaceAlias,@{N='IP';E={$_.IPv4Address.IPAddress}},@{N='Prefix';E={$_.IPv4Address.PrefixLength}},@{N='Gateway';E={$_.IPv4DefaultGateway.NextHop}} | ConvertTo-Json -Depth 5 -Compress""",
        "ad": r"""$ErrorActionPreference='Stop'
$r=[ordered]@{Computer=$env:COMPUTERNAME;DomainJoined=$false;Domain=$null;Forest=$null;DomainController=$false;Error=$null}
try {$c=Get-CimInstance Win32_ComputerSystem; $r.DomainJoined=[bool]$c.PartOfDomain; $r.Domain=$c.Domain} catch {$r.Error=$_.Exception.Message}
try {Import-Module ActiveDirectory -ErrorAction Stop; $d=Get-ADDomain -ErrorAction Stop; $r.Domain=$d.DNSRoot; $r.Forest=$d.Forest; $r.DomainController=[bool](Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction SilentlyContinue)} catch {$r.Error=$_.Exception.Message}
[pscustomobject]$r | ConvertTo-Json -Depth 6 -Compress""",
        "dns": r"""$ErrorActionPreference='Stop'
$r=[ordered]@{Service='DNS';Status=$null;Zones=@();Error=$null}
try {$r.Status=(Get-Service DNS -ErrorAction Stop).Status.ToString(); Import-Module DnsServer -ErrorAction Stop; $r.Zones=@(Get-DnsServerZone -ErrorAction Stop | Select-Object ZoneName,ZoneType,IsDsIntegrated)} catch {$r.Error=$_.Exception.Message}
[pscustomobject]$r | ConvertTo-Json -Depth 6 -Compress""",
        "dhcp": r"""$ErrorActionPreference='Stop'
$r=[ordered]@{Service='DHCP';Status=$null;Scopes=@();AuthorizedServers=@();Error=$null}
try {$r.Status=(Get-Service DHCPServer -ErrorAction Stop).Status.ToString(); Import-Module DhcpServer -ErrorAction Stop; $r.Scopes=@(Get-DhcpServerv4Scope -ErrorAction Stop | Select-Object ScopeId,Name,StartRange,EndRange,State); $r.AuthorizedServers=@(Get-DhcpServerInDC -ErrorAction SilentlyContinue | Select-Object DnsName,IPAddress)} catch {$r.Error=$_.Exception.Message}
[pscustomobject]$r | ConvertTo-Json -Depth 6 -Compress"""
    }
    if kind not in scripts:
        raise ValueError("Module inconnu")
    raw = run_ps(scripts[kind], runner=runner)
    return json.loads(raw) if raw else []

def check_roles(runner=None):
    script = """$ErrorActionPreference='Stop'
Import-Module ServerManager -ErrorAction Stop
Get-WindowsFeature -Name AD-Domain-Services,DNS,DHCP | Select-Object Name,Installed | ConvertTo-Json -Compress"""
    return json.loads(run_ps(script, runner=runner))

def plan_scope(network, start, end, server_ip):
    server_ip = validate_ipv4(server_ip)
    scope = validate_scope(network, start, end, (server_ip,))
    return {**scope, "server_ip": server_ip, "mode": "PREVIEW_ONLY"}

def export_report(data, path):
    from pathlib import Path
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
