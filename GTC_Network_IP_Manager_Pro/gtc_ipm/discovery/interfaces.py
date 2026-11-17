"""Interfaces et routes IPv4 locales (lecture seule)."""
from __future__ import annotations

import ipaddress
from typing import Any

from ..core.models import Interface, Route
from ..core.psrunner import as_list, parse_json_list, ps_json

SCRIPT_INTERFACES = r"""
$ErrorActionPreference='Stop'
$alias=@{}
try { Get-NetAdapter -ErrorAction Stop | ForEach-Object { $alias[[int]$_.ifIndex]=$_.Name } } catch {}
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" | ForEach-Object {
  [pscustomobject]@{
    Alias=$alias[[int]$_.InterfaceIndex]; Description=$_.Description; Mac=$_.MACAddress
    IPAddress=@($_.IPAddress); IPSubnet=@($_.IPSubnet); Gateway=@($_.DefaultIPGateway)
    Dns=@($_.DNSServerSearchOrder); DhcpEnabled=[bool]$_.DHCPEnabled
    DhcpServer=$_.DHCPServer; Suffix=$_.DNSDomain }
} | ConvertTo-Json -Depth 4 -Compress
"""

SCRIPT_ROUTES = r"""
$ErrorActionPreference='Stop'
Get-NetRoute -AddressFamily IPv4 | Where-Object {
  $_.DestinationPrefix -notlike '224.*' -and $_.DestinationPrefix -ne '255.255.255.255/32' -and
  $_.DestinationPrefix -notlike '127.*' -and $_.DestinationPrefix -notlike '169.254.*' } |
  ForEach-Object { [pscustomobject]@{ Destination=$_.DestinationPrefix; NextHop=$_.NextHop
  Metric=[int]$_.RouteMetric; Interface=$_.InterfaceAlias } } | ConvertTo-Json -Compress
"""


def _v4(value: Any) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ValueError:
        return ""


def _prefix(mask: Any) -> int:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return -1


def parse_interfaces(text: str) -> list[Interface]:
    out: list[Interface] = []
    for d in parse_json_list(text):
        ips = [_v4(x) for x in as_list(d.get("IPAddress"))]
        masks = as_list(d.get("IPSubnet"))
        gws = [g for g in (_v4(x) for x in as_list(d.get("Gateway"))) if g]
        dns = [x for x in (_v4(y) for y in as_list(d.get("Dns"))) if x]
        for i, ip in enumerate(ips):
            if not ip or ip.startswith("169.254."):
                continue
            pre = _prefix(masks[i]) if i < len(masks) else -1
            if not 1 <= pre <= 32:
                continue
            out.append(Interface(
                alias=str(d.get("Alias") or d.get("Description") or "Interface"),
                ipv4=ip, prefix=pre, mac=str(d.get("Mac") or ""),
                gateway=gws[0] if gws else "", dns_servers=dns,
                dhcp_enabled=bool(d.get("DhcpEnabled")),
                dhcp_server=_v4(d.get("DhcpServer")) if d.get("DhcpServer") else "",
                dns_suffix=str(d.get("Suffix") or "")))
    return out


def parse_routes(text: str) -> list[Route]:
    out = []
    for d in parse_json_list(text):
        try:
            net = ipaddress.ip_network(str(d.get("Destination")), strict=False)
        except ValueError:
            continue
        out.append(Route(str(net), str(d.get("NextHop") or ""), int(d.get("Metric") or 0),
                         str(d.get("Interface") or "")))
    return out


def collect_interfaces() -> list[Interface]:
    return parse_interfaces_from(ps_json(SCRIPT_INTERFACES, timeout=45))


def parse_interfaces_from(items: list[dict]) -> list[Interface]:
    import json
    return parse_interfaces(json.dumps(items))


def collect_routes() -> list[Route]:
    import json
    return parse_routes(json.dumps(ps_json(SCRIPT_ROUTES, timeout=45)))
