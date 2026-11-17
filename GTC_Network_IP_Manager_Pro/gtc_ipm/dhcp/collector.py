"""Lecture DHCP en lecture seule (module DhcpServer / RSAT requis)."""
from __future__ import annotations

import ipaddress
import json

from ..core.models import DhcpData, DhcpLease, DhcpScope
from ..core.psrunner import SourceUnavailable, as_list, parse_json_list, ps_json, valid_host

SCRIPT_DHCP_SERVERS = r"""
$ErrorActionPreference='Stop'
Import-Module DhcpServer -ErrorAction Stop
Get-DhcpServerInDC | ForEach-Object { [pscustomobject]@{ Name=$_.DnsName; IP=$_.IPAddress.ToString() } } |
  ConvertTo-Json -Compress
"""

SCRIPT_DHCP_SERVER = r"""
$ErrorActionPreference='Stop'
Import-Module DhcpServer -ErrorAction Stop
$srv=$env:GTCARG_SERVER
$scopes=@(Get-DhcpServerv4Scope -ComputerName $srv -ErrorAction Stop)
$res = foreach ($sc in $scopes) {
  $errs=@()
  $ex=@(); $ls=@(); $rs=@(); $gw=''
  try { $ex=@(Get-DhcpServerv4ExclusionRange -ComputerName $srv -ScopeId $sc.ScopeId -ErrorAction Stop |
        ForEach-Object { [pscustomobject]@{Start=$_.StartRange.ToString();End=$_.EndRange.ToString()} }) } catch { $errs+="exclusions: $($_.Exception.Message)" }
  try { $ls=@(Get-DhcpServerv4Lease -ComputerName $srv -ScopeId $sc.ScopeId -ErrorAction Stop |
        ForEach-Object { [pscustomobject]@{IP=$_.IPAddress.ToString();Mac=$_.ClientId;Host=$_.HostName;State=[string]$_.AddressState;Expires=[string]$_.LeaseExpiryTime} }) } catch { $errs+="baux: $($_.Exception.Message)" }
  try { $rs=@(Get-DhcpServerv4Reservation -ComputerName $srv -ScopeId $sc.ScopeId -ErrorAction Stop |
        ForEach-Object { [pscustomobject]@{IP=$_.IPAddress.ToString();Mac=$_.ClientId;Host=$_.Name} }) } catch { $errs+="réservations: $($_.Exception.Message)" }
  try { $o=Get-DhcpServerv4OptionValue -ComputerName $srv -ScopeId $sc.ScopeId -OptionId 3 -ErrorAction Stop; $gw=[string]($o.Value -join ',') } catch {}
  [pscustomobject]@{ ScopeId=$sc.ScopeId.ToString(); Name=$sc.Name; Mask=$sc.SubnetMask.ToString()
    Start=$sc.StartRange.ToString(); End=$sc.EndRange.ToString(); State=[string]$sc.State
    Gateway=$gw; Exclusions=$ex; Leases=$ls; Reservations=$rs; Errors=$errs }
}
$res | ConvertTo-Json -Depth 5 -Compress
"""


def parse_servers(text: str) -> list[str]:
    out = []
    for d in parse_json_list(text):
        ip = str(d.get("IP") or "").strip()
        try:
            ip = str(ipaddress.IPv4Address(ip))
        except ValueError:
            ip = ""
        v = ip or str(d.get("Name") or "").strip()
        if v and v not in out:
            out.append(v)
    return out


def parse_server_scopes(server: str, text: str, data: DhcpData) -> None:
    for sc in parse_json_list(text):
        sid = str(sc.get("ScopeId") or "")
        scope = DhcpScope(server=server, scope_id=sid, name=str(sc.get("Name") or ""),
                          subnet_mask=str(sc.get("Mask") or ""), start=str(sc.get("Start") or ""),
                          end=str(sc.get("End") or ""), state=str(sc.get("State") or ""),
                          gateway=str(sc.get("Gateway") or ""))
        for e in as_list(sc.get("Exclusions")):
            if isinstance(e, dict) and e.get("Start") and e.get("End"):
                scope.exclusions.append((str(e["Start"]), str(e["End"])))
        data.scopes.append(scope)
        for key, resv in (("Leases", False), ("Reservations", True)):
            for l in as_list(sc.get(key)):
                if not isinstance(l, dict) or not l.get("IP"):
                    continue
                data.leases.append(DhcpLease(
                    server=server, scope_id=sid, ip=str(l["IP"]), mac=str(l.get("Mac") or ""),
                    hostname=str(l.get("Host") or ""),
                    state="ActiveReservation" if resv else str(l.get("State") or ""),
                    expires=str(l.get("Expires") or ""), reservation=resv))
        errs = [str(x) for x in as_list(sc.get("Errors"))]
        if errs:
            data.errors.append(f"{server} / {sid} : " + " ; ".join(errs))
        else:
            data.queried_scopes.add(f"{server}|{sid}")


def collect_dhcp(extra_servers: list[str]) -> DhcpData:
    data = DhcpData()
    servers: list[str] = []
    try:
        servers = parse_servers(json.dumps(ps_json(SCRIPT_DHCP_SERVERS, timeout=45)))
    except SourceUnavailable as e:
        data.errors.append(f"Annuaire des serveurs DHCP illisible : {e}")
    for s in extra_servers:
        if s and s not in servers:
            servers.append(s)
    data.servers = servers
    if not servers:
        raise SourceUnavailable("Aucun serveur DHCP identifié. " + " ".join(data.errors))
    ok = 0
    for srv in servers:
        try:
            host = srv
            try:
                host = str(ipaddress.IPv4Address(srv))
            except ValueError:
                host = valid_host(srv)
            parse_server_scopes(srv, json.dumps(ps_json(SCRIPT_DHCP_SERVER, {"SERVER": host}, 180)), data)
            ok += 1
        except (SourceUnavailable, ValueError) as e:
            data.errors.append(f"{srv} : {e}")
    if ok == 0:
        raise SourceUnavailable("Aucun serveur DHCP interrogeable en lecture. " + " | ".join(data.errors[:3]))
    return data
