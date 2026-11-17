"""Domaine Active Directory : détection et inventaire des ordinateurs (lecture seule).

Utilise ADSI/LDAP via PowerShell (aucun RSAT requis), avec les droits de la
session courante. Aucun identifiant n'est demandé ni stocké.
"""
from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from typing import Any, Optional

from ..core.models import AdComputer, DomainInfo
from ..core.psrunner import (SourceUnavailable, parse_json_list, ps_json,
                             valid_host)

SCRIPT_DOMAIN = r"""
$ErrorActionPreference='Stop'
$cs=Get-CimInstance Win32_ComputerSystem
[pscustomobject]@{ Name=$cs.Name; Domain=$cs.Domain; PartOf=[bool]$cs.PartOfDomain
  Role=[int]$cs.DomainRole; UserDnsDomain=$env:USERDNSDOMAIN; LogonServer=$env:LOGONSERVER } |
  ConvertTo-Json -Compress
"""

SCRIPT_SRV = r"""
$ErrorActionPreference='Stop'
Resolve-DnsName -Name ("_ldap._tcp.dc._msdcs." + $env:GTCARG_DOMAIN) -Type SRV -ErrorAction Stop |
  Where-Object { $_.Type -eq 'SRV' } |
  ForEach-Object { [pscustomobject]@{ Target=$_.NameTarget; Port=[int]$_.Port; Priority=[int]$_.Priority } } |
  ConvertTo-Json -Compress
"""

SCRIPT_AD_COMPUTERS = r"""
$ErrorActionPreference='Stop'
$s = [adsisearcher]'(&(objectCategory=computer)(objectClass=computer))'
$s.PageSize = 500
$s.ServerTimeLimit = New-TimeSpan -Seconds 90
[void]$s.PropertiesToLoad.AddRange(@('name','dnshostname','useraccountcontrol','lastlogontimestamp','operatingsystem','distinguishedname'))
$s.FindAll() | ForEach-Object {
  $p = $_.Properties
  [pscustomobject]@{ Name=[string](@($p['name'])[0]); Dns=[string](@($p['dnshostname'])[0])
    Uac=[int](@($p['useraccountcontrol'])[0]); Lls=[int64](@($p['lastlogontimestamp'])[0])
    Os=[string](@($p['operatingsystem'])[0]); Dn=[string](@($p['distinguishedname'])[0]) }
} | ConvertTo-Json -Compress
"""


def parse_domain(text: str) -> DomainInfo:
    items = parse_json_list(text)
    info = DomainInfo()
    if not items:
        info.evidence.append("Aucune information de domaine renvoyée par Windows.")
        return info
    d = items[0]
    dom = str(d.get("Domain") or "").strip()
    part = bool(d.get("PartOf"))
    env_dom = str(d.get("UserDnsDomain") or "").strip()
    if part and dom and "." in dom:
        info.in_domain, info.name = True, dom.lower()
        info.evidence.append(f"Win32_ComputerSystem : PartOfDomain=True, Domain={dom}")
        if env_dom and env_dom.lower() == dom.lower():
            info.evidence.append("USERDNSDOMAIN corrobore le domaine.")
        elif env_dom:
            info.evidence.append(f"USERDNSDOMAIN={env_dom} diffère du domaine machine (session locale ?).")
    elif part and dom:
        info.in_domain, info.name = True, dom.lower()
        info.evidence.append(f"Domaine NetBIOS « {dom} » (nom DNS non confirmé).")
    else:
        info.evidence.append("Ce poste n'est pas joint à un domaine (groupe de travail).")
    return info


def filetime_to_iso(v: Any) -> str:
    try:
        n = int(v)
    except (TypeError, ValueError):
        return ""
    if n <= 0 or n >= 0x7FFFFFFFFFFFFFFF:
        return ""
    try:
        dt = datetime.fromtimestamp((n - 116444736000000000) / 1e7, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    return dt.isoformat(timespec="seconds")


def parse_ad_computers(text: str, domain: str = "") -> list[AdComputer]:
    out = []
    for d in parse_json_list(text):
        name = str(d.get("Name") or "").strip()
        if not name:
            continue
        uac = d.get("Uac")
        dns = str(d.get("Dns") or "").strip().lower()
        out.append(AdComputer(
            name=name, dns_hostname=dns or (f"{name.lower()}.{domain}" if domain else ""),
            enabled=None if uac is None else not (int(uac) & 2),
            last_logon=filetime_to_iso(d.get("Lls")), os=str(d.get("Os") or ""),
            distinguished_name=str(d.get("Dn") or "")))
    return sorted(out, key=lambda c: c.name.lower())


def parse_srv(text: str) -> list[str]:
    seen, out = set(), []
    for d in sorted(parse_json_list(text), key=lambda x: int(x.get("Priority") or 0)):
        t = str(d.get("Target") or "").rstrip(".").lower()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out


def collect_domain() -> DomainInfo:
    info = parse_domain(json.dumps(ps_json(SCRIPT_DOMAIN, timeout=45)))
    if info.in_domain and "." in info.name:
        try:
            targets = parse_srv(json.dumps(ps_json(SCRIPT_SRV, {"DOMAIN": valid_host(info.name)}, 45)))
            info.domain_controllers = targets
            info.evidence.append(f"SRV _ldap._tcp.dc._msdcs.{info.name} : {len(targets)} contrôleur(s).")
            for t in targets:
                try:
                    for ai in socket.getaddrinfo(t, None, socket.AF_INET, socket.SOCK_STREAM):
                        ip = ai[4][0]
                        if ip not in info.dc_addresses:
                            info.dc_addresses.append(ip)
                except OSError:
                    info.evidence.append(f"Le contrôleur {t} ne se résout pas en IPv4.")
        except SourceUnavailable as e:
            info.evidence.append(f"Requête SRV impossible : {e}")
    return info


def collect_ad_computers(domain: DomainInfo, server: Optional[str] = None) -> list[AdComputer]:
    if not domain.in_domain:
        raise SourceUnavailable("Poste hors domaine : inventaire AD non réalisé "
                                "(aucun identifiant n'est demandé par l'application).")
    return parse_ad_computers(json.dumps(ps_json(SCRIPT_AD_COMPUTERS, timeout=150)), domain.name)


def tcp_check(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def stale(last_logon_iso: str, days: int) -> bool:
    if not last_logon_iso:
        return False
    try:
        dt = datetime.fromisoformat(last_logon_iso)
    except ValueError:
        return False
    return (datetime.now(timezone.utc) - dt).days > days
