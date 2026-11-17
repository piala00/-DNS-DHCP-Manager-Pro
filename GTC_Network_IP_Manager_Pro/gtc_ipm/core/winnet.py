"""Détection native Windows (ctypes, registre, route/arp) : rapide, sans PowerShell.

PowerShell peut être très lent (antivirus, WMI dégradé). Ces fonctions sont donc la
voie principale pour interfaces, routes, domaine et voisinage ; PowerShell ne sert
que de complément.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import sys
from typing import Optional

from .models import DomainInfo, Interface, Route
from .psrunner import SourceUnavailable

IS_WINDOWS = sys.platform == "win32"
_ROUTE_RE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s*$")


def _need_windows() -> None:
    if not IS_WINDOWS:
        raise SourceUnavailable("Fonction native Windows indisponible sur ce système.")


def _flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _valid_v4(s: str) -> Optional[str]:
    try:
        a = ipaddress.IPv4Address(s)
    except ValueError:
        return None
    return None if str(a) == "0.0.0.0" else str(a)


def parse_route_print(text: str) -> list[Route]:
    """Parse la sortie de `route print -4` (lignes numériques, indépendantes de la langue)."""
    out: list[Route] = []
    seen = set()
    for ln in text.splitlines():
        m = _ROUTE_RE.match(ln)
        if not m:
            continue
        dest, mask, gw, ifc, metric = m.groups()
        try:
            net = ipaddress.ip_network(f"{dest}/{mask}", strict=False)
        except ValueError:
            continue
        if (net.is_multicast or net.is_loopback or net.is_link_local
                or str(net) == "255.255.255.255/32"):
            continue
        hop = "" if gw.lower().startswith("on") or not _valid_v4(gw) else gw
        key = (str(net), hop, ifc)
        if key in seen:
            continue
        seen.add(key)
        out.append(Route(str(net), hop, int(metric), ifc))
    return out


def collect_routes_native() -> list[Route]:
    _need_windows()
    try:
        p = subprocess.run(["route", "print", "-4"], capture_output=True, timeout=20,
                           creationflags=_flags(), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SourceUnavailable(f"route print impossible : {e}") from e
    return parse_route_print(p.stdout.decode("cp850", errors="replace"))


def _ip_list(node) -> list[tuple[str, str]]:
    res = []
    while node:
        ip = node.IpAddress.split(b"\0")[0].decode("ascii", "ignore")
        mask = node.IpMask.split(b"\0")[0].decode("ascii", "ignore")
        res.append((ip, mask))
        node = node.Next.contents if node.Next else None
    return res


def global_dns_servers() -> list[str]:
    """Serveurs DNS configurés (GetNetworkParams)."""
    _need_windows()
    import ctypes
    from ctypes import POINTER, Structure, byref, c_char, c_ulong, c_uint, windll

    class IP_ADDR_STRING(Structure):
        pass
    IP_ADDR_STRING._fields_ = [("Next", POINTER(IP_ADDR_STRING)), ("IpAddress", c_char * 16),
                               ("IpMask", c_char * 16), ("Context", c_ulong)]

    class FIXED_INFO(Structure):
        _fields_ = [("HostName", c_char * 132), ("DomainName", c_char * 132),
                    ("CurrentDnsServer", POINTER(IP_ADDR_STRING)), ("DnsServerList", IP_ADDR_STRING),
                    ("NodeType", c_uint), ("ScopeId", c_char * 260), ("EnableRouting", c_uint),
                    ("EnableProxy", c_uint), ("EnableDns", c_uint)]
    size = c_ulong(0)
    windll.iphlpapi.GetNetworkParams(None, byref(size))
    buf = ctypes.create_string_buffer(size.value)
    if windll.iphlpapi.GetNetworkParams(buf, byref(size)) != 0:
        return []
    info = ctypes.cast(buf, POINTER(FIXED_INFO)).contents
    out = []
    for ip, _ in _ip_list(info.DnsServerList):
        v = _valid_v4(ip)
        if v and v not in out:
            out.append(v)
    return out


def collect_interfaces_native() -> list[Interface]:
    """Interfaces IPv4 via GetAdaptersInfo (adresse, masque, passerelle, DHCP, MAC)."""
    _need_windows()
    import ctypes
    from ctypes import POINTER, Structure, byref, c_char, c_int, c_ubyte, c_uint, c_ulong, c_ulonglong, windll

    class IP_ADDR_STRING(Structure):
        pass
    IP_ADDR_STRING._fields_ = [("Next", POINTER(IP_ADDR_STRING)), ("IpAddress", c_char * 16),
                               ("IpMask", c_char * 16), ("Context", c_ulong)]

    class IP_ADAPTER_INFO(Structure):
        pass
    IP_ADAPTER_INFO._fields_ = [
        ("Next", POINTER(IP_ADAPTER_INFO)), ("ComboIndex", c_ulong), ("AdapterName", c_char * 260),
        ("Description", c_char * 132), ("AddressLength", c_uint), ("Address", c_ubyte * 8),
        ("Index", c_ulong), ("Type", c_uint), ("DhcpEnabled", c_uint),
        ("CurrentIpAddress", POINTER(IP_ADDR_STRING)), ("IpAddressList", IP_ADDR_STRING),
        ("GatewayList", IP_ADDR_STRING), ("DhcpServer", IP_ADDR_STRING), ("HaveWins", c_int),
        ("PrimaryWinsServer", IP_ADDR_STRING), ("SecondaryWinsServer", IP_ADDR_STRING),
        ("LeaseObtained", c_ulonglong), ("LeaseExpires", c_ulonglong)]

    size = c_ulong(0)
    windll.iphlpapi.GetAdaptersInfo(None, byref(size))
    if size.value == 0:
        return []
    buf = ctypes.create_string_buffer(size.value)
    rc = windll.iphlpapi.GetAdaptersInfo(buf, byref(size))
    if rc != 0:
        raise SourceUnavailable(f"GetAdaptersInfo a échoué (code {rc}).")
    try:
        dns = global_dns_servers()
    except Exception:  # noqa: BLE001
        dns = []
    suffix = ""
    try:
        suffix = primary_dns_suffix()
    except Exception:  # noqa: BLE001
        pass
    out: list[Interface] = []
    node = ctypes.cast(buf, POINTER(IP_ADAPTER_INFO)).contents
    while True:
        mac = ":".join(f"{b:02x}" for b in node.Address[:node.AddressLength])
        desc = node.Description.split(b"\0")[0].decode("cp1252", "replace")
        gws = [g for g in (_valid_v4(i) for i, _ in _ip_list(node.GatewayList)) if g]
        dhcp = _valid_v4(node.DhcpServer.IpAddress.split(b"\0")[0].decode("ascii", "ignore")) or ""
        for ip, mask in _ip_list(node.IpAddressList):
            v = _valid_v4(ip)
            if not v or v.startswith("169.254."):
                continue
            try:
                pre = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
            except ValueError:
                continue
            out.append(Interface(alias=desc, ipv4=v, prefix=pre, mac=mac,
                                 gateway=gws[0] if gws else "", dns_servers=list(dns),
                                 dhcp_enabled=bool(node.DhcpEnabled), dhcp_server=dhcp if node.DhcpEnabled else "",
                                 dns_suffix=suffix))
        if not node.Next:
            break
        node = node.Next.contents
    return out


def primary_dns_suffix() -> str:
    _need_windows()
    import winreg
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters") as k:
        for name in ("Domain", "DhcpDomain"):
            try:
                v, _ = winreg.QueryValueEx(k, name)
                if v:
                    return str(v).lower()
            except FileNotFoundError:
                pass
    return ""


def join_status() -> tuple[int, str]:
    """(type, nom) via NetGetJoinInformation. type 3 = domaine, 2 = groupe de travail."""
    _need_windows()
    import ctypes
    from ctypes import byref, c_uint, c_void_p, c_wchar_p, windll
    name = c_wchar_p()
    typ = c_uint(0)
    rc = windll.netapi32.NetGetJoinInformation(None, byref(name), byref(typ))
    if rc != 0:
        raise SourceUnavailable(f"NetGetJoinInformation a échoué (code {rc}).")
    value = name.value or ""
    windll.netapi32.NetApiBufferFree(ctypes.cast(name, c_void_p))
    return typ.value, value


def detect_domain_native(tcp_check=None) -> DomainInfo:
    """Domaine et contrôleurs sans PowerShell."""
    _need_windows()
    info = DomainInfo()
    typ, netbios = join_status()
    if typ != 3:
        info.evidence.append("NetGetJoinInformation : ce poste n'est pas joint à un domaine "
                             f"(statut {typ}, « {netbios} »).")
        return info
    info.in_domain = True
    dns = ""
    try:
        dns = primary_dns_suffix()
    except Exception:  # noqa: BLE001
        pass
    env = os.environ.get("USERDNSDOMAIN", "").lower()
    info.name = dns if "." in dns else (env if "." in env else (dns or netbios.lower()))
    info.evidence.append(f"NetGetJoinInformation : joint au domaine « {netbios} » ; suffixe DNS : {dns or '?'}")
    if env and env == info.name:
        info.evidence.append("USERDNSDOMAIN corrobore le domaine.")
    candidates: list[str] = []
    ls = os.environ.get("LOGONSERVER", "").lstrip("\\")
    if ls:
        info.domain_controllers.append(ls.lower())
        info.evidence.append(f"LOGONSERVER (session) : {ls}")
        try:
            candidates += [ai[4][0] for ai in socket.getaddrinfo(ls, None, socket.AF_INET, socket.SOCK_STREAM)]
        except OSError:
            info.evidence.append(f"{ls} ne se résout pas en IPv4.")
    if "." in info.name:
        try:
            ips = [ai[4][0] for ai in socket.getaddrinfo(info.name, None, socket.AF_INET, socket.SOCK_STREAM)]
            info.evidence.append(f"Enregistrements A de {info.name} (contrôleurs) : {', '.join(sorted(set(ips)))}")
            candidates += ips
        except OSError:
            info.evidence.append(f"{info.name} ne se résout pas via DNS.")
    for ip in dict.fromkeys(candidates):
        if tcp_check is None or tcp_check(ip, 389):
            info.dc_addresses.append(ip)
        else:
            info.evidence.append(f"{ip} : LDAP 389 injoignable, non retenu comme contrôleur.")
    return info
