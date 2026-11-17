"""Sondes réseau : ping (ICMP), voisinage ARP. Concurrence bornée, annulable."""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import json
import re
import subprocess
import threading
from typing import Callable, Optional

from ..core.models import Observation, now_iso
from ..core.psrunner import IS_WINDOWS, SourceUnavailable, _flags, ps_json
from ..planning.planner import norm_mac

SCRIPT_NEIGHBORS = r"""
$ErrorActionPreference='Stop'
Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -in 'Reachable','Stale','Delay','Probe','Permanent' } |
  ForEach-Object { [pscustomobject]@{ IP=$_.IPAddress; Mac=$_.LinkLayerAddress; State=[string]$_.State
  Interface=$_.InterfaceAlias } } | ConvertTo-Json -Compress
"""

_ARP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+(\w+)")


def ping_host(ip: str, timeout_ms: int = 700) -> bool:
    """Vrai uniquement si une réponse d'écho (TTL=) est reçue. Windows renvoie
    code 0 pour « hôte inaccessible » : on lit donc la sortie."""
    ip = str(ipaddress.IPv4Address(ip))
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_ms)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_ms / 1000))), ip]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout_ms / 1000 + 3,
                           creationflags=_flags(), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return p.returncode == 0 and b"ttl=" in p.stdout.lower()


def parse_neighbors(text: str) -> dict[str, tuple[str, str]]:
    """ip -> (mac, état) à partir de la sortie JSON de Get-NetNeighbor."""
    out: dict[str, tuple[str, str]] = {}
    for d in (json.loads(text) if text.strip() else []):
        if not isinstance(d, dict):
            continue
        out_ip = str(d.get("IP") or "")
        mac = norm_mac(str(d.get("Mac") or ""))
        try:
            a = ipaddress.IPv4Address(out_ip)
        except ValueError:
            continue
        if mac and not a.is_multicast and str(a) != "255.255.255.255":
            out[out_ip] = (mac, str(d.get("State") or ""))
    return out


def parse_arp_a(text: str) -> dict[str, tuple[str, str]]:
    out: dict[str, tuple[str, str]] = {}
    for m in _ARP_RE.finditer(text):
        ip, mac, kind = m.groups()
        mac = norm_mac(mac)
        try:
            a = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if mac and not a.is_multicast and ip != "255.255.255.255":
            out[ip] = (mac, kind)
    return out


def read_neighbors() -> dict[str, tuple[str, str]]:
    """`arp -a` d'abord (natif, rapide) ; Get-NetNeighbor en repli."""
    try:
        p = subprocess.run(["arp", "-a"], capture_output=True, timeout=15, creationflags=_flags(),
                           stdin=subprocess.DEVNULL)
        found = parse_arp_a(p.stdout.decode("cp850", errors="replace"))
        if found:
            return found
    except (OSError, subprocess.TimeoutExpired):
        pass
    if not IS_WINDOWS:
        raise SourceUnavailable("Table ARP illisible.")
    return parse_neighbors(json.dumps(ps_json(SCRIPT_NEIGHBORS, timeout=30)))


def sweep(network: ipaddress.IPv4Network, ping: Callable[[str, int], bool],
          timeout_ms: int, concurrency: int, cancel: threading.Event,
          progress: Optional[Callable[[int, int], None]] = None
          ) -> tuple[dict[str, bool], bool]:
    """Ping de toutes les adresses hôtes. Retourne ({ip: répondu}, terminé).
    Ne sont comptées « sondées » que les adresses effectivement testées."""
    hosts = [str(h) for h in (network.hosts() if network.prefixlen < 31 else network)]
    results: dict[str, bool] = {}
    done = 0

    def work(ip: str):
        if cancel.is_set():
            return ip, None
        return ip, ping(ip, timeout_ms)

    with cf.ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        for ip, ok in ex.map(work, hosts):
            if ok is not None:
                results[ip] = ok
            done += 1
            if progress and done % 8 == 0:
                progress(done, len(hosts))
    if progress:
        progress(len(hosts), len(hosts))
    return results, not cancel.is_set() and len(results) == len(hosts)


def build_observations(pings: dict[str, bool], neighbors: dict[str, tuple[str, str]],
                       network: ipaddress.IPv4Network, ptr: dict[str, str]
                       ) -> list[Observation]:
    ts = now_iso()
    obs: dict[str, Observation] = {}
    for ip, ok in pings.items():
        if ok:
            obs[ip] = Observation(ip=ip, methods=["ping"], observed_at=ts)
    for ip, (mac, state) in neighbors.items():
        try:
            if ipaddress.IPv4Address(ip) not in network:
                continue
        except ValueError:
            continue
        if state.lower() in ("incomplete", "unreachable"):
            continue
        o = obs.setdefault(ip, Observation(ip=ip, observed_at=ts))
        o.mac = mac
        o.methods.append("arp" + (" (périmée)" if state.lower() in ("stale", "dynamique", "dynamic") and ip not in pings
                                  else ""))
    for ip, o in obs.items():
        if ip in ptr:
            o.hostname = ptr[ip]
            o.methods.append("ptr")
    return sorted(obs.values(), key=lambda o: int(ipaddress.IPv4Address(o.ip)))
