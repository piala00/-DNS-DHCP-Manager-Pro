"""Construit les preuves par adresse IP à partir d'un Snapshot (données réelles
ou simulées par les tests)."""
from __future__ import annotations

import ipaddress
from typing import Iterable, Optional

from ..core.models import Evidence, Snapshot
from . import planner as P

MAX_RANGE = 70000


def _ips_in_range(start: str, end: str, net: ipaddress.IPv4Network) -> Iterable[str]:
    try:
        a, b = int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end))
    except ValueError:
        return
    if b < a or b - a > MAX_RANGE:
        return
    lo = max(a, int(net.network_address))
    hi = min(b, int(net.broadcast_address))
    for i in range(lo, hi + 1):
        yield str(ipaddress.IPv4Address(i))


def collect_evidence(snap: Snapshot, net: ipaddress.IPv4Network,
                     static_inventory: Optional[dict[str, str]] = None,
                     user_excluded: Optional[list[tuple[str, str]]] = None
                     ) -> dict[str, list[Evidence]]:
    ev: dict[str, list[Evidence]] = {}

    def add(ip: str, e: Evidence) -> None:
        try:
            if ipaddress.IPv4Address(ip) in net:
                ev.setdefault(ip, []).append(e)
        except ValueError:
            pass

    ts = snap.finished_at or snap.started_at
    for itf in snap.interfaces:
        add(itf.ipv4, Evidence(P.LOCAL_IFACE, "Interfaces locales", itf.alias, ts, itf.mac))
        if itf.gateway:
            add(itf.gateway, Evidence(P.ROLE_GATEWAY, "Interfaces locales", itf.alias, ts))
        for d in itf.dns_servers:
            add(d, Evidence(P.ROLE_DNS, "Interfaces locales", itf.alias, ts))
        if itf.dhcp_server:
            add(itf.dhcp_server, Evidence(P.ROLE_DHCP_SERVER, "Interfaces locales", itf.alias, ts))
    for ip in snap.domain.dc_addresses:
        add(ip, Evidence(P.ROLE_DC, "Domaine AD", snap.domain.name, ts))
    for o in snap.observations:
        add(o.ip, Evidence(P.OBSERVED, "Découverte réseau", "+".join(o.methods),
                           o.observed_at or ts, o.mac, o.hostname))
    for c in snap.ad_computers:
        for ip in c.ipv4:
            add(ip, Evidence(P.DNS_A, "DNS/AD", c.dns_hostname or c.name, ts, "", c.name))
    for sc in snap.dhcp.scopes:
        try:
            sc_net = ipaddress.ip_network(f"{sc.scope_id}/{sc.subnet_mask}", strict=False)
        except ValueError:
            continue
        if not sc_net.overlaps(net):
            continue
        for ip in _ips_in_range(sc.start, sc.end, net):
            add(ip, Evidence(P.DHCP_DYNAMIC, f"DHCP {sc.server}", f"étendue {sc.scope_id}", ts))
        for a, b in sc.exclusions:
            for ip in _ips_in_range(a, b, net):
                add(ip, Evidence(P.DHCP_EXCLUSION, f"DHCP {sc.server}", f"{a}-{b}", ts))
    for ls in snap.dhcp.leases:
        kind = P.DHCP_RESERVATION if ls.reservation else P.DHCP_LEASE
        if not ls.reservation and ls.state and ls.state.lower() not in ("active", "activereservation"):
            continue  # bail expiré / offre : non concluant
        add(ls.ip, Evidence(kind, f"DHCP {ls.server}", ls.hostname, ts, ls.mac, ls.hostname))
    for ip, label in (static_inventory or {}).items():
        add(ip, Evidence(P.STATIC_INVENTORY, "Inventaire statique", label, ts))
    for a, b in user_excluded or []:
        for ip in _ips_in_range(a, b, net):
            add(ip, Evidence(P.USER_EXCLUDED, "Paramètres", f"{a}-{b}", ts))
    return ev
