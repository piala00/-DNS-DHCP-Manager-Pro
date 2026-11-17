"""Moteur de plan d'adressage IPv4.

Principe : une adresse n'est jamais « libre » parce qu'elle ne répond pas au
ping. Le statut DISPONIBLE_CONFIRMÉE n'est attribué que si plusieurs contrôles
indépendants concordent, et reste conditionnel et daté.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..core.models import (CANDIDATE, CONFLIT, DHCP_DYNAMIQUE, DISPONIBLE,
                           EXCLUE, INCONNUE, OCCUPEE, RESERVEE, Evidence,
                           IpEntry, now_iso)

# Types de preuves
ROLE_GATEWAY = "passerelle"
ROLE_DNS = "serveur_dns"
ROLE_DC = "controleur_domaine"
ROLE_DHCP_SERVER = "serveur_dhcp"
LOCAL_IFACE = "interface_locale"
STATIC_INVENTORY = "inventaire_statique"
OBSERVED = "observee"          # réponse ARP / ping
DHCP_LEASE = "bail_dhcp"
DHCP_RESERVATION = "reservation_dhcp"
DHCP_EXCLUSION = "exclusion_dhcp"
DHCP_DYNAMIC = "plage_dhcp_dynamique"
DNS_A = "dns_a"
DNS_PTR = "dns_ptr"
USER_EXCLUDED = "exclusion_utilisateur"

ACTIVE_KINDS = {ROLE_GATEWAY, ROLE_DNS, ROLE_DC, ROLE_DHCP_SERVER,
                LOCAL_IFACE, STATIC_INVENTORY, OBSERVED}
MAC_KINDS = {OBSERVED, DHCP_LEASE, DHCP_RESERVATION}

_LABELS = {
    ROLE_GATEWAY: "passerelle", ROLE_DNS: "serveur DNS",
    ROLE_DC: "contrôleur de domaine", ROLE_DHCP_SERVER: "serveur DHCP",
    LOCAL_IFACE: "interface de ce poste", STATIC_INVENTORY: "inventaire statique",
    OBSERVED: "hôte observé", DHCP_LEASE: "bail DHCP",
    DHCP_RESERVATION: "réservation DHCP", DHCP_EXCLUSION: "exclusion DHCP",
    DHCP_DYNAMIC: "plage DHCP dynamique", DNS_A: "enregistrement DNS A",
    DNS_PTR: "enregistrement DNS PTR", USER_EXCLUDED: "exclusion utilisateur",
}


def norm_mac(mac: str) -> str:
    m = "".join(c for c in (mac or "").lower() if c in "0123456789abcdef")
    if len(m) != 12 or m in ("000000000000", "ffffffffffff"):
        return ""
    return ":".join(m[i:i + 2] for i in range(0, 12, 2))


@dataclass
class NetworkContext:
    network: ipaddress.IPv4Network
    local_segment: bool = True     # ARP/ping fiables (même segment L2)
    scanned: set[str] = field(default_factory=set)  # IP sondées (ping/ARP)
    dhcp_queried: bool = False     # lecture administrative DHCP réussie
    dns_ok: bool = False           # DNS a répondu pour ce réseau
    ad_ok: bool = False            # inventaire AD lu


def rfc1918_warning(net: ipaddress.IPv4Network) -> Optional[str]:
    """Avertit si le réseau n'est pas dans les plages privées RFC1918."""
    if net.is_private and not net.is_link_local and not net.is_loopback:
        # is_private est plus large que RFC1918 (CGNAT, doc...) : on teste strictement
        for p in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            if net.subnet_of(ipaddress.ip_network(p)):
                return None
    if net.is_link_local:
        return f"{net} est en adressage APIPA (169.254.0.0/16) : aucune configuration valide reçue."
    return (f"{net} n'appartient pas aux plages privées RFC1918 (10/8, 172.16/12, "
            f"192.168/16). Vérifiez qu'il s'agit bien de l'adressage voulu : ces "
            f"adresses sont routables sur Internet. Aucune configuration n'est modifiée.")


def _fmt(ev: Evidence) -> str:
    label = _LABELS.get(ev.kind, ev.kind)
    extra = f" ({ev.detail})" if ev.detail else ""
    return f"{label} [{ev.source}]{extra}"


def classify_ip(ip: str, ctx: NetworkContext, evs: list[Evidence],
                checked_at: str) -> IpEntry:
    net = ctx.network
    addr = ipaddress.ip_address(ip)
    sources = sorted({e.source for e in evs})
    kinds = {e.kind for e in evs}
    mac = next((norm_mac(e.mac) for e in evs if norm_mac(e.mac)), "")
    name = next((e.name for e in evs if e.name), "")

    def entry(status: str, why: str, preferred: bool = False) -> IpEntry:
        return IpEntry(ip=ip, status=status, justification=why, network=str(net),
                       checked_at=checked_at, sources=sources, hostname=name,
                       mac=mac, preferred=preferred)

    # 1. adresses réservées par la structure du réseau
    if net.prefixlen <= 30 and addr in (net.network_address, net.broadcast_address):
        kind = "réseau" if addr == net.network_address else "diffusion (broadcast)"
        return entry(EXCLUE, f"Adresse de {kind} du sous-réseau {net}.")
    if USER_EXCLUDED in kinds:
        return entry(EXCLUE, "Exclue par l'utilisateur : " +
                     "; ".join(_fmt(e) for e in evs if e.kind == USER_EXCLUDED))

    # 2. conflits : plusieurs adresses MAC distinctes pour une même IP
    macs = {norm_mac(e.mac) for e in evs if e.kind in MAC_KINDS and norm_mac(e.mac)}
    if len(macs) >= 2:
        detail = "; ".join(f"{_fmt(e)} MAC {norm_mac(e.mac)}"
                           for e in evs if e.kind in MAC_KINDS and norm_mac(e.mac))
        return entry(CONFLIT, "Plusieurs adresses MAC pour la même IP : " + detail)

    active = [e for e in evs if e.kind in ACTIVE_KINDS]
    leases = [e for e in evs if e.kind == DHCP_LEASE]
    resv = [e for e in evs if e.kind == DHCP_RESERVATION]
    excl = DHCP_EXCLUSION in kinds
    dyn = DHCP_DYNAMIC in kinds and not excl

    # 3. utilisation avérée
    if active:
        if dyn and leases:
            return entry(DHCP_DYNAMIQUE, "Bail DHCP actif et hôte observé : " +
                         "; ".join(_fmt(e) for e in active + leases))
        why = "; ".join(_fmt(e) for e in active)
        if resv:
            why += "; " + "; ".join(_fmt(e) for e in resv)
        if dyn:
            why += " — attention : hôte actif dans une plage DHCP dynamique sans bail connu."
        return entry(OCCUPEE, why)
    if leases:
        return entry(DHCP_DYNAMIQUE if dyn or not excl else OCCUPEE,
                     "Bail DHCP : " + "; ".join(_fmt(e) for e in leases))
    if resv:
        return entry(RESERVEE, "Réservation DHCP sans hôte observé : " +
                     "; ".join(_fmt(e) for e in resv))
    if dyn:
        return entry(DHCP_DYNAMIQUE, "Dans une plage DHCP dynamique : jamais proposée en statique "
                     "sans réservation ou exclusion coordonnée avec l'administrateur DHCP.")

    # 4. aucune preuve d'utilisation
    dns_recs = [e for e in evs if e.kind in (DNS_A, DNS_PTR)]
    if dns_recs:
        return entry(INCONNUE, "Enregistrement DNS sans hôte observé (peut être périmé) : " +
                     "; ".join(_fmt(e) for e in dns_recs))
    if ip not in ctx.scanned:
        why = "Adresse non analysée (hors plage sondée)."
        if excl:
            why = "Dans une exclusion DHCP mais non analysée : " + why
        return entry(EXCLUE if excl else INCONNUE, why, preferred=excl)

    missing = []
    if not ctx.local_segment:
        missing.append("sous-réseau distant : ARP non visible, silence ICMP non concluant")
    if not ctx.dhcp_queried:
        missing.append("DHCP non lu en administration")
    if not ctx.dns_ok:
        missing.append("DNS non vérifié")
    if not ctx.ad_ok:
        missing.append("inventaire AD non lu")
    note = " Zone d'exclusion DHCP (adaptée aux IP statiques)." if excl else ""
    ts = f" Contrôles effectués le {checked_at}; valable uniquement à cet instant, à revalider avant affectation."
    if not missing:
        return entry(DISPONIBLE,
                     "Aucune réponse ICMP/ARP, aucun enregistrement DNS A/PTR, absente de l'AD, "
                     "du DHCP (baux, réservations) et des IP connues." + note + ts, preferred=excl)
    return entry(CANDIDATE,
                 "Aucune réponse ICMP/ARP et aucun enregistrement trouvé, mais : " +
                 "; ".join(missing) + "." + note + ts, preferred=excl)


def build_plan(ctx: NetworkContext, evidence: dict[str, list[Evidence]],
               checked_at: Optional[str] = None, max_hosts: int = 4096
               ) -> list[IpEntry]:
    """Classe chaque adresse du réseau (limité à max_hosts)."""
    checked_at = checked_at or now_iso()
    net = ctx.network
    if net.num_addresses > max_hosts:
        raise ValueError(f"Réseau trop grand ({net.num_addresses} adresses, max {max_hosts}).")
    return [classify_ip(str(a), ctx, evidence.get(str(a), []), checked_at) for a in net]


def propose_candidates(plan: Iterable[IpEntry], count: int = 20) -> list[IpEntry]:
    """Sélectionne des adresses à proposer : confirmées d'abord, exclusions DHCP
    en priorité, jamais de plage dynamique."""
    pool = [e for e in plan if e.status in (DISPONIBLE, CANDIDATE)]
    pool.sort(key=lambda e: (e.status != DISPONIBLE, not e.preferred,
                             int(ipaddress.ip_address(e.ip))))
    return pool[:count]


def summarize(plan: Iterable[IpEntry]) -> dict[str, int]:
    out: dict[str, int] = {}
    for e in plan:
        out[e.status] = out.get(e.status, 0) + 1
    return out
