"""Vérification ponctuelle d'une adresse avant affectation (lecture seule)."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from ..dns import resolver
from .models import now_iso


@dataclass
class VerifyResult:
    ip: str
    verdict: str
    lines: list[str] = field(default_factory=list)
    positive: bool = False
    checked_at: str = ""

    def text(self) -> str:
        return "\n".join([f"Adresse {self.ip} — contrôles du {self.checked_at}", *self.lines, "",
                          self.verdict])


def verify_ip(ip: str, col, timeout_ms: int = 800, plan_status: str = "",
              plan_justification: str = "") -> VerifyResult:
    ip = str(ipaddress.IPv4Address(ip.strip()))
    r = VerifyResult(ip=ip, verdict="", checked_at=now_iso())
    if plan_status:
        r.lines.append(f"Plan d'adressage : {plan_status} — {plan_justification}")
    ping_ok = bool(col.ping(ip, timeout_ms))
    r.lines.append("Ping ICMP : " + ("réponse reçue" if ping_ok else "aucune réponse (non concluant : un pare-feu peut bloquer)"))
    mac = ""
    try:
        nb = col.neighbors()
        if ip in nb:
            mac = nb[ip][0]
            r.lines.append(f"Voisinage ARP : entrée trouvée, MAC {mac} (état {nb[ip][1]})")
        else:
            r.lines.append("Voisinage ARP : aucune entrée")
    except Exception as e:  # noqa: BLE001
        r.lines.append(f"Voisinage ARP : illisible ({e})")
    st, name = col.resolve_ptr(ip)
    if st == resolver.RESOLVED:
        r.lines.append(f"DNS inverse (PTR) : {name}")
        fst, ips = col.resolve_a(name)
        r.lines.append(f"DNS direct de {name} : {', '.join(ips) if ips else fst}")
    elif st == resolver.ABSENT:
        r.lines.append("DNS inverse (PTR) : aucun enregistrement")
    else:
        r.lines.append("DNS inverse (PTR) : DNS indisponible, contrôle non réalisé")
    r.positive = ping_ok or bool(mac) or st == resolver.RESOLVED
    if r.positive:
        r.verdict = ("ADRESSE UTILISÉE OU ENREGISTRÉE : ne pas l'affecter sans clarifier "
                     "(hôte actif, entrée ARP ou enregistrement DNS).")
    else:
        r.verdict = ("Aucune trace d'utilisation à cet instant. Ce n'est PAS une garantie : "
                     "confirmez avec l'administrateur DHCP/DNS (baux, réservations, IP statiques) "
                     "avant toute affectation.")
    return r
