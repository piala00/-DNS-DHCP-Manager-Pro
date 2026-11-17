"""Détection de la voie Internet (passerelle du fournisseur) et tests de connectivité.
Lecture seule : connexions TCP/UDP sortantes de test uniquement."""
from __future__ import annotations

import ipaddress
import random
import socket
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

from .models import Interface, now_iso

TEST_TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 443)]
TEST_NAME = "www.google.com"


@dataclass
class InternetPath:
    interface: str
    ipv4: str
    network: str
    gateway: str
    dhcp: bool
    dhcp_server: str
    dns_servers: list[str] = field(default_factory=list)
    internet_ok: bool = False
    detail: str = ""
    checked_at: str = ""


def tcp_from(src_ip: str, host: str, port: int, timeout: float = 3.0) -> bool:
    """Connexion TCP sortante en forçant l'adresse source (donc la carte testée)."""
    try:
        with socket.create_connection((host, port), timeout=timeout, source_address=(src_ip, 0)):
            return True
    except OSError:
        return False


def detect_internet_paths(interfaces: list[Interface], tcp: Callable = tcp_from) -> list[InternetPath]:
    out = []
    for i in interfaces:
        if not i.gateway:
            continue
        net = ipaddress.ip_network(f"{i.ipv4}/{i.prefix}", strict=False)
        p = InternetPath(i.alias, i.ipv4, str(net), i.gateway, i.dhcp_enabled, i.dhcp_server,
                         list(i.dns_servers), checked_at=now_iso())
        ok = [f"{h}:{pt}" for h, pt in TEST_TARGETS if tcp(i.ipv4, h, pt)]
        p.internet_ok = bool(ok)
        p.detail = (f"Internet joignable via {i.gateway} (TCP {', '.join(ok)})." if ok else
                    f"Aucune connexion sortante vers Internet depuis {i.ipv4} via {i.gateway}.")
        out.append(p)
    return out


# --- requête DNS minimale (UDP) -------------------------------------------------
def build_dns_query(name: str, qid: Optional[int] = None) -> bytes:
    qid = random.randint(0, 65535) if qid is None else qid
    q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.strip(".").split(".")) + b"\0"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)


def parse_dns_answer(data: bytes, qid: int) -> tuple[str, list[str]]:
    """('ok'|'nxdomain'|'erreur'|'invalide', [adresses A])."""
    if len(data) < 12:
        return "invalide", []
    rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    if rid != qid:
        return "invalide", []
    rcode = flags & 0xF
    if rcode == 3:
        return "nxdomain", []
    if rcode != 0:
        return f"erreur (rcode {rcode})", []
    pos = 12
    for _ in range(qd):
        while pos < len(data) and data[pos] != 0:
            pos += 1 + data[pos] if data[pos] < 0xC0 else 2
            if data[pos - 1:pos] and data[pos - 2] >= 0xC0:
                break
        pos += 5
    ips = []
    for _ in range(an):
        if pos >= len(data):
            break
        if data[pos] >= 0xC0:
            pos += 2
        else:
            while pos < len(data) and data[pos] != 0:
                pos += 1 + data[pos]
            pos += 1
        if pos + 10 > len(data):
            break
        typ, _, _, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        if typ == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in data[pos:pos + 4]))
        pos += rdlen
    return ("ok" if ips else "vide"), ips


def dns_lookup(server: str, name: str, timeout: float = 3.0) -> tuple[str, list[str]]:
    qid = random.randint(0, 65535)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(build_dns_query(name, qid), (server, 53))
        data, _ = s.recvfrom(2048)
        return parse_dns_answer(data, qid)
    except socket.timeout:
        return "sans réponse", []
    except OSError as e:
        return f"erreur réseau ({e})", []
    finally:
        s.close()


def connectivity_report(interfaces: list[Interface], domain_name: str = "", dc_ips: Optional[list[str]] = None,
                        tcp: Callable = tcp_from, lookup: Callable = dns_lookup,
                        ping: Optional[Callable[[str, int], bool]] = None) -> list[str]:
    """Rapport étape par étape : quelle étape échoue ? (aucune modification)."""
    lines = [f"Test de connectivité du {now_iso()}"]
    paths = detect_internet_paths(interfaces, tcp)
    if not interfaces:
        return lines + ["Aucune interface IPv4 configurée."]
    for i in interfaces:
        lines.append(f"\nCarte « {i.alias} » {i.cidr} — passerelle {i.gateway or 'AUCUNE'} — "
                     f"{'DHCP' if i.dhcp_enabled else 'adresse fixe'}")
        if not i.gateway:
            lines.append("  [!] Pas de passerelle : aucun accès Internet possible depuis cette carte.")
        else:
            if ping is not None:
                lines.append(f"  Passerelle {i.gateway} : " + ("répond au ping" if ping(i.gateway, 800)
                                                              else "ne répond pas au ping (peut être filtré)"))
            gw_in_subnet = ipaddress.ip_address(i.gateway) in ipaddress.ip_network(i.cidr, strict=False)
            if not gw_in_subnet:
                lines.append(f"  [!] La passerelle {i.gateway} n'est pas dans le sous-réseau {i.cidr} : "
                             "masque ou passerelle erronés.")
        p = next((x for x in paths if x.ipv4 == i.ipv4), None)
        if p:
            lines.append("  Internet : " + ("OK. " if p.internet_ok else "ÉCHEC. ") + p.detail)
        for d in i.dns_servers:
            st, ips = lookup(d, TEST_NAME)
            lines.append(f"  DNS {d} -> {TEST_NAME} : {st} {', '.join(ips[:2])}")
            if domain_name:
                st2, ips2 = lookup(d, domain_name)
                lines.append(f"  DNS {d} -> {domain_name} : {st2} {', '.join(ips2[:2])}")
    ok_any = any(p.internet_ok for p in paths)
    lines.append("")
    if not ok_any:
        lines.append("CONCLUSION : aucune carte n'atteint Internet. Vérifiez la passerelle (celle de la box du "
                     "fournisseur) et que le masque correspond à son sous-réseau.")
    else:
        lines.append("CONCLUSION : Internet est joignable par IP ; si les sites ne s'ouvrent pas, le DNS "
                     "(résolution externe ci-dessus) est en cause.")
    return lines


def internet_plan(target_network: str, paths: list[InternetPath], dc_dns: list[str]) -> list[str]:
    """Texte de recommandation pour configurer une adresse fixe dans target_network
    sans perdre Internet."""
    tnet = ipaddress.ip_network(target_network)
    good = [p for p in paths if p.internet_ok]
    if not good:
        return ["Accès Internet : aucune passerelle Internet fonctionnelle n'a été détectée par l'analyse. "
                "Renseignez la passerelle du fournisseur à la main après l'avoir testée (bouton « Tester la connectivité »)."]
    p = good[0]
    gw = ipaddress.ip_address(p.gateway)
    pnet = ipaddress.ip_network(p.network)
    lines = [f"Accès Internet détecté : passerelle {p.gateway} (carte « {p.interface} », réseau {p.network}, "
             f"{'obtenue par DHCP de ' + p.dhcp_server if p.dhcp else 'adresse fixe'})."]
    if gw in tnet:
        lines += [f"La passerelle {p.gateway} est dans {tnet} : utilisez-la comme passerelle par défaut.",
                  f"DNS : {', '.join(dc_dns) or '<DNS du domaine>'} (le DNS du domaine doit avoir un redirecteur vers Internet)."]
    else:
        lines += [
            f"ATTENTION : la passerelle Internet {p.gateway} est dans {pnet}, PAS dans {tnet} (réseau du domaine).",
            "Une adresse fixe dans " + str(tnet) + " avec une autre passerelle fait perdre Internet. Deux solutions :",
            f"  A (recommandée, propre) : changer l'adresse LAN de la box pour qu'elle soit dans {tnet} "
            f"(adresse libre de ce plan), DHCP de la box désactivé si le DHCP est géré par le serveur ; "
            "puis utiliser cette adresse comme passerelle de tous les postes.",
            f"  B (sans toucher à la box) : deux adresses sur la même carte. Adresse principale dans {pnet} "
            f"(passerelle {p.gateway}) + adresse secondaire dans {tnet} (sans passerelle) pour le domaine. "
            "Analysez d'abord " + str(pnet) + " pour choisir une adresse libre.",
            "  Commandes B (à exécuter manuellement en administrateur, après sauvegarde de la configuration) :",
            f'    netsh interface ip set address "<carte>" static <IP dans {pnet}> {pnet.netmask} {p.gateway}',
            f'    netsh interface ip add address "<carte>" <IP dans {tnet}> {tnet.netmask}',
            f'    netsh interface ip set dns "<carte>" static {dc_dns[0] if dc_dns else "<DNS du domaine>"}',
            "DNS : mettez le DNS du domaine en premier ; il doit avoir un redirecteur (DNS externe) pour "
            "résoudre Internet, sinon ajoutez en second le DNS de la box ou 8.8.8.8 en connaissance de cause."]
    return lines


def candidate_gateways(interfaces: list[Interface], routes: list, ping: Callable[[str, int], bool],
                       timeout_ms: int = 700) -> list[str]:
    """Équipements susceptibles d'être la passerelle d'un réseau local : passerelles déclarées,
    serveurs DHCP, routes par défaut, et premières/dernières adresses usuelles (.1/.254).
    Seuls ceux qui répondent sont retenus (information, sans conclusion sur Internet)."""
    cands: dict[str, str] = {}
    for i in interfaces:
        net = ipaddress.ip_network(f"{i.ipv4}/{i.prefix}", strict=False)
        if i.gateway:
            cands.setdefault(i.gateway, f"passerelle déclarée sur {i.alias}")
        if i.dhcp_server:
            cands.setdefault(i.dhcp_server, f"serveur DHCP de {i.alias}")
        if net.prefixlen <= 30 and net.num_addresses <= 1024:
            hosts = list(net.hosts())
            for h in (hosts[0], hosts[-1]):
                if str(h) != i.ipv4:
                    cands.setdefault(str(h), f"adresse usuelle de routeur dans {net}")
    for r in routes:
        if r.destination == "0.0.0.0/0" and r.next_hop:
            cands.setdefault(r.next_hop, "route par défaut")
    return [f"{ip} ({why}) répond" for ip, why in cands.items() if ping(ip, timeout_ms)]


def remember_paths(known: dict, paths: list[InternetPath]) -> bool:
    """Mémorise les voies Internet qui fonctionnent (utile avant de passer en adresse fixe,
    quand la configuration DHCP d'origine va disparaître). Retourne True si changement."""
    changed = False
    for p in paths:
        if not p.internet_ok:
            continue
        key = f"{p.gateway}@{p.network}"
        rec = {"gateway": p.gateway, "network": p.network, "interface": p.interface, "dhcp": p.dhcp,
               "dhcp_server": p.dhcp_server, "dns": list(p.dns_servers), "saved_at": p.checked_at}
        if known.get(key) != rec:
            known[key] = rec
            changed = True
    return changed


def remembered_as_paths(known: dict) -> list[InternetPath]:
    out = []
    for rec in known.values():
        try:
            out.append(InternetPath(rec["interface"], "", rec["network"], rec["gateway"], bool(rec.get("dhcp")),
                                    rec.get("dhcp_server", ""), list(rec.get("dns", [])), True,
                                    f"Passerelle MÉMORISÉE le {rec.get('saved_at', '?')} (elle avait donné accès à "
                                    "Internet) : à revérifier avec « Tester la connectivité ».", rec.get("saved_at", "")))
        except KeyError:
            continue
    return out


def best_gateway_for(target_network: str, paths: list[InternetPath]) -> Optional[InternetPath]:
    """Passerelle Internet utilisable directement dans target_network (même sous-réseau)."""
    tnet = ipaddress.ip_network(target_network)
    for p in paths:
        if p.internet_ok and ipaddress.ip_address(p.gateway) in tnet:
            return p
    return None
