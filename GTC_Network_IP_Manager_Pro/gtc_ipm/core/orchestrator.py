"""Orchestrateur d'analyse : enchaîne les sources, jamais d'exception fatale,
annulable, sans aucune écriture sur le réseau, l'AD, le DHCP ou le DNS."""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..ad import inventory as ad
from ..dhcp import collector as dhcp
from ..discovery import interfaces as ifc
from ..discovery import scan
from ..dns import resolver
from ..planning import planner as P
from ..planning.evidence import collect_evidence
from .models import (CONFLIT, SRC_CANCELLED, SRC_OK, SRC_PARTIAL, SRC_SKIPPED,
                     SRC_UNAVAILABLE, AdComputer, DomainInfo, Evidence, Snapshot, SourceStatus,
                     now_iso)
from .psrunner import SourceUnavailable
from .settings import Settings

Progress = Callable[[int, str], None]


@dataclass
class Collectors:
    """Points d'injection (les tests y branchent des données SIMULÉES)."""
    interfaces: Callable = ifc.collect_interfaces
    routes: Callable = ifc.collect_routes
    domain: Callable = ad.collect_domain
    ad_computers: Callable = ad.collect_ad_computers
    dhcp: Callable = dhcp.collect_dhcp
    ping: Callable = scan.ping_host
    neighbors: Callable = scan.read_neighbors
    resolve_a: Callable = resolver.resolve_a
    resolve_ptr: Callable = resolver.resolve_ptr
    tcp_check: Callable = ad.tcp_check


@dataclass
class Options:
    networks: list[str] = field(default_factory=list)  # CIDR explicitement choisis
    query_ad: bool = True
    query_dhcp: bool = True
    settings: Settings = field(default_factory=Settings)


def local_network_of(itf) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(f"{itf.ipv4}/{itf.prefix}", strict=False)


def discover_local(collectors: Collectors) -> tuple[list, list]:
    return collectors.interfaces(), collectors.routes()


def run_analysis(opts: Options, col: Collectors, cancel: threading.Event,
                 progress: Optional[Progress] = None,
                 log: Optional[Callable[[str], None]] = None) -> Snapshot:
    snap = Snapshot(started_at=now_iso())
    st = opts.settings

    def say(pct: int, msg: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        snap.log.append(line)
        if log:
            log(line)
        if progress:
            progress(pct, msg)

    def step(name: str, fn: Callable[[SourceStatus], None], pct: int) -> None:
        s = SourceStatus(name=name, started_at=now_iso())
        snap.sources.append(s)
        if cancel.is_set():
            s.state, s.detail = SRC_CANCELLED, "Analyse annulée avant cette étape."
            return
        say(pct, f"{name}…")
        t0 = time.monotonic()
        try:
            fn(s)
            if s.state == SRC_SKIPPED:
                s.state = SRC_OK
        except SourceUnavailable as e:
            s.state, s.detail = SRC_UNAVAILABLE, str(e)
            say(pct, f"{name} : inaccessible — {e}")
        except Exception as e:  # noqa: BLE001 - jamais de fermeture brutale
            s.state, s.detail = SRC_UNAVAILABLE, f"Erreur inattendue : {type(e).__name__}: {e}"
            say(pct, f"{name} : erreur — {e}")
        s.duration_s = round(time.monotonic() - t0, 2)

    # 1. Interfaces et routes -------------------------------------------------
    def s_interfaces(s: SourceStatus) -> None:
        snap.interfaces = col.interfaces()
        s.count = len(snap.interfaces)
        snap.local_networks = sorted({str(local_network_of(i)) for i in snap.interfaces})
        if not snap.interfaces:
            s.state, s.detail = SRC_PARTIAL, "Aucune interface IPv4 configurée (hors APIPA)."
        try:
            snap.routes = col.routes()
        except SourceUnavailable as e:
            snap.warnings.append(f"Routes illisibles : {e}")
            s.state, s.detail = SRC_PARTIAL, f"Routes illisibles : {e}"

    step("Interfaces et routes locales", s_interfaces, 3)

    # 2. Domaine ---------------------------------------------------------------
    def s_domain(s: SourceStatus) -> None:
        snap.domain = DomainInfo(detected=False)
        snap.domain = col.domain()
        for hint in st.dc_hints:
            if cancel.is_set():
                break
            r389, r88 = col.tcp_check(hint, 389), col.tcp_check(hint, 88)
            snap.domain.evidence.append(
                f"Hypothèse contrôleur {hint} : LDAP 389 {'ouvert' if r389 else 'fermé/injoignable'}, "
                f"Kerberos 88 {'ouvert' if r88 else 'fermé/injoignable'}.")
            if r389 and r88 and hint not in snap.domain.dc_addresses:
                snap.domain.dc_addresses.append(hint)
        for dc in snap.domain.dc_addresses:
            if cancel.is_set():
                break
            checks = {p: col.tcp_check(dc, p) for p in (53, 88, 389, 445)}
            snap.domain.evidence.append(
                f"Contrôleur {dc} : " + ", ".join(f"{p} {'OK' if ok else 'KO'}" for p, ok in checks.items()))
            same = any(ipaddress.ip_address(dc) in local_network_of(i) for i in snap.interfaces)
            if not same:
                snap.domain.evidence.append(
                    f"{dc} est dans un autre sous-réseau que ce poste : normal pour un domaine, "
                    "à condition que le routage, le DNS et les ports AD soient accessibles.")
        s.count = len(snap.domain.dc_addresses)
        if not snap.domain.in_domain:
            s.state, s.detail = SRC_PARTIAL, "; ".join(snap.domain.evidence[:1])

    step("Domaine Active Directory", s_domain, 8)
    if not snap.domain.detected and not snap.domain.evidence:
        snap.domain.evidence.append("Détection du domaine impossible (voir état de la source) : "
                                    "le poste n'est pas déclaré « hors domaine ».")

    # 3. Inventaire AD + 4. DNS ---------------------------------------------------
    def s_ad(s: SourceStatus) -> None:
        if not opts.query_ad:
            s.state, s.detail = SRC_SKIPPED, "Désactivé par l'utilisateur."
            return
        snap.ad_computers = col.ad_computers(snap.domain)
        s.count = len(snap.ad_computers)

    step("Inventaire des ordinateurs AD", s_ad, 15)

    def s_dns_ad(s: SourceStatus) -> None:
        comps = snap.ad_computers
        if not comps:
            s.state, s.detail = SRC_SKIPPED, "Aucune machine AD à résoudre."
            return

        def one(c: AdComputer) -> None:
            if cancel.is_set():
                return
            host = c.dns_hostname or c.name
            c.dns_status, c.ipv4 = col.resolve_a(host)
            c.observed_at = now_iso()

        with cf.ThreadPoolExecutor(max_workers=min(32, st.concurrency)) as ex:
            list(ex.map(one, comps))
        unavailable = sum(1 for c in comps if c.dns_status == resolver.UNAVAILABLE)
        s.count = sum(1 for c in comps if c.dns_status == resolver.RESOLVED)
        if unavailable:
            s.state = SRC_PARTIAL
            s.detail = f"{unavailable} résolution(s) impossible(s) (DNS indisponible, pas « absent »)."

    step("Résolution DNS des machines AD", s_dns_ad, 25)

    # 5. DHCP -----------------------------------------------------------------
    def s_dhcp(s: SourceStatus) -> None:
        if not opts.query_dhcp:
            s.state, s.detail = SRC_SKIPPED, "Désactivé par l'utilisateur."
            return
        extra = [i.dhcp_server for i in snap.interfaces if i.dhcp_server]
        snap.dhcp = col.dhcp(sorted(set(extra)))
        s.count = len(snap.dhcp.scopes)
        if snap.dhcp.errors:
            s.state, s.detail = SRC_PARTIAL, " | ".join(snap.dhcp.errors[:3])

    step("DHCP (étendues, baux, réservations, exclusions)", s_dhcp, 35)

    # 6. Découverte réseau --------------------------------------------------------
    nets: list[ipaddress.IPv4Network] = []
    for c in opts.networks:
        try:
            n = ipaddress.ip_network(c, strict=False)
        except ValueError:
            snap.warnings.append(f"Réseau ignoré (CIDR invalide) : {c}")
            continue
        if not isinstance(n, ipaddress.IPv4Network):
            snap.warnings.append(f"Réseau ignoré (IPv6 non pris en charge) : {c}")
        elif n.num_addresses > st.max_hosts:
            snap.warnings.append(f"Réseau {n} ignoré : {n.num_addresses} adresses > limite {st.max_hosts}. "
                                 "Augmentez la limite dans Paramètres pour un balayage volontaire.")
        else:
            nets.append(n)

    pings: dict[str, dict[str, bool]] = {}

    def s_scan(s: SourceStatus) -> None:
        if not nets:
            s.state, s.detail = SRC_SKIPPED, "Aucun réseau sélectionné."
            return
        all_obs = []
        incomplete = []
        for i, n in enumerate(nets):
            base = 40 + int(35 * i / len(nets))
            say(base, f"Balayage de {n} ({n.num_addresses} adresses)…")
            res, done = scan.sweep(
                n, col.ping, st.ping_timeout_ms, st.concurrency, cancel,
                lambda d, t, b=base, n=n: progress and progress(b + int(35 / len(nets) * d / max(t, 1)),
                                                                f"Balayage de {n} : {d}/{t}"))
            pings[str(n)] = res
            snap.scanned_ips[str(n)] = sorted(res, key=lambda x: int(ipaddress.IPv4Address(x)))
            # PTR sur chaque adresse sondée (vérification DNS inverse)
            ptr_unavail, ptr_answered = 0, 0
            if not cancel.is_set():
                def one(ip: str):
                    return ip, col.resolve_ptr(ip)
                with cf.ThreadPoolExecutor(max_workers=min(32, st.concurrency)) as ex:
                    for ip, (status, name) in ex.map(one, list(res)):
                        if status == resolver.RESOLVED:
                            snap.ptr[ip] = name
                            ptr_answered += 1
                        elif status == resolver.UNAVAILABLE:
                            ptr_unavail += 1
                        else:
                            ptr_answered += 1
            snap.dns_ok[str(n)] = ptr_answered > 0 and ptr_unavail <= max(1, len(res) // 20)
            try:
                nb = col.neighbors()
            except SourceUnavailable as e:
                nb = {}
                snap.warnings.append(f"Table ARP illisible : {e}")
            all_obs += scan.build_observations(res, nb, n, snap.ptr)
            snap.scanned_networks.append(str(n))
            if not done:
                incomplete.append(str(n))
        snap.observations = all_obs
        s.count = len(all_obs)
        if cancel.is_set():
            s.state, s.detail = SRC_CANCELLED, f"Annulé : réseaux incomplets {', '.join(incomplete)}"
        elif incomplete:
            s.state = SRC_PARTIAL

    step("Découverte réseau (ping, ARP, DNS inverse)", s_scan, 40)

    # 7. Rapprochement AD / observations ----------------------------------------------
    match_ad_and_observations(snap, st.stale_days)

    # 8. Plan d'adressage -----------------------------------------------------------------
    if cancel.is_set():
        snap.cancelled = True
        snap.warnings.append("Analyse annulée : plan d'adressage non calculé (données incomplètes).")
    else:
        say(90, "Calcul du plan d'adressage…")
        build_plans(snap, nets, pings, st)
    snap.finished_at = now_iso()
    say(100, "Analyse annulée." if snap.cancelled else "Analyse terminée.")
    return snap


def match_ad_and_observations(snap: Snapshot, stale_days: int) -> None:
    obs_by_ip = {o.ip: o for o in snap.observations}
    scanned = set()
    for lst in snap.scanned_ips.values():
        scanned.update(lst)
    ad_names = {c.name.lower() for c in snap.ad_computers}
    ad_names |= {c.dns_hostname.split(".")[0].lower() for c in snap.ad_computers if c.dns_hostname}
    ad_ips = {ip for c in snap.ad_computers for ip in c.ipv4}
    for o in snap.observations:
        if o.hostname:
            o.in_domain = o.hostname.split(".")[0].lower() in ad_names
        elif o.ip in ad_ips:
            o.in_domain = True
    for c in snap.ad_computers:
        seen = [obs_by_ip[ip] for ip in c.ipv4 if ip in obs_by_ip]
        notes = []
        if seen:
            c.mac = next((o.mac for o in seen if o.mac), "")
            c.verification = "Active (observée sur le réseau)"
        elif c.dns_status == resolver.UNAVAILABLE:
            c.verification = "DNS indisponible : non vérifiable"
        elif c.dns_status == resolver.ABSENT:
            c.verification = "Aucun enregistrement DNS"
        elif c.dns_status == resolver.RESOLVED:
            if any(ip in scanned for ip in c.ipv4):
                c.verification = "Enregistrée au DNS, sans réponse (éteinte, pare-feu ou donnée périmée)"
            else:
                c.verification = "Enregistrée au DNS, hors plages analysées"
        if c.enabled is False:
            notes.append("compte désactivé")
        if ad.stale(c.last_logon, stale_days):
            notes.append(f"dernier contact AD > {stale_days} j")
        if notes:
            c.verification += " — " + ", ".join(notes)


def build_plans(snap: Snapshot, nets: list[ipaddress.IPv4Network],
                pings: dict[str, dict[str, bool]], st: Settings) -> None:
    local = [ipaddress.ip_network(n) for n in snap.local_networks]
    dhcp_ok_servers = {k for k in snap.dhcp.queried_scopes}
    for n in nets:
        if str(n) not in snap.scanned_ips:
            continue
        w = P.rfc1918_warning(n)
        if w:
            snap.warnings.append(w)
        local_seg = any(n.subnet_of(l) or n == l for l in local)
        # DHCP « lu » pour ce réseau : une étendue correspondante interrogée sans erreur
        dhcp_read = any(
            f"{sc.server}|{sc.scope_id}" in dhcp_ok_servers and
            ipaddress.ip_network(f"{sc.scope_id}/{sc.subnet_mask}", strict=False).overlaps(n)
            for sc in snap.dhcp.scopes if sc.subnet_mask)
        ctx = P.NetworkContext(
            network=n, local_segment=local_seg, scanned=set(snap.scanned_ips[str(n)]),
            dhcp_queried=dhcp_read, dns_ok=snap.dns_ok.get(str(n), False),
            ad_ok=bool(snap.ad_computers))
        ev = collect_evidence(snap, n, st.static_inventory,
                              [(a, b) for a, b in st.user_excluded])
        # PTR trouvés sur des IP silencieuses
        for ip, name in snap.ptr.items():
            try:
                if ipaddress.IPv4Address(ip) in n:
                    ev.setdefault(ip, []).append(Evidence(P.DNS_PTR, "DNS inverse", name, snap.finished_at, "", name))
            except ValueError:
                pass
        plan = P.build_plan(ctx, ev, now_iso(), max(st.max_hosts, n.num_addresses))
        snap.plan[str(n)] = plan
        snap.candidates[str(n)] = P.propose_candidates(plan, st.candidate_count)
        snap.conflicts += [e for e in plan if e.status == CONFLIT]
