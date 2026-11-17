"""Tests des parseurs et de l'orchestrateur avec des données SIMULÉES.

Ces jeux de données sont des échantillons au format de sortie PowerShell ; ils ne
représentent aucun résultat de production.
"""
import ipaddress
import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from gtc_ipm.ad import inventory as ad  # noqa: E402
from gtc_ipm.core import orchestrator as orch  # noqa: E402
from gtc_ipm.core.models import (CANDIDATE, DISPONIBLE, DhcpData, DomainInfo,  # noqa: E402
                                 Interface, Route, SRC_CANCELLED, SRC_OK,
                                 SRC_PARTIAL, SRC_UNAVAILABLE, AdComputer)
from gtc_ipm.core.psrunner import (SourceUnavailable, clean_ps_error, parse_json_list,  # noqa: E402
                                   valid_host, valid_ip)
from gtc_ipm.core.settings import Settings  # noqa: E402
from gtc_ipm.dhcp import collector as dh  # noqa: E402
from gtc_ipm.discovery import interfaces as ifc  # noqa: E402
from gtc_ipm.discovery import scan  # noqa: E402
from gtc_ipm.dns import resolver  # noqa: E402


# --- psrunner ---------------------------------------------------------------
def test_parse_json_variants():
    assert parse_json_list("") == []
    assert parse_json_list('{"a":1}') == [{"a": 1}]
    assert parse_json_list('﻿[{"a":1},{"b":2}]') == [{"a": 1}, {"b": 2}]
    assert parse_json_list("null") == [] and parse_json_list("[]") == []


def test_clean_clixml_error():
    raw = ('#< CLIXML\r\n<Objs Version="1.1.0.1"><S S="Error">Import-Module : Le module sp&#233;cifi&#233; '
           'DhcpServer est introuvable._x000D__x000A_</S><S S="Error">At line:1</S></Objs>')
    out = clean_ps_error(raw)
    assert "CLIXML" not in out and "spécifié" in out and "_x000D_" not in out
    assert clean_ps_error("erreur simple") == "erreur simple"


@pytest.mark.parametrize("bad", ["a b", "x;rm -rf", "$(calc)", "a`b", "", "-bad-", "x" * 300])
def test_valid_host_rejects_injection(bad):
    with pytest.raises(ValueError):
        valid_host(bad)


def test_valid_ip():
    assert valid_ip(" 10.0.0.1 ") == "10.0.0.1"
    with pytest.raises(ValueError):
        valid_ip("10.0.0.1; calc")


# --- interfaces -------------------------------------------------------------
IFACES = json.dumps([
    {"Alias": "Ethernet", "Mac": "AA:BB:CC:00:00:01", "IPAddress": ["192.168.1.151", "fe80::1"],
     "IPSubnet": ["255.255.255.0", "64"], "Gateway": ["192.168.1.1"], "Dns": ["172.168.4.245"],
     "DhcpEnabled": True, "DhcpServer": "192.168.1.1", "Suffix": "gtc.local"},
    {"Alias": "APIPA", "IPAddress": ["169.254.3.4"], "IPSubnet": ["255.255.0.0"]},
    {"Alias": "VPN", "IPAddress": ["10.8.0.2"], "IPSubnet": ["255.255.255.252"], "Gateway": None,
     "Dns": None, "DhcpEnabled": False}])


def test_parse_interfaces():
    r = ifc.parse_interfaces(IFACES)
    assert [i.ipv4 for i in r] == ["192.168.1.151", "10.8.0.2"]  # APIPA et IPv6 ignorés
    e = r[0]
    assert e.prefix == 24 and e.gateway == "192.168.1.1" and e.dhcp_server == "192.168.1.1"
    assert e.dns_servers == ["172.168.4.245"] and r[1].prefix == 30 and r[1].dns_servers == []


def test_parse_interfaces_single_object_and_garbage_mask():
    one = json.dumps({"Alias": "x", "IPAddress": "10.0.0.5", "IPSubnet": "255.0.0.0"})
    assert ifc.parse_interfaces(one)[0].prefix == 8
    assert ifc.parse_interfaces(json.dumps({"IPAddress": ["10.0.0.5"], "IPSubnet": ["bad"]})) == []


def test_parse_routes():
    r = ifc.parse_routes(json.dumps([{"Destination": "172.168.4.0/24", "NextHop": "192.168.1.254",
                                      "Metric": 5, "Interface": "Ethernet"}, {"Destination": "junk"}]))
    assert len(r) == 1 and r[0].next_hop == "192.168.1.254"


# --- AD ---------------------------------------------------------------------
def test_parse_domain_joined():
    d = ad.parse_domain(json.dumps({"Name": "PC1", "Domain": "gtc.local", "PartOf": True,
                                    "UserDnsDomain": "GTC.LOCAL"}))
    assert d.in_domain and d.name == "gtc.local" and any("corrobore" in e for e in d.evidence)


def test_parse_domain_workgroup():
    d = ad.parse_domain(json.dumps({"Name": "PC1", "Domain": "WORKGROUP", "PartOf": False}))
    assert not d.in_domain


def test_filetime_and_computers():
    assert ad.filetime_to_iso(0) == "" and ad.filetime_to_iso("x") == ""
    assert ad.filetime_to_iso(133500000000000000).startswith("2024-")
    text = json.dumps([
        {"Name": "PC-A", "Dns": "pc-a.gtc.local", "Uac": 4096, "Lls": 133500000000000000, "Os": "Windows 11"},
        {"Name": "PC-B", "Dns": "", "Uac": 4098, "Lls": 0}])
    comps = ad.parse_ad_computers(text, "gtc.local")
    assert comps[0].enabled is True and comps[1].enabled is False       # bit 2 = désactivé
    assert comps[1].dns_hostname == "pc-b.gtc.local" and comps[1].last_logon == ""


def test_stale():
    assert ad.stale("2001-01-01T00:00:00+00:00", 90) and not ad.stale("", 90)


def test_parse_srv_ordering():
    t = json.dumps([{"Target": "dc2.gtc.local.", "Priority": 10}, {"Target": "dc1.gtc.local.", "Priority": 0},
                    {"Target": "dc1.gtc.local.", "Priority": 0}])
    assert ad.parse_srv(t) == ["dc1.gtc.local", "dc2.gtc.local"]


def test_ad_collection_refused_outside_domain():
    with pytest.raises(SourceUnavailable):
        ad.collect_ad_computers(DomainInfo(in_domain=False))


# --- DHCP -------------------------------------------------------------------
DHCP_JSON = json.dumps([{
    "ScopeId": "192.168.1.0", "Name": "LAN", "Mask": "255.255.255.0", "Start": "192.168.1.100",
    "End": "192.168.1.200", "State": "Active", "Gateway": "192.168.1.1",
    "Exclusions": [{"Start": "192.168.1.100", "End": "192.168.1.110"}],
    "Leases": [{"IP": "192.168.1.120", "Mac": "aa-bb-cc-dd-ee-01", "Host": "laptop", "State": "Active"}],
    "Reservations": {"IP": "192.168.1.30", "Mac": "aa-bb-cc-dd-ee-02", "Host": "printer"}, "Errors": []},
    {"ScopeId": "192.168.2.0", "Name": "B", "Mask": "255.255.255.0", "Start": "192.168.2.10",
     "End": "192.168.2.20", "State": "Active", "Exclusions": [], "Leases": [], "Reservations": [],
     "Errors": ["baux: accès refusé"]}])


def test_parse_dhcp_scopes_and_partial_errors():
    d = DhcpData()
    dh.parse_server_scopes("srv", DHCP_JSON, d)
    assert len(d.scopes) == 2 and d.scopes[0].exclusions == [("192.168.1.100", "192.168.1.110")]
    assert [l.reservation for l in d.leases] == [False, True]
    assert d.queried_scopes == {"srv|192.168.1.0"}      # le scope en erreur n'est pas « lu »
    assert d.errors and "accès refusé" in d.errors[0]


def test_parse_dhcp_servers():
    assert dh.parse_servers(json.dumps([{"Name": "dhcp1.gtc.local", "IP": "10.0.0.2"},
                                        {"Name": "x", "IP": "bad"}])) == ["10.0.0.2", "x"]


# --- scan -------------------------------------------------------------------
def test_parse_arp_a_windows():
    txt = """Interface : 192.168.1.151 --- 0x5
  Adresse Internet      Adresse physique      Type
  192.168.1.1           aa-bb-cc-00-00-01     dynamique
  192.168.1.255         ff-ff-ff-ff-ff-ff     statique
  224.0.0.22            01-00-5e-00-00-16     statique
"""
    r = scan.parse_arp_a(txt)
    assert list(r) == ["192.168.1.1"] and r["192.168.1.1"][0] == "aa:bb:cc:00:00:01"


def test_parse_neighbors_filters_invalid():
    t = json.dumps([{"IP": "192.168.1.1", "Mac": "AA-BB-CC-00-00-01", "State": "Reachable"},
                    {"IP": "192.168.1.9", "Mac": "00-00-00-00-00-00", "State": "Stale"},
                    {"IP": "224.0.0.1", "Mac": "01-00-5E-00-00-01", "State": "Permanent"}])
    assert list(scan.parse_neighbors(t)) == ["192.168.1.1"]


def test_sweep_cancel_marks_incomplete():
    ev = threading.Event()
    net = ipaddress.ip_network("10.0.0.0/28")
    calls = []

    def ping(ip, t):
        calls.append(ip)
        if len(calls) >= 3:
            ev.set()
        return False
    res, done = scan.sweep(net, ping, 100, 1, ev)
    assert done is False and len(res) < 14


def test_dns_resolver_localhost_and_absent():
    st, ips = resolver.resolve_a("localhost")
    assert st == resolver.RESOLVED and "127.0.0.1" in ips
    st, _ = resolver.resolve_a("hote-inexistant-gtc.invalid")
    assert st in (resolver.ABSENT, resolver.UNAVAILABLE)


# --- orchestrateur (collecteurs SIMULÉS) --------------------------------------
def fake_collectors(dhcp_fail=False, ad_fail=False, dns_unavailable=False):
    live = {"192.168.1.1", "192.168.1.151", "192.168.1.20"}

    def dhcp_fn(extra):
        if dhcp_fail:
            raise SourceUnavailable("Module DhcpServer absent (simulé)")
        d = DhcpData(servers=["192.168.1.1"])
        dh.parse_server_scopes("192.168.1.1", DHCP_JSON, d)
        d.scopes, d.errors = d.scopes[:1], []
        return d

    def ad_fn(domain, server=None):
        if ad_fail:
            raise SourceUnavailable("Droits insuffisants (simulé)")
        return [AdComputer("PC-OK", "pc-ok.gtc.local", True),
                AdComputer("PC-GONE", "pc-gone.gtc.local", True),
                AdComputer("PC-NODNS", "pc-nodns.gtc.local", False)]

    def a_fn(host):
        if dns_unavailable:
            return resolver.UNAVAILABLE, []
        return {"pc-ok.gtc.local": (resolver.RESOLVED, ["192.168.1.20"]),
                "pc-gone.gtc.local": (resolver.RESOLVED, ["192.168.1.60"])}.get(host, (resolver.ABSENT, []))

    return orch.Collectors(
        interfaces=lambda: [Interface("Ethernet", "192.168.1.151", 24, "AA:BB:CC:00:00:01", "192.168.1.1",
                                      ["192.168.1.1"], True, "192.168.1.1")],
        routes=lambda: [Route("172.168.4.0/24", "192.168.1.254")],
        domain=lambda: DomainInfo(True, "gtc.local", ["dc1.gtc.local"], ["172.168.4.254"], ["simulé"]),
        ad_computers=ad_fn, dhcp=dhcp_fn,
        ping=lambda ip, t: ip in live,
        neighbors=lambda: {"192.168.1.1": ("aa:bb:cc:00:00:01", "Reachable"),
                           "192.168.1.20": ("aa:bb:cc:00:00:20", "Reachable")},
        resolve_a=a_fn,
        resolve_ptr=lambda ip: ((resolver.RESOLVED, "pc-ok.gtc.local") if ip == "192.168.1.20"
                                else (resolver.ABSENT, "")),
        tcp_check=lambda h, p, timeout=2.0: True,
        tcp_from=lambda src, h, p, timeout=3.0: True)


def opts(**kw):
    s = Settings()
    s.concurrency = 8
    return orch.Options(networks=["192.168.1.0/24"], settings=s, **kw)


def test_full_analysis_simulated():
    snap = orch.run_analysis(opts(), fake_collectors(), threading.Event())
    assert all(s.state == SRC_OK for s in snap.sources), [(s.name, s.state, s.detail) for s in snap.sources]
    by = {c.name: c for c in snap.ad_computers}
    assert by["PC-OK"].verification.startswith("Active")
    assert "sans réponse" in by["PC-GONE"].verification          # DNS seul != active
    assert by["PC-NODNS"].verification.startswith("Aucun enregistrement DNS")
    assert "compte désactivé" in by["PC-NODNS"].verification
    plan = {e.ip: e for e in snap.plan["192.168.1.0/24"]}
    assert plan["192.168.1.60"].status == "INCONNUE"             # enregistrement périmé potentiel
    assert plan["192.168.1.20"].status == "OCCUPÉE"
    assert plan["192.168.1.105"].status == DISPONIBLE            # exclusion DHCP, silencieuse
    assert plan["192.168.1.150"].status == "DHCP_DYNAMIQUE"
    assert snap.candidates["192.168.1.0/24"][0].ip == "192.168.1.100"
    assert snap.domain.dc_addresses == ["172.168.4.254"]
    assert any("autre sous-réseau" in e for e in snap.domain.evidence)


def test_dhcp_unavailable_degrades_to_candidates_never_confirmed():
    snap = orch.run_analysis(opts(), fake_collectors(dhcp_fail=True), threading.Event())
    st = {s.name.split(" ")[0]: s for s in snap.sources}
    assert st["DHCP"].state == SRC_UNAVAILABLE and "simulé" in st["DHCP"].detail
    statuses = {e.status for e in snap.plan["192.168.1.0/24"]}
    assert DISPONIBLE not in statuses and CANDIDATE in statuses


def test_ad_unavailable_blocks_confirmation():
    snap = orch.run_analysis(opts(), fake_collectors(ad_fail=True), threading.Event())
    assert snap.ad_computers == []
    assert DISPONIBLE not in {e.status for e in snap.plan["192.168.1.0/24"]}


def test_dns_unavailable_is_not_absent():
    snap = orch.run_analysis(opts(), fake_collectors(dns_unavailable=True), threading.Event())
    assert all(c.verification.startswith("DNS indisponible") for c in snap.ad_computers)
    assert any(s.state == SRC_PARTIAL for s in snap.sources)


def test_cancel_before_start_builds_no_plan():
    ev = threading.Event()
    ev.set()
    snap = orch.run_analysis(opts(), fake_collectors(), ev)
    assert snap.cancelled and snap.plan == {}
    assert all(s.state == SRC_CANCELLED for s in snap.sources)


def test_cancel_during_scan_builds_no_plan():
    ev = threading.Event()
    col = fake_collectors()
    n = [0]

    def ping(ip, t):
        n[0] += 1
        if n[0] == 5:
            ev.set()
        return False
    col.ping = ping
    snap = orch.run_analysis(opts(), col, ev)
    assert snap.cancelled and snap.plan == {} and "annulée" in " ".join(snap.warnings)


def test_unexpected_exception_is_contained():
    col = fake_collectors()
    col.interfaces = lambda: 1 / 0
    snap = orch.run_analysis(opts(), col, threading.Event())
    assert snap.sources[0].state == SRC_UNAVAILABLE and "ZeroDivisionError" in snap.sources[0].detail


def test_network_too_large_is_skipped_with_warning():
    o = opts()
    o.networks = ["10.0.0.0/8", "bad", "fe80::/64"]
    snap = orch.run_analysis(o, fake_collectors(), threading.Event())
    assert len(snap.warnings) == 3 and snap.plan == {}


def test_remote_network_is_never_confirmed_and_warns_non_rfc1918():
    o = opts()
    o.networks = ["172.168.4.0/24"]
    col = fake_collectors()
    snap = orch.run_analysis(o, col, threading.Event())
    plan = snap.plan["172.168.4.0/24"]
    assert DISPONIBLE not in {e.status for e in plan}
    assert any("RFC1918" in w for w in snap.warnings)


def test_settings_roundtrip_and_clamp(tmp_path):
    p = tmp_path / "s.json"
    s = Settings(max_hosts=999999, concurrency=0)
    s.save(p)
    s2 = Settings.load(p)
    assert s2.max_hosts == 4096 and s2.concurrency == 1 and s2.dc_hints == []
    assert Settings.load(tmp_path / "missing.json").max_hosts == 1024


# --- détection native / régressions issues d'un poste réel --------------------
ROUTE_FR = """===========================================================================
Table de routage IPv4
===========================================================================
Itinéraires actifs :
Destination réseau    Masque réseau  Adr. passerelle   Adr. interface Métrique
          0.0.0.0          0.0.0.0     172.168.4.1    172.168.4.50     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
     172.168.4.0    255.255.255.0         On-link     172.168.4.50    281
   192.168.1.0    255.255.255.0     172.168.4.254    172.168.4.50     26
        224.0.0.0        240.0.0.0         On-link     172.168.4.50    281
  255.255.255.255  255.255.255.255         On-link     172.168.4.50    281
"""


def test_parse_route_print_locale_independent():
    from gtc_ipm.core.winnet import parse_route_print
    r = {x.destination: x for x in parse_route_print(ROUTE_FR)}
    assert set(r) == {"0.0.0.0/0", "172.168.4.0/24", "192.168.1.0/24"}
    assert r["0.0.0.0/0"].next_hop == "172.168.4.1" and r["172.168.4.0/24"].next_hop == ""


def test_domain_detection_failure_is_not_reported_as_workgroup():
    col = fake_collectors()

    def boom():
        raise SourceUnavailable("Délai dépassé (45 s).")
    col.domain = boom
    # ad_computers réel : domaine non détecté => on tente quand même l'AD, sans dire « hors domaine »
    called = []
    col.ad_computers = lambda d, server=None: called.append(d.detected) or []
    snap = orch.run_analysis(opts(), col, threading.Event())
    assert called == [False]
    assert not snap.domain.detected and any("n'est pas déclaré" in e for e in snap.domain.evidence)
    dom = next(x for x in snap.sources if x.name.startswith("Domaine"))
    assert dom.state == SRC_UNAVAILABLE and "Délai" in dom.detail


def test_real_workgroup_message_only_when_detected():
    with pytest.raises(SourceUnavailable, match="hors domaine"):
        ad.collect_ad_computers(DomainInfo(in_domain=False, detected=True))


def test_native_functions_refuse_cleanly_off_windows():
    from gtc_ipm.core import winnet
    if winnet.IS_WINDOWS:
        pytest.skip("Windows")
    for fn in (winnet.collect_interfaces_native, winnet.collect_routes_native, winnet.join_status):
        with pytest.raises(SourceUnavailable):
            fn()


def test_duplicate_dns_servers_are_deduplicated():
    t = json.dumps({"Alias": "Wi-Fi", "IPAddress": ["192.168.1.135"], "IPSubnet": ["255.255.255.0"],
                    "Dns": ["192.168.1.1", "192.168.1.1"]})
    assert ifc.parse_interfaces(t)[0].dns_servers == ["192.168.1.1"]


def test_dhcp_non_windows_server_skipped_fast(monkeypatch):
    monkeypatch.setattr(dh, "_rpc_reachable", lambda h, t=3.0: False)
    monkeypatch.setattr(dh, "ps_json", lambda *a, **k: (_ for _ in ()).throw(SourceUnavailable("x")))
    with pytest.raises(SourceUnavailable) as e:
        dh.collect_dhcp(["192.168.1.1"])
    assert "135" in str(e.value)


def test_config_sheet_uses_domain_dns_and_warns_about_public_dns():
    from gtc_ipm.core.models import IpEntry, Snapshot
    from gtc_ipm.reports.export import config_sheet
    snap = Snapshot(interfaces=[Interface("Eth", "172.168.4.18", 24, "", "172.168.4.45",
                                          ["172.168.4.245", "8.8.8.8"])],
                    domain=DomainInfo(True, "gtcagences.lan", [], ["172.168.4.245"]))
    e = IpEntry("172.168.4.10", "CANDIDATE_À_VÉRIFIER", "x", "172.168.4.0/24", "NOW")
    t = config_sheet(e, snap)
    assert "DNS à configurer  : 172.168.4.245" in t and "8.8.8.8" in t and "ATTENTION" in t
    snap.interfaces[0].dns_servers = ["172.168.4.245"]
    assert "ATTENTION" not in config_sheet(e, snap)


# --- voie Internet / connectivité ---------------------------------------------------
from gtc_ipm.core import internet as inet  # noqa: E402


def test_internet_path_detected_from_orchestrator():
    snap = orch.run_analysis(opts(), fake_collectors(), threading.Event())
    assert len(snap.internet) == 1 and snap.internet[0].internet_ok and snap.internet[0].gateway == "192.168.1.1"
    assert any("192.168.1.1" in c for c in snap.gateway_candidates)


def test_no_internet_is_reported_not_assumed():
    col = fake_collectors()
    col.tcp_from = lambda *a, **k: False
    snap = orch.run_analysis(opts(), col, threading.Event())
    src = next(x for x in snap.sources if x.name.startswith("Accès Internet"))
    assert src.state == SRC_PARTIAL and not snap.internet[0].internet_ok


def test_dns_packet_roundtrip():
    q = inet.build_dns_query("www.google.com", 0x1234)
    assert q[:2] == b"\x12\x34" and q.endswith(b"\x00\x01\x00\x01")
    resp = (b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:] +
            b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x8e\xfa\xb8\x64")
    assert inet.parse_dns_answer(resp, 0x1234) == ("ok", ["142.250.184.100"])
    assert inet.parse_dns_answer(resp, 0x9999)[0] == "invalide"
    nx = b"\x12\x34\x81\x83\x00\x01\x00\x00\x00\x00\x00\x00" + q[12:]
    assert inet.parse_dns_answer(nx, 0x1234)[0] == "nxdomain"


def test_connectivity_report_pinpoints_dns_vs_gateway():
    itf = Interface("Eth", "192.168.1.151", 24, "", "192.168.1.1", ["10.9.9.9"], True, "192.168.1.1")
    r = "\n".join(inet.connectivity_report([itf], "corp.lan", tcp=lambda *a, **k: True,
                                            lookup=lambda s, n, t=3.0: ("sans réponse", []), ping=lambda i, t: True))
    assert "Internet : OK" in r and "sans réponse" in r and "DNS" in r.split("CONCLUSION")[1]
    bad = Interface("Eth", "172.168.4.10", 24, "", "192.168.1.1", [])
    r2 = "\n".join(inet.connectivity_report([bad], tcp=lambda *a, **k: False, lookup=lambda *a, **k: ("ok", [])))
    assert "pas dans le sous-réseau" in r2 and "aucune carte n'atteint Internet" in r2


def test_internet_plan_adapts_to_any_site():
    # Site A : la box est dans un autre sous-réseau que le réseau cible
    p = inet.InternetPath("Eth", "192.168.1.151", "192.168.1.0/24", "192.168.1.1", True, "192.168.1.1",
                          internet_ok=True)
    t = "\n".join(inet.internet_plan("172.168.4.0/24", [p], ["172.168.4.245"]))
    assert "PAS dans 172.168.4.0/24" in t and "netsh interface ip add address" in t and "255.255.255.0" in t
    # Site B (autre FAI, autre plage) : la box est dans le réseau cible
    p2 = inet.InternetPath("Eth", "10.20.0.5", "10.20.0.0/24", "10.20.0.254", False, "", internet_ok=True)
    t2 = "\n".join(inet.internet_plan("10.20.0.0/24", [p2], ["10.20.0.2"]))
    assert "utilisez-la comme passerelle" in t2 and "netsh" not in t2
    assert "aucune passerelle Internet" in "\n".join(inet.internet_plan("10.20.0.0/24", [], []))


def test_config_sheet_contains_internet_section():
    from gtc_ipm.core.models import IpEntry, Snapshot
    from gtc_ipm.reports.export import config_sheet
    snap = Snapshot(interfaces=[Interface("Eth", "192.168.1.151", 24, "", "192.168.1.1", ["172.168.4.245"], True)],
                    internet=[inet.InternetPath("Eth", "192.168.1.151", "192.168.1.0/24", "192.168.1.1", True, "",
                                                internet_ok=True)],
                    domain=DomainInfo(True, "x.lan", [], ["172.168.4.245"]))
    t = config_sheet(IpEntry("172.168.4.10", "CANDIDATE_À_VÉRIFIER", "x", "172.168.4.0/24", "NOW"), snap)
    assert "ACCÈS INTERNET" in t and "192.168.1.1" in t


def test_working_gateway_is_remembered_and_reused_after_switching_to_static():
    from gtc_ipm.core.models import IpEntry, Snapshot
    from gtc_ipm.reports.export import config_sheet
    known: dict = {}
    # 1) analyse en DHCP : la box donne Internet
    ok = inet.InternetPath("Eth", "192.168.1.151", "192.168.1.0/24", "192.168.1.1", True, "192.168.1.1",
                           ["192.168.1.1"], True, "ok", "T1")
    assert inet.remember_paths(known, [ok]) and not inet.remember_paths(known, [ok])
    # 2) après passage en fixe : plus d'Internet détecté, mais la passerelle mémorisée est proposée
    lost = inet.InternetPath("Eth", "192.168.1.200", "192.168.1.0/24", "192.168.1.1", False, "", [], False, "KO", "T2")
    snap = Snapshot(interfaces=[Interface("Eth", "192.168.1.200", 24, "", "192.168.1.1", [])], internet=[lost])
    t = config_sheet(IpEntry("192.168.1.50", "CANDIDATE_À_VÉRIFIER", "x", "192.168.1.0/24", "NOW"), snap,
                     known_internet=known)
    assert "Passerelle        : 192.168.1.1  (passerelle Internet mémorisée)" in t
    # une passerelle ayant échoué n'est jamais mémorisée
    assert not inet.remember_paths({}, [lost])


def test_sheet_never_prints_unconfirmed_foreign_gateway_as_valid():
    from gtc_ipm.core.models import IpEntry, Snapshot
    from gtc_ipm.reports.export import config_sheet
    snap = Snapshot(interfaces=[Interface("Eth", "172.168.4.18", 24, "", "172.168.4.45", [])])
    t = config_sheet(IpEntry("172.168.4.10", "CANDIDATE_À_VÉRIFIER", "x", "172.168.4.0/24", "NOW"), snap)
    assert "NON confirmée comme accès Internet" in t
    snap.interfaces[0].gateway = "192.168.1.1"
    assert "aucune passerelle Internet dans ce réseau" in config_sheet(
        IpEntry("172.168.4.10", "CANDIDATE_À_VÉRIFIER", "x", "172.168.4.0/24", "NOW"), snap)
