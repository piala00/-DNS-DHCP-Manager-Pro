"""Tests métier du plan d'adressage. Les données sont SIMULÉES (jeux de test)."""
import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from gtc_ipm.core.models import (CANDIDATE, CONFLIT, DHCP_DYNAMIQUE, DISPONIBLE,  # noqa: E402
                                 EXCLUE, INCONNUE, OCCUPEE, RESERVEE, DhcpData,
                                 DhcpLease, DhcpScope, DomainInfo, AdComputer,
                                 Interface, Observation, Snapshot)
from gtc_ipm.planning import planner as P  # noqa: E402
from gtc_ipm.planning.evidence import collect_evidence  # noqa: E402

NET = ipaddress.ip_network("192.168.1.0/24")


def snap_base():
    s = Snapshot(started_at="T0", finished_at="T1")
    s.interfaces = [Interface("Ethernet", "192.168.1.151", 24, "AA:BB:CC:00:00:01",
                              "192.168.1.1", ["192.168.1.1"], True, "192.168.1.1")]
    return s


def ctx(**kw):
    base = dict(network=NET, local_segment=True,
                scanned={str(a) for a in NET}, dhcp_queried=True, dns_ok=True, ad_ok=True)
    base.update(kw)
    return P.NetworkContext(**base)


def plan_map(snap, c, **kw):
    ev = collect_evidence(snap, c.network, **kw)
    return {e.ip: e for e in P.build_plan(c, ev, "NOW")}


def test_network_and_broadcast_excluded():
    m = plan_map(snap_base(), ctx())
    assert m["192.168.1.0"].status == EXCLUE
    assert m["192.168.1.255"].status == EXCLUE


def test_slash31_has_no_network_broadcast_exclusion():
    c = P.NetworkContext(network=ipaddress.ip_network("10.0.0.0/31"),
                         scanned={"10.0.0.0", "10.0.0.1"}, dhcp_queried=True,
                         dns_ok=True, ad_ok=True)
    plan = P.build_plan(c, {}, "NOW")
    assert all(e.status != EXCLUE for e in plan)


def test_roles_are_occupied():
    m = plan_map(snap_base(), ctx())
    assert m["192.168.1.1"].status == OCCUPEE      # passerelle + DNS + DHCP
    assert m["192.168.1.151"].status == OCCUPEE    # ce poste


def test_silent_ip_with_all_checks_is_confirmed_but_conditional():
    m = plan_map(snap_base(), ctx())
    e = m["192.168.1.50"]
    assert e.status == DISPONIBLE
    assert "valable uniquement" in e.justification and e.checked_at == "NOW"


def test_ping_silence_alone_never_confirms():
    # DHCP non lu, DNS non vérifié, AD non lu -> seulement CANDIDATE
    m = plan_map(snap_base(), ctx(dhcp_queried=False, dns_ok=False, ad_ok=False))
    e = m["192.168.1.50"]
    assert e.status == CANDIDATE
    assert "DHCP non lu" in e.justification and "DNS non vérifié" in e.justification


def test_remote_subnet_cannot_be_confirmed():
    m = plan_map(snap_base(), ctx(local_segment=False))
    assert m["192.168.1.50"].status == CANDIDATE
    assert "distant" in m["192.168.1.50"].justification


def test_unscanned_ip_is_unknown():
    m = plan_map(snap_base(), ctx(scanned=set()))
    assert m["192.168.1.50"].status == INCONNUE


def test_dns_record_without_host_is_unknown_not_free():
    s = snap_base()
    s.ad_computers = [AdComputer("PC-OLD", "pc-old.gtc.local", True, ipv4=["192.168.1.60"])]
    m = plan_map(s, ctx())
    assert m["192.168.1.60"].status == INCONNUE
    assert "périmé" in m["192.168.1.60"].justification


def test_dhcp_dynamic_range_never_proposed():
    s = snap_base()
    s.dhcp = DhcpData(scopes=[DhcpScope("dhcp1", "192.168.1.0", "", "255.255.255.0",
                                        "192.168.1.100", "192.168.1.200")])
    m = plan_map(s, ctx())
    assert m["192.168.1.150"].status == DHCP_DYNAMIQUE
    cands = P.propose_candidates(m.values(), 500)
    lo, hi = int(ipaddress.ip_address("192.168.1.100")), int(ipaddress.ip_address("192.168.1.200"))
    assert cands and all(not lo <= int(ipaddress.ip_address(c.ip)) <= hi for c in cands)


def test_exclusion_range_inside_dynamic_is_eligible_and_preferred():
    s = snap_base()
    s.dhcp = DhcpData(scopes=[DhcpScope("dhcp1", "192.168.1.0", "", "255.255.255.0",
                                        "192.168.1.10", "192.168.1.200",
                                        exclusions=[("192.168.1.10", "192.168.1.20")])])
    m = plan_map(s, ctx())
    assert m["192.168.1.15"].status == DISPONIBLE and m["192.168.1.15"].preferred
    assert m["192.168.1.30"].status == DHCP_DYNAMIQUE
    first = P.propose_candidates(m.values(), 3)
    assert [e.ip for e in first] == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]


def test_reservation_and_lease():
    s = snap_base()
    s.dhcp = DhcpData(scopes=[DhcpScope("dhcp1", "192.168.1.0", "", "255.255.255.0",
                                        "192.168.1.100", "192.168.1.200")],
                      leases=[DhcpLease("dhcp1", "192.168.1.0", "192.168.1.120", "aa-bb-cc-dd-ee-01",
                                        "laptop", "Active"),
                              DhcpLease("dhcp1", "192.168.1.0", "192.168.1.30", "aa-bb-cc-dd-ee-02",
                                        "printer", "ActiveReservation", reservation=True),
                              DhcpLease("dhcp1", "192.168.1.0", "192.168.1.121", "aa-bb-cc-dd-ee-03",
                                        "old", "Expired")])
    m = plan_map(s, ctx())
    assert m["192.168.1.120"].status == DHCP_DYNAMIQUE
    assert m["192.168.1.30"].status == RESERVEE
    assert m["192.168.1.121"].status == DHCP_DYNAMIQUE  # plage dynamique, bail expiré ignoré


def test_mac_mismatch_is_conflict():
    s = snap_base()
    s.dhcp = DhcpData(leases=[DhcpLease("d", "192.168.1.0", "192.168.1.77", "aa-bb-cc-dd-ee-01",
                                        "a", "Active")])
    s.observations = [Observation("192.168.1.77", "11:22:33:44:55:66", "b", ["arp"])]
    m = plan_map(s, ctx())
    assert m["192.168.1.77"].status == CONFLIT


def test_same_mac_in_different_formats_is_not_conflict():
    s = snap_base()
    s.dhcp = DhcpData(leases=[DhcpLease("d", "192.168.1.0", "192.168.1.77", "AA-BB-CC-DD-EE-01",
                                        "a", "Active")])
    s.observations = [Observation("192.168.1.77", "aa:bb:cc:dd:ee:01", "a", ["arp"])]
    assert plan_map(s, ctx())["192.168.1.77"].status != CONFLIT


def test_null_and_broadcast_mac_ignored():
    assert P.norm_mac("00-00-00-00-00-00") == "" and P.norm_mac("ff:ff:ff:ff:ff:ff") == ""
    assert P.norm_mac("AA-BB-CC-DD-EE-01") == "aa:bb:cc:dd:ee:01"


def test_observed_host_outside_domain_is_occupied():
    s = snap_base()
    s.observations = [Observation("192.168.1.88", "aa:aa:aa:aa:aa:aa", "", ["ping"])]
    assert plan_map(s, ctx())["192.168.1.88"].status == OCCUPEE


def test_static_inventory_and_user_exclusion():
    m = plan_map(snap_base(), ctx(), static_inventory={"192.168.1.9": "imprimante"},
                 user_excluded=[("192.168.1.240", "192.168.1.250")])
    assert m["192.168.1.9"].status == OCCUPEE
    assert m["192.168.1.245"].status == EXCLUE


def test_overlapping_scopes_other_network_ignored():
    s = snap_base()
    s.dhcp = DhcpData(scopes=[DhcpScope("d", "172.168.4.0", "", "255.255.255.0",
                                        "172.168.4.10", "172.168.4.200")])
    m = plan_map(s, ctx())
    assert all(e.status != DHCP_DYNAMIQUE for e in m.values())


def test_dc_in_other_subnet_does_not_affect_plan():
    s = snap_base()
    s.domain = DomainInfo(True, "gtc.local", ["dc1"], ["172.168.4.254"])
    m = plan_map(s, ctx())
    assert "172.168.4.254" not in m


def test_network_too_large_refused():
    c = P.NetworkContext(network=ipaddress.ip_network("10.0.0.0/8"))
    with pytest.raises(ValueError):
        P.build_plan(c, {})


@pytest.mark.parametrize("cidr,warn", [
    ("172.168.4.0/24", True), ("192.168.1.0/24", False), ("10.1.0.0/16", False),
    ("172.20.0.0/16", False), ("172.32.0.0/16", True), ("169.254.1.0/24", True)])
def test_rfc1918_warning(cidr, warn):
    assert bool(P.rfc1918_warning(ipaddress.ip_network(cidr))) is warn


def test_summarize_counts():
    m = plan_map(snap_base(), ctx())
    s = P.summarize(m.values())
    assert sum(s.values()) == 256 and s[EXCLUE] == 2
