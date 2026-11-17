"""Test d'intégration RÉEL, à lancer sur Windows (CI windows-latest) : aucune donnée simulée.

1. Chaque script PowerShell de l'application est analysé par le parseur PowerShell
   (détecte toute erreur de syntaxe).
2. Les collecteurs en lecture seule s'exécutent pour de vrai sur la machine.
   Hors domaine / sans module DHCP, une SourceUnavailable explicite est le résultat attendu.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gtc_ipm.ad import inventory as ad  # noqa: E402
import time  # noqa: E402
from gtc_ipm.core import winnet  # noqa: E402
from gtc_ipm.core.psrunner import IS_WINDOWS, SourceUnavailable, run_powershell  # noqa: E402
from gtc_ipm.dhcp import collector as dh  # noqa: E402
from gtc_ipm.discovery import interfaces as ifc  # noqa: E402
from gtc_ipm.discovery import scan  # noqa: E402
from gtc_ipm.dns import resolver  # noqa: E402

PARSE = r"""
$errs=$null; $tok=$null
[void][System.Management.Automation.Language.Parser]::ParseInput($env:GTCARG_CODE,[ref]$tok,[ref]$errs)
if ($errs.Count -gt 0) { $errs | ForEach-Object { $_.Message + ' @' + $_.Extent.StartLineNumber }; exit 3 }
'OK'
"""

SCRIPTS = {
    "interfaces": ifc.SCRIPT_INTERFACES, "routes": ifc.SCRIPT_ROUTES, "voisins": scan.SCRIPT_NEIGHBORS,
    "domaine": ad.SCRIPT_DOMAIN, "srv": ad.SCRIPT_SRV, "ad": ad.SCRIPT_AD_COMPUTERS,
    "dhcp-serveurs": dh.SCRIPT_DHCP_SERVERS, "dhcp-serveur": dh.SCRIPT_DHCP_SERVER,
}


def main() -> int:
    if not IS_WINDOWS:
        print("Ce test nécessite Windows.")
        return 2
    failures = 0
    for name, code in SCRIPTS.items():
        try:
            out = run_powershell(PARSE, {"CODE": code}, 60)
            print(f"[syntaxe] {name}: {out}")
        except SourceUnavailable as e:
            print(f"[syntaxe] {name}: ERREUR {e}")
            failures += 1

    def attempt(label, fn):
        nonlocal failures
        try:
            r = fn()
            print(f"[réel] {label}: OK -> {r if not isinstance(r, (list, dict)) else len(r)} élément(s)")
            return r
        except SourceUnavailable as e:
            print(f"[réel] {label}: source inaccessible (attendu hors domaine/RSAT) -> {e}")
        except Exception as e:  # noqa: BLE001
            print(f"[réel] {label}: ERREUR INATTENDUE {type(e).__name__}: {e}")
            failures += 1

    for label, fn in (("natif interfaces", winnet.collect_interfaces_native),
                      ("natif routes", winnet.collect_routes_native),
                      ("natif DNS", winnet.global_dns_servers),
                      ("natif jonction domaine", winnet.join_status),
                      ("natif domaine", lambda: winnet.detect_domain_native(None))):
        t0 = time.time()
        r = attempt(label, fn)
        print(f"   durée {time.time() - t0:.2f}s ->", r if not isinstance(r, list) else [str(x)[:120] for x in r[:3]])
    t0 = time.time()
    ps_if = attempt("interfaces (PowerShell)", lambda: ifc.parse_interfaces_from(ifc.ps_json(ifc.SCRIPT_INTERFACES, timeout=60)))
    print(f"   durée PowerShell {time.time() - t0:.2f}s")
    nat_if = winnet.collect_interfaces_native()
    if ps_if is not None and sorted(i.ipv4 for i in ps_if) != sorted(i.ipv4 for i in nat_if):
        print("DIFFÉRENCE interfaces natif/PowerShell:", [i.ipv4 for i in nat_if], [i.ipv4 for i in ps_if])
        failures += 1
    itfs = attempt("interfaces", ifc.collect_interfaces)
    attempt("routes", ifc.collect_routes)
    dom = attempt("domaine", ad.collect_domain)
    if dom is not None:
        print("   domaine:", dom.in_domain, dom.name, dom.evidence)
    attempt("voisinage ARP", scan.read_neighbors)
    attempt("DHCP", lambda: dh.collect_dhcp([]))
    print("[réel] ping 127.0.0.1:", scan.ping_host("127.0.0.1", 1000))
    print("[réel] DNS localhost:", resolver.resolve_a("localhost"))
    if itfs is not None and not itfs:
        print("   (aucune interface IPv4 non-APIPA sur ce runner)")
    print("ÉCHECS:", failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
