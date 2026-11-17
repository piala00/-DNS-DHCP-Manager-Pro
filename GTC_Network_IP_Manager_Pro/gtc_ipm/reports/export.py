"""Exports CSV (UTF-8 BOM) et XLSX, fiche de configuration, diagnostic.
Aucune donnée inventée : un onglet vide reste vide, avec son en-tête."""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Iterable

from ..core.models import IpEntry, Snapshot, __version__

TABLES = ["Machines AD", "Réseau", "DHCP", "Plan", "Conflits", "Diagnostic", "Sources"]
_FORMULA = re.compile(r"^[=+\-@\t\r]")


def safe_cell(v):
    """Neutralise l'injection de formules CSV/Excel (=, +, -, @)."""
    if isinstance(v, str) and _FORMULA.match(v) and not re.fullmatch(r"-?\d+([.,]\d+)?", v):
        return "'" + v
    return v


def tables(snap: Snapshot) -> dict[str, tuple[list[str], list[list]]]:
    t: dict[str, tuple[list[str], list[list]]] = {}
    t["Machines AD"] = (
        ["Nom", "FQDN", "Compte activé", "Dernier contact AD (approx.)", "Système", "IPv4 (DNS)",
         "État DNS", "MAC observée", "Vérification", "Source", "Relevé"],
        [[c.name, c.dns_hostname, {True: "oui", False: "non", None: "?"}[c.enabled], c.last_logon, c.os,
          ", ".join(c.ipv4), c.dns_status, c.mac, c.verification, c.source, c.observed_at]
         for c in snap.ad_computers])
    net_rows = [[i.alias, i.ipv4, i.prefix, i.mac, i.gateway, ", ".join(i.dns_servers),
                 "oui" if i.dhcp_enabled else "non", i.dhcp_server, i.dns_suffix, "Interface locale"]
                for i in snap.interfaces]
    net_rows += [[o.hostname, o.ip, "", o.mac, "", "", "", "", "",
                  "Observé : " + ", ".join(o.methods) + (
                      "" if o.in_domain is None else (" ; domaine" if o.in_domain else " ; hors domaine AD"))]
                 for o in snap.observations]
    t["Réseau"] = (["Nom/Alias", "IPv4", "Préfixe", "MAC", "Passerelle", "DNS", "DHCP", "Serveur DHCP",
                    "Suffixe DNS", "Source"], net_rows)
    dh_rows = [[s.server, "Étendue", s.scope_id, s.name, s.subnet_mask, s.start, s.end, s.state,
                "; ".join(f"{a}-{b}" for a, b in s.exclusions)] for s in snap.dhcp.scopes]
    dh_rows += [[l.server, "Réservation" if l.reservation else "Bail", l.scope_id, l.hostname, l.mac, l.ip,
                 "", l.state, l.expires] for l in snap.dhcp.leases]
    t["DHCP"] = (["Serveur", "Type", "Étendue", "Nom", "Masque/MAC", "Début/IP", "Fin", "État",
                  "Exclusions/Expiration"], dh_rows)
    plan_rows = [[e.network, e.ip, e.status, e.hostname, e.mac, e.justification, ", ".join(e.sources),
                  e.checked_at] for entries in snap.plan.values() for e in entries]
    t["Plan"] = (["Réseau", "IP", "Statut", "Nom", "MAC", "Justification", "Sources", "Contrôlé le"], plan_rows)
    t["Conflits"] = (["Réseau", "IP", "Statut", "Justification", "Contrôlé le"],
                     [[e.network, e.ip, e.status, e.justification, e.checked_at] for e in snap.conflicts])
    diag = [["Application", f"GTC Network IP Manager Pro {__version__}"],
            ["Début", snap.started_at], ["Fin", snap.finished_at],
            ["Annulée", "oui" if snap.cancelled else "non"],
            ["Domaine", snap.domain.name or ("(hors domaine)" if not snap.domain.in_domain else "?")],
            ["Contrôleurs (adresses)", ", ".join(snap.domain.dc_addresses)]]
    diag += [["Constat domaine", x] for x in snap.domain.evidence]
    diag += [["Avertissement", w] for w in snap.warnings]
    diag += [["Erreur DHCP", e] for e in snap.dhcp.errors]
    diag += [["Réseaux sondés", n] for n in snap.scanned_networks]
    t["Diagnostic"] = (["Élément", "Valeur"], diag)
    t["Sources"] = (["Source", "État", "Détail", "Durée (s)", "Éléments", "Début"],
                    [[s.name, s.state, s.detail, s.duration_s, s.count, s.started_at] for s in snap.sources])
    return t


def export_csv_table(headers: list[str], rows: Iterable[list], path: str | Path) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(headers)
        for r in rows:
            w.writerow([safe_cell(c) for c in r])


def export_csv_folder(snap: Snapshot, folder: str | Path) -> list[Path]:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    out = []
    for name, (h, rows) in tables(snap).items():
        p = folder / (name.replace(" ", "_") + ".csv")
        export_csv_table(h, rows, p)
        out.append(p)
    return out


def export_xlsx(snap: Snapshot, path: str | Path) -> None:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill
    from openpyxl.utils import get_column_letter
    wb = Workbook()
    wb.remove(wb.active)
    for name, (h, rows) in tables(snap).items():
        ws = wb.create_sheet(name[:31])
        ws.append(h)
        for c in ws[1]:
            c.font = Font(bold=True, color="FFFFFF")
            c.fill = PatternFill("solid", fgColor="1F4E79")
        for r in rows:
            ws.append([safe_cell(c) for c in r])
        ws.freeze_panes = "A2"
        if rows:
            ws.auto_filter.ref = ws.dimensions
        for i, col in enumerate(ws.columns, 1):
            width = max((len(str(c.value)) for c in col if c.value is not None), default=8)
            ws.column_dimensions[get_column_letter(i)].width = min(60, width + 2)
    wb.save(path)


def config_sheet(entry: IpEntry, snap: Snapshot, hostname: str = "<NOM-DU-PC>") -> str:
    """Fiche de configuration pour un nouveau poste. Texte seulement : l'application
    ne modifie ni l'IP ni l'appartenance au domaine."""
    import ipaddress
    net = ipaddress.ip_network(entry.network)
    itf = next((i for i in snap.interfaces if ipaddress.ip_address(i.ipv4) in net), None)
    gw = itf.gateway if itf and itf.gateway else "<à renseigner : passerelle non détectée>"
    dns = ", ".join(itf.dns_servers) if itf and itf.dns_servers else (
        ", ".join(snap.domain.dc_addresses) or "<à renseigner : DNS AD>")
    lines = [
        "FICHE DE CONFIGURATION — nouveau poste (à appliquer manuellement)",
        f"Établie le : {entry.checked_at}",
        "",
        f"Nom de la machine : {hostname}",
        f"Adresse IPv4      : {entry.ip}",
        f"Masque            : {net.netmask} (/{net.prefixlen})",
        f"Passerelle        : {gw}",
        f"DNS (contrôleurs) : {dns}",
        f"Domaine           : {snap.domain.name or '<non détecté>'}",
        "",
        f"Statut de l'adresse : {entry.status}",
        f"Justification : {entry.justification}",
        "",
        "Contrôles avant affectation :",
        "  [ ] Revalider l'adresse (bouton « Vérifier l'adresse »).",
        "  [ ] Faire créer une réservation ou une exclusion DHCP par l'administrateur DHCP.",
        "  [ ] Vérifier la passerelle, le DNS et l'accès au contrôleur de domaine (ports 53, 88, 389, 445).",
        "  [ ] Sauvegarder la configuration réseau actuelle du poste (retour arrière).",
        "  [ ] Après configuration : ping passerelle, nslookup du domaine, jonction au domaine.",
        "",
        "Cette application n'a modifié aucune configuration (lecture seule).",
    ]
    return "\n".join(lines)


def diagnostic_json(snap: Snapshot) -> str:
    """Diagnostic exportable (sans secrets)."""
    return json.dumps({
        "application": f"GTC Network IP Manager Pro {__version__}",
        "debut": snap.started_at, "fin": snap.finished_at, "annulee": snap.cancelled,
        "sources": [s.__dict__ for s in snap.sources], "avertissements": snap.warnings,
        "domaine": snap.domain.__dict__, "erreurs_dhcp": snap.dhcp.errors, "journal": snap.log[-500:],
    }, ensure_ascii=False, indent=2)
