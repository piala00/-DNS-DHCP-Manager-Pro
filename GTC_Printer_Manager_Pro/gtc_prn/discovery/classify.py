"""Classification des imprimantes et liaison avec les programmes qui les ont installées.

Règle de prudence : on ne PRÉTEND jamais qu'une imprimante est « transférable » sans le dire :
un port propre à un programme (moniteur de port tiers) n'est pas recréé par Windows sur l'autre poste.
"""
from __future__ import annotations

import ntpath
import re
from dataclasses import dataclass

from ..core.models import DriverInfo, Inventory, MonitorInfo, PortInfo, PrinterInfo, ProgramInfo

NETWORK_MONITORS = {"standard tcp/ip port", "wsd port", "lpr port"}
BUILTIN_PORT_NAMES = {"portprompt:", "file:", "nul:", "shrfax:"}
VIRTUAL_HINTS = ("pdf", "xps", "onenote", "fax", "print to file", "enregistrer", "to file")


@dataclass
class Classification:
    kind: str
    port_class: str      # standard | integre | specifique
    advice: str


def classify(printer: PrinterInfo, port: PortInfo | None, driver: DriverInfo | None) -> Classification:
    monitor = (port.monitor if port else "").lower()
    pname = printer.port.lower()
    text = f"{printer.name} {printer.driver}".lower()
    if printer.name.startswith("\\\\"):
        return Classification("Imprimante partagée (connexion réseau)", "standard",
                              "Se reconnecte au serveur d'impression : rien à transférer, seulement la connexion.")
    if monitor in NETWORK_MONITORS:
        return Classification("Réseau (TCP/IP)", "standard",
                              "Transférable : le port TCP/IP est recréé sur l'autre poste.")
    if pname.startswith("usb") or monitor == "usb monitor":
        return Classification("USB", "integre",
                              "Port USB créé automatiquement quand l'appareil est branché ; transférer le pilote seulement.")
    if pname in BUILTIN_PORT_NAMES or pname.startswith("xpsport") or (
            monitor == "local port" and any(h in text for h in VIRTUAL_HINTS)):
        return Classification("Virtuelle (PDF / fichier)", "integre",
                              "Le port existe par défaut sous Windows : le pilote et la file suffisent.")
    if monitor == "local port" or re.match(r"^(lpt|com)\d", pname):
        return Classification("Locale (LPT/COM)", "integre", "Port local standard de Windows.")
    mon = port.monitor if port else "inconnu"
    virt = any(h in text for h in VIRTUAL_HINTS)
    return Classification(("Virtuelle" if virt else "Spécifique") + f" (moniteur « {mon} »)", "specifique",
                          "Le port appartient à un programme : sur l'autre poste, réinstallez d'abord ce programme "
                          "(sa sauvegarde ne recrée pas toujours le port). Voir « Programme probable ».")


def _norm(p: str) -> str:
    return ntpath.normcase(ntpath.normpath(p.strip('" '))) if p else ""


def probable_programs(printer: PrinterInfo, port: PortInfo | None, driver: DriverInfo | None,
                      monitors: list[MonitorInfo], programs: list[ProgramInfo]) -> list[ProgramInfo]:
    """Programmes probablement à l'origine de l'imprimante : on retient d'abord les chemins
    (DLL du moniteur ou fichiers du pilote sous le dossier d'installation), puis le fabricant."""
    paths: list[str] = []
    if driver:
        paths += [driver.driver_path, driver.config_file, driver.data_file, driver.help_file, driver.inf_path]
        paths += driver.dependent_files
    if port:
        mon = next((m for m in monitors if m.name.lower() == port.monitor.lower()), None)
        if mon and mon.dll:
            paths.append(mon.dll)
    paths = [_norm(p) for p in paths if p and ("\\" in p)]
    found: list[ProgramInfo] = []
    for pr in programs:
        loc = _norm(pr.install_location)
        if len(loc) > 8 and any(p == loc or p.startswith(loc + "\\") for p in paths):
            found.append(pr)
    if not found and driver and driver.manufacturer and driver.manufacturer.lower() not in ("microsoft", "microsoft corporation"):
        m = driver.manufacturer.lower()
        found = [pr for pr in programs if pr.publisher and (m in pr.publisher.lower() or pr.publisher.lower() in m)]
    return found[:5]


def annotate(inv: Inventory, all_programs: list[ProgramInfo]) -> None:
    """Complète l'inventaire : type, portabilité, fabricant, programmes probables."""
    related: dict[str, ProgramInfo] = {}
    for d in inv.drivers:
        d.microsoft_inbox = d.manufacturer.lower().startswith("microsoft") or d.name.lower().startswith("microsoft ")
        d.package_dir = _driver_store_dir(d.inf_path)
        d.exportable = bool(d.package_dir) and not d.microsoft_inbox
    for p in inv.printers:
        drv, port = inv.driver_of(p), inv.port_of(p)
        c = classify(p, port, drv)
        p.kind, p.port_class, p.advice = c.kind, c.port_class, c.advice
        p.manufacturer = drv.manufacturer if drv else ""
        progs = probable_programs(p, port, drv, inv.monitors, all_programs)
        p.probable_programs = [f"{x.name} {x.version}".strip() for x in progs]
        for x in progs:
            related[x.name] = x
    inv.programs = list(related.values())


def _driver_store_dir(inf_path: str) -> str:
    """Dossier du paquet de pilote (DriverStore\\FileRepository\\<paquet>), seul exportable proprement."""
    marker = "\\driverstore\\filerepository\\"
    i = inf_path.lower().replace("/", "\\").find(marker)
    if i < 0:
        return ""
    start = i + len(marker)
    pkg = inf_path[start:].replace("/", "\\").split("\\")[0]
    return inf_path[:start] + pkg if pkg else ""
