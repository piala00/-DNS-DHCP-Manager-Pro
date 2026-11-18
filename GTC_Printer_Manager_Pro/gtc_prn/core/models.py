"""Modèles de données partagés. Aucune dépendance Qt ni Windows."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

__version__ = "1.0.0"


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


@dataclass
class PrinterInfo:
    name: str
    driver: str = ""
    port: str = ""
    share_name: str = ""
    comment: str = ""
    location: str = ""
    attributes: int = 0
    status: int = 0
    is_default: bool = False
    # Renseignés par la classification
    kind: str = ""
    port_class: str = ""     # standard | integre | specifique
    advice: str = ""
    # Renseigné à l'inventaire
    manufacturer: str = ""
    probable_programs: list[str] = field(default_factory=list)


@dataclass
class DriverInfo:
    name: str
    environment: str = ""
    version: int = 0
    manufacturer: str = ""
    inf_path: str = ""
    driver_path: str = ""
    config_file: str = ""
    data_file: str = ""
    help_file: str = ""
    dependent_files: list[str] = field(default_factory=list)
    monitor_name: str = ""
    microsoft_inbox: bool = False
    exportable: bool = False     # paquet de pilote copiable (DriverStore)
    package_dir: str = ""


@dataclass
class PortInfo:
    name: str
    monitor: str = ""
    description: str = ""
    port_type: int = 0
    host_address: str = ""
    port_number: int = 0
    protocol: int = 0


@dataclass
class MonitorInfo:
    name: str
    dll: str = ""


@dataclass
class ProgramInfo:
    name: str
    publisher: str = ""
    version: str = ""
    install_location: str = ""


@dataclass
class SystemInfo:
    hostname: str = ""
    os_caption: str = ""
    os_build: str = ""
    arch: str = ""
    is_admin: bool = False
    spooler_running: Any = None     # True / False / None (inconnu)
    printbrm_available: bool = False
    collected_at: str = ""


@dataclass
class Inventory:
    system: SystemInfo = field(default_factory=SystemInfo)
    printers: list[PrinterInfo] = field(default_factory=list)
    drivers: list[DriverInfo] = field(default_factory=list)
    ports: list[PortInfo] = field(default_factory=list)
    monitors: list[MonitorInfo] = field(default_factory=list)
    programs: list[ProgramInfo] = field(default_factory=list)   # uniquement ceux liés à une imprimante
    warnings: list[str] = field(default_factory=list)

    def driver_of(self, printer: PrinterInfo) -> "DriverInfo | None":
        return next((d for d in self.drivers if d.name == printer.driver), None)

    def port_of(self, printer: PrinterInfo) -> "PortInfo | None":
        return next((p for p in self.ports if p.name.lower() == printer.port.lower()), None)


def inventory_to_dict(inv: Inventory) -> dict:
    d = asdict(inv)
    d["format"] = "gtc-prn-inventory"
    d["version"] = 1
    return d


def inventory_from_dict(d: dict) -> Inventory:
    if d.get("format") != "gtc-prn-inventory" or d.get("version") != 1:
        raise ValueError("Ce fichier n'est pas un inventaire GTC Printer Manager (format ou version inconnus).")

    def build(cls, items):
        names = cls.__dataclass_fields__
        return [cls(**{k: v for k, v in it.items() if k in names}) for it in items or []]
    inv = Inventory()
    names = SystemInfo.__dataclass_fields__
    inv.system = SystemInfo(**{k: v for k, v in (d.get("system") or {}).items() if k in names})
    inv.printers = build(PrinterInfo, d.get("printers"))
    inv.drivers = build(DriverInfo, d.get("drivers"))
    inv.ports = build(PortInfo, d.get("ports"))
    inv.monitors = build(MonitorInfo, d.get("monitors"))
    inv.programs = build(ProgramInfo, d.get("programs"))
    inv.warnings = list(d.get("warnings") or [])
    return inv
