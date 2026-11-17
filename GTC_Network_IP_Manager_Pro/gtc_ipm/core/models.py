"""Modèles de données partagés. Aucune dépendance Qt ni Windows."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

__version__ = "1.0.0"

# Statuts du plan d'adressage (jamais de statut « libre » sans preuve).
OCCUPEE = "OCCUPÉE"
RESERVEE = "RÉSERVÉE"
EXCLUE = "EXCLUE"
DHCP_DYNAMIQUE = "DHCP_DYNAMIQUE"
CONFLIT = "CONFLIT"
INCONNUE = "INCONNUE"
CANDIDATE = "CANDIDATE_À_VÉRIFIER"
DISPONIBLE = "DISPONIBLE_CONFIRMÉE"

ALL_STATUSES = (OCCUPEE, RESERVEE, EXCLUE, DHCP_DYNAMIQUE, CONFLIT, INCONNUE,
                CANDIDATE, DISPONIBLE)

# États d'une source de données
SRC_OK = "OK"
SRC_PARTIAL = "PARTIEL"
SRC_UNAVAILABLE = "INACCESSIBLE"
SRC_SKIPPED = "IGNORÉE"
SRC_CANCELLED = "ANNULÉE"


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


@dataclass
class Interface:
    alias: str
    ipv4: str
    prefix: int
    mac: str = ""
    gateway: str = ""
    dns_servers: list[str] = field(default_factory=list)
    dhcp_enabled: bool = False
    dhcp_server: str = ""
    dns_suffix: str = ""

    @property
    def cidr(self) -> str:
        return f"{self.ipv4}/{self.prefix}"


@dataclass
class Route:
    destination: str  # CIDR
    next_hop: str
    metric: int = 0
    interface: str = ""


@dataclass
class DomainInfo:
    in_domain: bool = False
    name: str = ""
    domain_controllers: list[str] = field(default_factory=list)  # noms ou IP
    dc_addresses: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


@dataclass
class AdComputer:
    name: str
    dns_hostname: str = ""
    enabled: Optional[bool] = None
    last_logon: str = ""  # ISO, approximatif (lastLogonTimestamp)
    os: str = ""
    distinguished_name: str = ""
    ipv4: list[str] = field(default_factory=list)  # résolution DNS
    dns_status: str = ""  # "résolu", "absent", "indisponible", ""
    mac: str = ""
    verification: str = "Non vérifié"
    source: str = "AD"
    observed_at: str = ""


@dataclass
class DhcpScope:
    server: str
    scope_id: str
    name: str = ""
    subnet_mask: str = ""
    start: str = ""
    end: str = ""
    state: str = ""
    exclusions: list[tuple[str, str]] = field(default_factory=list)
    gateway: str = ""


@dataclass
class DhcpLease:
    server: str
    scope_id: str
    ip: str
    mac: str = ""
    hostname: str = ""
    state: str = ""
    expires: str = ""
    reservation: bool = False


@dataclass
class DhcpData:
    servers: list[str] = field(default_factory=list)
    scopes: list[DhcpScope] = field(default_factory=list)
    leases: list[DhcpLease] = field(default_factory=list)  # baux + réservations
    queried_scopes: set[str] = field(default_factory=set)  # scopes lus avec succès
    errors: list[str] = field(default_factory=list)


@dataclass
class Observation:
    """Un hôte observé sur le réseau (hors source AD)."""
    ip: str
    mac: str = ""
    hostname: str = ""
    methods: list[str] = field(default_factory=list)  # ping, arp, ptr
    observed_at: str = ""
    in_domain: Optional[bool] = None


@dataclass
class SourceStatus:
    name: str
    state: str = SRC_SKIPPED
    detail: str = ""
    duration_s: float = 0.0
    count: int = 0
    started_at: str = ""


@dataclass
class Evidence:
    kind: str  # voir planning.planner
    source: str
    detail: str = ""
    observed_at: str = ""
    mac: str = ""
    name: str = ""


@dataclass
class IpEntry:
    ip: str
    status: str
    justification: str
    network: str
    checked_at: str
    sources: list[str] = field(default_factory=list)
    hostname: str = ""
    mac: str = ""
    preferred: bool = False  # IP issue d'une exclusion DHCP (zone dédiée aux statiques)


@dataclass
class Snapshot:
    """Résultat complet d'une analyse."""
    started_at: str = ""
    finished_at: str = ""
    interfaces: list[Interface] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    domain: DomainInfo = field(default_factory=DomainInfo)
    ad_computers: list[AdComputer] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    dhcp: DhcpData = field(default_factory=DhcpData)
    sources: list[SourceStatus] = field(default_factory=list)
    plan: dict[str, list[IpEntry]] = field(default_factory=dict)  # par réseau
    candidates: dict[str, list[IpEntry]] = field(default_factory=dict)
    conflicts: list[IpEntry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scanned_networks: list[str] = field(default_factory=list)
    scanned_ips: dict[str, list[str]] = field(default_factory=dict)  # réseau -> IP sondées
    ptr: dict[str, str] = field(default_factory=dict)  # IP -> nom PTR
    dns_ok: dict[str, bool] = field(default_factory=dict)  # réseau -> DNS a répondu
    local_networks: list[str] = field(default_factory=list)
    log: list[str] = field(default_factory=list)
    cancelled: bool = False
