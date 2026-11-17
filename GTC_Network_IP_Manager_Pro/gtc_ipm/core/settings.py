"""Paramètres locaux (JSON minimal, aucun secret)."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path


def app_dir() -> Path:
    base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    p = Path(base) / "GTC_Network_IP_Manager_Pro"
    p.mkdir(parents=True, exist_ok=True)
    return p


@dataclass
class Settings:
    # Indications facultatives de l'utilisateur : des HYPOTHÈSES, vérifiées à l'analyse.
    # Aucune valeur propre à un site n'est codée : tout est détecté sur le réseau où tourne le logiciel.
    dc_hints: list[str] = field(default_factory=list)
    dns_hints: list[str] = field(default_factory=list)
    extra_networks: list[str] = field(default_factory=list)  # CIDR ajoutés par l'utilisateur
    static_inventory: dict[str, str] = field(default_factory=dict)  # IP -> libellé
    user_excluded: list[list[str]] = field(default_factory=list)  # [[début, fin], ...]
    max_hosts: int = 1024
    ping_timeout_ms: int = 700
    concurrency: int = 48
    candidate_count: int = 20
    stale_days: int = 90
    # Passerelles Internet qui ont fonctionné (mémorisées à l'analyse, ex. en DHCP), par passerelle
    known_internet: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None = None) -> "Settings":
        path = path or app_dir() / "settings.json"
        s = cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for k, v in data.items():
                if hasattr(s, k):
                    setattr(s, k, v)
        except (OSError, ValueError):
            pass
        s.max_hosts = max(16, min(int(s.max_hosts), 4096))
        s.concurrency = max(1, min(int(s.concurrency), 128))
        s.ping_timeout_ms = max(100, min(int(s.ping_timeout_ms), 5000))
        return s

    def save(self, path: Path | None = None) -> None:
        path = path or app_dir() / "settings.json"
        try:
            path.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False),
                            encoding="utf-8")
        except OSError:
            pass
