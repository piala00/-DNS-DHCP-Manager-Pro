"""Dossier de travail local (journaux, travaux). Aucun secret."""
from __future__ import annotations

import os
from pathlib import Path


def app_dir() -> Path:
    base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    p = Path(base) / "GTC_Printer_Manager_Pro"
    p.mkdir(parents=True, exist_ok=True)
    return p
