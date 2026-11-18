"""Collecte de l'inventaire complet (lecture seule). Les collecteurs sont injectables pour les tests."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..core.models import Inventory
from ..core.psrunner import SourceUnavailable
from . import classify, winprint


@dataclass
class Collectors:
    system: Callable = winprint.collect_system
    printers: Callable = winprint.collect_printers
    drivers: Callable = winprint.collect_drivers
    ports: Callable = winprint.collect_ports
    monitors: Callable = winprint.collect_monitors
    programs: Callable = winprint.collect_programs


def collect_inventory(col: Collectors | None = None) -> Inventory:
    col = col or Collectors()
    inv = Inventory()
    programs = []
    for label, attr in (("système", "system"), ("imprimantes", "printers"), ("pilotes", "drivers"),
                        ("ports", "ports"), ("moniteurs de port", "monitors"), ("programmes installés", "programs")):
        try:
            value = getattr(col, attr)()
        except SourceUnavailable as e:
            inv.warnings.append(f"Lecture des {label} impossible : {e}")
            continue
        except Exception as e:  # noqa: BLE001 - une source en échec ne doit jamais arrêter l'analyse
            inv.warnings.append(f"Lecture des {label} en erreur : {type(e).__name__}: {e}")
            continue
        if attr == "system":
            inv.system = value
        elif attr == "programs":
            programs = value
        else:
            setattr(inv, attr, value)
    classify.annotate(inv, programs)
    if not inv.printers and not inv.warnings:
        inv.warnings.append("Aucune imprimante installée sur ce poste.")
    return inv
