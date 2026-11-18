"""Travail de sauvegarde / restauration, décrit dans un fichier JSON pour pouvoir être exécuté dans un
processus élevé (UAC) lancé par la fenêtre principale."""
from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from typing import Callable

from ..discovery.inventory import Collectors, collect_inventory
from . import engine

IS_WINDOWS = sys.platform == "win32"


@dataclass
class Job:
    action: str                                   # backup | restore
    dest_dir: str = ""                            # sauvegarde : dossier à créer
    printbrm: bool = False
    selected_printers: list[str] = field(default_factory=list)
    make_zip: bool = True
    source: str = ""                              # restauration : dossier ou ZIP
    method: str = "selective"
    result_path: str = ""

    def validate(self) -> list[str]:
        errs = []
        if self.action not in ("backup", "restore"):
            errs.append("Action inconnue.")
        if self.action == "backup":
            if not self.dest_dir:
                errs.append("Dossier de destination manquant.")
            if not self.printbrm and not self.selected_printers:
                errs.append("Choisissez au moins une méthode : sauvegarde complète ou imprimantes cochées.")
        if self.action == "restore":
            if not self.source:
                errs.append("Sauvegarde à restaurer manquante.")
            if self.method not in ("selective", "printbrm"):
                errs.append("Méthode de restauration inconnue.")
            if self.method == "selective" and not self.selected_printers:
                errs.append("Cochez au moins une imprimante à restaurer.")
        return errs

    def needs_admin(self) -> bool:
        # PrintBrm et toute modification du système exigent les droits administrateur ;
        # une sauvegarde sélective ne fait que lire et copier.
        return self.action == "restore" or self.printbrm

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, text: str) -> "Job":
        d = json.loads(text)
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


def execute_job(job: Job, say: Callable[[str], None] = lambda m: None, col: Collectors | None = None,
                runner: Callable = engine.default_runner, ps: Callable = engine.default_ps) -> engine.JobResult:
    errs = job.validate()
    if errs:
        r = engine.JobResult(action=job.action)
        r.add("Paramètres", "ECHEC", " ".join(errs))
        return r
    say("Lecture de ce poste…")
    inv = collect_inventory(col)
    try:
        if job.action == "backup":
            res = engine.run_backup(engine.BackupOptions(job.dest_dir, job.printbrm, job.selected_printers,
                                                         job.make_zip), inv, runner, say)
        else:
            bs = engine.load_backup(job.source)
            res = engine.run_restore(engine.RestoreOptions(job.method, job.selected_printers), bs, inv, runner,
                                     ps, say, reload=lambda: collect_inventory(col))
    except (ValueError, OSError) as e:
        res = engine.JobResult(action=job.action)
        res.add("Travail", "ECHEC", str(e))
    if job.result_path:
        try:
            with open(job.result_path, "w", encoding="utf-8") as f:
                f.write(res.to_json())
        except OSError:
            pass
    return res


# ---- élévation (UAC) -------------------------------------------------------------
def is_admin() -> bool:
    if not IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    import ctypes
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def launch_elevated(args: list[str]) -> None:
    """Relance cet exécutable avec l'invite UAC."""
    if not IS_WINDOWS:
        raise OSError("L'élévation n'est disponible que sous Windows.")
    import ctypes
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, list(args)
    else:
        exe, params = sys.executable, [os.path.abspath(sys.argv[0])] + list(args)
    line = " ".join('"' + a.replace('"', '') + '"' for a in params)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, line, None, 1)
    if rc <= 32:
        raise OSError("Élévation refusée ou impossible (code %d)." % rc)
