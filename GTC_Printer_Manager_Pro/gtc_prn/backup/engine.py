"""Sauvegarde et restauration des imprimantes.

Deux méthodes complémentaires :
  1. « Complète » : PrintBrm.exe (outil intégré à Windows) exporte TOUTES les files, pilotes et ports
     TCP/IP/WSD/LPR dans un fichier .printerExport.
  2. « Sélective » : pour les imprimantes choisies, copie du paquet de pilote (DriverStore) + paramètres
     (nom, pilote, port, partage) ; à la restauration : pnputil + Add-PrinterDriver/Port/Printer.

Honnêteté : un port propre à un programme (moniteur tiers) n'est PAS recréé par ces méthodes ; la
restauration le signale (« PORT MANQUANT ») et indique le programme à réinstaller.
"""
from __future__ import annotations

import csv
import json
import ntpath
import os
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

from ..core import psrunner
from ..core.models import Inventory, PrinterInfo, inventory_from_dict, inventory_to_dict, now_iso
from ..core.psrunner import SourceUnavailable
from ..discovery import winprint

IS_WINDOWS = sys.platform == "win32"
Runner = Callable[[list], "tuple[int, str]"]
Say = Callable[[str], None]

INVENTORY_FILE = "inventaire.json"
SELECTION_FILE = "selection.json"
PRINTBRM_FILE = "sauvegarde.printerExport"

# PowerShell (scripts statiques ; valeurs passées par variables d'environnement GTCARG_*)
PS_HAS_DRIVER = "if (Get-PrinterDriver -Name $env:GTCARG_DRIVER -ErrorAction SilentlyContinue) {'yes'} else {'no'}"
PS_HAS_PORT = "if (Get-PrinterPort -Name $env:GTCARG_PORT -ErrorAction SilentlyContinue) {'yes'} else {'no'}"
PS_HAS_PRINTER = "if (Get-Printer -Name $env:GTCARG_NAME -ErrorAction SilentlyContinue) {'yes'} else {'no'}"
PS_ADD_DRIVER = "Add-PrinterDriver -Name $env:GTCARG_DRIVER -ErrorAction Stop; 'ok'"
PS_ADD_TCP_PORT = ("$a=@{Name=$env:GTCARG_PORT;PrinterHostAddress=$env:GTCARG_HOST;ErrorAction='Stop'};"
                   "if ($env:GTCARG_PORTNUM -and [int]$env:GTCARG_PORTNUM -gt 0){$a.PortNumber=[int]$env:GTCARG_PORTNUM};"
                   "Add-PrinterPort @a; 'ok'")
PS_ADD_PRINTER = ("$a=@{Name=$env:GTCARG_NAME;DriverName=$env:GTCARG_DRIVER;PortName=$env:GTCARG_PORT;ErrorAction='Stop'};"
                  "if ($env:GTCARG_SHARE){$a.Shared=$true;$a.ShareName=$env:GTCARG_SHARE};"
                  "if ($env:GTCARG_COMMENT){$a.Comment=$env:GTCARG_COMMENT};"
                  "if ($env:GTCARG_LOCATION){$a.Location=$env:GTCARG_LOCATION};"
                  "Add-Printer @a; 'ok'")
PS_REMOVE_PRINTER = "Remove-Printer -Name $env:GTCARG_NAME -ErrorAction Stop; 'ok'"
PS_SCRIPTS = {"has_driver": PS_HAS_DRIVER, "has_port": PS_HAS_PORT, "has_printer": PS_HAS_PRINTER,
              "add_driver": PS_ADD_DRIVER, "add_tcp_port": PS_ADD_TCP_PORT, "add_printer": PS_ADD_PRINTER,
              "remove_printer": PS_REMOVE_PRINTER}


def default_runner(cmd: list) -> "tuple[int, str]":
    p = subprocess.run(cmd, capture_output=True, timeout=900, stdin=subprocess.DEVNULL,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    raw = p.stdout + p.stderr
    for enc in ("utf-8", "cp850"):
        try:
            return p.returncode, raw.decode(enc).strip()
        except UnicodeDecodeError:
            continue
    return p.returncode, raw.decode("cp850", "replace").strip()


def default_ps(script: str, args: dict) -> str:
    return psrunner.run_powershell(script, args, timeout=180)


# ------------------------------------------------------------------ résultats
@dataclass
class Item:
    label: str
    status: str      # OK | ATTENTION | ECHEC
    detail: str = ""


@dataclass
class JobResult:
    ok: bool = False
    action: str = ""
    path: str = ""
    items: list[Item] = field(default_factory=list)
    finished_at: str = ""

    def add(self, label: str, status: str, detail: str = "") -> None:
        self.items.append(Item(label, status, detail))

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, text: str) -> "JobResult":
        d = json.loads(text)
        r = cls(**{k: v for k, v in d.items() if k != "items"})
        r.items = [Item(**i) for i in d.get("items", [])]
        return r


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._")[:80] or "x"


def printbrm_cmd(mode: str, file: str, force: bool = False) -> list[str]:
    if mode not in ("b", "r"):
        raise ValueError("mode PrintBrm invalide")
    cmd = [winprint.printbrm_path(), "-" + mode, "-f", file]
    if force and mode == "r":
        cmd += ["-o", "force"]
    return cmd


# ------------------------------------------------------------------ sauvegarde
@dataclass
class BackupOptions:
    dest_dir: str
    printbrm: bool = True
    selected_printers: list[str] = field(default_factory=list)   # paquets de pilotes + paramètres
    make_zip: bool = True


def _write_csv(inv: Inventory, path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["Nom", "Type", "Pilote", "Fabricant", "Port", "Moniteur", "Adresse", "Partage", "Par défaut",
                    "Programme probable", "Conseil"])
        for p in inv.printers:
            port = inv.port_of(p)
            w.writerow([_csv_safe(x) for x in (p.name, p.kind, p.driver, p.manufacturer, p.port,
                                               port.monitor if port else "", port.host_address if port else "",
                                               p.share_name, "oui" if p.is_default else "",
                                               "; ".join(p.probable_programs), p.advice)])


def _csv_safe(v: str) -> str:
    v = str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@") else v


def run_backup(opts: BackupOptions, inv: Inventory, runner: Runner = default_runner,
               say: Say = lambda m: None) -> JobResult:
    res = JobResult(action="backup")
    root = Path(opts.dest_dir)
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        res.add("Dossier de destination", "ECHEC", str(e))
        res.finished_at = now_iso()
        return res
    res.path = str(root)
    say("Écriture de l'inventaire…")
    (root / INVENTORY_FILE).write_text(json.dumps(inventory_to_dict(inv), ensure_ascii=False, indent=1), encoding="utf-8")
    _write_csv(inv, root / "inventaire.csv")
    res.add("Inventaire (JSON + CSV)", "OK", f"{len(inv.printers)} imprimante(s)")

    selected = [p for p in inv.printers if p.name in set(opts.selected_printers)]
    missing = set(opts.selected_printers) - {p.name for p in selected}
    for n in sorted(missing):
        res.add(f"Imprimante « {n} »", "ECHEC", "introuvable sur ce poste")
    manifest = []
    for p in selected:
        say(f"Pilote de « {p.name} »…")
        drv, port = inv.driver_of(p), inv.port_of(p)
        entry = {"printer": asdict(p), "driver": asdict(drv) if drv else None, "port": asdict(port) if port else None,
                 "package": ""}
        if not drv:
            res.add(f"{p.name}", "ATTENTION", "pilote introuvable dans l'inventaire : paramètres seuls sauvegardés")
        elif drv.microsoft_inbox:
            res.add(f"{p.name}", "OK", "pilote intégré à Windows : aucun paquet à copier")
        elif not drv.exportable:
            res.add(f"{p.name}", "ATTENTION", "pas de paquet de pilote exportable (pilote sans INF) : "
                    "seule la sauvegarde complète ou le programme d'origine permet de le réinstaller")
        else:
            dest = root / "drivers" / slug(drv.name)
            try:
                _copy_package(drv.package_dir, dest)
                entry["package"] = f"drivers/{slug(drv.name)}"
                entry["inf"] = ntpath.basename(drv.inf_path)
                res.add(f"{p.name}", "OK", f"paquet de pilote copié ({_count(dest)} fichiers)")
            except OSError as e:
                res.add(f"{p.name}", "ECHEC", f"copie du pilote impossible : {e}")
        if port and p.port_class == "specifique":
            progs = ", ".join(p.probable_programs) or "programme inconnu"
            res.add(f"{p.name} (port « {p.port} »)", "ATTENTION",
                    f"port propre à un programme ({port.monitor}) : à recréer en réinstallant {progs}")
        manifest.append(entry)
    (root / SELECTION_FILE).write_text(json.dumps({"format": "gtc-prn-selection", "version": 1,
                                                   "created_at": now_iso(), "printers": manifest},
                                                  ensure_ascii=False, indent=1), encoding="utf-8")

    if opts.printbrm:
        say("Sauvegarde complète Windows (PrintBrm)… peut durer plusieurs minutes.")
        target = root / PRINTBRM_FILE
        if target.exists():
            target.unlink()                     # PrintBrm n'écrase pas un fichier existant
        if not inv.system.printbrm_available and not os.path.exists(winprint.printbrm_path()):
            res.add("Sauvegarde complète (PrintBrm)", "ECHEC", "PrintBrm.exe est absent de ce Windows")
        else:
            rc, out = runner(printbrm_cmd("b", str(target)))
            if rc == 0 and target.exists() and target.stat().st_size > 0:
                res.add("Sauvegarde complète (PrintBrm)", "OK", f"{target.stat().st_size // 1024} Ko")
            else:
                if target.exists() and target.stat().st_size == 0:
                    target.unlink()
                res.add("Sauvegarde complète (PrintBrm)", "ECHEC", f"code {rc} : {out[:300]}")
    _write_readme(root, inv, opts)
    if opts.make_zip:
        say("Compression…")
        z = shutil.make_archive(str(root), "zip", root_dir=str(root))
        res.add("Archive ZIP", "OK", z)
        res.path = z
    res.ok = not any(i.status == "ECHEC" for i in res.items)
    res.finished_at = now_iso()
    return res


def _copy_package(src: str, dest: Path) -> None:
    if not os.path.isdir(src):
        raise OSError(f"dossier du pilote introuvable : {src}")
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)


def _count(path: Path) -> int:
    return sum(1 for _ in path.rglob("*") if _.is_file())


def _write_readme(root: Path, inv: Inventory, opts: BackupOptions) -> None:
    (root / "LISEZ-MOI.txt").write_text(
        "Sauvegarde GTC Printer Manager Pro\r\n"
        f"Poste : {inv.system.hostname} ({inv.system.os_caption} {inv.system.os_build}, {inv.system.arch})\r\n"
        f"Date : {now_iso()}\r\n\r\n"
        "Restauration : ouvrir GTC Printer Manager Pro sur l'autre poste, onglet Restauration, charger ce dossier ou ce ZIP.\r\n"
        "Le poste cible doit avoir la meme architecture (x64 sur x64). Les droits administrateur sont demandes.\r\n"
        "Un port propre a un programme (ex. imprimante PDF d'un logiciel) n'est pas recree : reinstaller d'abord le programme.\r\n",
        encoding="utf-8")


# ------------------------------------------------------------------ chargement
@dataclass
class BackupSet:
    root: Path
    inventory: Inventory
    selection: list[dict]
    has_printbrm: bool
    source: str


def load_backup(path: str, work_dir: Optional[str] = None) -> BackupSet:
    p = Path(path)
    if p.is_file() and p.suffix.lower() == ".zip":
        import tempfile
        out = Path(work_dir or tempfile.mkdtemp(prefix="gtcprn_"))
        with zipfile.ZipFile(p) as z:
            base = out.resolve()
            for m in z.infolist():
                tgt = (out / m.filename).resolve()
                if base != tgt and base not in tgt.parents:
                    raise ValueError(f"Archive refusée (chemin dangereux) : {m.filename}")
            z.extractall(out)
        root = out
    elif p.is_dir():
        root = p
    else:
        raise ValueError("Choisissez un dossier de sauvegarde ou un fichier ZIP.")
    inv_file = root / INVENTORY_FILE
    if not inv_file.exists():
        raise ValueError("Ce dossier n'est pas une sauvegarde GTC Printer Manager (inventaire.json absent).")
    inv = inventory_from_dict(json.loads(inv_file.read_text(encoding="utf-8")))
    sel: list[dict] = []
    sf = root / SELECTION_FILE
    if sf.exists():
        sel = json.loads(sf.read_text(encoding="utf-8")).get("printers", [])
    return BackupSet(root, inv, sel, (root / PRINTBRM_FILE).exists(), str(p))


# ------------------------------------------------------------------ restauration
PRESENT = "DÉJÀ PRÉSENTE"
TO_RESTORE = "À RESTAURER"
PORT_MISSING = "PORT MANQUANT"
DRIVER_MISSING = "PILOTE MANQUANT"
INCOMPATIBLE = "INCOMPATIBLE"


@dataclass
class RestoreRow:
    name: str
    kind: str
    driver: str
    status: str
    note: str


def compatibility(backup: Inventory, local: Inventory) -> list[str]:
    msgs = []
    if backup.system.arch and local.system.arch and backup.system.arch != local.system.arch:
        msgs.append(f"Architecture différente (sauvegarde : {backup.system.arch}, ce poste : {local.system.arch}) : "
                    "la restauration est refusée.")
    elif backup.system.os_caption and local.system.os_caption and backup.system.os_caption != local.system.os_caption:
        msgs.append(f"Version de Windows différente (sauvegarde : {backup.system.os_caption}, ce poste : "
                    f"{local.system.os_caption}) : la restauration peut échouer pour certains pilotes.")
    return msgs


def plan_restore(backup: BackupSet, local: Inventory) -> list[RestoreRow]:
    """Compare la sauvegarde à CE poste, imprimante par imprimante (aucune modification)."""
    incompatible = any("refusée" in m for m in compatibility(backup.inventory, local))
    local_names = {p.name.lower() for p in local.printers}
    local_drivers = {d.name.lower() for d in local.drivers}
    local_ports = {p.name.lower() for p in local.ports}
    packages = {e["printer"]["name"]: e for e in backup.selection}
    rows = []
    for p in backup.inventory.printers:
        drv = backup.inventory.driver_of(p)
        base = (p.name, p.kind, p.driver)
        if incompatible:
            rows.append(RestoreRow(*base, INCOMPATIBLE, "architecture différente"))
        elif p.name.lower() in local_names:
            rows.append(RestoreRow(*base, PRESENT, "rien à faire"))
        elif p.port_class == "specifique" and p.port.lower() not in local_ports:
            progs = ", ".join(p.probable_programs) or "le programme d'origine"
            rows.append(RestoreRow(*base, PORT_MISSING, f"réinstaller d'abord : {progs}"))
        elif p.driver.lower() not in local_drivers and not (
                (drv and drv.microsoft_inbox) or (p.name in packages and packages[p.name].get("package"))
                or backup.has_printbrm):
            rows.append(RestoreRow(*base, DRIVER_MISSING, "aucun paquet de pilote dans cette sauvegarde"))
        else:
            rows.append(RestoreRow(*base, TO_RESTORE, "pilote + port + file d'impression"))
    return rows


@dataclass
class RestoreOptions:
    method: str = "selective"           # selective | printbrm
    printers: list[str] = field(default_factory=list)


def run_restore(opts: RestoreOptions, backup: BackupSet, local: Inventory, runner: Runner = default_runner,
                ps: Callable = default_ps, say: Say = lambda m: None,
                reload: Callable[[], Inventory] = None) -> JobResult:
    res = JobResult(action="restore", path=backup.source)
    problems = compatibility(backup.inventory, local)
    if any("refusée" in m for m in problems):
        res.add("Compatibilité", "ECHEC", problems[0])
        res.finished_at = now_iso()
        return res
    for m in problems:
        res.add("Compatibilité", "ATTENTION", m)
    if opts.method == "printbrm":
        _restore_printbrm(backup, runner, res, say)
    else:
        _restore_selective(opts, backup, local, runner, ps, res, say)
    # Vérification finale : on relit CE poste
    if reload:
        say("Vérification finale…")
        now = reload()
        have = {p.name.lower(): p for p in now.printers}
        ports = {p.name.lower() for p in now.ports}
        wanted = [p for p in backup.inventory.printers if opts.method == "printbrm" or p.name in opts.printers]
        for p in wanted:
            if p.name.lower() not in have:
                res.add(f"Vérification « {p.name} »", "ECHEC", "absente après restauration")
            elif p.port.lower() not in ports:
                res.add(f"Vérification « {p.name} »", "ATTENTION", f"présente, mais le port « {p.port} » manque")
            else:
                res.add(f"Vérification « {p.name} »", "OK", "présente avec son port")
    res.ok = not any(i.status == "ECHEC" for i in res.items)
    res.finished_at = now_iso()
    return res


def _restore_printbrm(backup: BackupSet, runner: Runner, res: JobResult, say: Say) -> None:
    f = backup.root / PRINTBRM_FILE
    if not f.exists():
        res.add("Restauration complète (PrintBrm)", "ECHEC", "cette sauvegarde ne contient pas de fichier PrintBrm")
        return
    say("Restauration complète Windows (PrintBrm)… peut durer plusieurs minutes.")
    rc, out = runner(printbrm_cmd("r", str(f), force=True))
    res.add("Restauration complète (PrintBrm)", "OK" if rc == 0 else "ECHEC", out[:300] if rc else "terminée")


def _restore_selective(opts: RestoreOptions, backup: BackupSet, local: Inventory, runner: Runner, ps: Callable,
                       res: JobResult, say: Say) -> None:
    entries = {e["printer"]["name"]: e for e in backup.selection}
    for name in opts.printers:
        say(f"Restauration de « {name} »…")
        e = entries.get(name)
        src = next((p for p in backup.inventory.printers if p.name == name), None)
        if e is None and src is None:
            res.add(name, "ECHEC", "absente de la sauvegarde")
            continue
        printer = PrinterInfo(**{k: v for k, v in (e["printer"] if e else asdict(src)).items()
                                 if k in PrinterInfo.__dataclass_fields__})
        try:
            _restore_one(printer, e, backup, runner, ps, res, say)
        except (SourceUnavailable, ValueError, OSError) as ex:
            res.add(name, "ECHEC", str(ex)[:400])


def _yes(ps: Callable, key: str, **args) -> bool:
    return "yes" in ps(PS_SCRIPTS[key], {k.upper(): v for k, v in args.items()})


def _restore_one(p: PrinterInfo, entry: Optional[dict], backup: BackupSet, runner: Runner, ps: Callable,
                 res: JobResult, say: Say) -> None:
    for label, val in (("Nom", p.name), ("Pilote", p.driver), ("Port", p.port)):
        psrunner.valid_text(val, label)
    if _yes(ps, "has_printer", name=p.name):
        res.add(p.name, "OK", "déjà présente : conservée telle quelle")
        return
    # 1. pilote
    if not _yes(ps, "has_driver", driver=p.driver):
        pkg = (entry or {}).get("package")
        inf = (entry or {}).get("inf")
        if pkg and inf:
            folder = backup.root / pkg
            infp = folder / inf
            if not infp.exists():
                res.add(p.name, "ECHEC", f"INF du pilote absent de la sauvegarde ({pkg})")
                return
            say(f"Installation du pilote « {p.driver} »…")
            rc, out = runner(["pnputil", "/add-driver", str(infp), "/install"])
            if rc not in (0, 3010):
                res.add(p.name, "ECHEC", f"pnputil a échoué (code {rc}) : {out[:300]}")
                return
        ps(PS_ADD_DRIVER, {"DRIVER": p.driver})
        res.add(f"{p.name} (pilote)", "OK", p.driver)
    # 2. port
    if not _yes(ps, "has_port", port=p.port):
        port = (entry or {}).get("port") or {}
        if port.get("monitor") == "Standard TCP/IP Port" and port.get("host_address"):
            ps(PS_ADD_TCP_PORT, {"PORT": p.port, "HOST": port["host_address"],
                                 "PORTNUM": str(int(port.get("port_number") or 0))})
            res.add(f"{p.name} (port)", "OK", f"port TCP/IP {port['host_address']} créé")
        else:
            progs = ", ".join(p.probable_programs) or "le programme d'origine"
            res.add(f"{p.name} (port)", "ECHEC", f"le port « {p.port} » n'existe pas ici et ne peut pas être "
                    f"recréé automatiquement : réinstallez {progs}, puis relancez la restauration")
            return
    # 3. file d'impression
    ps(PS_ADD_PRINTER, {"NAME": p.name, "DRIVER": p.driver, "PORT": p.port, "SHARE": p.share_name,
                        "COMMENT": p.comment, "LOCATION": p.location})
    res.add(p.name, "OK", "file d'impression créée")
