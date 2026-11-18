"""Auto-diagnostic de démarrage : explique POURQUOI le logiciel ne peut pas charger Qt.

Contrôles (sans Qt, uniquement bibliothèque standard) :
- chaque .dll / .pyd du dossier est-il un exécutable Windows valide, de la bonne architecture, non tronqué ?
- le manifeste integrity.json (créé à la compilation) correspond-il aux fichiers présents (taille + SHA-256) ?
- architecture réelle du PC / de Windows.
"""
import hashlib
import json
import os
import platform
import struct
import sys
import tempfile
from pathlib import Path
from typing import Optional

MACHINES = {0x014C: "x86 (32 bits)", 0x8664: "x64", 0xAA64: "ARM64", 0x01C4: "ARM", 0x0200: "IA64"}
EXPECTED_MACHINE = 0x8664
INTEGRITY_FILE = "integrity.json"
SKIP_SUFFIXES = (".md",)


def machine_name(m) -> str:
    return MACHINES.get(m, f"inconnue (0x{m:04X})") if m is not None else "illisible"


def pe_check(path: Path) -> tuple[bool, Optional[int], str]:
    """(valide, architecture, raison). Valide = en-tête MZ/PE lisible ET architecture x64."""
    try:
        size = path.stat().st_size
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError as e:
        return False, None, f"lecture impossible ({e})"
    if size == 0:
        return False, None, "fichier vide (0 octet)"
    if len(head) < 64 or head[:2] != b"MZ":
        return False, None, "ce n'est pas un exécutable Windows (en-tête MZ absent) : fichier corrompu"
    pe = struct.unpack_from("<I", head, 60)[0]
    if pe + 6 > len(head) or head[pe:pe + 4] != b"PE\0\0":
        return False, None, "en-tête PE absent ou illisible : fichier corrompu ou tronqué"
    machine = struct.unpack_from("<H", head, pe + 4)[0]
    if machine != EXPECTED_MACHINE:
        return False, machine, f"architecture {machine_name(machine)} au lieu de x64"
    return True, machine, "ok"


def scan_binaries(root: Path) -> list[str]:
    problems = []
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() in (".dll", ".pyd") and p.is_file():
            ok, _m, why = pe_check(p)
            if not ok:
                problems.append(f"{p.relative_to(root)} : {why} (taille {p.stat().st_size} octets)")
    return problems


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def make_manifest(root: Path) -> dict:
    files = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name != INTEGRITY_FILE and p.suffix.lower() not in SKIP_SUFFIXES:
            files[p.relative_to(root).as_posix()] = {"size": p.stat().st_size, "sha256": _sha256(p)}
    return {"format": "gtc-prn-integrity", "version": 1, "files": files}


def verify_manifest(root: Path) -> Optional[list[str]]:
    """None = pas de manifeste (version fichier unique, ou non construit) ; sinon liste des écarts."""
    mf = root / INTEGRITY_FILE
    if not mf.is_file():
        return None
    try:
        data = json.loads(mf.read_text("utf-8"))
        files = data["files"]
    except (OSError, ValueError, KeyError) as e:
        return [f"manifeste {INTEGRITY_FILE} illisible ({e})"]
    problems = []
    for rel, meta in files.items():
        p = root / rel
        if not p.is_file():
            problems.append(f"{rel} : MANQUANT")
        elif p.stat().st_size != meta["size"]:
            problems.append(f"{rel} : taille {p.stat().st_size} au lieu de {meta['size']} (copie incomplète)")
        elif _sha256(p) != meta["sha256"]:
            problems.append(f"{rel} : contenu différent de l'original (fichier corrompu)")
    return problems


def app_root() -> Optional[Path]:
    """Dossier de l'application quand elle est figée (EXE) ; None sinon."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return None


def system_facts() -> list[str]:
    env = os.environ
    facts = [f"Python embarqué : {platform.architecture()[0]} / machine={platform.machine()}",
             f"PROCESSOR_ARCHITECTURE={env.get('PROCESSOR_ARCHITECTURE', '?')}  "
             f"PROCESSOR_ARCHITEW6432={env.get('PROCESSOR_ARCHITEW6432', '-')}",
             f"Windows : {platform.platform()}"]
    return facts


def diagnose(root: Optional[Path] = None) -> tuple[list[str], list[str]]:
    """(lignes du rapport, problèmes). Aucun problème => le dossier est sain."""
    root = root or app_root()
    lines = list(system_facts())
    problems: list[str] = []
    if root is None:
        lines.append("Dossier de l'application : non figé (exécution depuis les sources), contrôle des fichiers ignoré.")
        return lines, problems
    lines.append(f"Dossier de l'application : {root}")
    bad = scan_binaries(root)
    problems += [f"[format] {m}" for m in bad]
    mism = verify_manifest(root)
    if mism is None:
        lines.append("Manifeste d'intégrité : absent (version fichier unique ou non généré).")
    else:
        problems += [f"[intégrité] {m}" for m in mism]
        lines.append(f"Manifeste d'intégrité : vérifié, {len(mism)} écart(s).")
    return lines, problems


def build_report(error_text: str = "", root: Optional[Path] = None) -> tuple[str, list[str]]:
    lines, problems = diagnose(root)
    out = ["GTC Printer Manager Pro - rapport de diagnostic", ""]
    if error_text:
        out += ["Erreur au démarrage :", error_text.strip(), ""]
    out += lines + [""]
    if problems:
        out.append(f"{len(problems)} PROBLÈME(S) TROUVÉ(S) :")
        out += [f" - {p}" for p in problems[:60]]
        if len(problems) > 60:
            out.append(f" ... et {len(problems) - 60} autre(s)")
        out += ["", "Conclusion : le dossier est incomplet ou abîmé. Retéléchargez le ZIP DIRECTEMENT sur ce PC,",
                "vérifiez son SHA-256 avec SHA256SUMS.txt, puis extrayez-le sur le disque C: (pas depuis le ZIP ni une clé)."]
    else:
        out += ["Aucun fichier invalide : tous les .dll/.pyd sont des exécutables x64 valides.",
                "Conclusion : le dossier est sain ; la cause est sur ce PC (architecture, antivirus, système). "
                "Envoyez ce rapport."]
    return "\n".join(out), problems


def write_report(text: str) -> str:
    d = os.environ.get("GTC_PRN_DIAG_DIR") or tempfile.gettempdir()
    path = os.path.join(d, "GTC_Printer_Manager_Pro_diagnostic.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def show_error(title: str, text: str) -> None:
    """Boîte de dialogue native (sans Qt, donc utilisable quand Qt ne se charge pas)."""
    if os.environ.get("GTC_PRN_NO_DIALOG") or not sys.platform.startswith("win"):
        return
    import ctypes
    ctypes.windll.user32.MessageBoxW(None, text, title, 0x10)   # MB_ICONERROR


def startup_failure(exc: BaseException) -> int:
    """Appelé quand `import PySide6` échoue : rapport + message clair. Code retour 3."""
    import traceback
    err = "".join(traceback.format_exception_only(type(exc), exc))
    try:
        text, problems = build_report(err)
        path = write_report(text)
    except Exception as e:  # noqa: BLE001 - le diagnostic ne doit jamais masquer l'erreur d'origine
        text, problems, path = f"{err}\n(diagnostic impossible : {e})", [], "(non écrit)"
    head = (f"{len(problems)} fichier(s) invalide(s) détecté(s) dans le dossier du logiciel." if problems
            else "Le chargement de l'interface (Qt) a échoué alors que les fichiers semblent valides.")
    show_error("GTC Printer Manager Pro - démarrage impossible",
               f"{head}\n\n{err.strip()}\n\nRapport complet : {path}\n\n" + "\n".join(text.splitlines()[-4:]))
    print(text, file=sys.stderr)
    return 3
