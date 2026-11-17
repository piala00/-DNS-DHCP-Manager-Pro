"""Profil du site : export depuis une machine DU domaine, import sur un poste hors domaine.

Le profil est une PHOTO DATÉE (domaine, contrôleurs, DNS, plan d'adressage, voies Internet).
À l'import, aucune adresse n'est jamais « DISPONIBLE_CONFIRMÉE » : le poste n'est pas sur le
segment, donc rien n'a pu être vérifié en direct. Elles deviennent « CANDIDATE_À_VÉRIFIER ».
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict

from . import internet as inet
from .models import CANDIDATE, DISPONIBLE, DomainInfo, IpEntry, Snapshot, now_iso
from ..planning.planner import propose_candidates

FORMAT = "gtc-ipm-profile"
VERSION = 1
MAX_ENTRIES = 70000


class ProfileError(ValueError):
    pass


def build_profile(snap: Snapshot, hostname: str = "", known_internet: dict | None = None) -> dict:
    if not snap.plan:
        raise ProfileError("Aucun plan d'adressage à exporter : lancez d'abord une analyse.")
    return {
        "format": FORMAT, "version": VERSION, "created_at": now_iso(), "source_host": hostname,
        "domain": {"in_domain": snap.domain.in_domain, "name": snap.domain.name,
                   "controllers": list(snap.domain.domain_controllers),
                   "dc_addresses": list(snap.domain.dc_addresses)},
        "dns": sorted({d for i in snap.interfaces for d in i.dns_servers}),
        "internet": [asdict(p) for p in snap.internet],
        "known_internet": dict(known_internet or {}),
        "networks": {net: [asdict(e) for e in entries] for net, entries in snap.plan.items()},
    }


def dump_profile(profile: dict) -> str:
    return json.dumps(profile, ensure_ascii=False, indent=1)


def import_profile(text: str) -> Snapshot:
    try:
        d = json.loads(text)
    except json.JSONDecodeError as e:
        raise ProfileError(f"Fichier illisible (JSON invalide) : {e}") from e
    if not isinstance(d, dict) or d.get("format") != FORMAT:
        raise ProfileError("Ce fichier n'est pas un profil de site GTC Network IP Manager.")
    if d.get("version") != VERSION:
        raise ProfileError(f"Version de profil non prise en charge : {d.get('version')}.")
    dom = d.get("domain") or {}
    nets = d.get("networks") or {}
    if not isinstance(nets, dict) or not nets:
        raise ProfileError("Le profil ne contient aucun réseau.")
    snap = Snapshot()
    snap.started_at = snap.finished_at = d.get("created_at", "")
    snap.imported_from = f"{d.get('source_host') or 'machine inconnue'} le {d.get('created_at', '?')}"
    snap.domain = DomainInfo(in_domain=bool(dom.get("in_domain")), name=str(dom.get("name", "")),
                             domain_controllers=[str(x) for x in dom.get("controllers", [])],
                             dc_addresses=[], evidence=["Profil importé (non vérifié en direct)"])
    for a in dom.get("dc_addresses", []):
        snap.domain.dc_addresses.append(str(ipaddress.IPv4Address(a)))
    total = 0
    for net, entries in nets.items():
        try:
            ipaddress.IPv4Network(net)
        except ValueError as e:
            raise ProfileError(f"Réseau invalide dans le profil : {net}") from e
        out = []
        for e in entries:
            total += 1
            if total > MAX_ENTRIES:
                raise ProfileError("Profil trop volumineux.")
            try:
                ipaddress.IPv4Address(e["ip"])
                ent = IpEntry(**{k: v for k, v in e.items() if k in IpEntry.__dataclass_fields__})
            except (KeyError, ValueError, TypeError) as ex:
                raise ProfileError(f"Entrée invalide dans le profil ({ex}).") from ex
            if ent.status == DISPONIBLE:
                ent.status = CANDIDATE
                ent.justification = ("Libre au moment de l'export du profil (" + d.get("created_at", "?")
                                     + "), NON re-vérifiée depuis ce poste. " + ent.justification)
            out.append(ent)
        snap.plan[net] = out
        snap.candidates[net] = propose_candidates(out)
    snap.internet = [inet.InternetPath(**{k: v for k, v in p.items() if k in inet.InternetPath.__dataclass_fields__})
                     for p in d.get("internet", [])]
    snap.known_internet = dict(d.get("known_internet") or {})
    snap.warnings.append("PROFIL IMPORTÉ de " + snap.imported_from + " : photo datée. Les adresses ne sont pas "
                         "vérifiées en direct ; une adresse peut avoir été prise depuis. Après application, "
                         "le contrôleur de domaine doit répondre, sinon retour arrière automatique.")
    return snap


# --- Bibliothèque de profils nommés (un fichier JSON par site/domaine) -----------------
import re  # noqa: E402
from pathlib import Path  # noqa: E402


def slugify(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip()).strip("._")
    return s[:80]


def save_profile(folder: Path, name: str, profile: dict) -> Path:
    slug = slugify(name)
    if not slug:
        raise ProfileError("Nom de profil vide ou invalide.")
    profile = dict(profile, profile_name=name.strip())
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{slug}.json"
    path.write_text(dump_profile(profile), encoding="utf-8")
    return path


def list_profiles(folder: Path) -> list[dict]:
    out = []
    if not folder.is_dir():
        return out
    for p in sorted(folder.glob("*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            if d.get("format") != FORMAT:
                continue
            out.append({"name": d.get("profile_name") or p.stem, "domain": (d.get("domain") or {}).get("name", ""),
                        "created_at": d.get("created_at", ""), "networks": len(d.get("networks") or {}),
                        "path": str(p)})
        except (OSError, ValueError):
            continue
    return out


def load_profile_file(path: str | Path) -> Snapshot:
    snap = import_profile(Path(path).read_text(encoding="utf-8"))
    try:
        snap.profile_name = json.loads(Path(path).read_text(encoding="utf-8")).get("profile_name", "")
    except (OSError, ValueError):
        pass
    return snap


def delete_profile(folder: Path, path: str) -> None:
    p = Path(path).resolve()
    if p.parent != folder.resolve() or p.suffix != ".json":
        raise ProfileError("Suppression refusée : fichier hors de la bibliothèque.")
    p.unlink()
