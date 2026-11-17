"""Application d'une configuration IPv4 statique (ACTION EXPLICITE, jamais pendant un scan).

Sécurités : validation stricte, sauvegarde complète de la configuration réseau avant toute
modification (`netsh interface dump`), vérification de la connectivité après application,
confirmation de l'utilisateur sous délai, et retour arrière automatique en cas d'échec,
de refus ou d'absence de réponse. Les commandes sont des listes d'arguments (pas de shell).
"""
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .models import now_iso

IS_WINDOWS = sys.platform == "win32"
Runner = Callable[[list], "tuple[int, bytes]"]


@dataclass
class NetPlan:
    adapter_index: int
    adapter_label: str
    ip: str
    prefix: int
    gateway: str = ""
    dns: list[str] = field(default_factory=list)
    confirm_timeout_s: int = 60
    check_hosts: list[str] = field(default_factory=list)  # hôtes devant répondre après application (DC)
    backup_path: str = ""
    result_path: str = ""

    def validate(self) -> list[str]:
        errs = []
        if self.adapter_index <= 0:
            errs.append("Index de la carte réseau inconnu.")
        try:
            addr = ipaddress.IPv4Address(self.ip)
            if not 1 <= self.prefix <= 30:
                errs.append("Préfixe invalide (1 à 30).")
            else:
                net = ipaddress.IPv4Network(f"{self.ip}/{self.prefix}", strict=False)
                if addr in (net.network_address, net.broadcast_address):
                    errs.append("L'adresse est celle du réseau ou de diffusion.")
                if self.gateway:
                    g = ipaddress.IPv4Address(self.gateway)
                    if g not in net:
                        errs.append(f"La passerelle {g} n'est pas dans le sous-réseau {net}.")
                    if g == addr:
                        errs.append("La passerelle ne peut pas être l'adresse du poste.")
            if addr.is_loopback or addr.is_multicast or addr.is_link_local or addr.is_unspecified:
                errs.append("Adresse non utilisable.")
        except ValueError as e:
            errs.append(f"Adresse invalide : {e}")
        for d in self.dns:
            try:
                ipaddress.IPv4Address(d)
            except ValueError:
                errs.append(f"DNS invalide : {d}")
        for h in self.check_hosts:
            try:
                ipaddress.IPv4Address(h)
            except ValueError:
                errs.append(f"Hôte à vérifier invalide : {h}")
        if len(self.dns) > 4:
            errs.append("Au plus 4 serveurs DNS.")
        return errs

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, text: str) -> "NetPlan":
        return cls(**json.loads(text))


def build_commands(plan: NetPlan) -> list[list[str]]:
    errs = plan.validate()
    if errs:
        raise ValueError("; ".join(errs))
    idx = str(int(plan.adapter_index))
    mask = str(ipaddress.IPv4Network(f"{plan.ip}/{plan.prefix}", strict=False).netmask)
    addr = ["netsh", "interface", "ipv4", "set", "address", f"name={idx}", "source=static",
            f"address={ipaddress.IPv4Address(plan.ip)}", f"mask={mask}"]
    if plan.gateway:
        addr += [f"gateway={ipaddress.IPv4Address(plan.gateway)}", "gwmetric=1"]
    cmds = [addr]
    for n, d in enumerate(plan.dns, 1):
        ip = str(ipaddress.IPv4Address(d))
        if n == 1:
            cmds.append(["netsh", "interface", "ipv4", "set", "dnsservers", f"name={idx}", "source=static",
                         f"address={ip}", "validate=no"])
        else:
            cmds.append(["netsh", "interface", "ipv4", "add", "dnsservers", f"name={idx}", f"address={ip}",
                         f"index={n}", "validate=no"])
    if not plan.dns:
        cmds.append(["netsh", "interface", "ipv4", "set", "dnsservers", f"name={idx}", "source=dhcp"])
    return cmds


def default_runner(cmd: list) -> "tuple[int, bytes]":
    p = subprocess.run(cmd, capture_output=True, timeout=60, stdin=subprocess.DEVNULL,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return p.returncode, p.stdout + p.stderr


def backup_config(path: str, runner: Runner = default_runner) -> None:
    rc, out = runner(["netsh", "interface", "dump"])
    if rc != 0 or len(out.strip()) < 50:
        raise RuntimeError("Sauvegarde de la configuration réseau impossible : modification annulée.")
    Path(path).write_bytes(out)


def restore_config(path: str, runner: Runner = default_runner) -> bool:
    if not os.path.exists(path):
        return False
    rc, _ = runner(["netsh", "-f", path])
    return rc == 0


@dataclass
class ApplyResult:
    status: str = "failed"   # kept | rolled_back | failed | rollback_failed
    messages: list[str] = field(default_factory=list)
    verification: list[str] = field(default_factory=list)
    finished_at: str = ""


def apply_with_rollback(plan: NetPlan, runner: Runner = default_runner,
                        verify: Optional[Callable[[], "tuple[bool, list[str]]"]] = None,
                        confirm: Optional[Callable[[int, list[str]], bool]] = None,
                        say: Callable[[str], None] = lambda m: None,
                        settle_s: float = 4.0) -> ApplyResult:
    res = ApplyResult()
    cmds = build_commands(plan)          # valide ; lève ValueError sinon
    say("Sauvegarde de la configuration réseau actuelle…")
    try:
        backup_config(plan.backup_path, runner)
    except Exception as e:  # noqa: BLE001
        res.messages.append(str(e))
        res.finished_at = now_iso()
        return res
    res.messages.append(f"Sauvegarde : {plan.backup_path}")

    def rollback(reason: str) -> None:
        say(f"Retour arrière : {reason}")
        ok = restore_config(plan.backup_path, runner)
        res.status = "rolled_back" if ok else "rollback_failed"
        res.messages.append(f"{reason} — " + ("configuration d'origine restaurée."
                                                if ok else f"RESTAURATION ÉCHOUÉE : exécutez « netsh -f \"{plan.backup_path}\" »."))

    for c in cmds:
        say("Application : " + " ".join(c[3:6]))
        rc, out = runner(c)
        if rc != 0:
            res.messages.append(f"Commande en échec ({rc}) : {' '.join(c)} -> {out.decode('cp850', 'replace').strip()[:200]}")
            rollback("échec d'une commande")
            res.finished_at = now_iso()
            return res
    time.sleep(settle_s)
    ok, lines = (verify() if verify else (True, []))
    res.verification = lines
    if not ok:
        say("La vérification de connectivité a échoué.")
    keep = confirm(plan.confirm_timeout_s, lines) if confirm else ok
    if keep:
        res.status = "kept"
        res.messages.append("Configuration conservée (elle persiste après redémarrage).")
    else:
        rollback("refus, délai dépassé ou vérification échouée" if not ok else "annulation par l'utilisateur ou délai dépassé")
    res.finished_at = now_iso()
    return res


# --- élévation de privilèges --------------------------------------------------
def is_admin() -> bool:
    if not IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    import ctypes
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def in_remote_session() -> bool:
    return os.environ.get("SESSIONNAME", "").upper().startswith("RDP")


def launch_elevated(args: list[str]) -> None:
    """Relance cet exécutable avec l'invite UAC (« Exécuter en tant qu'administrateur »)."""
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
