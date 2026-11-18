"""Exécution sûre de PowerShell.

Les scripts sont des chaînes statiques ; les valeurs variables sont validées puis
transmises par variables d'environnement (GTCARG_*), jamais concaténées.
"""
from __future__ import annotations

import base64
import html
import json
import os
import re
import subprocess
import sys
from typing import Any, Optional

IS_WINDOWS = sys.platform == "win32"


class SourceUnavailable(Exception):
    """Source de données inaccessible (permission, module absent, hors Windows...)."""


def valid_text(value: str, label: str = "valeur", max_len: int = 260) -> str:
    """Texte libre (nom d'imprimante, pilote, port…) : transmis par variable d'environnement,
    jamais concaténé ; on refuse seulement les caractères de contrôle et les longueurs absurdes."""
    v = str(value)
    if not v.strip() or len(v) > max_len or any(ord(c) < 32 for c in v):
        raise ValueError(f"{label} invalide : {value!r}")
    return v


def _flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if IS_WINDOWS else 0


def run_powershell(script: str, args: Optional[dict[str, str]] = None,
                   timeout: float = 60.0) -> str:
    if not IS_WINDOWS:
        raise SourceUnavailable("Cette source nécessite Windows et PowerShell.")
    prefix = ("$ProgressPreference='SilentlyContinue';"
              "try{[Console]::OutputEncoding=[System.Text.Encoding]::UTF8}catch{};")
    encoded = base64.b64encode((prefix + script).encode("utf-16-le")).decode("ascii")
    env = dict(os.environ)
    for k, v in (args or {}).items():
        if not re.fullmatch(r"[A-Z0-9_]{1,32}", k):
            raise ValueError("Nom d'argument invalide")
        env["GTCARG_" + k] = v
    try:
        p = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-InputFormat", "None",
             "-ExecutionPolicy", "Bypass",
             "-EncodedCommand", encoded],
            capture_output=True, timeout=timeout, env=env, creationflags=_flags(),
            stdin=subprocess.DEVNULL)
    except FileNotFoundError as e:
        raise SourceUnavailable("PowerShell introuvable.") from e
    except subprocess.TimeoutExpired as e:
        raise SourceUnavailable(f"Délai dépassé ({timeout:.0f} s).") from e
    out = p.stdout.decode("utf-8", errors="replace").strip()
    if p.returncode != 0:
        err = clean_ps_error(p.stderr.decode("utf-8", errors="replace"))
        raise SourceUnavailable((err or out or f"code {p.returncode}")[:500])
    return out


def clean_ps_error(text: str) -> str:
    """PowerShell peut renvoyer ses erreurs au format CLIXML : on en extrait le texte."""
    text = (text or "").strip()
    if text.startswith("#< CLIXML"):
        parts = re.findall(r'<S S="Error">(.*?)</S>', text, flags=re.S)
        text = " ".join(parts)
        text = html.unescape(text.replace("_x000D__x000A_", " "))
        text = re.sub(r"\s+", " ", text).strip()
    return text


def parse_json_list(text: str) -> list[dict[str, Any]]:
    """Accepte '', un objet, ou une liste (ConvertTo-Json renvoie un objet seul
    quand il n'y a qu'un élément)."""
    text = (text or "").strip().lstrip("﻿")
    if not text:
        return []
    data = json.loads(text)
    if isinstance(data, dict):
        return [data]
    if not isinstance(data, list):   # 'null' : aucune donnée
        return []
    return [d for d in data if isinstance(d, dict)]


def ps_json(script: str, args: Optional[dict[str, str]] = None,
            timeout: float = 60.0) -> list[dict[str, Any]]:
    return parse_json_list(run_powershell(script, args, timeout))


def as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return [x for x in v if x is not None]
    return [v]
