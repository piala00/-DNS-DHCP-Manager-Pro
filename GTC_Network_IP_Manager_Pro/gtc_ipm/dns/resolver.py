"""Résolution DNS A/PTR. Distingue « absent » de « indisponible »."""
from __future__ import annotations

import socket

ABSENT = "absent"
UNAVAILABLE = "indisponible"
RESOLVED = "résolu"

# 11001 WSAHOST_NOT_FOUND, 11004 WSANO_DATA (Windows) ; 1 HOST_NOT_FOUND, 4 NO_DATA (Unix)
_ABSENT_CODES = {11001, 11004, 1, 4, -2, -5, -8}


def _is_absent(e: OSError) -> bool:
    code = getattr(e, "errno", None)
    if code is None and e.args:
        code = e.args[0] if isinstance(e.args[0], int) else None
    return code in _ABSENT_CODES


def resolve_a(name: str) -> tuple[str, list[str]]:
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as e:
        return (ABSENT if _is_absent(e) else UNAVAILABLE), []
    ips = sorted({i[4][0] for i in infos})
    return (RESOLVED if ips else ABSENT), ips


def resolve_ptr(ip: str) -> tuple[str, str]:
    try:
        return RESOLVED, socket.gethostbyaddr(ip)[0]
    except OSError as e:
        return (ABSENT if _is_absent(e) else UNAVAILABLE), ""
