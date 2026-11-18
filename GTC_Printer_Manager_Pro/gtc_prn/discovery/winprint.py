"""Lecture NATIVE (ctypes + registre) des imprimantes, pilotes, ports, moniteurs et programmes.

Aucun PowerShell : rapide et fiable même sur les postes où PowerShell est lent. Lecture seule.
Sur un système non Windows, chaque fonction lève SourceUnavailable.
"""
from __future__ import annotations

import ctypes
import os
import platform
import re
import subprocess
import sys
from ctypes import wintypes
from typing import Any, Iterator

from ..core.models import (DriverInfo, MonitorInfo, PortInfo, PrinterInfo, ProgramInfo, SystemInfo, now_iso)
from ..core.psrunner import SourceUnavailable

IS_WINDOWS = sys.platform == "win32"
PRINTER_ENUM_LOCAL = 0x2
PRINTER_ENUM_CONNECTIONS = 0x4
ERROR_INSUFFICIENT_BUFFER = 122
PRINT_KEY = r"SYSTEM\CurrentControlSet\Control\Print"
UNINSTALL_KEYS = (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                  r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")


class PRINTER_INFO_2W(ctypes.Structure):
    _fields_ = [("pServerName", wintypes.LPWSTR), ("pPrinterName", wintypes.LPWSTR),
                ("pShareName", wintypes.LPWSTR), ("pPortName", wintypes.LPWSTR),
                ("pDriverName", wintypes.LPWSTR), ("pComment", wintypes.LPWSTR),
                ("pLocation", wintypes.LPWSTR), ("pDevMode", ctypes.c_void_p),
                ("pSepFile", wintypes.LPWSTR), ("pPrintProcessor", wintypes.LPWSTR),
                ("pDatatype", wintypes.LPWSTR), ("pParameters", wintypes.LPWSTR),
                ("pSecurityDescriptor", ctypes.c_void_p), ("Attributes", wintypes.DWORD),
                ("Priority", wintypes.DWORD), ("DefaultPriority", wintypes.DWORD),
                ("StartTime", wintypes.DWORD), ("UntilTime", wintypes.DWORD),
                ("Status", wintypes.DWORD), ("cJobs", wintypes.DWORD), ("AveragePPM", wintypes.DWORD)]


class PORT_INFO_2W(ctypes.Structure):
    _fields_ = [("pPortName", wintypes.LPWSTR), ("pMonitorName", wintypes.LPWSTR),
                ("pDescription", wintypes.LPWSTR), ("fPortType", wintypes.DWORD),
                ("Reserved", wintypes.DWORD)]


class DRIVER_INFO_3W(ctypes.Structure):
    _fields_ = [("cVersion", wintypes.DWORD), ("pName", wintypes.LPWSTR), ("pEnvironment", wintypes.LPWSTR),
                ("pDriverPath", wintypes.LPWSTR), ("pDataFile", wintypes.LPWSTR),
                ("pConfigFile", wintypes.LPWSTR), ("pHelpFile", wintypes.LPWSTR),
                ("pDependentFiles", ctypes.c_void_p), ("pMonitorName", wintypes.LPWSTR),
                ("pDefaultDataType", wintypes.LPWSTR)]


def _need_windows() -> None:
    if not IS_WINDOWS:
        raise SourceUnavailable("La lecture des imprimantes nécessite Windows.")


def _winspool():
    _need_windows()
    lib = ctypes.WinDLL("winspool.drv", use_last_error=True)
    lib.EnumPrintersW.argtypes = [wintypes.DWORD, wintypes.LPWSTR, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    lib.EnumPrintersW.restype = wintypes.BOOL
    lib.EnumPortsW.argtypes = [wintypes.LPWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                               ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    lib.EnumPortsW.restype = wintypes.BOOL
    lib.EnumPrinterDriversW.argtypes = [wintypes.LPWSTR, wintypes.LPWSTR, wintypes.DWORD, ctypes.c_void_p,
                                        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                        ctypes.POINTER(wintypes.DWORD)]
    lib.EnumPrinterDriversW.restype = wintypes.BOOL
    lib.GetDefaultPrinterW.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    lib.GetDefaultPrinterW.restype = wintypes.BOOL
    return lib


def _enum(call, prefix: tuple, level: int, struct) -> list:
    """Double appel classique (taille puis données) ; retourne une liste de structures VIVANTES
    (leurs chaînes pointent dans le tampon : à convertir tout de suite)."""
    needed, count = wintypes.DWORD(0), wintypes.DWORD(0)
    call(*prefix, level, None, 0, ctypes.byref(needed), ctypes.byref(count))
    err = ctypes.get_last_error()
    if needed.value == 0:
        if err not in (0, ERROR_INSUFFICIENT_BUFFER):
            raise SourceUnavailable(f"Énumération impossible (code {err}).")
        return []
    buf = ctypes.create_string_buffer(needed.value)
    if not call(*prefix, level, buf, needed.value, ctypes.byref(needed), ctypes.byref(count)):
        raise SourceUnavailable(f"Énumération impossible (code {ctypes.get_last_error()}).")
    arr = (struct * count.value).from_buffer(buf)
    _KEEP.append(buf)
    del _KEEP[:-4]
    return list(arr)


_KEEP: list = []


def _multi_sz(ptr) -> list[str]:
    out: list[str] = []
    if not ptr:
        return out
    off = 0
    while True:
        s = ctypes.wstring_at(ptr + off)
        if not s:
            break
        out.append(s)
        off += (len(s) + 1) * 2
    return out


def default_printer_name() -> str:
    lib = _winspool()
    size = wintypes.DWORD(0)
    lib.GetDefaultPrinterW(None, ctypes.byref(size))
    if size.value == 0:
        return ""
    buf = ctypes.create_unicode_buffer(size.value)
    return buf.value if lib.GetDefaultPrinterW(buf, ctypes.byref(size)) else ""


def collect_printers() -> list[PrinterInfo]:
    lib = _winspool()
    default = default_printer_name()
    out = []
    for p in _enum(lib.EnumPrintersW, (PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS, None), 2, PRINTER_INFO_2W):
        name = p.pPrinterName or ""
        out.append(PrinterInfo(name=name, driver=p.pDriverName or "", port=p.pPortName or "",
                               share_name=p.pShareName or "", comment=p.pComment or "",
                               location=p.pLocation or "", attributes=int(p.Attributes),
                               status=int(p.Status), is_default=(name == default)))
    return out


def collect_ports() -> list[PortInfo]:
    lib = _winspool()
    out = []
    for p in _enum(lib.EnumPortsW, (None,), 2, PORT_INFO_2W):
        out.append(PortInfo(name=p.pPortName or "", monitor=p.pMonitorName or "",
                            description=p.pDescription or "", port_type=int(p.fPortType)))
    # Adresse des ports TCP/IP standard (registre)
    for port in out:
        if port.monitor == "Standard TCP/IP Port":
            v = _reg_values(PRINT_KEY + r"\Monitors\Standard TCP/IP Port\Ports" + "\\" + port.name)
            port.host_address = str(v.get("IPAddress") or v.get("HostName") or "")
            port.port_number = int(v.get("PortNumber") or 0)
            port.protocol = int(v.get("Protocol") or 0)
    return out


def _environment() -> str:
    m = platform.machine().upper()
    if m in ("AMD64", "X86_64"):
        return "Windows x64"
    if m == "ARM64":
        return "Windows ARM64"
    return "Windows NT x86"


def collect_drivers() -> list[DriverInfo]:
    lib = _winspool()
    out = []
    for d in _enum(lib.EnumPrinterDriversW, (None, None), 3, DRIVER_INFO_3W):
        name = d.pName or ""
        info = DriverInfo(name=name, environment=d.pEnvironment or "", version=int(d.cVersion),
                          driver_path=d.pDriverPath or "", config_file=d.pConfigFile or "",
                          data_file=d.pDataFile or "", help_file=d.pHelpFile or "",
                          dependent_files=_multi_sz(d.pDependentFiles), monitor_name=d.pMonitorName or "")
        base = PRINT_KEY + r"\Environments" + "\\" + (info.environment or _environment()) + r"\Drivers"
        for ver in (f"Version-{info.version}", "Version-3", "Version-4"):
            v = _reg_values(base + "\\" + ver + "\\" + name)
            if v:
                info.manufacturer = str(v.get("Manufacturer") or "")
                info.inf_path = str(v.get("InfPath") or "")
                break
        out.append(info)
    return out


def _reg_values(path: str, hive=None) -> dict[str, Any]:
    if not IS_WINDOWS:
        return {}
    import winreg
    hive = winreg.HKEY_LOCAL_MACHINE if hive is None else hive
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            out, i = {}, 0
            while True:
                try:
                    n, v, _t = winreg.EnumValue(k, i)
                except OSError:
                    break
                out[n] = v
                i += 1
            return out
    except OSError:
        return {}


def _reg_subkeys(path: str, hive=None) -> Iterator[str]:
    if not IS_WINDOWS:
        return
    import winreg
    hive = winreg.HKEY_LOCAL_MACHINE if hive is None else hive
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            i = 0
            while True:
                try:
                    yield winreg.EnumKey(k, i)
                except OSError:
                    return
                i += 1
    except OSError:
        return


def collect_monitors() -> list[MonitorInfo]:
    _need_windows()
    return [MonitorInfo(name=n, dll=str(_reg_values(PRINT_KEY + r"\Monitors" + "\\" + n).get("Driver") or ""))
            for n in _reg_subkeys(PRINT_KEY + r"\Monitors")]


def collect_programs() -> list[ProgramInfo]:
    _need_windows()
    import winreg
    seen, out = set(), []
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for key in UNINSTALL_KEYS:
            for sub in _reg_subkeys(key, hive):
                v = _reg_values(key + "\\" + sub, hive)
                name = str(v.get("DisplayName") or "").strip()
                if not name or (name, str(v.get("DisplayVersion") or "")) in seen:
                    continue
                seen.add((name, str(v.get("DisplayVersion") or "")))
                out.append(ProgramInfo(name=name, publisher=str(v.get("Publisher") or ""),
                                       version=str(v.get("DisplayVersion") or ""),
                                       install_location=str(v.get("InstallLocation") or "").strip('" ')))
    return out


def printbrm_path() -> str:
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "spool", "tools", "PrintBrm.exe")


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return False


def _spooler_running():
    try:
        p = subprocess.run(["sc", "query", "Spooler"], capture_output=True, timeout=15, stdin=subprocess.DEVNULL,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        txt = p.stdout.decode("cp850", "replace")
        if p.returncode != 0 and not txt.strip():
            return None
        return bool(re.search(r"\bRUNNING\b", txt))
    except (OSError, subprocess.SubprocessError):
        return None


def collect_system() -> SystemInfo:
    _need_windows()
    cv = _reg_values(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
    build = str(cv.get("CurrentBuildNumber") or "")
    disp = str(cv.get("DisplayVersion") or cv.get("ReleaseId") or "")
    return SystemInfo(hostname=platform.node(), os_caption=str(cv.get("ProductName") or "Windows"),
                      os_build=(build + (" " + disp if disp else "")).strip(), arch=_environment(),
                      is_admin=_is_admin(), spooler_running=_spooler_running(),
                      printbrm_available=os.path.exists(printbrm_path()), collected_at=now_iso())
