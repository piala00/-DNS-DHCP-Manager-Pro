"""Auto-diagnostic de démarrage : fichiers faux (DLL tronquée, mauvaise architecture, manifeste) sur un faux dossier."""
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from gtc_prn.core import diagnostic as d  # noqa: E402


def pe(machine=0x8664, pad=2000) -> bytes:
    b = bytearray(0x80) + b"PE\0\0" + struct.pack("<H", machine) + bytes(pad)
    b[:2] = b"MZ"
    struct.pack_into("<I", b, 60, 0x80)
    return bytes(b)


def make_dir(tmp):
    (tmp / "_internal" / "PySide6").mkdir(parents=True)
    (tmp / "_internal" / "PySide6" / "Qt6Widgets.dll").write_bytes(pe())
    (tmp / "_internal" / "python312.dll").write_bytes(pe())
    (tmp / "_internal" / "ext.pyd").write_bytes(pe())
    (tmp / "app.exe").write_bytes(pe())
    (tmp / "README_FR.md").write_text("x")
    return tmp


def test_valid_dir_is_clean(tmp_path):
    root = make_dir(tmp_path)
    assert d.scan_binaries(root) == []
    assert d.verify_manifest(root) is None                      # pas de manifeste : pas une erreur
    text, problems = d.build_report("", root)
    assert problems == [] and "Aucun fichier invalide" in text


def test_detects_truncated_garbage_wrong_arch(tmp_path):
    root = make_dir(tmp_path)
    q = root / "_internal" / "PySide6"
    (q / "Qt6Widgets.dll").write_bytes(b"")                      # vide
    (q / "Qt6Gui.dll").write_bytes(b"\0" * 5000)                  # mis à zéro
    (q / "Qt6Core.dll").write_bytes(pe(machine=0xAA64))           # ARM64
    (q / "Qt6Svg.dll").write_bytes(pe(machine=0x014C))            # 32 bits
    (q / "Qt6Net.dll").write_bytes(pe()[:90])                     # tronqué dans l'en-tête
    probs = d.scan_binaries(root)
    joined = "\n".join(probs)
    assert len(probs) == 5
    assert "Qt6Widgets.dll : fichier vide" in joined and "Qt6Gui.dll : ce n'est pas un exécutable" in joined
    assert "ARM64 au lieu de x64" in joined and "x86 (32 bits) au lieu de x64" in joined
    assert "Qt6Net.dll" in joined


def test_manifest_roundtrip_and_tampering(tmp_path):
    root = make_dir(tmp_path)
    (root / d.INTEGRITY_FILE).write_text(json.dumps(d.make_manifest(root)))
    assert d.verify_manifest(root) == []
    assert "README_FR.md" not in (root / d.INTEGRITY_FILE).read_text()          # les .md sont exclus
    dll = root / "_internal" / "python312.dll"
    dll.write_bytes(pe(pad=1999))                                               # taille différente
    ext = root / "_internal" / "ext.pyd"
    ext.write_bytes(pe()[:-1] + b"\x01")                                        # même taille, contenu différent
    (root / "app.exe").unlink()                                                 # manquant
    out = "\n".join(d.verify_manifest(root))
    assert "python312.dll : taille" in out and "ext.pyd : contenu différent" in out and "app.exe : MANQUANT" in out


def test_manifest_unreadable(tmp_path):
    root = make_dir(tmp_path)
    (root / d.INTEGRITY_FILE).write_text("{pas du json")
    assert "illisible" in d.verify_manifest(root)[0]


def test_startup_failure_writes_report_and_returns_3(tmp_path, monkeypatch, capsys):
    root = make_dir(tmp_path / "app")
    (root / "_internal" / "PySide6" / "Qt6Widgets.dll").write_bytes(b"\0" * 3000)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(root / "app.exe"))
    monkeypatch.setenv("GTC_PRN_NO_DIALOG", "1")
    monkeypatch.setenv("GTC_PRN_DIAG_DIR", str(tmp_path))
    err = ImportError("DLL load failed while importing QtWidgets: %1 n'est pas une application Win32 valide.")
    assert d.startup_failure(err) == 3
    rep = (tmp_path / "GTC_Printer_Manager_Pro_diagnostic.txt").read_text("utf-8")
    assert "Qt6Widgets.dll" in rep and "1 PROBLÈME(S)" in rep and "%1 n'est pas une application Win32" in rep
    assert "PROCESSOR_ARCHITECTURE" in rep and "Retéléchargez" in rep
    assert "Qt6Widgets.dll" in capsys.readouterr().err


def test_startup_failure_healthy_folder_says_so(tmp_path, monkeypatch):
    root = make_dir(tmp_path / "app")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(root / "app.exe"))
    monkeypatch.setenv("GTC_PRN_NO_DIALOG", "1")
    monkeypatch.setenv("GTC_PRN_DIAG_DIR", str(tmp_path))
    assert d.startup_failure(ImportError("x")) == 3
    assert "le dossier est sain" in (tmp_path / "GTC_Printer_Manager_Pro_diagnostic.txt").read_text("utf-8")


def test_cli_diagnose_from_sources(tmp_path):
    out = tmp_path / "r.txt"
    r = subprocess.run([sys.executable, os.path.join(ROOT, "main.py"), "--diagnose", str(out)], capture_output=True)
    assert r.returncode == 0 and "non figé" in out.read_text("utf-8")


def test_make_integrity_tool(tmp_path):
    root = make_dir(tmp_path)
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "make_integrity.py"), str(root)], capture_output=True, text=True)
    assert r.returncode == 0 and "4 fichiers" in r.stdout and d.verify_manifest(Path(root)) == []
