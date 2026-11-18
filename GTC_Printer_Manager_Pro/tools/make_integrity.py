"""Écrit integrity.json (taille + SHA-256 de chaque fichier) dans le dossier de l'application compilée.
Usage : python tools/make_integrity.py <dossier>"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pathlib import Path  # noqa: E402

from gtc_prn.core.diagnostic import INTEGRITY_FILE, make_manifest  # noqa: E402

root = Path(sys.argv[1])
m = make_manifest(root)
(root / INTEGRITY_FILE).write_text(json.dumps(m, indent=1), encoding="utf-8")
print(f"{INTEGRITY_FILE}: {len(m['files'])} fichiers")
