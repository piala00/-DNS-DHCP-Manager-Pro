"""Tests automatiques de la logique réelle, sans ouvrir de fenêtre Tkinter."""
import ast
import ipaddress
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path("app.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)
FUNCTIONS = [n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name in {"powershell", "discover"}]
assert len(FUNCTIONS) == 2, "Missing core diagnostic functions"
namespace = {"subprocess": subprocess, "json": json}
exec(compile(ast.Module(body=FUNCTIONS, type_ignores=[]), "app.py", "exec"), namespace)

class DiagnosticTests(unittest.TestCase):
    def test_powershell_success(self):
        with patch.object(subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = " OK \n"
            self.assertEqual(namespace["powershell"]("Write-Output OK"), "OK")
            self.assertEqual(run.call_args.kwargs["timeout"], 45)

    def test_powershell_failure(self):
        with patch.object(subprocess, "run") as run:
            run.return_value.returncode = 1
            run.return_value.stderr = "Access denied"
            with self.assertRaisesRegex(RuntimeError, "Access denied"):
                namespace["powershell"]("bad")

    def test_discover_json(self):
        payload = {"Host": "LAB-DC01", "Network": [{"IP": "10.77.0.10", "Prefix": 24}], "Roles": {"DNS": True, "DHCP": False, "AD-Domain-Services": True}}
        with patch.dict(namespace, {"powershell": lambda script: json.dumps(payload)}):
            self.assertEqual(namespace["discover"](), payload)

    def test_discover_bad_json(self):
        with patch.dict(namespace, {"powershell": lambda script: "invalid"}):
            with self.assertRaises(json.JSONDecodeError):
                namespace["discover"]()

    def test_network(self):
        for ip in ("10.77.0.10", "172.16.2.10", "192.168.1.10"):
            addr = ipaddress.IPv4Address(ip)
            self.assertTrue(addr.is_private)
            self.assertEqual(ipaddress.IPv4Network(f"{addr}/24", strict=False).prefixlen, 24)

if __name__ == "__main__":
    unittest.main(verbosity=2)
