import json
import unittest
from unittest.mock import Mock
import server_core as core

class BackendTests(unittest.TestCase):
    def test_valid_ipv4(self):
        self.assertEqual(core.validate_ipv4("10.17.80.11"), "10.17.80.11")
    def test_reject_invalid_ipv4(self):
        for ip in ("bad", "127.0.0.1", "224.0.0.1", "::1"):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                core.validate_ipv4(ip)
    def test_domain(self):
        self.assertEqual(core.validate_domain("Example.Local"), "example.local")
        for domain in ("bad", "-bad.local", "bad_.local", "a..local"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                core.validate_domain(domain)
    def test_dhcp_scope(self):
        result = core.validate_scope("10.77.0.0/24", "10.77.0.100", "10.77.0.200")
        self.assertEqual(result["start"], "10.77.0.100")
    def test_reject_dhcp_outside_subnet(self):
        with self.assertRaises(ValueError):
            core.validate_scope("10.77.0.0/24", "10.78.0.100", "10.78.0.200")
    def test_reject_dhcp_reversed(self):
        with self.assertRaises(ValueError):
            core.validate_scope("10.77.0.0/24", "10.77.0.200", "10.77.0.100")
    def test_reject_server_in_scope(self):
        with self.assertRaises(ValueError):
            core.plan_scope("10.77.0.0/24", "10.77.0.100", "10.77.0.200", "10.77.0.110")
    def test_ps_failure(self):
        runner=Mock(return_value=Mock(returncode=1,stderr="access denied",stdout=""))
        with self.assertRaisesRegex(RuntimeError, "access denied"):
            core.run_ps("Get-Service",runner=runner)
    def test_inspection_all_modules(self):
        for kind in ("network","ad","dns","dhcp"):
            with self.subTest(kind=kind):
                runner=Mock(return_value=Mock(returncode=0,stdout='{"ok":true}',stderr=""))
                self.assertEqual(core.inspect(kind,runner=runner),{"ok":True})
                self.assertIn("powershell.exe",runner.call_args.args[0])
    def test_unknown_module(self):
        with self.assertRaises(ValueError):
            core.inspect("invalid")
    def test_roles(self):
        runner=Mock(return_value=Mock(returncode=0,stdout='[{"Name":"DNS","Installed":true}]',stderr=""))
        self.assertTrue(core.check_roles(runner)[0]["Installed"])

if __name__=="__main__":
    unittest.main(verbosity=2)
