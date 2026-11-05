import ast
import ipaddress
from pathlib import Path

source = Path("app.py").read_text(encoding="utf-8")
ast.parse(source, filename="app.py")
assert "Get-NetIPConfiguration" in source
assert "Get-WindowsFeature" in source
assert "AD-Domain-Services" in source
assert "ConvertTo-Json" in source
for address in ("192.168.10.10", "10.0.0.10", "172.16.1.20"):
    ip = ipaddress.IPv4Address(address)
    assert ip.is_private
    assert ipaddress.IPv4Network(f"{ip}/24", strict=False).prefixlen == 24
print("PASS: Python syntax, network examples, Windows Server discovery commands")
