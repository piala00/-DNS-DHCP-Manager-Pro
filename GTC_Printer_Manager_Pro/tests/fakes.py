"""Données SIMULÉES (clairement hors production) reproduisant un poste type."""
from gtc_prn.core.models import (DriverInfo, MonitorInfo, PortInfo, PrinterInfo, ProgramInfo, SystemInfo)
from gtc_prn.discovery.inventory import Collectors

SYSTEM = SystemInfo(hostname="PC-SIM", os_caption="Windows 10 Pro", os_build="19045 22H2", arch="Windows x64",
                    is_admin=True, spooler_running=True, printbrm_available=True, collected_at="2026-01-01T10:00:00+01:00")
PRINTERS = [
    PrinterInfo("Microsoft Print to PDF", "Microsoft Print To PDF", "PORTPROMPT:"),
    PrinterInfo("Bureau HP", "HP Universal Printing PCL 6", "IP_192.168.1.50", is_default=True),
    PrinterInfo("Sage PDF", "Sage PDF Driver", "SAGEPDF:"),
    PrinterInfo("\\\\SRV\\Compta", "Brother HL", "\\\\SRV\\Compta"),
    PrinterInfo("Etiquettes USB", "ZDesigner", "USB001"),
]
DRIVERS = [
    DriverInfo("Microsoft Print To PDF", "Windows x64", 4, "Microsoft",
               r"C:\WINDOWS\System32\DriverStore\FileRepository\prnms009.inf_amd64_aaa\prnms009.inf"),
    DriverInfo("HP Universal Printing PCL 6", "Windows x64", 3, "HP",
               r"C:\WINDOWS\System32\DriverStore\FileRepository\hpcu255u.inf_amd64_bbb\hpcu255u.inf"),
    DriverInfo("Sage PDF Driver", "Windows x64", 3, "Sage",
               r"C:\WINDOWS\System32\DriverStore\FileRepository\sagepdf.inf_amd64_ccc\sagepdf.inf",
               driver_path=r"C:\Windows\System32\spool\drivers\x64\3\sagepdf.dll", monitor_name="SagePdfPort"),
    DriverInfo("Brother HL", "Windows x64", 3, "Brother", ""),
    DriverInfo("ZDesigner", "Windows x64", 3, "Zebra", ""),
]
PORTS = [
    PortInfo("PORTPROMPT:", "Local Port"), PortInfo("IP_192.168.1.50", "Standard TCP/IP Port",
                                                     host_address="192.168.1.50", port_number=9100, protocol=1),
    PortInfo("SAGEPDF:", "SagePdfPort"), PortInfo("USB001", "USB Monitor"),
]
MONITORS = [MonitorInfo("Local Port", r"C:\Windows\System32\localspl.dll"),
            MonitorInfo("SagePdfPort", r"C:\Program Files\Sage\PdfPrinter\sagepdfmon.dll")]
PROGRAMS = [ProgramInfo("Sage 100c Gestion commerciale", "Sage", "12.0", r"C:\Program Files\Sage\PdfPrinter"),
            ProgramInfo("7-Zip", "Igor Pavlov", "23", r"C:\Program Files\7-Zip")]


def fake_collectors(**over) -> Collectors:
    import copy
    c = Collectors(system=lambda: copy.deepcopy(SYSTEM), printers=lambda: copy.deepcopy(PRINTERS),
                   drivers=lambda: copy.deepcopy(DRIVERS), ports=lambda: copy.deepcopy(PORTS),
                   monitors=lambda: copy.deepcopy(MONITORS), programs=lambda: copy.deepcopy(PROGRAMS))
    for k, v in over.items():
        setattr(c, k, v)
    return c


def store_collectors(root, **over):
    """Collecteurs simulés dont les paquets de pilotes existent VRAIMENT sur disque (pour tester la copie)."""
    import copy
    store = root / "Windows" / "System32" / "DriverStore" / "FileRepository"
    drivers = copy.deepcopy(DRIVERS)
    for d in drivers:
        if d.inf_path and d.manufacturer != "Microsoft":
            name = d.inf_path.split("\\")[-1]
            pkg = store / (name + "_pkg")
            pkg.mkdir(parents=True, exist_ok=True)
            (pkg / name).write_text("; inf")
            (pkg / "driver.dll").write_bytes(b"MZ")
            d.inf_path = str(pkg / name)
    return fake_collectors(drivers=lambda: copy.deepcopy(drivers), **over)
