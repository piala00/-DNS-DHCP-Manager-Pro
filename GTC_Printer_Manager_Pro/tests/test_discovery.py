import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from fakes import fake_collectors  # noqa: E402
from gtc_prn.core.models import inventory_from_dict, inventory_to_dict  # noqa: E402
from gtc_prn.core.psrunner import SourceUnavailable  # noqa: E402
from gtc_prn.discovery import classify, winprint  # noqa: E402
from gtc_prn.discovery.inventory import collect_inventory  # noqa: E402


def by_name(inv):
    return {p.name: p for p in inv.printers}


def test_classification_of_each_kind():
    inv = collect_inventory(fake_collectors())
    p = by_name(inv)
    assert p["Microsoft Print to PDF"].kind.startswith("Virtuelle") and p["Microsoft Print to PDF"].port_class == "integre"
    assert p["Bureau HP"].kind == "Réseau (TCP/IP)" and p["Bureau HP"].port_class == "standard"
    assert p["Sage PDF"].port_class == "specifique" and "SagePdfPort" in p["Sage PDF"].kind
    assert "réinstallez d'abord ce programme" in p["Sage PDF"].advice
    assert p["\\\\SRV\\Compta"].kind.startswith("Imprimante partagée")
    assert p["Etiquettes USB"].kind == "USB"


def test_probable_program_found_by_install_path_not_just_name():
    inv = collect_inventory(fake_collectors())
    sage = by_name(inv)["Sage PDF"]
    assert sage.probable_programs == ["Sage 100c Gestion commerciale 12.0"]     # via la DLL du moniteur
    assert [x.name for x in inv.programs] == ["Sage 100c Gestion commerciale"]    # 7-Zip n'est pas lié
    assert by_name(inv)["Microsoft Print to PDF"].probable_programs == []


def test_driver_package_export_rules():
    inv = collect_inventory(fake_collectors())
    d = {x.name: x for x in inv.drivers}
    assert d["Microsoft Print To PDF"].microsoft_inbox and not d["Microsoft Print To PDF"].exportable
    assert d["Sage PDF Driver"].exportable and d["Sage PDF Driver"].package_dir.endswith("sagepdf.inf_amd64_ccc")
    assert not d["Brother HL"].exportable and d["Brother HL"].package_dir == ""    # pas d'INF : pas de paquet


def test_failing_source_is_reported_not_fatal():
    def boom():
        raise SourceUnavailable("accès refusé")
    inv = collect_inventory(fake_collectors(drivers=boom, programs=lambda: 1 / 0))
    assert len(inv.printers) == 5
    assert any("pilotes impossible" in w and "accès refusé" in w for w in inv.warnings)
    assert any("programmes installés en erreur" in w for w in inv.warnings)


def test_empty_machine_has_explicit_message():
    inv = collect_inventory(fake_collectors(printers=lambda: [], drivers=lambda: [], ports=lambda: []))
    assert inv.printers == [] and "Aucune imprimante" in inv.warnings[0]


def test_inventory_json_roundtrip_and_validation():
    inv = collect_inventory(fake_collectors())
    back = inventory_from_dict(inventory_to_dict(inv))
    assert [p.name for p in back.printers] == [p.name for p in inv.printers]
    assert back.system.hostname == "PC-SIM" and back.drivers[2].package_dir == inv.drivers[2].package_dir
    with pytest.raises(ValueError):
        inventory_from_dict({"format": "autre"})


@pytest.mark.skipif(sys.platform == "win32", reason="test du refus hors Windows")
def test_native_functions_refuse_cleanly_off_windows():
    for fn in (winprint.collect_printers, winprint.collect_ports, winprint.collect_drivers,
               winprint.collect_monitors, winprint.collect_programs, winprint.collect_system):
        with pytest.raises(SourceUnavailable):
            fn()


@pytest.mark.parametrize("inf,exp", [
    (r"C:\Windows\System32\DriverStore\FileRepository\x.inf_amd64_1\x.inf", r"C:\Windows\System32\DriverStore\FileRepository\x.inf_amd64_1"),
    (r"C:\Windows\INF\oem5.inf", ""), ("", "")])
def test_driver_store_dir(inf, exp):
    assert classify._driver_store_dir(inf) == exp
