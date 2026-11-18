"""Sauvegarde / restauration avec exécuteurs SIMULÉS : aucune modification réelle d'imprimante ici."""
import os
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from fakes import fake_collectors  # noqa: E402
from gtc_prn.backup import engine  # noqa: E402
from gtc_prn.backup.job import Job, execute_job  # noqa: E402
from gtc_prn.core.models import PrinterInfo  # noqa: E402
from gtc_prn.discovery.inventory import collect_inventory  # noqa: E402


@pytest.fixture
def inv():
    return collect_inventory(fake_collectors())


@pytest.fixture
def fake_store(tmp_path, monkeypatch, inv):
    """Un faux DriverStore pour le pilote Sage PDF."""
    store = tmp_path / "store" / "sagepdf.inf_amd64_ccc"
    store.mkdir(parents=True)
    (store / "sagepdf.inf").write_text("; inf")
    (store / "sagepdf.dll").write_bytes(b"MZ")
    hp = tmp_path / "store" / "hpcu255u.inf_amd64_bbb"
    hp.mkdir()
    (hp / "hpcu255u.inf").write_text("; inf")
    for d in inv.drivers:
        if d.name == "Sage PDF Driver":
            d.package_dir = str(store)
        if d.name == "HP Universal Printing PCL 6":
            d.package_dir = str(hp)
    return store


class Runner:
    def __init__(self, rc=0, make_file=True):
        self.calls, self.rc, self.make_file = [], rc, make_file

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        if "-b" in cmd and self.make_file and self.rc == 0:
            Path(cmd[cmd.index("-f") + 1]).write_bytes(b"PRINTBRM" * 50)
        return self.rc, "ok" if self.rc == 0 else "erreur simulée"


class PS:
    """Simule Get-/Add- : état d'un poste cible."""
    def __init__(self, drivers=(), ports=(), printers=()):
        self.drivers, self.ports, self.printers = set(drivers), set(ports), set(printers)
        self.calls = []

    def __call__(self, script, args):
        self.calls.append((script, dict(args)))
        if script == engine.PS_HAS_DRIVER:
            return "yes" if args["GTCARG_DRIVER" if "GTCARG_DRIVER" in args else "DRIVER"] in self.drivers else "no"
        if script == engine.PS_HAS_PORT:
            return "yes" if args["PORT"] in self.ports else "no"
        if script == engine.PS_HAS_PRINTER:
            return "yes" if args["NAME"] in self.printers else "no"
        if script == engine.PS_ADD_DRIVER:
            self.drivers.add(args["DRIVER"])
        elif script == engine.PS_ADD_TCP_PORT:
            self.ports.add(args["PORT"])
        elif script == engine.PS_ADD_PRINTER:
            self.printers.add(args["NAME"])
        return "ok"


def test_backup_writes_inventory_csv_packages_and_zip(tmp_path, inv, fake_store):
    r = Runner()
    dest = tmp_path / "bk"
    res = engine.run_backup(engine.BackupOptions(str(dest), True, ["Sage PDF", "Microsoft Print to PDF", "Brother"], True),
                            inv, r)
    assert (dest / "inventaire.json").exists() and (dest / "drivers/Sage_PDF_Driver/sagepdf.inf").exists()
    assert (dest / "sauvegarde.printerExport").stat().st_size > 0 and (dest / "LISEZ-MOI.txt").exists()
    labels = {i.label: i for i in res.items}
    assert labels["Sage PDF"].status == "OK" and "paquet de pilote copié" in labels["Sage PDF"].detail
    assert labels["Microsoft Print to PDF"].detail.startswith("pilote intégré")
    assert labels["Imprimante « Brother »"].status == "ECHEC"                         # imprimante inexistante signalée
    port_item = next(i for i in res.items if "SAGEPDF:" in i.label)
    assert port_item.status == "ATTENTION" and "Sage 100c" in port_item.detail
    assert res.path.endswith(".zip") and zipfile.is_zipfile(res.path)
    assert not res.ok                                                  # un échec => pas « ok »
    assert r.calls[0][1:3] == ["-b", "-f"]


def test_csv_is_formula_safe(tmp_path, inv):
    inv.printers[0].name = "=cmd|' /c calc'!A0"
    engine.run_backup(engine.BackupOptions(str(tmp_path / "x"), False, [inv.printers[1].name], False), inv, Runner())
    assert "'=cmd" in (tmp_path / "x" / "inventaire.csv").read_text("utf-8-sig")


def test_printbrm_failure_is_reported(tmp_path, inv):
    res = engine.run_backup(engine.BackupOptions(str(tmp_path / "b"), True, [], False), inv, Runner(rc=1))
    assert any(i.label.startswith("Sauvegarde complète") and i.status == "ECHEC" and "erreur simulée" in i.detail
               for i in res.items) and not res.ok


def test_printbrm_existing_file_is_replaced(tmp_path, inv):
    d = tmp_path / "b"
    d.mkdir()
    (d / "sauvegarde.printerExport").write_bytes(b"old")
    engine.run_backup(engine.BackupOptions(str(d), True, [], False), inv, Runner())
    assert (d / "sauvegarde.printerExport").read_bytes().startswith(b"PRINTBRM")


def test_load_backup_folder_and_zip_and_zip_slip(tmp_path, inv, fake_store):
    res = engine.run_backup(engine.BackupOptions(str(tmp_path / "bk"), False, ["Sage PDF"], True), inv, Runner())
    a = engine.load_backup(str(tmp_path / "bk"))
    b = engine.load_backup(res.path, work_dir=str(tmp_path / "ex"))
    assert len(a.inventory.printers) == len(b.inventory.printers) == 5 and a.selection[0]["package"]
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr("../evil.txt", "x")
    with pytest.raises(ValueError, match="dangereux"):
        engine.load_backup(str(bad), work_dir=str(tmp_path / "ex2"))
    with pytest.raises(ValueError):
        engine.load_backup(str(tmp_path))


def local_with(inv_names=(), arch="Windows x64", extra_ports=("PORTPROMPT:",)):
    from fakes import PRINTERS, PORTS
    import copy
    c = fake_collectors(printers=lambda: [p for p in copy.deepcopy(PRINTERS) if p.name in inv_names],
                        drivers=lambda: [], ports=lambda: [p for p in copy.deepcopy(PORTS) if p.name in extra_ports])
    i = collect_inventory(c)
    i.system.arch = arch
    return i


def test_plan_restore_statuses(tmp_path, inv, fake_store):
    engine.run_backup(engine.BackupOptions(str(tmp_path / "bk"), False, ["Sage PDF", "Bureau HP"], False), inv, Runner())
    bs = engine.load_backup(str(tmp_path / "bk"))
    rows = {r.name: r for r in engine.plan_restore(bs, local_with(["Microsoft Print to PDF"]))}
    assert rows["Microsoft Print to PDF"].status == engine.PRESENT
    assert rows["Sage PDF"].status == engine.PORT_MISSING and "Sage 100c" in rows["Sage PDF"].note
    assert rows["Bureau HP"].status == engine.TO_RESTORE
    assert rows["\\\\SRV\\Compta"].status == engine.DRIVER_MISSING          # pas de paquet ni PrintBrm
    rows = {r.name: r for r in engine.plan_restore(bs, local_with([], arch="Windows NT x86"))}
    assert {r.status for r in rows.values()} == {engine.INCOMPATIBLE}


def test_selective_restore_installs_driver_port_printer_in_order(tmp_path, inv, fake_store):
    engine.run_backup(engine.BackupOptions(str(tmp_path / "bk"), False, ["Bureau HP", "Sage PDF"], False), inv, Runner())
    bs = engine.load_backup(str(tmp_path / "bk"))
    target = local_with([])
    r, ps = Runner(), PS()
    res = engine.run_restore(engine.RestoreOptions("selective", ["Bureau HP"]), bs, target, r, ps)
    assert res.ok, res.items
    assert "Bureau HP" in ps.printers and "IP_192.168.1.50" in ps.ports                  # port TCP/IP recréé
    add_port = next(a for s, a in ps.calls if s == engine.PS_ADD_TCP_PORT)
    assert add_port["HOST"] == "192.168.1.50" and add_port["PORTNUM"] == "9100"
    scripts = [s for s, _ in ps.calls]
    assert scripts.index(engine.PS_ADD_DRIVER) < scripts.index(engine.PS_ADD_TCP_PORT) < scripts.index(engine.PS_ADD_PRINTER)
    assert r.calls[0][:2] == ["pnputil", "/add-driver"] and r.calls[0][2].endswith("hpcu255u.inf")   # paquet copié -> pnputil


def test_selective_restore_uses_pnputil_when_package_available(tmp_path, inv, fake_store):
    engine.run_backup(engine.BackupOptions(str(tmp_path / "bk"), False, ["Sage PDF"], False), inv, Runner())
    bs = engine.load_backup(str(tmp_path / "bk"))
    # le poste cible a déjà le port du programme réinstallé
    r, ps = Runner(), PS(ports={"SAGEPDF:"})
    res = engine.run_restore(engine.RestoreOptions("selective", ["Sage PDF"]), bs, local_with([]), r, ps)
    assert res.ok and "Sage PDF" in ps.printers
    assert r.calls[0][:2] == ["pnputil", "/add-driver"] and r.calls[0][2].endswith("sagepdf.inf") and r.calls[0][3] == "/install"


def test_selective_restore_refuses_missing_custom_port_with_program_hint(tmp_path, inv, fake_store):
    engine.run_backup(engine.BackupOptions(str(tmp_path / "bk"), False, ["Sage PDF"], False), inv, Runner())
    bs = engine.load_backup(str(tmp_path / "bk"))
    res = engine.run_restore(engine.RestoreOptions("selective", ["Sage PDF"]), bs, local_with([]), Runner(), PS())
    bad = [i for i in res.items if i.status == "ECHEC"]
    assert bad and "réinstallez" in bad[0].detail and "Sage 100c" in bad[0].detail and not res.ok


def test_restore_skips_existing_and_pnputil_failure_is_reported(tmp_path, inv, fake_store):
    engine.run_backup(engine.BackupOptions(str(tmp_path / "bk"), False, ["Sage PDF"], False), inv, Runner())
    bs = engine.load_backup(str(tmp_path / "bk"))
    res = engine.run_restore(engine.RestoreOptions("selective", ["Sage PDF"]), bs, local_with([]), Runner(),
                             PS(printers={"Sage PDF"}))
    assert res.items[-1].detail.startswith("déjà présente")
    res = engine.run_restore(engine.RestoreOptions("selective", ["Sage PDF"]), bs, local_with([]), Runner(rc=5),
                             PS(ports={"SAGEPDF:"}))
    assert not res.ok and "pnputil a échoué" in res.items[-1].detail


def test_printbrm_restore_and_final_verification(tmp_path, inv):
    engine.run_backup(engine.BackupOptions(str(tmp_path / "bk"), True, [], False), inv, Runner())
    bs = engine.load_backup(str(tmp_path / "bk"))
    assert bs.has_printbrm
    r = Runner()
    res = engine.run_restore(engine.RestoreOptions("printbrm"), bs, local_with([]), r, PS(),
                             reload=lambda: local_with(["Bureau HP"], extra_ports=("PORTPROMPT:",)))
    assert r.calls[0][1:] == ["-r", "-f", str(tmp_path / "bk" / "sauvegarde.printerExport"), "-o", "force"]
    st = {i.label: i for i in res.items}
    assert st["Vérification « Bureau HP »"].status == "ATTENTION"          # présente mais port manquant
    assert st["Vérification « Sage PDF »"].status == "ECHEC" and not res.ok


def test_restore_refused_on_other_architecture(tmp_path, inv):
    engine.run_backup(engine.BackupOptions(str(tmp_path / "bk"), True, [], False), inv, Runner())
    bs = engine.load_backup(str(tmp_path / "bk"))
    r = Runner()
    res = engine.run_restore(engine.RestoreOptions("printbrm"), bs, local_with([], arch="Windows NT x86"), r, PS())
    assert not res.ok and r.calls == [] and "Architecture différente" in res.items[0].detail


def test_job_validation_and_execution(tmp_path):
    assert Job("backup").validate() and Job("backup", dest_dir="x").validate()
    assert Job("restore", source="s", method="selective").validate()
    assert not Job("backup", dest_dir="x", selected_printers=["a"]).validate()
    assert Job("restore", source="s").needs_admin() and Job("backup", printbrm=True).needs_admin()
    assert not Job("backup", selected_printers=["a"]).needs_admin()
    j = Job("backup", dest_dir=str(tmp_path / "o"), selected_printers=["Microsoft Print to PDF"], make_zip=False,
            result_path=str(tmp_path / "r.json"))
    assert Job.from_json(j.to_json()) == j
    res = execute_job(j, col=fake_collectors(), runner=Runner())
    assert res.ok and engine.JobResult.from_json((tmp_path / "r.json").read_text("utf-8")).ok
    bad = execute_job(Job("restore", source=str(tmp_path / "nope"), selected_printers=["a"]), col=fake_collectors())
    assert not bad.ok and "Choisissez un dossier" in bad.items[0].detail


def test_scripts_use_env_args_only_no_string_building():
    for name, s in engine.PS_SCRIPTS.items():
        assert "GTCARG_" in s and "{" in s or "GTCARG_" in s, name
        assert '"' not in s.replace("''", ""), name                    # aucune concaténation entre guillemets
    with pytest.raises(ValueError):
        engine.psrunner.valid_text("a\nb")
    _ = PrinterInfo
