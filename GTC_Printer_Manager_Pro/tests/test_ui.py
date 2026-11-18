"""Parcours utilisateur complet en Qt « offscreen ». Collecteurs et exécuteurs SIMULÉS (hors production)."""
import os
import sys
import time
import zipfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

pytest.importorskip("PySide6")
from PySide6.QtCore import QEvent, QItemSelectionModel, Qt  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from fakes import PRINTERS, fake_collectors, store_collectors  # noqa: E402
from gtc_prn.backup import engine  # noqa: E402
from gtc_prn.backup.job import Job, execute_job  # noqa: E402
from gtc_prn.ui.main_window import TAB_NAMES, MainWindow  # noqa: E402
from test_engine import PS, Runner  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def wait(app, cond, timeout=15):
    t0 = time.time()
    while not cond():
        app.processEvents()
        time.sleep(0.01)
        assert time.time() - t0 < timeout, "délai dépassé"


def dispose(app, w):
    """Destruction ordonnée (avant QApplication) : évite un plantage à la sortie du processus."""
    w.close()
    if w.job_dialog:
        w.job_dialog.worker.wait(30000)
        w.job_dialog.deleteLater()
    w.deleteLater()
    app.sendPostedEvents(None, QEvent.DeferredDelete)
    app.processEvents()


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    import gtc_prn.ui.main_window as mw
    monkeypatch.setattr(mw, "app_dir", lambda: tmp_path / "appdata")
    (tmp_path / "appdata").mkdir()
    return tmp_path


def select_names(view, names):
    """Sélectionne dans le tableau (lignes du PROXY, triées) les imprimantes demandées."""
    sm, m = view.selectionModel(), view.model()
    sm.clearSelection()
    for r in range(m.rowCount()):
        if m.index(r, 0).data() in names:
            sm.select(m.index(r, 0), QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)


def live(ps, with_ports=()):
    """Poste cible simulé dont l'état suit ce que la restauration y a fait (objet PS)."""
    import copy
    from fakes import DRIVERS, PORTS
    return fake_collectors(
        printers=lambda: [copy.deepcopy(p) for p in PRINTERS if p.name in ps.printers],
        drivers=lambda: [copy.deepcopy(d) for d in DRIVERS if d.name in ps.drivers],
        ports=lambda: [copy.deepcopy(p) for p in PORTS if p.name in (ps.ports | set(with_ports))])


def make(app, col, tmp, admin=True, **kw):
    w = MainWindow(collectors=col, auto_detect=False, **kw)
    w._admin = lambda: admin
    w.job_executor = lambda job, say: execute_job(job, say, col=col, runner=Runner(), ps=PS())
    w.show()
    w.btn_analyze.click()
    wait(app, lambda: w.inventory is not None and not w.worker.isRunning())
    return w


def test_startup_before_analysis(app):
    w = MainWindow(collectors=fake_collectors(), auto_detect=False)
    w.show()
    assert [w.tabs.tabText(i) for i in range(w.tabs.count())] == TAB_NAMES
    assert not w.btn_backup.isEnabled() and not w.btn_restore.isEnabled() and w.btn_analyze.isEnabled()
    assert all(v.text() == "—" for v in w.kpis.values())               # aucun faux chiffre avant l'analyse
    for i in range(w.tabs.count()):
        w.tabs.setCurrentIndex(i)
        app.processEvents()
    dispose(app, w)


def test_analysis_kpis_table_filter_and_detail(app, isolated):
    w = make(app, fake_collectors(), isolated)
    k = w.kpis
    assert k["Imprimantes"].text() == "5" and k["Virtuelles (PDF / fichier)"].text() == "2"
    assert k["Réseau (TCP/IP)"].text() == "1" and k["Port propre à un programme"].text() == "1"
    assert k["Pilotes exportables"].text() == "2" and k["Droits administrateur"].text() == "OUI"
    assert w.proxy.rowCount() == 5 and w.btn_backup.isEnabled()
    w.filter_edit.setText("sage")
    assert w.proxy.rowCount() == 1
    w.view.selectRow(0)
    txt = w.detail.toPlainText()
    assert "Sage PDF" in txt and "Sage 100c Gestion commerciale" in txt and "réinstallez" in txt
    w.filter_edit.clear()
    w.view.sortByColumn(0, Qt.AscendingOrder)
    assert w.pick_list.count() == 5
    dispose(app, w)


def test_backup_then_restore_on_another_machine(app, isolated):
    src_store = isolated / "src"
    src_store.mkdir()
    w = make(app, store_collectors(src_store), isolated)
    for i in range(w.pick_list.count()):
        if w.pick_list.item(i).data(Qt.UserRole) in ("Sage PDF", "Bureau HP"):
            w.pick_list.item(i).setCheckState(Qt.Checked)
    assert w.checked_printers() == ["Bureau HP", "Sage PDF"]
    w.chk_printbrm.setChecked(False)
    w.dest_edit.setText(str(isolated / "usb"))
    w.btn_backup.click()
    wait(app, lambda: "TERMINÉ" in w.backup_out.toPlainText())
    out = w.backup_out.toPlainText()
    assert "SANS ÉCHEC" in out and "paquet de pilote copié" in out and "port propre à un programme" in out
    zips = list((isolated / "usb").glob("*.zip"))
    assert len(zips) == 1 and zipfile.is_zipfile(zips[0])
    dispose(app, w)

    # --- autre poste : aucune imprimante installée, on charge le ZIP ---
    ps = PS(ports={"SAGEPDF:"})                 # le programme Sage a été réinstallé : son port existe
    other = live(ps)
    w2 = MainWindow(collectors=other, auto_detect=False)
    w2._admin = lambda: True
    w2.job_executor = lambda job, say: execute_job(job, say, col=other, runner=Runner(), ps=ps)
    w2.show()
    w2.btn_analyze.click()
    wait(app, lambda: w2.inventory is not None and not w2.worker.isRunning())
    assert w2.inventory.printers == [] and not w2.btn_restore.isEnabled()
    w2.load_backup(str(zips[0]))
    rows = {r.name: r for r in w2.restore_model.objs}
    assert rows["Bureau HP"].status == engine.TO_RESTORE and rows["Sage PDF"].status == engine.TO_RESTORE
    assert w2.btn_restore.isEnabled() and "PC-SIM" in w2.restore_info.text()
    # rien n'est sélectionné => refus clair, rien d'exécuté
    w2.btn_restore.click()
    assert "Cochez au moins une imprimante" in w2.restore_out.toPlainText() and not ps.printers
    select_names(w2.restore_view, ["Bureau HP", "Sage PDF"])
    assert sorted(w2.selected_restore_names()) == ["Bureau HP", "Sage PDF"]
    asked = []
    w2._confirm = lambda t: (asked.append(t) or False)
    w2.btn_restore.click()
    assert asked and "MODIFIE" in asked[0] and "Bureau HP" in asked[0] and not ps.printers      # refus => rien fait
    assert "annulée" in w2.restore_out.toPlainText()
    w2._confirm = lambda t: True
    w2.btn_restore.click()
    wait(app, lambda: "TERMINÉ" in w2.restore_out.toPlainText())
    assert ps.printers == {"Bureau HP", "Sage PDF"} and "IP_192.168.1.50" in ps.ports
    txt = w2.restore_out.toPlainText()
    assert txt.startswith("TERMINÉ SANS ÉCHEC") and "Vérification « Sage PDF » — présente avec son port" in txt
    wait(app, lambda: w2.kpis["Imprimantes"].text() == "2")                    # l'analyse est relancée toute seule
    dispose(app, w2)


def test_restore_reports_missing_program_port(app, isolated):
    src = isolated / "s"
    src.mkdir()
    col = store_collectors(src)
    res = engine.run_backup(engine.BackupOptions(str(isolated / "b"), False, ["Sage PDF"], False),
                            __import__("gtc_prn.discovery.inventory", fromlist=["x"]).collect_inventory(col), Runner())
    assert res.ok
    ps = PS()                                    # le programme Sage n'est PAS réinstallé : port absent
    other = live(ps)
    w = MainWindow(collectors=other, auto_detect=False)
    w._admin = lambda: True
    w.job_executor = lambda job, say: execute_job(job, say, col=other, runner=Runner(), ps=ps)
    w.show()
    w.btn_analyze.click()
    wait(app, lambda: w.inventory is not None and not w.worker.isRunning())
    w.load_backup(str(isolated / "b"))
    row = next(r for r in w.restore_model.objs if r.name == "Sage PDF")
    assert row.status == engine.PORT_MISSING and "Sage 100c" in row.note      # prévenu AVANT d'agir
    select_names(w.restore_view, ["Sage PDF"])
    w._confirm = lambda t: True
    w.btn_restore.click()
    wait(app, lambda: "TERMINÉ" in w.restore_out.toPlainText())
    t = w.restore_out.toPlainText()
    assert "AVEC DES ÉCHECS" in t and "réinstallez" in t and not ps.printers
    dispose(app, w)


def test_non_admin_restore_goes_through_uac_helper(app, isolated):
    col = fake_collectors(printers=lambda: [], drivers=lambda: [], ports=lambda: [])
    src = fake_collectors()
    engine.run_backup(engine.BackupOptions(str(isolated / "b"), False, ["Microsoft Print to PDF"], False),
                      __import__("gtc_prn.discovery.inventory", fromlist=["x"]).collect_inventory(src), Runner())
    w = MainWindow(collectors=col, auto_detect=False)
    w._admin = lambda: False
    launched = []
    w._launch = lambda args: launched.append(args)
    w._confirm = lambda t: True
    w.show()
    w.btn_analyze.click()
    wait(app, lambda: w.inventory is not None and not w.worker.isRunning())
    w.load_backup(str(isolated / "b"))
    select_names(w.restore_view, ["Microsoft Print to PDF"])
    w.btn_restore.click()
    assert launched and launched[0][0] == "--prn-job"
    job = Job.from_json(Path(launched[0][1]).read_text("utf-8"))
    assert job.action == "restore" and job.selected_printers == ["Microsoft Print to PDF"] and job.result_path
    r = engine.JobResult(ok=True, action="restore")
    r.add("Microsoft Print to PDF", "OK", "file d'impression créée")
    Path(job.result_path).write_text(r.to_json(), encoding="utf-8")        # ce que ferait la fenêtre élevée
    wait(app, lambda: "file d'impression créée" in w.restore_out.toPlainText())
    # UAC refusé / fenêtre fermée : message clair
    w._job_finished("", w.restore_out)
    assert "refusée" in w.restore_out.toPlainText()
    dispose(app, w)


def test_unreadable_backup_and_other_arch_are_explained(app, isolated):
    w = make(app, fake_collectors(), isolated)
    w.load_backup(str(isolated))
    assert "illisible" in w.restore_info.text() and not w.btn_restore.isEnabled()
    src = fake_collectors()
    inv_mod = __import__("gtc_prn.discovery.inventory", fromlist=["x"])
    inv = inv_mod.collect_inventory(src)
    inv.system.arch = "Windows NT x86"
    engine.run_backup(engine.BackupOptions(str(isolated / "b32"), False, ["Bureau HP"], False), inv, Runner())
    w.load_backup(str(isolated / "b32"))
    assert "refusée" in w.restore_info.text()
    assert {r.status for r in w.restore_model.objs} == {engine.INCOMPATIBLE}
    select_names(w.restore_view, ["Bureau HP"])
    w._confirm = lambda t: True
    w.btn_restore.click()
    assert "incompatible" in w.restore_out.toPlainText()
    dispose(app, w)


def test_failed_source_shows_warning_not_crash(app, isolated):
    from gtc_prn.core.psrunner import SourceUnavailable

    def boom():
        raise SourceUnavailable("spouleur arrêté")
    w = make(app, fake_collectors(printers=boom), isolated)
    assert "spouleur arrêté" in w.warn_box.toPlainText() and w.kpis["Imprimantes"].text() == "0"
    assert not w.btn_backup.isEnabled()
    dispose(app, w)


def test_close_while_analysing_does_not_hang(app, isolated):
    import threading
    gate = threading.Event()

    def slow():
        gate.wait(2)
        return list(PRINTERS)
    w = MainWindow(collectors=fake_collectors(printers=slow), auto_detect=False)
    w.show()
    w.btn_analyze.click()
    QTest.qWait(50)
    t0 = time.time()
    gate.set()
    dispose(app, w)
    assert time.time() - t0 < 10
