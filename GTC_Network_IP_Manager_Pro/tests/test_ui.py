"""Tests d'interface (Qt « offscreen »). Collecteurs SIMULÉS, clairement hors production."""
import os
import sys
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

pytest.importorskip("PySide6")
from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from gtc_ipm.core.settings import Settings  # noqa: E402
from gtc_ipm.ui.main_window import TAB_NAMES, MainWindow  # noqa: E402
from test_connectors import fake_collectors  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def wait(app, cond, timeout=15):
    t0 = time.time()
    while not cond():
        app.processEvents()
        time.sleep(0.01)
        assert time.time() - t0 < timeout, "délai dépassé"


def make(app, col=None):
    s = Settings()
    s.concurrency = 8
    w = MainWindow(collectors=col or fake_collectors(), settings=s)
    w.show()
    wait(app, lambda: w.detector.isFinished())
    app.processEvents()
    return w


def click(w):
    QTest.mouseClick(w, Qt.LeftButton)


def test_startup_tabs_and_disabled_buttons(app):
    w = make(app)
    assert [w.tabs.tabText(i) for i in range(w.tabs.count())] == TAB_NAMES
    assert w.net_list.count() == 1 and w.checked_networks() == ["192.168.1.0/24"]
    # Aucun faux résultat avant analyse
    assert all(v.text() == "—" for k, v in w.kpis.items() if k in ("IP occupées", "Adresses candidates", "Conflits"))
    assert not w.btn_xlsx.isEnabled() and "analyse" in w.btn_xlsx.toolTip().lower()
    assert not w.btn_cancel.isEnabled() and w.btn_analyze.isEnabled()
    for i in range(w.tabs.count()):
        w.tabs.setCurrentIndex(i)
        app.processEvents()
    w.close()


def test_full_workflow(app, tmp_path):
    w = make(app)
    click(w.btn_analyze)
    wait(app, lambda: w.snapshot is not None and not w.worker.isRunning())
    snap = w.snapshot
    assert w.progress.value() == 100 and not snap.cancelled
    assert w.kpis["Machines AD"].text() == "3" and w.kpis["Machines AD actives"].text() == "1"
    assert w.kpis["Domaine détecté"].text() == "gtc.local"
    # Machines du domaine : filtre
    assert w.ad_proxy.rowCount() == 3
    w.ad_filter.setText("pc-gone")
    assert w.ad_proxy.rowCount() == 1
    w.ad_view.selectRow(0)
    assert "sans réponse" in w.ad_detail.toPlainText()
    w.ad_filter.clear()
    # Équipements
    assert w.net_model.rowCount() >= 3
    w.net_filter.setText("aa:bb:cc:00:00:20")
    assert w.net_proxy.rowCount() == 1
    # Plan + filtre de statut
    assert w.plan_model.rowCount() == 256
    w.plan_status.setCurrentText("DISPONIBLE_CONFIRMÉE")
    assert 0 < w.plan_proxy.rowCount() < 256
    w.plan_status.setCurrentText("Tous")
    assert w.plan_proxy.rowCount() == 256
    # Tri numérique des IP
    w.plan_view.sortByColumn(0, Qt.DescendingOrder)
    assert w.plan_proxy.data(w.plan_proxy.index(0, 0)) == "192.168.1.255"
    # Candidates -> vérification -> fiche
    assert w.cand_model.rowCount() == 20 and w.cand_model.rows[0][0] == "192.168.1.100"
    w.cand_view.selectRow(0)
    assert w.btn_cfg.isEnabled()
    click(w.btn_verify)
    wait(app, lambda: w.last_verify is not None)
    assert "PAS une garantie" in w.verify_out.toPlainText()
    sheet = w.config_sheet_text()
    assert "192.168.1.100" in sheet and "255.255.255.0" in sheet and "lecture seule" in sheet
    w.verify_ip_edit.setText("192.168.1.20")
    w.last_verify = None
    click(w.btn_verify)
    wait(app, lambda: w.last_verify is not None)
    assert "UTILISÉE" in w.verify_out.toPlainText()
    w.verify_ip_edit.setText("pas une ip")
    click(w.btn_verify)
    assert "valide" in w.verify_out.toPlainText()
    # Voie Internet + test de connectivité
    assert w.kpis["Accès Internet"].text() == "OUI via 192.168.1.1"
    click(w.btn_conn)
    wait(app, lambda: "CONCLUSION" in w.verify_out.toPlainText())
    assert "Internet : OK" in w.verify_out.toPlainText()
    # Exports
    assert w.btn_xlsx.isEnabled()
    x = tmp_path / "plan.xlsx"
    w.do_export_xlsx(str(x))
    import openpyxl
    wb = openpyxl.load_workbook(x)
    assert wb.sheetnames == ["Machines AD", "Réseau", "DHCP", "Plan", "Conflits", "Diagnostic", "Sources"]
    assert wb["Machines AD"].max_row == 4 and wb["Plan"].max_row == 257
    files = w.do_export_csv(str(tmp_path / "csv"))
    assert len(files) == 7
    raw = (tmp_path / "csv" / "Machines_AD.csv").read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")                 # UTF-8 BOM
    w.do_export_diag(str(tmp_path / "d.json"))
    assert (tmp_path / "d.json").read_text(encoding="utf-8").startswith("{")
    w.close()


def test_cancel_button_stops_scan_and_ui_stays_responsive(app):
    col = fake_collectors()
    gate = threading.Event()

    def slow_ping(ip, t):
        gate.wait(0.05)
        return False
    col.ping = slow_ping
    w = make(app, col)
    click(w.btn_analyze)
    wait(app, lambda: w.worker.isRunning() and w.progress.value() >= 3)
    assert w.btn_cancel.isEnabled() and not w.btn_analyze.isEnabled()
    click(w.btn_cancel)
    wait(app, lambda: w.snapshot is not None and not w.worker.isRunning())
    assert w.snapshot.cancelled and w.snapshot.plan == {}
    assert "annulée" in w.progress_label.text().lower()
    assert w.btn_analyze.isEnabled() and not w.btn_cancel.isEnabled()
    assert not w.btn_cfg.isEnabled()
    w.close()


def test_source_errors_are_visible_not_fatal(app):
    w = make(app, fake_collectors(dhcp_fail=True, ad_fail=True))
    click(w.btn_analyze)
    wait(app, lambda: w.snapshot is not None and not w.worker.isRunning())
    txt = w.warn_box.toPlainText()
    assert "INACCESSIBLE" in txt and "simulé" in txt
    assert w.kpis["Machines AD"].text() == "non lu"
    assert w.src_model.rowCount() == 7
    w.close()


def test_add_network_and_warnings(app):
    w = make(app)
    w.net_add.setText("172.168.4.0/24")
    w.add_network()
    assert "172.168.4.0/24" in w.checked_networks()
    assert w.net_warn.isVisible() and "RFC1918" in w.net_warn.text()
    w.net_add.setText("n'importe quoi")
    w.add_network()
    assert "invalide" in w.progress_label.text()
    w.net_add.setText("10.0.0.0/8")
    w.add_network()
    assert "limite" in w.net_warn.text()
    w.close()


def test_settings_validation(app, tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    w = make(app)
    w.s_dc.setText("172.168.4.254, pas-une-ip")
    assert w._collect_settings(save=False) is None and not w.s_msg.isHidden()
    w.s_dc.setText("172.168.4.254")
    w.s_static.setPlainText("192.168.1.9;imprimante")
    w.s_excl.setPlainText("192.168.1.240-192.168.1.250")
    s = w._collect_settings(save=True)
    assert s and s.static_inventory == {"192.168.1.9": "imprimante"} and w.s_msg.isHidden()
    assert (tmp_path / "GTC_Network_IP_Manager_Pro" / "settings.json").exists()
    w.close()


def test_close_while_running_does_not_hang(app):
    col = fake_collectors()
    col.ping = lambda ip, t: (time.sleep(0.02), False)[1]
    w = make(app, col)
    click(w.btn_analyze)
    wait(app, lambda: w.worker.isRunning())
    t0 = time.time()
    w.close()
    assert time.time() - t0 < 10 and not w.worker.isRunning()
