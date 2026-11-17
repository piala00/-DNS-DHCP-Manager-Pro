"""Profils de sites : export, bibliothèque nommée, import (jamais « confirmée »), application."""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from gtc_ipm.core import netconfig as nc  # noqa: E402
from gtc_ipm.core import profile as prof  # noqa: E402
from gtc_ipm.core.models import CANDIDATE, DISPONIBLE  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402
from test_ui import _ready_window, wait, click  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def analysed(app, monkeypatch, tmp_path):
    return _ready_window(app, monkeypatch, tmp_path)


def test_export_import_downgrades_confirmed_and_keeps_domain(app, monkeypatch, tmp_path):
    w = analysed(app, monkeypatch, tmp_path)
    assert any(e.status == DISPONIBLE for es in w.snapshot.plan.values() for e in es)   # il y a des confirmées
    text = prof.dump_profile(prof.build_profile(w.snapshot, "PC-TEST", {}))
    snap = prof.import_profile(text)
    allst = {e.status for es in snap.plan.values() for e in es}
    assert DISPONIBLE not in allst and CANDIDATE in allst
    assert snap.domain.name == "gtc.local" and snap.domain.dc_addresses == w.snapshot.domain.dc_addresses
    assert snap.imported_from.startswith("PC-TEST") and "PROFIL IMPORTÉ" in snap.warnings[0]
    n = next(iter(snap.plan))
    assert len(snap.plan[n]) == 256 and snap.candidates[n]
    assert all("NON re-vérifiée" in e.justification for es in snap.candidates.values() for e in es)
    w.close()


@pytest.mark.parametrize("text,msg", [
    ("pas du json", "illisible"), ("[]", "pas un profil"), ('{"format": "x"}', "pas un profil"),
    ('{"format": "gtc-ipm-profile", "version": 9}', "Version"),
    ('{"format": "gtc-ipm-profile", "version": 1, "networks": {}}', "aucun réseau"),
    ('{"format": "gtc-ipm-profile", "version": 1, "networks": {"pas-un-reseau": []}}', "invalide"),
    ('{"format": "gtc-ipm-profile", "version": 1, "networks": {"10.0.0.0/24": [{"ip": "999.1.1.1"}]}}', "invalide")])
def test_import_rejects_bad_files(text, msg):
    with pytest.raises(prof.ProfileError, match=msg):
        prof.import_profile(text)


def test_library_save_list_load_delete_and_name_safety(tmp_path):
    from gtc_ipm.core.models import Snapshot, IpEntry
    s = Snapshot()
    s.plan = {"10.0.0.0/24": [IpEntry("10.0.0.5", DISPONIBLE, "ok", "10.0.0.0/24", "2026-01-01")]}
    d = prof.build_profile(s, "H")
    folder = tmp_path / "lib"
    p1 = prof.save_profile(folder, "gtc.local", d)
    p2 = prof.save_profile(folder, "../../evil name", d)
    assert p2.parent == folder and ".." not in p2.name                      # pas d'évasion de dossier
    names = [x["name"] for x in prof.list_profiles(folder)]
    assert names == sorted(names) and "gtc.local" in names and "../../evil name" in names
    assert prof.load_profile_file(p1).profile_name == "gtc.local"
    with pytest.raises(prof.ProfileError):
        prof.delete_profile(folder, str(tmp_path / "autre.json"))
    prof.delete_profile(folder, str(p1))
    assert len(prof.list_profiles(folder)) == 1
    with pytest.raises(prof.ProfileError):
        prof.save_profile(folder, "   ", d)
    with pytest.raises(prof.ProfileError):
        prof.build_profile(Snapshot(), "H")                                  # rien à exporter


def test_ui_save_load_and_apply_from_imported_profile(app, monkeypatch, tmp_path):
    w = analysed(app, monkeypatch, tmp_path)
    w.profile_save("gtc.local")
    assert w.prof_list.count() == 1 and "gtc.local" in w.prof_list.item(0).text()
    w.close()
    # « autre poste » : aucune analyse, on charge le profil du domaine
    w2 = _ready_window(app, monkeypatch, tmp_path)
    w2.snapshot = None
    w2.prof_list.setCurrentRow(0)
    w2.profile_load_selected()
    assert w2.snapshot.imported_from and w2.kpis["Domaine détecté"].text() == "gtc.local"
    assert w2.cand_model.rowCount() > 0
    launched = []
    w2._launch = lambda a: launched.append(a)
    w2._confirm_apply = lambda t: (launched.append(("txt", t)) or True)
    local = _local_ifs()
    for i in local:
        i.index = 7
    w2.collectors.interfaces = lambda: local
    w2.cand_view.selectRow(0)
    click(w2.btn_apply)
    wait(app, lambda: len(launched) >= 2)
    assert "PROFIL IMPORTÉ" in launched[0][1] and "pas pu être vérifiée en direct" in launched[0][1]
    plan = nc.NetPlan.from_json(open(launched[1][1], encoding="utf-8").read())
    assert plan.adapter_index == 7 and plan.check_hosts == w2.snapshot.domain.dc_addresses and not plan.validate()
    # un profil importé ne peut pas être ré-enregistré comme une analyse
    with pytest.raises(prof.ProfileError):
        w2.profile_save("x")
    w2.close()


def _local_ifs():
    from test_connectors import fake_collectors
    return fake_collectors().interfaces()


def test_post_apply_verification_requires_domain_controller(app, tmp_path):
    from gtc_ipm.ui.apply_dialog import ApplyDialog
    from test_connectors import fake_collectors
    col = fake_collectors()
    itf = col.interfaces()[0]
    plan = nc.NetPlan(7, "x", itf.ipv4, itf.prefix, itf.gateway, [], check_hosts=["172.168.4.245"])
    d = ApplyDialog(plan, collectors=col, settle_s=0)
    col.ping = lambda h, t: False
    col.tcp_from = lambda *a, **k: False
    ok, lines = d._make_verify(col)()
    assert not ok and any("NON joignable" in x for x in lines)               # DC muet => retour arrière
    col.ping = lambda h, t: True
    ok, lines = d._make_verify(col)()
    assert ok and any("joignable." in x and "NON" not in x for x in lines)
    plan2 = nc.NetPlan(7, "x", "10.9.9.9", 24, "", [], check_hosts=["172.168.4.245"])
    ok, lines = ApplyDialog(plan2, collectors=col, settle_s=0)._make_verify(col)()
    assert not ok and "n'a pas pris" in lines[0]                              # la carte n'a pas pris l'IP
    d.close()
