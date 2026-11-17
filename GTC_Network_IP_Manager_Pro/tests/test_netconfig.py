"""Tests de la configuration statique : commandes, validation, sauvegarde, retour arrière.
Exécuteur de commandes SIMULÉ : aucune modification réelle de carte réseau n'est faite ici."""
import json
import os
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from gtc_ipm.core import netconfig as nc  # noqa: E402


def plan(tmp_path, **kw):
    base = dict(adapter_index=12, adapter_label="Ethernet (192.168.1.151/24)", ip="192.168.1.50", prefix=24,
                gateway="192.168.1.1", dns=["172.168.4.245", "8.8.8.8"], confirm_timeout_s=2,
                backup_path=str(tmp_path / "bk.txt"), result_path=str(tmp_path / "res.json"))
    base.update(kw)
    return nc.NetPlan(**base)


class FakeRunner:
    def __init__(self, fail_on=None, dump=b"# netsh dump " + b"x" * 80):
        self.calls, self.fail_on, self.dump = [], fail_on, dump

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        if cmd[:3] == ["netsh", "interface", "dump"]:
            return 0, self.dump
        if self.fail_on and self.fail_on in cmd:
            return 1, b"Erreur simulee"
        return 0, b"Ok."


def test_build_commands_exact():
    c = nc.build_commands(nc.NetPlan(12, "x", "192.168.1.50", 24, "192.168.1.1", ["172.168.4.245", "8.8.8.8"]))
    assert c[0] == ["netsh", "interface", "ipv4", "set", "address", "name=12", "source=static",
                    "address=192.168.1.50", "mask=255.255.255.0", "gateway=192.168.1.1", "gwmetric=1"]
    assert c[1][:6] == ["netsh", "interface", "ipv4", "set", "dnsservers", "name=12"] and "address=172.168.4.245" in c[1]
    assert c[2][3] == "add" and "index=2" in c[2] and "address=8.8.8.8" in c[2]
    assert all(isinstance(a, str) for cmd in c for a in cmd)


@pytest.mark.parametrize("kw,msg", [
    (dict(ip="192.168.1.0"), "réseau"), (dict(ip="192.168.1.255"), "diffusion"),
    (dict(gateway="10.0.0.1"), "sous-réseau"), (dict(gateway="192.168.1.50"), "passerelle ne peut pas"),
    (dict(ip="127.0.0.1", gateway=""), "non utilisable"), (dict(ip="169.254.1.1", gateway=""), "non utilisable"),
    (dict(ip="192.168.1.50; calc"), "invalide"), (dict(dns=["8.8.8.8; x"]), "DNS invalide"),
    (dict(adapter_index=0), "Index"), (dict(prefix=31), "Préfixe"), (dict(dns=["1.1.1.1"] * 5), "Au plus 4")])
def test_validation_rejects(tmp_path, kw, msg):
    errs = plan(tmp_path, **kw).validate()
    assert errs and any(msg in e for e in errs), errs
    with pytest.raises(ValueError):
        nc.build_commands(plan(tmp_path, **kw))


def test_no_gateway_and_no_dns_allowed(tmp_path):
    c = nc.build_commands(plan(tmp_path, gateway="", dns=[]))
    assert not any(a.startswith("gateway=") for a in c[0]) and c[1][-1] == "source=dhcp"


def test_plan_json_roundtrip(tmp_path):
    p = plan(tmp_path)
    assert nc.NetPlan.from_json(p.to_json()) == p


def test_apply_kept(tmp_path):
    r = FakeRunner()
    res = nc.apply_with_rollback(plan(tmp_path), r, lambda: (True, ["ok"]), lambda t, l: True, settle_s=0)
    assert res.status == "kept" and os.path.exists(tmp_path / "bk.txt")
    assert r.calls[0] == ["netsh", "interface", "dump"]                  # sauvegarde AVANT toute modification
    assert not any(c[:2] == ["netsh", "-f"] for c in r.calls)             # pas de restauration


def test_apply_rolled_back_when_user_declines(tmp_path):
    r = FakeRunner()
    res = nc.apply_with_rollback(plan(tmp_path), r, lambda: (True, []), lambda t, l: False, settle_s=0)
    assert res.status == "rolled_back" and r.calls[-1] == ["netsh", "-f", str(tmp_path / "bk.txt")]


def test_apply_rolled_back_when_command_fails(tmp_path):
    r = FakeRunner(fail_on="dnsservers")
    res = nc.apply_with_rollback(plan(tmp_path), r, settle_s=0)
    assert res.status == "rolled_back" and any("Commande en échec" in m for m in res.messages)


def test_backup_failure_prevents_any_change(tmp_path):
    r = FakeRunner(dump=b"")
    res = nc.apply_with_rollback(plan(tmp_path), r, settle_s=0)
    assert res.status == "failed" and len(r.calls) == 1                   # seule la tentative de sauvegarde


def test_failed_verification_still_asks_and_defaults_to_rollback(tmp_path):
    seen = []
    r = FakeRunner()
    res = nc.apply_with_rollback(plan(tmp_path), r, lambda: (False, ["pas d'Internet"]),
                                 lambda t, l: seen.append(l) or False, settle_s=0)
    assert res.status == "rolled_back" and seen == [["pas d'Internet"]]


def test_rollback_failure_is_reported_loudly(tmp_path):
    class R(FakeRunner):
        def __call__(self, cmd):
            if cmd[:2] == ["netsh", "-f"]:
                self.calls.append(cmd)
                return 1, b"x"
            return super().__call__(cmd)
    res = nc.apply_with_rollback(plan(tmp_path), R(), lambda: (True, []), lambda t, l: False, settle_s=0)
    assert res.status == "rollback_failed" and any("RESTAURATION ÉCHOUÉE" in m for m in res.messages)


# --- fenêtre élevée (Qt offscreen, exécuteur simulé) -----------------------------------
@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def run_dialog(app, p, runner, click=None):
    from gtc_ipm.ui.apply_dialog import ApplyDialog
    d = ApplyDialog(p, runner=runner, collectors=None, settle_s=0)
    d.show()
    d.start()
    t0 = time.time()
    while d.outcome is None:
        app.processEvents()
        if click and d.btn_keep.isEnabled():
            (d.btn_keep if click == "keep" else d.btn_undo).click()
            click = None
        time.sleep(0.01)
        assert time.time() - t0 < 20
    return d


def dispose(app, d):
    """Détruit la fenêtre dans l'ordre (avant QApplication), sinon plantage à la sortie du processus."""
    from PySide6.QtCore import QEvent
    d.close()
    d.worker.wait(30000)
    d.deleteLater()
    app.sendPostedEvents(None, QEvent.DeferredDelete)
    app.processEvents()


def test_dialog_keep_writes_result(app, tmp_path):
    d = run_dialog(app, plan(tmp_path), FakeRunner(), click="keep")
    assert d.outcome.status == "kept" and json.loads((tmp_path / "res.json").read_text("utf-8"))["status"] == "kept"
    dispose(app, d)


def test_dialog_timeout_rolls_back_automatically(app, tmp_path):
    r = FakeRunner()
    d = run_dialog(app, plan(tmp_path, confirm_timeout_s=2), r, click=None)   # personne ne clique
    assert d.outcome.status == "rolled_back" and r.calls[-1][:2] == ["netsh", "-f"]
    dispose(app, d)


def test_dialog_undo_button(app, tmp_path):
    d = run_dialog(app, plan(tmp_path), FakeRunner(), click="undo")
    assert d.outcome.status == "rolled_back"
    dispose(app, d)
