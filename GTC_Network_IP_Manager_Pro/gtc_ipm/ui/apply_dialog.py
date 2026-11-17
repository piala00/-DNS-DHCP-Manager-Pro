"""Fenêtre d'application de la configuration statique (processus ÉLEVÉ).

Affiche chaque étape, vérifie la connectivité, puis demande confirmation avec un compte à
rebours : sans confirmation, l'ancienne configuration est restaurée automatiquement.
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QThread, QTimer, Signal
from PySide6.QtWidgets import (QDialog, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout)

from ..core import internet as inet
from ..core import netconfig as nc


class _Worker(QThread):
    say = Signal(str)
    ask = Signal(int, str)          # délai, résumé de vérification
    finished_result = Signal(object)

    def __init__(self, plan, runner, verify, settle_s):
        super().__init__()
        self.plan, self.runner, self.verify, self.settle_s = plan, runner, verify, settle_s
        self._answer = threading.Event()
        self._keep = False

    def answer(self, keep: bool) -> None:
        self._keep = keep
        self._answer.set()

    def _confirm(self, timeout: int, lines: list[str]) -> bool:
        self.ask.emit(timeout, "\n".join(lines))
        self._answer.wait(timeout + 5)
        return self._keep and self._answer.is_set()

    def run(self) -> None:
        try:
            res = nc.apply_with_rollback(self.plan, self.runner, self.verify, self._confirm,
                                         self.say.emit, self.settle_s)
        except Exception as e:  # noqa: BLE001
            res = nc.ApplyResult("failed", [f"{type(e).__name__}: {e}"])
        self.finished_result.emit(res)


class ApplyDialog(QDialog):
    def __init__(self, plan: nc.NetPlan, runner: Callable = nc.default_runner,
                 collectors=None, settle_s: float = 4.0, parent=None):
        super().__init__(parent)
        self.plan, self.result = plan, None
        self.setWindowTitle("Application de la configuration réseau")
        self.resize(640, 460)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"<b>Carte :</b> {plan.adapter_label}<br><b>Nouvelle configuration :</b> "
                             f"{plan.ip}/{plan.prefix}, passerelle {plan.gateway or 'aucune'}, "
                             f"DNS {', '.join(plan.dns) or 'automatique'}"))
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        lay.addWidget(self.log, 1)
        self.countdown = QLabel("")
        lay.addWidget(self.countdown)
        row = QHBoxLayout()
        self.btn_keep = QPushButton("Conserver cette configuration")
        self.btn_undo = QPushButton("Annuler (revenir en arrière)")
        self.btn_close = QPushButton("Fermer")
        self.btn_keep.setEnabled(False)
        self.btn_undo.setEnabled(False)
        self.btn_close.setEnabled(False)
        for b in (self.btn_keep, self.btn_undo, self.btn_close):
            row.addWidget(b)
        lay.addLayout(row)
        self.btn_keep.clicked.connect(lambda: self._decide(True))
        self.btn_undo.clicked.connect(lambda: self._decide(False))
        self.btn_close.clicked.connect(self.accept)
        self._left = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        verify = self._make_verify(collectors)
        self.worker = _Worker(plan, runner, verify, settle_s)
        self.worker.say.connect(self.log.appendPlainText)
        self.worker.ask.connect(self._on_ask)
        self.worker.finished_result.connect(self._on_done)

    def start(self) -> None:
        self.worker.start()

    def _make_verify(self, collectors):
        plan = self.plan

        def verify():
            if collectors is None:
                return True, ["(vérification non disponible)"]
            itfs = collectors.interfaces()
            lines: list[str] = []
            ok = True
            me = next((i for i in itfs if i.ipv4 == plan.ip), None)
            if me is None:
                return False, [f"La carte n'a pas pris l'adresse {plan.ip}."]
            lines.append(f"Adresse {plan.ip}/{plan.prefix} active sur « {me.alias} ».")
            for h in plan.check_hosts:               # contrôleur(s) de domaine : au moins un doit répondre
                up = collectors.ping(h, 1500) or collectors.tcp_from(plan.ip, h, 389, 3.0) \
                    or collectors.tcp_from(plan.ip, h, 53, 3.0)
                lines.append(f"Contrôleur de domaine {h} : " + ("joignable." if up else "NON joignable."))
                ok = ok and up if len(plan.check_hosts) == 1 else ok
            if len(plan.check_hosts) > 1:
                ok = any("joignable." in x and "NON" not in x for x in lines)
            if plan.gateway:
                paths = inet.detect_internet_paths([me], collectors.tcp_from)
                net_ok = any(p.internet_ok for p in paths)
                lines.append("Internet : " + ("OK." if net_ok else "ÉCHEC (voir passerelle)."))
                if not plan.check_hosts:
                    ok = ok and net_ok
            return ok, lines
        return verify

    def _on_ask(self, timeout: int, summary: str) -> None:
        self.log.appendPlainText("\n--- Vérification ---\n" + summary)
        self._left = timeout
        self.btn_keep.setEnabled(True)
        self.btn_undo.setEnabled(True)
        self._tick()
        self.timer.start(1000)

    def _tick(self) -> None:
        self.countdown.setText(f"Sans confirmation, retour automatique à l'ancienne configuration dans {self._left} s.")
        if self._left <= 0:
            self._decide(False)
        self._left -= 1

    def _decide(self, keep: bool) -> None:
        self.timer.stop()
        self.btn_keep.setEnabled(False)
        self.btn_undo.setEnabled(False)
        self.worker.answer(keep)

    def _on_done(self, res) -> None:
        self.result = res
        self.timer.stop()
        label = {"kept": "Configuration conservée.", "rolled_back": "Ancienne configuration restaurée.",
                 "failed": "Échec : rien n'a été modifié ou tout a été annulé.",
                 "rollback_failed": "ATTENTION : la restauration a échoué."}.get(res.status, res.status)
        self.log.appendPlainText("\n" + label + "\n" + "\n".join(res.messages))
        self.countdown.setText(label)
        self.btn_close.setEnabled(True)
        if self.plan.result_path:
            import json
            from dataclasses import asdict
            try:
                Path(self.plan.result_path).write_text(json.dumps(asdict(res), ensure_ascii=False, indent=2),
                                                       encoding="utf-8")
            except OSError:
                pass

    def closeEvent(self, e) -> None:
        if self.worker.isRunning():
            self._decide(False)
            self.worker.wait(30000)
        super().closeEvent(e)
