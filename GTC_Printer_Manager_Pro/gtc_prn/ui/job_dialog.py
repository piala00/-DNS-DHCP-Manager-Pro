"""Fenêtre d'exécution d'un travail (processus normal ou processus élevé par UAC)."""
from __future__ import annotations

from typing import Callable

from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout

from ..backup.engine import JobResult
from ..backup.job import Job, execute_job
from .worker import JobWorker

MARK = {"OK": "[OK]", "ATTENTION": "[ATTENTION]", "ECHEC": "[ÉCHEC]"}


def format_result(res: JobResult) -> str:
    head = "TERMINÉ SANS ÉCHEC" if res.ok else "TERMINÉ AVEC DES ÉCHECS (voir ci-dessous)"
    lines = [head] + [f"{MARK.get(i.status, i.status)} {i.label} — {i.detail}" for i in res.items]
    if res.path:
        lines.append(f"\nEmplacement : {res.path}")
    return "\n".join(lines)


class JobDialog(QDialog):
    def __init__(self, job: Job, executor: Callable = execute_job, parent=None):
        super().__init__(parent)
        self.job, self.outcome = job, None
        self.setWindowTitle("Sauvegarde des imprimantes" if job.action == "backup" else "Restauration des imprimantes")
        self.resize(720, 460)
        lay = QVBoxLayout(self)
        self.status = QLabel("Travail en cours… ne fermez pas cette fenêtre.")
        lay.addWidget(self.status)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        lay.addWidget(self.log, 1)
        row = QHBoxLayout()
        row.addStretch(1)
        self.btn_close = QPushButton("Fermer")
        self.btn_close.setEnabled(False)
        self.btn_close.clicked.connect(self.accept)
        row.addWidget(self.btn_close)
        lay.addLayout(row)
        self.worker = JobWorker(job, executor, self)
        self.worker.say.connect(self.log.appendPlainText)
        self.worker.finished_result.connect(self._on_done)

    def start(self) -> None:
        self.worker.start()

    def _on_done(self, res: JobResult) -> None:
        self.outcome = res
        self.status.setText("Terminé." if res.ok else "Terminé avec des échecs.")
        self.log.appendPlainText("\n" + format_result(res))
        self.btn_close.setEnabled(True)
        if self.job.result_path:
            try:
                with open(self.job.result_path, "w", encoding="utf-8") as f:
                    f.write(res.to_json())
            except OSError:
                pass

    def closeEvent(self, e) -> None:
        if self.worker.isRunning():
            e.ignore()          # on ne coupe jamais un travail en cours (restauration à moitié faite)
            return
        super().closeEvent(e)
