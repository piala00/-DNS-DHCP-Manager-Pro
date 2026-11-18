"""Threads de travail (aucun appel Windows dans le thread de l'interface)."""
from __future__ import annotations

import os
import threading
import time
from typing import Callable

from PySide6.QtCore import QThread, Signal

from ..backup.job import Job, execute_job
from ..discovery.inventory import Collectors, collect_inventory


class InventoryWorker(QThread):
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, collectors: Collectors, parent=None):
        super().__init__(parent)
        self.collectors = collectors

    def run(self) -> None:
        try:
            self.done.emit(collect_inventory(self.collectors))
        except Exception as e:  # noqa: BLE001
            self.failed.emit(f"{type(e).__name__}: {e}")


class JobWorker(QThread):
    say = Signal(str)
    finished_result = Signal(object)

    def __init__(self, job: Job, executor: Callable = execute_job, parent=None):
        super().__init__(parent)
        self.job, self.executor = job, executor

    def run(self) -> None:
        from ..backup import engine
        try:
            res = self.executor(self.job, self.say.emit)
        except Exception as e:  # noqa: BLE001
            res = engine.JobResult(action=self.job.action)
            res.add("Travail", "ECHEC", f"{type(e).__name__}: {e}")
        self.finished_result.emit(res)


class ResultWaiter(QThread):
    """Attend le fichier de résultat écrit par le processus élevé."""
    done = Signal(str)

    def __init__(self, path: str, timeout_s: int = 3600, parent=None):
        super().__init__(parent)
        self.path, self.timeout_s = path, timeout_s
        self._stop = threading.Event()

    def cancel(self) -> None:
        self._stop.set()

    def run(self) -> None:
        t0 = time.time()
        while time.time() - t0 < self.timeout_s and not self._stop.is_set():
            if os.path.exists(self.path):
                time.sleep(0.4)
                try:
                    with open(self.path, encoding="utf-8") as f:
                        self.done.emit(f.read())
                    return
                except OSError:
                    pass
            self._stop.wait(0.5)
        if not self._stop.is_set():
            self.done.emit("")
