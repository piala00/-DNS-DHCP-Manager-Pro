from __future__ import annotations

import logging
import threading
import traceback

from PySide6.QtCore import QThread, Signal

from ..core import orchestrator as orch
from ..core import internet as inet
from ..core.verify import verify_ip

_log = logging.getLogger("gtc_ipm")


class AnalysisWorker(QThread):
    progress = Signal(int, str)
    log_line = Signal(str)
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, options, collectors, parent=None):
        super().__init__(parent)
        self.options, self.collectors = options, collectors
        self.cancel_event = threading.Event()

    def cancel(self) -> None:
        self.cancel_event.set()

    def run(self) -> None:
        try:
            snap = orch.run_analysis(self.options, self.collectors, self.cancel_event,
                                     self.progress.emit, self.log_line.emit)
            self.done.emit(snap)
        except Exception as e:  # noqa: BLE001
            _log.error("Analyse en échec\n%s", traceback.format_exc())
            self.failed.emit(f"{type(e).__name__}: {e}")


class DetectWorker(QThread):
    done = Signal(object, object, str)

    def __init__(self, collectors, parent=None):
        super().__init__(parent)
        self.collectors = collectors

    def run(self) -> None:
        try:
            ifs, routes = orch.discover_local(self.collectors)
            self.done.emit(ifs, routes, "")
        except Exception as e:  # noqa: BLE001
            self.done.emit([], [], str(e))


class VerifyWorker(QThread):
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, ip, collectors, timeout_ms, status="", why="", parent=None):
        super().__init__(parent)
        self.args = (ip, collectors, timeout_ms, status, why)

    def run(self) -> None:
        try:
            ip, col, t, st, why = self.args
            self.done.emit(verify_ip(ip, col, t, st, why))
        except Exception as e:  # noqa: BLE001
            self.failed.emit(f"{type(e).__name__}: {e}")


class ConnectivityWorker(QThread):
    done = Signal(str)

    def __init__(self, collectors, domain_name="", dc_ips=None, parent=None):
        super().__init__(parent)
        self.collectors, self.domain_name, self.dc_ips = collectors, domain_name, dc_ips or []

    def run(self) -> None:
        try:
            itfs = self.collectors.interfaces()  # relu à chaque test : reflète la configuration actuelle
            lines = inet.connectivity_report(itfs, self.domain_name, self.dc_ips, self.collectors.tcp_from,
                                             inet.dns_lookup, self.collectors.ping)
            self.done.emit("\n".join(lines))
        except Exception as e:  # noqa: BLE001
            self.done.emit(f"Test impossible : {type(e).__name__}: {e}")
