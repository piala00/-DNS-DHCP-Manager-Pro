from __future__ import annotations

import logging
import logging.handlers

from .settings import app_dir


def setup_logging() -> logging.Logger:
    log = logging.getLogger("gtc_prn")
    if log.handlers:
        return log
    log.setLevel(logging.INFO)
    try:
        d = app_dir() / "logs"
        d.mkdir(parents=True, exist_ok=True)
        h = logging.handlers.RotatingFileHandler(d / "app.log", maxBytes=500_000, backupCount=3,
                                                 encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(h)
    except OSError:
        log.addHandler(logging.NullHandler())
    return log
