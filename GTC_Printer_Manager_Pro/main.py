"""Point d'entrée de GTC Printer Manager Pro."""
import json
import os
import sys
import traceback


def _selftest(out_path: str) -> int:
    """Démarrage non interactif : construit la fenêtre, parcourt les onglets, lit les imprimantes
    (lecture seule) et écrit un JSON de résultat. Utilisé par la CI sur l'EXE SANS Python."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    result = {"ok": False, "steps": []}
    try:
        from PySide6.QtWidgets import QApplication
        from gtc_prn.core.models import __version__
        from gtc_prn.discovery.inventory import collect_inventory
        from gtc_prn.ui.main_window import MainWindow, TAB_NAMES
        app = QApplication.instance() or QApplication(sys.argv)
        win = MainWindow(auto_detect=False)
        win.show()
        for i, name in enumerate(TAB_NAMES):
            win.tabs.setCurrentIndex(i)
            app.processEvents()
            result["steps"].append(f"onglet {name}")
        inv = collect_inventory()
        result["printers"] = [p.name for p in inv.printers]
        result["kinds"] = [p.kind for p in inv.printers]
        result["warnings"] = inv.warnings
        result["printbrm_available"] = inv.system.printbrm_available
        result["version"] = __version__
        result["tabs"] = win.tabs.count()
        result["ok"] = win.tabs.count() == len(TAB_NAMES)
        win.close()
    except Exception:  # noqa: BLE001
        result["error"] = traceback.format_exc()
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    return 0 if result["ok"] else 1


def _prn_job(job_path: str) -> int:
    """Mode helper (lancé avec élévation UAC) : exécute une sauvegarde/restauration avec une fenêtre de suivi."""
    from PySide6.QtCore import QEvent
    from PySide6.QtWidgets import QApplication
    from gtc_prn.backup.job import Job
    from gtc_prn.ui.job_dialog import JobDialog
    with open(job_path, encoding="utf-8") as f:
        job = Job.from_json(f.read())
    app = QApplication.instance() or QApplication(sys.argv)
    dlg = JobDialog(job)
    dlg.show()
    dlg.start()
    app.exec()
    ok = dlg.outcome is not None and dlg.outcome.ok
    dlg.worker.wait(30000)          # nettoyage ordonné : la fenêtre doit disparaître AVANT l'application Qt
    dlg.deleteLater()
    app.sendPostedEvents(None, QEvent.DeferredDelete)
    app.processEvents()
    return 0 if ok else 1


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == "--selftest":
        return _selftest(sys.argv[2])
    if len(sys.argv) >= 3 and sys.argv[1] == "--prn-job":
        return _prn_job(sys.argv[2])
    from PySide6.QtWidgets import QApplication, QMessageBox
    from gtc_prn.core.logging_setup import setup_logging
    from gtc_prn.ui.main_window import MainWindow
    log = setup_logging()

    def hook(et, ev, tb):
        log.error("Erreur non gérée", exc_info=(et, ev, tb))
        try:
            QMessageBox.critical(None, "Erreur inattendue", f"{et.__name__}: {ev}\n\nDétails : %APPDATA%\\GTC_Printer_Manager_Pro\\logs")
        except Exception:  # noqa: BLE001
            pass
    sys.excepthook = hook
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
