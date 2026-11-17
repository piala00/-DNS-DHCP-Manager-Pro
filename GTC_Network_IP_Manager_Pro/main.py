"""Point d'entrée de GTC Network IP Manager Pro."""
import json
import os
import sys
import traceback


def _selftest(out_path: str) -> int:
    """Démarrage non interactif : construit la fenêtre, parcourt les onglets,
    lance une analyse sans réseau sélectionné, écrit un JSON de résultat."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    result = {"ok": False, "steps": []}
    try:
        from PySide6.QtWidgets import QApplication
        from gtc_ipm.core.models import __version__
        from gtc_ipm.core.settings import Settings
        from gtc_ipm.ui.main_window import MainWindow, TAB_NAMES
        app = QApplication.instance() or QApplication(sys.argv)
        win = MainWindow(settings=Settings(), auto_detect=False)
        win.show()
        for i, name in enumerate(TAB_NAMES):
            win.tabs.setCurrentIndex(i)
            app.processEvents()
            result["steps"].append(f"onglet {name}")
        __import__("openpyxl")  # présent dans l'exécutable ?
        result["version"] = __version__
        result["tabs"] = win.tabs.count()
        result["ok"] = win.tabs.count() == len(TAB_NAMES)
        win.close()
    except Exception:  # noqa: BLE001
        result["error"] = traceback.format_exc()
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    return 0 if result["ok"] else 1


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == "--selftest":
        return _selftest(sys.argv[2])
    from PySide6.QtWidgets import QApplication, QMessageBox
    from gtc_ipm.core.logging_setup import setup_logging
    from gtc_ipm.ui.main_window import MainWindow
    log = setup_logging()
    app = QApplication(sys.argv)
    app.setApplicationName("GTC Network IP Manager Pro")

    def hook(et, ev, tb):
        log.error("Exception non gérée\n%s", "".join(traceback.format_exception(et, ev, tb)))
        QMessageBox.critical(None, "Erreur inattendue",
                             f"{et.__name__}: {ev}\n\nLe détail est dans le journal (%APPDATA%\\GTC_Network_IP_Manager_Pro\\logs).")
    sys.excepthook = hook
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
