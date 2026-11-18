"""Fenêtre principale (français). Aucune modification du système sans confirmation explicite."""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Callable, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QLabel,
                               QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox, QPlainTextEdit,
                               QPushButton, QRadioButton, QTabWidget, QTableView, QVBoxLayout, QWidget)

from ..backup import engine
from ..backup.job import Job, execute_job, is_admin, launch_elevated
from ..core.models import Inventory, __version__
from ..core.settings import app_dir
from ..discovery.inventory import Collectors
from .job_dialog import JobDialog, format_result
from .tables import FilterProxy, TableModel
from .theme import STYLE
from .worker import InventoryWorker, ResultWaiter

_log = logging.getLogger("gtc_prn")
TAB_NAMES = ["Accueil", "Imprimantes", "Sauvegarde", "Restauration"]


def _table(model: TableModel):
    proxy = FilterProxy()
    proxy.setSourceModel(model)
    view = QTableView()
    view.setModel(proxy)
    view.setSortingEnabled(True)
    view.setAlternatingRowColors(True)
    view.setSelectionBehavior(QAbstractItemView.SelectRows)
    view.setEditTriggers(QAbstractItemView.NoEditTriggers)
    view.horizontalHeader().setStretchLastSection(True)
    view.verticalHeader().setVisible(False)
    return view, proxy


class MainWindow(QMainWindow):
    def __init__(self, collectors: Optional[Collectors] = None, auto_detect: bool = True, settings=None):
        super().__init__()
        self.collectors = collectors or Collectors()
        self.inventory: Optional[Inventory] = None
        self.backup_set: Optional[engine.BackupSet] = None
        self.worker: Optional[InventoryWorker] = None
        self.waiter: Optional[ResultWaiter] = None
        self.job_dialog: Optional[JobDialog] = None
        self.job_executor: Callable = execute_job          # remplaçable (tests)
        self._launch = launch_elevated                     # remplaçable (tests)
        self._admin = is_admin                             # remplaçable (tests)
        self._confirm: Callable[[str], bool] = self._ask_confirm
        self.setWindowTitle(f"GTC Printer Manager Pro {__version__}")
        self.resize(1180, 760)
        self.setStyleSheet(STYLE)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self._build_home()
        self._build_printers()
        self._build_backup()
        self._build_restore()
        self._refresh_enabled()
        self.statusBar().showMessage("Prêt. Lancez « Analyser les imprimantes ».")
        if auto_detect:
            self.analyze()

    # ------------------------------------------------------------------ Accueil
    def _build_home(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.addWidget(self._note("Détecte les imprimantes de ce poste, sauvegarde leurs pilotes et paramètres, et les "
                                 "restaure sur un autre poste. L'analyse est en lecture seule."))
        grid = QGridLayout()
        self.kpis: dict[str, QLabel] = {}
        titles = ["Imprimantes", "Virtuelles (PDF / fichier)", "Réseau (TCP/IP)", "Port propre à un programme",
                  "Pilotes exportables", "Windows", "Architecture", "Droits administrateur"]
        for n, t in enumerate(titles):
            card = QFrame()
            card.setObjectName("card")
            v = QVBoxLayout(card)
            val = QLabel("—")
            val.setObjectName("kpiValue")
            val.setWordWrap(True)
            title = QLabel(t)
            title.setObjectName("kpiTitle")
            v.addWidget(val)
            v.addWidget(title)
            grid.addWidget(card, n // 4, n % 4)
            self.kpis[t] = val
        lay.addLayout(grid)
        row = QHBoxLayout()
        self.btn_analyze = QPushButton("Analyser les imprimantes")
        self.btn_analyze.setObjectName("primary")
        self.btn_analyze.clicked.connect(self.analyze)
        row.addWidget(self.btn_analyze)
        row.addStretch(1)
        lay.addLayout(row)
        self.warn_box = QPlainTextEdit()
        self.warn_box.setReadOnly(True)
        self.warn_box.setPlaceholderText("Les avertissements de l'analyse apparaîtront ici.")
        lay.addWidget(self.warn_box, 1)
        self.tabs.addTab(w, TAB_NAMES[0])

    # ------------------------------------------------------------------ Imprimantes
    def _build_printers(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filtrer (nom, pilote, port, type, programme…)")
        lay.addWidget(self.filter_edit)
        self.model = TableModel(["Nom", "Type", "Pilote", "Fabricant", "Port", "Pilote exportable", "Programme probable"])
        self.view, self.proxy = _table(self.model)
        self.filter_edit.textChanged.connect(self.proxy.setFilterFixedString)
        self.view.selectionModel().selectionChanged.connect(self._show_detail)
        lay.addWidget(self.view, 3)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("Sélectionnez une imprimante pour voir le détail et le conseil de transfert.")
        lay.addWidget(self.detail, 2)
        self.tabs.addTab(w, TAB_NAMES[1])

    def _selected_printer(self):
        idx = self.view.currentIndex()
        if not idx.isValid() or self.inventory is None:
            return None
        return self.model.objs[self.proxy.mapToSource(idx).row()]

    def _show_detail(self, *_a) -> None:
        p = self._selected_printer()
        if not p or not self.inventory:
            self.detail.clear()
            return
        drv, port = self.inventory.driver_of(p), self.inventory.port_of(p)
        lines = [f"Imprimante : {p.name}" + ("  (par défaut)" if p.is_default else ""), f"Type : {p.kind}",
                 f"Pilote : {p.driver}" + (f"  — fabricant {drv.manufacturer}" if drv and drv.manufacturer else ""),
                 f"Port : {p.port}" + (f"  — moniteur « {port.monitor} »" if port else "")]
        if port and port.host_address:
            lines.append(f"Adresse : {port.host_address}:{port.port_number}")
        if drv:
            lines.append("Paquet de pilote : " + (drv.package_dir if drv.exportable else
                         ("intégré à Windows (rien à copier)" if drv.microsoft_inbox else "non exportable (pilote sans INF)")))
        lines.append("Programme probable : " + (", ".join(p.probable_programs) or "aucun détecté"))
        lines += ["", "Conseil : " + p.advice]
        self.detail.setPlainText("\n".join(lines))

    # ------------------------------------------------------------------ Sauvegarde
    def _build_backup(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.addWidget(self._note("Cochez les imprimantes dont vous voulez sauvegarder le pilote et les paramètres. "
                                 "La sauvegarde complète Windows (PrintBrm) exige les droits administrateur."))
        self.pick_list = QListWidget()
        lay.addWidget(self.pick_list, 2)
        self.chk_printbrm = QCheckBox("Sauvegarde complète Windows de TOUTES les imprimantes (PrintBrm, administrateur)")
        self.chk_zip = QCheckBox("Créer aussi un fichier ZIP unique (pratique pour copier sur une clé USB)")
        self.chk_zip.setChecked(True)
        lay.addWidget(self.chk_printbrm)
        lay.addWidget(self.chk_zip)
        row = QHBoxLayout()
        self.dest_edit = QLineEdit(str(Path.home() / "Documents"))
        btn_browse = QPushButton("Parcourir…")
        btn_browse.clicked.connect(self._browse_dest)
        row.addWidget(QLabel("Enregistrer dans :"))
        row.addWidget(self.dest_edit, 1)
        row.addWidget(btn_browse)
        lay.addLayout(row)
        self.btn_backup = QPushButton("Créer la sauvegarde")
        self.btn_backup.setObjectName("primary")
        self.btn_backup.clicked.connect(self.start_backup)
        lay.addWidget(self.btn_backup)
        self.backup_out = QPlainTextEdit()
        self.backup_out.setReadOnly(True)
        lay.addWidget(self.backup_out, 2)
        self.tabs.addTab(w, TAB_NAMES[2])

    def _browse_dest(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Dossier de destination", self.dest_edit.text())
        if d:
            self.dest_edit.setText(d)

    def checked_printers(self) -> list[str]:
        return [self.pick_list.item(i).data(Qt.UserRole) for i in range(self.pick_list.count())
                if self.pick_list.item(i).checkState() == Qt.Checked]

    def start_backup(self) -> None:
        host = (self.inventory.system.hostname if self.inventory else "") or "POSTE"
        dest = Path(self.dest_edit.text().strip() or ".") / f"GTC_Imprimantes_{engine.slug(host)}_{time.strftime('%Y%m%d_%H%M%S')}"
        job = Job("backup", dest_dir=str(dest), printbrm=self.chk_printbrm.isChecked(),
                  selected_printers=self.checked_printers(), make_zip=self.chk_zip.isChecked())
        errs = job.validate()
        if errs:
            self.backup_out.setPlainText("Impossible : " + " ".join(errs))
            return
        self._run_job(job, self.backup_out)

    # ------------------------------------------------------------------ Restauration
    def _build_restore(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.addWidget(self._note("Sur le poste où vous voulez retrouver les imprimantes : chargez une sauvegarde, "
                                 "vérifiez le tableau (aucune modification à ce stade), puis restaurez."))
        row = QHBoxLayout()
        b1, b2 = QPushButton("Ouvrir un dossier de sauvegarde…"), QPushButton("Ouvrir un fichier ZIP…")
        b1.clicked.connect(self._open_backup_dir)
        b2.clicked.connect(self._open_backup_zip)
        row.addWidget(b1)
        row.addWidget(b2)
        row.addStretch(1)
        lay.addLayout(row)
        self.restore_info = QLabel("Aucune sauvegarde chargée.")
        self.restore_info.setWordWrap(True)
        lay.addWidget(self.restore_info)
        self.restore_model = TableModel(["Imprimante", "Type", "Pilote", "État sur ce poste", "Détail"], status_col=3)
        self.restore_view, _p = _table(self.restore_model)
        self.restore_view.setSelectionMode(QAbstractItemView.ExtendedSelection)
        lay.addWidget(self.restore_view, 3)
        self.rb_selective = QRadioButton("Restaurer les imprimantes sélectionnées dans le tableau (pilote + port + file)")
        self.rb_printbrm = QRadioButton("Restauration complète Windows (PrintBrm) : TOUTES les imprimantes de la sauvegarde")
        self.rb_selective.setChecked(True)
        lay.addWidget(self.rb_selective)
        lay.addWidget(self.rb_printbrm)
        self.btn_restore = QPushButton("Restaurer…")
        self.btn_restore.setObjectName("primary")
        self.btn_restore.clicked.connect(self.start_restore)
        lay.addWidget(self.btn_restore)
        self.restore_out = QPlainTextEdit()
        self.restore_out.setReadOnly(True)
        lay.addWidget(self.restore_out, 2)
        self.tabs.addTab(w, TAB_NAMES[3])

    def _open_backup_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Dossier de sauvegarde")
        if d:
            self.load_backup(d)

    def _open_backup_zip(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, "Fichier de sauvegarde", "", "Sauvegarde (*.zip)")
        if f:
            self.load_backup(f)

    def load_backup(self, path: str) -> None:
        try:
            self.backup_set = engine.load_backup(path, work_dir=str(app_dir() / "restore_tmp" / time.strftime("%H%M%S")))
        except (ValueError, OSError, KeyError) as e:
            self.backup_set = None
            self.restore_model.set_rows([])
            self.restore_info.setText(f"Sauvegarde illisible : {e}")
            self._refresh_enabled()
            return
        self._show_restore_plan()
        self._refresh_enabled()

    def _show_restore_plan(self) -> None:
        bs = self.backup_set
        if not bs:
            return
        if self.inventory is None:
            self.restore_info.setText("Analysez d'abord ce poste (onglet Accueil) pour comparer avec la sauvegarde.")
            self.restore_model.set_rows([])
            return
        msgs = engine.compatibility(bs.inventory, self.inventory)
        s = bs.inventory.system
        self.restore_info.setText(f"Sauvegarde de {s.hostname} ({s.os_caption}, {s.arch}), "
                                  f"{'avec' if bs.has_printbrm else 'sans'} sauvegarde complète PrintBrm. "
                                  + " ".join(msgs))
        rows = engine.plan_restore(bs, self.inventory)
        self.restore_model.set_rows([[r.name, r.kind, r.driver, r.status, r.note] for r in rows], rows)
        self.rb_printbrm.setEnabled(bs.has_printbrm)
        if not bs.has_printbrm and self.rb_printbrm.isChecked():
            self.rb_selective.setChecked(True)

    def selected_restore_names(self) -> list[str]:
        names = []
        for idx in self.restore_view.selectionModel().selectedRows():
            row = self.restore_view.model().mapToSource(idx).row()
            names.append(self.restore_model.rows[row][0])
        return names

    def start_restore(self) -> None:
        if not self.backup_set:
            return
        method = "printbrm" if self.rb_printbrm.isChecked() else "selective"
        names = self.selected_restore_names() if method == "selective" else []
        job = Job("restore", source=self.backup_set.source, method=method, selected_printers=names)
        errs = job.validate()
        if errs:
            self.restore_out.setPlainText("Impossible : " + " ".join(errs))
            return
        blocked = [r for r in self.restore_model.objs if r.name in names and r.status in (engine.INCOMPATIBLE,)]
        if blocked:
            self.restore_out.setPlainText("Impossible : architecture incompatible avec ce poste.")
            return
        what = ("TOUTES les imprimantes de la sauvegarde (restauration Windows complète)" if method == "printbrm"
                else "Imprimantes : " + ", ".join(names))
        if not self._confirm(f"Cette action MODIFIE les imprimantes de ce poste.\n\n{what}\n\n"
                             "Les imprimantes déjà présentes ne sont pas remplacées (méthode sélective). "
                             "Windows demandera l'autorisation administrateur."):
            self.restore_out.setPlainText("Restauration annulée.")
            return
        self._run_job(job, self.restore_out)

    # ------------------------------------------------------------------ Travaux
    def _ask_confirm(self, text: str) -> bool:
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("Confirmer")
        box.setText(text)
        yes = box.addButton("Continuer", QMessageBox.AcceptRole)
        no = box.addButton("Annuler", QMessageBox.RejectRole)
        box.setDefaultButton(no)
        box.exec()
        return box.clickedButton() is yes

    def _run_job(self, job: Job, out: QPlainTextEdit) -> None:
        if job.needs_admin() and not self._admin():
            d = app_dir() / "jobs"
            d.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d_%H%M%S")
            job.result_path = str(d / f"resultat_{stamp}.json")
            jf = d / f"travail_{stamp}.json"
            jf.write_text(job.to_json(), encoding="utf-8")
            try:
                self._launch(["--prn-job", str(jf)])
            except OSError as e:
                out.setPlainText(f"Non lancé : {e}")
                return
            out.setPlainText("Travail en cours dans la fenêtre administrateur… (autorisez la demande Windows).")
            self.waiter = ResultWaiter(job.result_path, 3600, self)
            self.waiter.done.connect(lambda text, o=out: self._job_finished(text, o))
            self.waiter.start()
            return
        out.setPlainText("Travail en cours…")
        dlg = JobDialog(job, self.job_executor, self)
        self.job_dialog = dlg                           # fenêtre non bloquante : elle reste ouverte pour lire le journal
        dlg.worker.finished_result.connect(lambda res, o=out: self._job_finished(res.to_json(), o))
        dlg.show()
        dlg.start()

    def _job_finished(self, text: str, out: QPlainTextEdit) -> None:
        if not text:
            out.setPlainText("Aucun résultat reçu (autorisation administrateur refusée ou fenêtre fermée).")
            return
        res = engine.JobResult.from_json(text)
        out.setPlainText(format_result(res))
        self.statusBar().showMessage("Travail terminé." if res.ok else "Travail terminé avec des échecs.")
        self.analyze()

    # ------------------------------------------------------------------ Analyse
    def analyze(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        self.statusBar().showMessage("Analyse en cours…")
        self.btn_analyze.setEnabled(False)
        self.worker = InventoryWorker(self.collectors, self)
        self.worker.done.connect(self._on_inventory)
        self.worker.failed.connect(self._on_failed)
        self.worker.start()

    def _on_failed(self, msg: str) -> None:
        self.warn_box.setPlainText(f"Analyse impossible : {msg}")
        self.statusBar().showMessage("Analyse en échec.")
        self._refresh_enabled()

    def _on_inventory(self, inv: Inventory) -> None:
        self.inventory = inv
        s = inv.system
        k = self.kpis
        k["Imprimantes"].setText(str(len(inv.printers)))
        k["Virtuelles (PDF / fichier)"].setText(str(sum(p.kind.startswith("Virtuelle") for p in inv.printers)))
        k["Réseau (TCP/IP)"].setText(str(sum(p.kind.startswith("Réseau") for p in inv.printers)))
        k["Port propre à un programme"].setText(str(sum(p.port_class == "specifique" for p in inv.printers)))
        k["Pilotes exportables"].setText(str(sum(d.exportable for d in inv.drivers)))
        k["Windows"].setText(f"{s.os_caption} {s.os_build}".strip() or "—")
        k["Architecture"].setText(s.arch or "—")
        k["Droits administrateur"].setText("OUI" if s.is_admin else "NON (demandés au besoin)")
        warns = list(inv.warnings)
        if s.spooler_running is False:
            warns.append("Le service « Spouleur d'impression » n'est pas démarré : les imprimantes ne fonctionneront pas.")
        if not s.printbrm_available and s.collected_at:
            warns.append("PrintBrm.exe est absent de ce Windows : seule la méthode sélective est disponible.")
        self.warn_box.setPlainText("\n".join(warns))
        rows = [[p.name + (" (par défaut)" if p.is_default else ""), p.kind, p.driver, p.manufacturer, p.port,
                 ("oui" if (d := inv.driver_of(p)) and d.exportable else
                  "intégré à Windows" if d and d.microsoft_inbox else "non"),
                 ", ".join(p.probable_programs)] for p in inv.printers]
        self.model.set_rows(rows, list(inv.printers))
        self.pick_list.clear()
        for p in inv.printers:
            it = QListWidgetItem(f"{p.name}   —   {p.kind}")
            it.setData(Qt.UserRole, p.name)
            it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            it.setCheckState(Qt.Unchecked)
            self.pick_list.addItem(it)
        if self.backup_set:
            self._show_restore_plan()
        self.statusBar().showMessage(f"{len(inv.printers)} imprimante(s) détectée(s).")
        self._refresh_enabled()

    def _refresh_enabled(self) -> None:
        running = bool(self.worker and self.worker.isRunning())
        has = self.inventory is not None and bool(self.inventory.printers)
        self.btn_analyze.setEnabled(not running)
        self.btn_backup.setEnabled(has and not running)
        self.btn_backup.setToolTip("" if has else "Lancez d'abord l'analyse : aucune imprimante connue.")
        self.btn_restore.setEnabled(self.backup_set is not None and self.inventory is not None and not running)

    @staticmethod
    def _note(text: str) -> QLabel:
        lb = QLabel(text)
        lb.setObjectName("note")
        lb.setWordWrap(True)
        return lb

    def closeEvent(self, e) -> None:
        if self.job_dialog and self.job_dialog.worker.isRunning():
            self.job_dialog.worker.wait(60000)
        for wk in (self.worker, self.waiter):
            if wk and wk.isRunning():
                if hasattr(wk, "cancel"):
                    wk.cancel()
                wk.wait(8000)
        super().closeEvent(e)
