"""Fenêtre principale (PySide6). Toutes les opérations réseau tournent dans des
threads ; l'interface ne se fige jamais."""
from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFileDialog, QFormLayout,
                               QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QMainWindow, QMessageBox, QPlainTextEdit,
                               QHeaderView, QProgressBar, QPushButton, QSpinBox, QSplitter, QTableView,
                               QTabWidget, QVBoxLayout, QWidget, QDialog)

from ..core import orchestrator as orch
from ..core.models import OCCUPEE, SRC_OK, ALL_STATUSES, Snapshot, __version__
from ..core.settings import Settings
from ..planning import planner as P
from ..reports import export as rx
from . import theme
from .tables import FilterProxy, TableModel
from .worker import AnalysisWorker, DetectWorker, VerifyWorker

_log = logging.getLogger("gtc_ipm")
TAB_NAMES = ["Accueil", "Machines du domaine", "Équipements du réseau", "Plan d'adressage",
             "Paramètres", "Rapports"]


def _table(model: TableModel, stretch: int = -1) -> tuple[QTableView, FilterProxy]:
    proxy = FilterProxy()
    proxy.setSourceModel(model)
    v = QTableView()
    v.setModel(proxy)
    v.setSortingEnabled(True)
    v.setAlternatingRowColors(True)
    v.setSelectionBehavior(QAbstractItemView.SelectRows)
    v.setSelectionMode(QAbstractItemView.SingleSelection)
    v.setEditTriggers(QAbstractItemView.NoEditTriggers)
    h = v.horizontalHeader()
    h.setSectionsMovable(True)
    h.setStretchLastSection(stretch < 0)
    h.setMinimumSectionSize(70)
    for i in range(len(model.headers)):
        h.setSectionResizeMode(i, QHeaderView.Stretch if i == stretch else QHeaderView.ResizeToContents)
    v.verticalHeader().setVisible(False)
    return v, proxy


def _kpi(title: str) -> tuple[QFrame, QLabel]:
    f = QFrame()
    f.setObjectName("card")
    lay = QVBoxLayout(f)
    t = QLabel(title)
    t.setObjectName("kpiTitle")
    v = QLabel("—")
    v.setObjectName("kpiValue")
    v.setWordWrap(True)
    v.setTextInteractionFlags(Qt.TextSelectableByMouse)
    lay.addWidget(t)
    lay.addWidget(v)
    f.setAccessibleName(title)
    return f, v


class ConfigSheetDialog(QDialog):
    def __init__(self, text: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Fiche de configuration du nouveau poste")
        self.resize(640, 480)
        lay = QVBoxLayout(self)
        self.edit = QPlainTextEdit(text)
        self.edit.setReadOnly(True)
        lay.addWidget(self.edit)
        row = QHBoxLayout()
        b1, b2, b3 = QPushButton("Copier"), QPushButton("Enregistrer en .txt…"), QPushButton("Fermer")
        b1.clicked.connect(lambda: QGuiApplication.clipboard().setText(text))
        b2.clicked.connect(self._save)
        b3.clicked.connect(self.accept)
        for b in (b1, b2, b3):
            row.addWidget(b)
        lay.addLayout(row)
        self.text = text

    def _save(self) -> None:
        p, _ = QFileDialog.getSaveFileName(self, "Enregistrer la fiche", "fiche_poste.txt", "Texte (*.txt)")
        if p:
            Path(p).write_text(self.text, encoding="utf-8")


class MainWindow(QMainWindow):
    def __init__(self, collectors: Optional[orch.Collectors] = None,
                 settings: Optional[Settings] = None, auto_detect: bool = True):
        super().__init__()
        self.collectors = collectors or orch.Collectors()
        self.settings = settings or Settings.load()
        self.snapshot: Optional[Snapshot] = None
        self.worker: Optional[AnalysisWorker] = None
        self.detector: Optional[DetectWorker] = None
        self.verifier: Optional[VerifyWorker] = None
        self.last_verify = None
        self.setWindowTitle(f"GTC Network IP Manager Pro {__version__}")
        self.resize(1250, 780)
        self.setStyleSheet(theme.STYLE)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self._build_home()
        self._build_ad()
        self._build_net()
        self._build_plan()
        self._build_settings()
        self._build_reports()
        self.statusBar().showMessage("Prêt. Lecture seule : aucune modification n'est faite sur votre réseau.")
        act = QAction("Analyser", self)
        act.setShortcut(QKeySequence("F5"))
        act.triggered.connect(self.start_analysis)
        self.addAction(act)
        self._refresh_enabled()
        if auto_detect:
            self.detect_networks()

    # ------------------------------------------------------------------ Accueil
    def _build_home(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        grid = QGridLayout()
        self.kpis: dict[str, QLabel] = {}
        titles = ["Domaine détecté", "Contrôleur(s) de domaine", "Serveur(s) DNS", "Serveur(s) DHCP",
                  "Sous-réseaux locaux", "Machines AD", "Machines AD actives", "IP occupées",
                  "Adresses candidates", "Conflits"]
        for i, t in enumerate(titles):
            f, v = _kpi(t)
            self.kpis[t] = v
            grid.addWidget(f, i // 5, i % 5)
        lay.addLayout(grid)

        box = QHBoxLayout()
        left = QVBoxLayout()
        left.addWidget(QLabel("<b>Réseaux à analyser</b> (seules les plages cochées sont sondées)"))
        self.net_list = QListWidget()
        self.net_list.setAccessibleName("Liste des réseaux à analyser")
        self.net_list.setMaximumHeight(130)
        self.net_list.itemChanged.connect(lambda *_: self._update_net_warnings())
        left.addWidget(self.net_list)
        add = QHBoxLayout()
        self.net_add = QLineEdit()
        self.net_add.setPlaceholderText("Ajouter un réseau CIDR, ex. 172.168.4.0/24")
        self.net_add.returnPressed.connect(self.add_network)
        b = QPushButton("Ajouter")
        b.clicked.connect(self.add_network)
        add.addWidget(self.net_add)
        add.addWidget(b)
        left.addLayout(add)
        self.net_warn = QLabel("")
        self.net_warn.setObjectName("warn")
        self.net_warn.setWordWrap(True)
        self.net_warn.setVisible(False)
        left.addWidget(self.net_warn)
        box.addLayout(left, 2)

        right = QVBoxLayout()
        self.btn_analyze = QPushButton("Analyser mon réseau")
        self.btn_analyze.setObjectName("primary")
        self.btn_analyze.clicked.connect(self.start_analysis)
        self.btn_cancel = QPushButton("Annuler")
        self.btn_cancel.clicked.connect(self.cancel_analysis)
        row = QHBoxLayout()
        row.addWidget(self.btn_analyze, 3)
        row.addWidget(self.btn_cancel, 1)
        right.addLayout(row)
        self.chk_ad = QCheckBox("Interroger l'annuaire Active Directory (lecture seule)")
        self.chk_dhcp = QCheckBox("Interroger le DHCP (lecture seule, droits requis)")
        self.chk_ad.setChecked(True)
        self.chk_dhcp.setChecked(True)
        right.addWidget(self.chk_ad)
        right.addWidget(self.chk_dhcp)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        right.addWidget(self.progress)
        self.progress_label = QLabel("Aucune analyse lancée.")
        self.progress_label.setObjectName("note")
        right.addWidget(self.progress_label)
        box.addLayout(right, 3)
        lay.addLayout(box)

        self.warn_box = QPlainTextEdit()
        self.warn_box.setReadOnly(True)
        self.warn_box.setMaximumHeight(90)
        self.warn_box.setPlaceholderText("Avertissements et limites de l'analyse apparaîtront ici.")
        lay.addWidget(self.warn_box)
        lay.addWidget(QLabel("<b>Journal</b>"))
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(5000)
        lay.addWidget(self.log_view, 1)
        self.tabs.addTab(w, TAB_NAMES[0])

    def detect_networks(self) -> None:
        self.detector = DetectWorker(self.collectors, self)
        self.detector.done.connect(self._on_detected)
        self.detector.start()

    def _on_detected(self, ifs, routes, err) -> None:
        self.net_list.blockSignals(True)
        self.net_list.clear()
        seen: set[str] = set()
        for i in ifs:
            n = orch.local_network_of(i)
            if str(n) in seen:
                continue
            seen.add(str(n))
            ok = n.num_addresses <= self.settings.max_hosts
            it = QListWidgetItem(f"{n}  — {i.alias} ({i.ipv4})" + ("" if ok else "  [trop grand : désactivé]"))
            it.setData(Qt.UserRole, str(n))
            it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            it.setCheckState(Qt.Checked if ok else Qt.Unchecked)
            self.net_list.addItem(it)
        for c in self.settings.extra_networks:
            self._add_item(c, checked=False)
        self.net_list.blockSignals(False)
        if err:
            self.progress_label.setText(f"Détection automatique indisponible : {err}. "
                                        "Vous pouvez ajouter les réseaux à la main.")
        elif not ifs:
            self.progress_label.setText("Aucune interface IPv4 valide détectée.")
        self._update_net_warnings()

    def _add_item(self, cidr: str, checked: bool) -> bool:
        try:
            n = ipaddress.ip_network(cidr.strip(), strict=False)
            if not isinstance(n, ipaddress.IPv4Network):
                raise ValueError("IPv4 uniquement")
        except ValueError as e:
            self.progress_label.setText(f"Réseau invalide « {cidr} » : {e}")
            return False
        for i in range(self.net_list.count()):
            if self.net_list.item(i).data(Qt.UserRole) == str(n):
                return False
        it = QListWidgetItem(f"{n}  — ajouté manuellement")
        it.setData(Qt.UserRole, str(n))
        it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
        it.setCheckState(Qt.Checked if checked else Qt.Unchecked)
        self.net_list.addItem(it)
        return True

    def add_network(self) -> None:
        text = self.net_add.text().strip()
        if text and self._add_item(text, checked=True):
            n = str(ipaddress.ip_network(text, strict=False))
            if n not in self.settings.extra_networks:
                self.settings.extra_networks.append(n)
                self.settings.save()
            self.net_add.clear()
        self._update_net_warnings()

    def checked_networks(self) -> list[str]:
        return [self.net_list.item(i).data(Qt.UserRole) for i in range(self.net_list.count())
                if self.net_list.item(i).checkState() == Qt.Checked]

    def _update_net_warnings(self) -> None:
        msgs = []
        for c in self.checked_networks():
            n = ipaddress.ip_network(c)
            w = P.rfc1918_warning(n)
            if w:
                msgs.append(w)
            if n.num_addresses > self.settings.max_hosts:
                msgs.append(f"{n} : {n.num_addresses} adresses, au-delà de la limite ({self.settings.max_hosts}) : "
                            "il sera ignoré tant que la limite n'est pas relevée dans Paramètres.")
            elif n.num_addresses > 512:
                msgs.append(f"{n} : grand réseau ({n.num_addresses} adresses), l'analyse sera plus longue.")
        self.net_warn.setText("\n".join(msgs))
        self.net_warn.setVisible(bool(msgs))

    # ------------------------------------------------------------ Analyse
    def start_analysis(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        self.settings = self._collect_settings(save=False) or self.settings
        opts = orch.Options(networks=self.checked_networks(), query_ad=self.chk_ad.isChecked(),
                            query_dhcp=self.chk_dhcp.isChecked(), settings=self.settings)
        self.log_view.clear()
        self.warn_box.clear()
        self.progress.setValue(0)
        self.worker = AnalysisWorker(opts, self.collectors, self)
        self.worker.progress.connect(self._on_progress)
        self.worker.log_line.connect(self.log_view.appendPlainText)
        self.worker.done.connect(self._on_done)
        self.worker.failed.connect(self._on_failed)
        self._refresh_enabled()
        self.worker.start()
        self._refresh_enabled()

    def cancel_analysis(self) -> None:
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.progress_label.setText("Annulation en cours…")
            self.btn_cancel.setEnabled(False)

    def _on_progress(self, pct: int, msg: str) -> None:
        self.progress.setValue(max(0, min(100, pct)))
        self.progress_label.setText(msg)

    def _on_failed(self, msg: str) -> None:
        self.progress_label.setText(f"L'analyse a échoué : {msg}")
        self.log_view.appendPlainText(f"ERREUR : {msg}")
        self._refresh_enabled()

    def _on_done(self, snap: Snapshot) -> None:
        self.snapshot = snap
        self.progress_label.setText("Analyse annulée (résultats partiels, plan non calculé)."
                                    if snap.cancelled else "Analyse terminée.")
        self.warn_box.setPlainText("\n".join(snap.warnings + [f"{s.name} : {s.state} — {s.detail}"
                                                              for s in snap.sources
                                                              if s.state not in (SRC_OK,) and s.detail]))
        self.populate(snap)
        self._refresh_enabled()
        self.statusBar().showMessage(f"Analyse du {snap.finished_at}")

    def _refresh_enabled(self) -> None:
        running = bool(self.worker and self.worker.isRunning())
        has = self.snapshot is not None
        has_plan = has and bool(self.snapshot.plan)
        self.btn_analyze.setEnabled(not running)
        self.btn_cancel.setEnabled(running)
        reason = "Lancez d'abord une analyse (« Analyser mon réseau »)."
        for b in (self.btn_csv, self.btn_xlsx, self.btn_diag):
            b.setEnabled(has and not running)
            b.setToolTip("" if has else reason)
        no_plan = "Aucun plan d'adressage : analyse non faite, annulée ou aucun réseau sélectionné."
        self.btn_verify.setEnabled(not running)
        self.btn_cfg.setEnabled(has_plan and bool(self.selected_candidate()))
        self.btn_cfg.setToolTip("" if has_plan else no_plan)

    # ------------------------------------------------------------ Population
    def populate(self, snap: Snapshot) -> None:
        k = self.kpis
        k["Domaine détecté"].setText(snap.domain.name if snap.domain.in_domain else "Hors domaine / non détecté")
        k["Contrôleur(s) de domaine"].setText(", ".join(snap.domain.dc_addresses) or "non identifié")
        dns = sorted({d for i in snap.interfaces for d in i.dns_servers})
        k["Serveur(s) DNS"].setText(", ".join(dns) or "—")
        dh = sorted({*snap.dhcp.servers, *(i.dhcp_server for i in snap.interfaces if i.dhcp_server)})
        k["Serveur(s) DHCP"].setText(", ".join(dh) or "—")
        k["Sous-réseaux locaux"].setText(", ".join(snap.local_networks) or "—")
        k["Machines AD"].setText(str(len(snap.ad_computers)) if snap.ad_computers else "non lu")
        active = sum(1 for c in snap.ad_computers if c.verification.startswith("Active"))
        k["Machines AD actives"].setText(str(active) if snap.ad_computers else "—")
        planned = bool(snap.plan)
        k["IP occupées"].setText(str(sum(1 for es in snap.plan.values() for e in es if e.status == OCCUPEE))
                                 if planned else "—")
        k["Adresses candidates"].setText(str(sum(len(c) for c in snap.candidates.values())) if planned else "—")
        k["Conflits"].setText(str(len(snap.conflicts)) if planned else "—")

        self.ad_model.set_rows(
            [[c.name, c.dns_hostname, {True: "oui", False: "non", None: "?"}[c.enabled], ", ".join(c.ipv4),
              c.dns_status, c.verification, c.last_logon[:10], c.os] for c in snap.ad_computers],
            list(snap.ad_computers))
        self.ad_count.setText(f"{len(snap.ad_computers)} ordinateur(s) AD" if snap.ad_computers
                              else "Aucune machine AD lue (voir Rapports > Sources pour la raison).")

        rows, objs = [], []
        for i in snap.interfaces:
            rows.append([i.ipv4, i.alias, i.mac, "Interface de ce poste", f"GW {i.gateway} / DNS {', '.join(i.dns_servers)}",
                         "—"])
            objs.append(i)
        for o in snap.observations:
            dom = {None: "inconnu", True: "oui", False: "non (hors domaine AD)"}[o.in_domain]
            rows.append([o.ip, o.hostname, o.mac, "Observé : " + ", ".join(o.methods), f"Domaine : {dom}",
                         o.observed_at])
            objs.append(o)
        self.net_model.set_rows(rows, objs)

        nets = list(snap.plan)
        self.plan_net.blockSignals(True)
        self.plan_net.clear()
        self.plan_net.addItems(nets)
        self.plan_net.blockSignals(False)
        self._fill_plan()

        self.src_model.set_rows(rx.tables(snap)["Sources"][1])

    def _fill_plan(self) -> None:
        snap = self.snapshot
        net = self.plan_net.currentText()
        if not snap or net not in snap.plan:
            self.plan_model.set_rows([], [])
            self.cand_model.set_rows([], [])
            return
        entries = snap.plan[net]
        self.plan_model.set_rows([[e.ip, e.status, e.hostname, e.mac, e.justification, e.checked_at]
                                  for e in entries], list(entries))
        cands = snap.candidates.get(net, [])
        self.cand_model.set_rows([[e.ip, e.status, "oui" if e.preferred else "", e.justification]
                                  for e in cands], list(cands))
        self._refresh_enabled()

    # ---------------------------------------------------------- Onglet AD
    def _build_ad(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        top = QHBoxLayout()
        self.ad_filter = QLineEdit()
        self.ad_filter.setPlaceholderText("Rechercher (nom, IP, état, système…)  — Ctrl+F")
        self.ad_filter.setClearButtonEnabled(True)
        top.addWidget(self.ad_filter)
        self.ad_count = QLabel("Lancez une analyse pour lire l'annuaire.")
        self.ad_count.setObjectName("note")
        top.addWidget(self.ad_count)
        lay.addLayout(top)
        self.ad_model = TableModel(["Nom", "FQDN", "Compte activé", "IPv4 (DNS)", "État DNS", "Vérification",
                                    "Dernier contact AD", "Système"])
        self.ad_view, self.ad_proxy = _table(self.ad_model, 5)
        self.ad_filter.textChanged.connect(self.ad_proxy.setFilterFixedString)
        self.ad_detail = QPlainTextEdit()
        self.ad_detail.setReadOnly(True)
        self.ad_detail.setPlaceholderText("Sélectionnez une machine pour voir ses détails et la fraîcheur des données.")
        sp = QSplitter(Qt.Vertical)
        sp.addWidget(self.ad_view)
        sp.addWidget(self.ad_detail)
        sp.setSizes([480, 160])
        lay.addWidget(sp, 1)
        lay.addWidget(self._note("Un objet AD n'est pas un hôte actif : le dernier contact AD (lastLogonTimestamp) "
                                 "est approximatif (≈14 jours) et le DNS peut être périmé."))
        self.ad_view.selectionModel().selectionChanged.connect(self._ad_selected)
        self.tabs.addTab(w, TAB_NAMES[1])

    def _ad_selected(self) -> None:
        idx = self.ad_view.currentIndex()
        if not idx.isValid():
            return
        c = self.ad_model.objs[self.ad_proxy.mapToSource(idx).row()]
        self.ad_detail.setPlainText(
            f"Nom : {c.name}\nFQDN : {c.dns_hostname}\nCompte activé : {({True: 'oui', False: 'non', None: 'inconnu'})[c.enabled]}\n"
            f"Dernier contact AD (approx.) : {c.last_logon or 'inconnu'}\nSystème : {c.os}\n"
            f"DN : {c.distinguished_name}\nIPv4 (DNS) : {', '.join(c.ipv4) or '—'}  (état : {c.dns_status})\n"
            f"MAC observée : {c.mac or '—'}\nVérification : {c.verification}\n"
            f"Source : {c.source}  — relevé DNS : {c.observed_at or '—'}")

    # ------------------------------------------------------ Onglet Réseau
    def _build_net(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.net_filter = QLineEdit()
        self.net_filter.setPlaceholderText("Rechercher (IP, nom, MAC, méthode…)")
        self.net_filter.setClearButtonEnabled(True)
        lay.addWidget(self.net_filter)
        self.net_model = TableModel(["IPv4", "Nom", "MAC", "Source / méthode", "Informations", "Observé le"])
        self.net_view, self.net_proxy = _table(self.net_model, 4)
        self.net_filter.textChanged.connect(self.net_proxy.setFilterFixedString)
        lay.addWidget(self.net_view, 1)
        lay.addWidget(self._note("Équipements réellement observés (ping, ARP, DNS inverse), y compris hors domaine. "
                                 "Un hôte silencieux n'est pas forcément absent."))
        self.tabs.addTab(w, TAB_NAMES[2])

    # -------------------------------------------------------- Onglet Plan
    def _build_plan(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        top = QHBoxLayout()
        top.addWidget(QLabel("Réseau :"))
        self.plan_net = QComboBox()
        self.plan_net.currentIndexChanged.connect(lambda *_: self._fill_plan())
        top.addWidget(self.plan_net)
        top.addWidget(QLabel("Statut :"))
        self.plan_status = QComboBox()
        self.plan_status.addItem("Tous")
        self.plan_status.addItems(list(ALL_STATUSES))
        self.plan_status.currentTextChanged.connect(
            lambda t: self.plan_proxy.set_column_filter(1, "" if t == "Tous" else t))
        top.addWidget(self.plan_status)
        self.plan_filter = QLineEdit()
        self.plan_filter.setPlaceholderText("Rechercher une IP, un nom…")
        self.plan_filter.setClearButtonEnabled(True)
        top.addWidget(self.plan_filter, 1)
        lay.addLayout(top)

        lay.addWidget(QLabel("<b>Adresses candidates</b> (jamais en plage DHCP dynamique)"))
        self.cand_model = TableModel(["IP", "Statut", "Excl. DHCP", "Justification"], status_col=1)
        self.cand_view, _ = _table(self.cand_model, 3)
        self.cand_view.sortByColumn(-1, Qt.AscendingOrder)  # garde l'ordre de proposition (meilleures d'abord)
        self.cand_view.selectionModel().selectionChanged.connect(lambda *_: self._refresh_enabled())
        sp = QSplitter(Qt.Vertical)
        sp.addWidget(self.cand_view)

        row = QHBoxLayout()
        self.verify_ip_edit = QLineEdit()
        self.verify_ip_edit.setPlaceholderText("IP à vérifier (ou sélectionnez une candidate)")
        self.btn_verify = QPushButton("Vérifier l'adresse")
        self.btn_verify.clicked.connect(self.verify_address)
        self.btn_cfg = QPushButton("Fiche de configuration…")
        self.btn_cfg.clicked.connect(self.show_config_sheet)
        row.addWidget(self.verify_ip_edit, 1)
        row.addWidget(self.btn_verify)
        row.addWidget(self.btn_cfg)
        rw = QWidget()
        rl = QVBoxLayout(rw)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addLayout(row)
        self.verify_out = QPlainTextEdit()
        self.verify_out.setReadOnly(True)
        self.verify_out.setMaximumHeight(150)
        rl.addWidget(self.verify_out)
        rl.addWidget(QLabel("<b>Plan complet</b>"))
        sp.addWidget(rw)

        self.plan_model = TableModel(["IP", "Statut", "Nom", "MAC", "Justification", "Contrôlé le"], status_col=1)
        self.plan_view, self.plan_proxy = _table(self.plan_model, 4)
        self.plan_filter.textChanged.connect(self.plan_proxy.setFilterFixedString)
        sp.addWidget(self.plan_view)
        sp.setSizes([180, 220, 320])
        lay.addWidget(sp, 1)
        lay.addWidget(self._note("« DISPONIBLE_CONFIRMÉE » est conditionnel et daté : ce n'est jamais une garantie. "
                                 "Une absence de réponse au ping ne suffit jamais à déclarer une adresse libre."))
        self.tabs.addTab(w, TAB_NAMES[3])

    def selected_candidate(self):
        idx = self.cand_view.currentIndex()
        if not idx.isValid():
            return None
        return self.cand_model.objs[self.cand_view.model().mapToSource(idx).row()]

    def verify_address(self) -> None:
        if self.verifier and self.verifier.isRunning():
            return
        text = self.verify_ip_edit.text().strip()
        cand = self.selected_candidate()
        if not text and cand:
            text = cand.ip
            self.verify_ip_edit.setText(text)
        try:
            ip = str(ipaddress.IPv4Address(text))
        except ValueError:
            self.verify_out.setPlainText("Saisissez une adresse IPv4 valide ou sélectionnez une candidate.")
            return
        status = why = ""
        if self.snapshot:
            for es in self.snapshot.plan.values():
                for e in es:
                    if e.ip == ip:
                        status, why = e.status, e.justification
        self.verify_out.setPlainText(f"Vérification de {ip} en cours…")
        self.btn_verify.setEnabled(False)
        self.verifier = VerifyWorker(ip, self.collectors, self.settings.ping_timeout_ms, status, why, self)
        self.verifier.done.connect(self._on_verified)
        self.verifier.failed.connect(lambda m: (self.verify_out.setPlainText(f"Vérification impossible : {m}"),
                                                self.btn_verify.setEnabled(True)))
        self.verifier.start()

    def _on_verified(self, res) -> None:
        self.last_verify = res
        self.verify_out.setPlainText(res.text())
        self.btn_verify.setEnabled(True)

    def config_sheet_text(self) -> str:
        e = self.selected_candidate()
        if not e or not self.snapshot:
            return ""
        return rx.config_sheet(e, self.snapshot)

    def show_config_sheet(self) -> None:
        t = self.config_sheet_text()
        if t:
            ConfigSheetDialog(t, self).exec()

    # -------------------------------------------------- Onglet Paramètres
    def _build_settings(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        form = QFormLayout()
        self.s_dc = QLineEdit(", ".join(self.settings.dc_hints))
        self.s_dns = QLineEdit(", ".join(self.settings.dns_hints))
        self.s_static = QPlainTextEdit("\n".join(f"{k};{v}" for k, v in self.settings.static_inventory.items()))
        self.s_static.setMaximumHeight(90)
        self.s_excl = QPlainTextEdit("\n".join(f"{a}-{b}" for a, b in self.settings.user_excluded))
        self.s_excl.setMaximumHeight(90)
        self.s_max = QSpinBox()
        self.s_max.setRange(16, 4096)
        self.s_max.setValue(self.settings.max_hosts)
        self.s_timeout = QSpinBox()
        self.s_timeout.setRange(100, 5000)
        self.s_timeout.setSingleStep(100)
        self.s_timeout.setValue(self.settings.ping_timeout_ms)
        self.s_conc = QSpinBox()
        self.s_conc.setRange(1, 128)
        self.s_conc.setValue(self.settings.concurrency)
        self.s_cand = QSpinBox()
        self.s_cand.setRange(1, 200)
        self.s_cand.setValue(self.settings.candidate_count)
        form.addRow("Contrôleur(s) de domaine supposé(s) (hypothèse, vérifiée) :", self.s_dc)
        form.addRow("DNS connu(s) (information, non utilisée comme preuve) :", self.s_dns)
        form.addRow("IP statiques connues (une par ligne : IP;libellé) :", self.s_static)
        form.addRow("Plages à exclure (une par ligne : début-fin) :", self.s_excl)
        form.addRow("Taille maximale d'un réseau sondé (adresses) :", self.s_max)
        form.addRow("Délai de ping (ms) :", self.s_timeout)
        form.addRow("Sondes simultanées :", self.s_conc)
        form.addRow("Nombre d'adresses candidates proposées :", self.s_cand)
        lay.addLayout(form)
        self.s_msg = QLabel("")
        self.s_msg.setObjectName("warn")
        self.s_msg.setVisible(False)
        lay.addWidget(self.s_msg)
        b = QPushButton("Enregistrer les paramètres")
        b.clicked.connect(lambda: self._collect_settings(save=True))
        lay.addWidget(b, 0, Qt.AlignLeft)
        lay.addWidget(self._note("Aucun mot de passe ni identifiant n'est demandé ou enregistré. "
                                 "Les connexions utilisent la session Windows en cours."))
        lay.addStretch(1)
        self.tabs.addTab(w, TAB_NAMES[4])

    def _collect_settings(self, save: bool) -> Optional[Settings]:
        errs = []

        def ips(text: str, what: str) -> list[str]:
            out = []
            for p in [x.strip() for x in text.replace(";", ",").split(",") if x.strip()]:
                try:
                    out.append(str(ipaddress.IPv4Address(p)))
                except ValueError:
                    errs.append(f"{what} : « {p} » n'est pas une adresse IPv4.")
            return out
        s = Settings(**{**self.settings.__dict__})
        s.dc_hints = ips(self.s_dc.text(), "Contrôleur")
        s.dns_hints = ips(self.s_dns.text(), "DNS")
        inv = {}
        for ln in self.s_static.toPlainText().splitlines():
            if not ln.strip():
                continue
            ip, _, label = ln.partition(";")
            try:
                inv[str(ipaddress.IPv4Address(ip.strip()))] = label.strip() or "statique"
            except ValueError:
                errs.append(f"IP statique invalide : « {ln.strip()} »")
        s.static_inventory = inv
        ex = []
        for ln in self.s_excl.toPlainText().splitlines():
            if not ln.strip():
                continue
            a, _, b = ln.partition("-")
            try:
                a, b = str(ipaddress.IPv4Address(a.strip())), str(ipaddress.IPv4Address((b or a).strip()))
                ex.append([a, b])
            except ValueError:
                errs.append(f"Plage invalide : « {ln.strip()} »")
        s.user_excluded = ex
        s.max_hosts, s.ping_timeout_ms = self.s_max.value(), self.s_timeout.value()
        s.concurrency, s.candidate_count = self.s_conc.value(), self.s_cand.value()
        self.s_msg.setText("\n".join(errs))
        self.s_msg.setVisible(bool(errs))
        if errs:
            return None
        if save:
            s.save()
            self.statusBar().showMessage("Paramètres enregistrés.", 5000)
        self.settings = s
        return s

    # --------------------------------------------------- Onglet Rapports
    def _build_reports(self) -> None:
        w = QWidget()
        lay = QVBoxLayout(w)
        row = QHBoxLayout()
        self.btn_csv = QPushButton("Exporter CSV (dossier)…")
        self.btn_xlsx = QPushButton("Exporter XLSX…")
        self.btn_diag = QPushButton("Exporter le diagnostic (JSON)…")
        self.btn_csv.clicked.connect(self._export_csv_dialog)
        self.btn_xlsx.clicked.connect(self._export_xlsx_dialog)
        self.btn_diag.clicked.connect(self._export_diag_dialog)
        for b in (self.btn_csv, self.btn_xlsx, self.btn_diag):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)
        lay.addWidget(QLabel("<b>État de chaque source</b>"))
        self.src_model = TableModel(["Source", "État", "Détail", "Durée (s)", "Éléments", "Début"])
        self.src_view, _ = _table(self.src_model, 2)
        lay.addWidget(self.src_view, 1)
        self.rep_msg = QLabel("")
        self.rep_msg.setObjectName("note")
        self.rep_msg.setWordWrap(True)
        lay.addWidget(self.rep_msg)
        self.tabs.addTab(w, TAB_NAMES[5])

    def do_export_csv(self, folder: str) -> list[Path]:
        files = rx.export_csv_folder(self.snapshot, folder)
        self.rep_msg.setText(f"{len(files)} fichiers CSV écrits dans {folder}")
        return files

    def do_export_xlsx(self, path: str) -> None:
        rx.export_xlsx(self.snapshot, path)
        self.rep_msg.setText(f"Classeur écrit : {path}")

    def do_export_diag(self, path: str) -> None:
        Path(path).write_text(rx.diagnostic_json(self.snapshot), encoding="utf-8")
        self.rep_msg.setText(f"Diagnostic écrit : {path}")

    def _guard(self, fn, *a) -> None:
        try:
            fn(*a)
        except OSError as e:
            QMessageBox.warning(self, "Export impossible", f"{e}\nChoisissez un autre emplacement "
                                "(le fichier est peut-être ouvert dans Excel).")

    def _export_csv_dialog(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Dossier d'export CSV")
        if d:
            self._guard(self.do_export_csv, d)

    def _export_xlsx_dialog(self) -> None:
        p, _ = QFileDialog.getSaveFileName(self, "Exporter XLSX", "GTC_Plan_Adressage.xlsx", "Excel (*.xlsx)")
        if p:
            self._guard(self.do_export_xlsx, p)

    def _export_diag_dialog(self) -> None:
        p, _ = QFileDialog.getSaveFileName(self, "Exporter le diagnostic", "diagnostic.json", "JSON (*.json)")
        if p:
            self._guard(self.do_export_diag, p)

    # ------------------------------------------------------------- Divers
    @staticmethod
    def _note(text: str) -> QLabel:
        lb = QLabel(text)
        lb.setObjectName("note")
        lb.setWordWrap(True)
        return lb

    def keyPressEvent(self, e) -> None:
        if e.matches(QKeySequence.Find):
            w = {1: self.ad_filter, 2: self.net_filter, 3: self.plan_filter}.get(self.tabs.currentIndex())
            if w:
                w.setFocus()
                return
        super().keyPressEvent(e)

    def closeEvent(self, e) -> None:
        for wk in (self.worker, self.detector, self.verifier):
            if wk and wk.isRunning():
                if hasattr(wk, "cancel"):
                    wk.cancel()
                wk.wait(8000)
        super().closeEvent(e)
