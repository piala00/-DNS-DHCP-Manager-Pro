"""Modèle de tableau générique, filtrable et triable."""
from __future__ import annotations

import ipaddress
from typing import Any, Optional

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QBrush, QColor

STATUS_COLORS = {
    "OCCUPÉE": "#fde2e2", "CONFLIT": "#f8b4b4", "RÉSERVÉE": "#fff0c2", "EXCLUE": "#e5e7eb",
    "DHCP_DYNAMIQUE": "#dbeafe", "INCONNUE": "#f3e8ff", "CANDIDATE_À_VÉRIFIER": "#fef9c3",
    "DISPONIBLE_CONFIRMÉE": "#d1fae5",
}


def sort_key(v: Any):
    s = str(v)
    try:
        return (0, int(ipaddress.IPv4Address(s)), "")
    except ValueError:
        pass
    try:
        return (1, float(s), "")
    except ValueError:
        return (2, 0, s.lower())


class TableModel(QAbstractTableModel):
    def __init__(self, headers: list[str], status_col: int = -1, parent=None):
        super().__init__(parent)
        self.headers = headers
        self.status_col = status_col
        self.rows: list[list[Any]] = []
        self.objs: list[Any] = []

    def set_rows(self, rows: list[list[Any]], objs: Optional[list[Any]] = None) -> None:
        self.beginResetModel()
        self.rows = rows
        self.objs = objs if objs is not None else [None] * len(rows)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.headers)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.headers[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        v = self.rows[index.row()][index.column()]
        if role in (Qt.DisplayRole, Qt.ToolTipRole):
            return "" if v is None else str(v)
        if role == Qt.BackgroundRole and index.column() == self.status_col:
            c = STATUS_COLORS.get(str(v))
            return QBrush(QColor(c)) if c else None
        if role == Qt.ForegroundRole and index.column() == self.status_col and str(v) in STATUS_COLORS:
            return QBrush(QColor("#111827"))
        return None


class FilterProxy(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.setFilterKeyColumn(-1)
        self._col = -1
        self._val = ""

    def lessThan(self, left, right):
        sm = self.sourceModel()
        return sort_key(sm.rows[left.row()][left.column()]) < sort_key(sm.rows[right.row()][right.column()])

    def set_column_filter(self, col: int, value: str) -> None:
        self._col, self._val = col, value
        self.beginFilterChange()
        self.endFilterChange()

    def filterAcceptsRow(self, row, parent):
        if not super().filterAcceptsRow(row, parent):
            return False
        if self._col >= 0 and self._val:
            idx = self.sourceModel().index(row, self._col, parent)
            return self.sourceModel().data(idx) == self._val
        return True
