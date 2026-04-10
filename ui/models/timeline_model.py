"""Qt model for Timeline tab."""
from __future__ import annotations
from datetime import datetime
from PySide6.QtCore import Qt, QModelIndex
from PySide6.QtGui import QColor

from ui.models.base_model import BaseTableModel
from core.data_model import TimelineEvent

_HEADERS = ["Time", "Type", "Description", "Src IP", "Dst IP"]

_TYPE_COLORS = {
    "Alert":      QColor("#ffcccc"),
    "Credential": QColor("#fff3cc"),
    "File":       QColor("#ddeeff"),
    "DNS":        QColor("#e8f5e9"),
    "Session":    QColor("#f5f5f5"),
    "Email":      QColor("#f3e5f5"),
}


class TimelineModel(BaseTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(_HEADERS, parent)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row: TimelineEvent = self._filtered[index.row()]
        if role == Qt.ItemDataRole.BackgroundRole:
            return _TYPE_COLORS.get(row.event_type)
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        col = index.column()
        if col == 0:
            return _fmt_ts(row.ts)
        if col == 1:
            return row.event_type
        if col == 2:
            return row.description
        if col == 3:
            return row.src_ip
        if col == 4:
            return row.dst_ip
        return None


def _fmt_ts(ts: float) -> str:
    if not ts:
        return ""
    return datetime.utcfromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
