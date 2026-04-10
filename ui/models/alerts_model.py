"""Qt model for Alerts tab."""
from __future__ import annotations
from datetime import datetime, timezone
from PySide6.QtCore import Qt, QModelIndex
from PySide6.QtGui import QColor

from ui.models.base_model import BaseTableModel
from core.data_model import Alert

_HEADERS = ["Severity", "Rule", "Src IP", "Dst IP", "Description", "Time", "Session"]

_SEVERITY_COLORS = {
    "High": QColor("#ffcccc"),
    "Medium": QColor("#fff3cc"),
    "Low": QColor("#ccf0ff"),
}


class AlertsModel(BaseTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(_HEADERS, parent)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row: Alert = self._filtered[index.row()]
        if role == Qt.ItemDataRole.BackgroundRole:
            return _SEVERITY_COLORS.get(row.severity)
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        col = index.column()
        if col == 0:
            return row.severity
        if col == 1:
            return row.rule_name
        if col == 2:
            return row.src_ip
        if col == 3:
            return row.dst_ip
        if col == 4:
            return row.description
        if col == 5:
            return _fmt_ts(row.ts)
        if col == 6:
            return row.related_session_id
        return None


def _fmt_ts(ts: float) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")
