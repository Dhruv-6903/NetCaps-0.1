"""Qt model for DNS tab."""
from __future__ import annotations
from datetime import datetime, timezone
from PySide6.QtCore import Qt, QModelIndex

from ui.models.base_model import BaseTableModel
from core.data_model import DnsEvent

_HEADERS = ["Time", "Src IP", "Query", "Type", "Status", "Responses", "Anomaly"]


class DnsModel(BaseTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(_HEADERS, parent)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        row: DnsEvent = self._filtered[index.row()]
        col = index.column()
        if col == 0:
            return _fmt_ts(row.ts)
        if col == 1:
            return row.src_ip
        if col == 2:
            return row.query
        if col == 3:
            return row.qtype
        if col == 4:
            return row.status
        if col == 5:
            return ", ".join(str(r) for r in row.responses[:3])
        if col == 6:
            return row.anomaly_reason if row.anomaly_flag else ""
        return None


def _fmt_ts(ts: float) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
