"""Qt model for Sessions tab."""
from __future__ import annotations
from datetime import datetime
from PySide6.QtCore import Qt, QModelIndex

from ui.models.base_model import BaseTableModel
from core.data_model import Session

_HEADERS = ["Proto", "Src IP", "Src Port", "Dst IP", "Dst Port",
            "State", "Sent", "Recv", "Packets", "Duration", "Start"]


class SessionsModel(BaseTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(_HEADERS, parent)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        row: Session = self._filtered[index.row()]
        col = index.column()
        if col == 0:
            return row.proto
        if col == 1:
            return row.src_ip
        if col == 2:
            return str(row.src_port)
        if col == 3:
            return row.dst_ip
        if col == 4:
            return str(row.dst_port)
        if col == 5:
            return row.state
        if col == 6:
            return _fmt_bytes(row.bytes_sent)
        if col == 7:
            return _fmt_bytes(row.bytes_recv)
        if col == 8:
            return str(row.packets)
        if col == 9:
            return f"{row.duration:.2f}s"
        if col == 10:
            return _fmt_ts(row.start_time)
        return None


def _fmt_bytes(b: int) -> str:
    if b >= 1_000_000:
        return f"{b / 1_000_000:.1f} MB"
    if b >= 1_000:
        return f"{b / 1_000:.1f} KB"
    return f"{b} B"


def _fmt_ts(ts: float) -> str:
    if not ts:
        return ""
    return datetime.utcfromtimestamp(ts).strftime("%H:%M:%S")
