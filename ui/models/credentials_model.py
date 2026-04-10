"""Qt model for Credentials tab."""
from __future__ import annotations
from datetime import datetime
from PySide6.QtCore import Qt, QModelIndex

from ui.models.base_model import BaseTableModel
from core.data_model import Credential

_HEADERS = ["Proto", "Type", "Src IP", "Dst IP", "Username", "Password", "Time"]


class CredentialsModel(BaseTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(_HEADERS, parent)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        row: Credential = self._filtered[index.row()]
        col = index.column()
        if col == 0:
            return row.proto
        if col == 1:
            return row.cred_type
        if col == 2:
            return row.src_ip
        if col == 3:
            return row.dst_ip
        if col == 4:
            return row.username
        if col == 5:
            return row.password
        if col == 6:
            return _fmt_ts(row.timestamp)
        return None


def _fmt_ts(ts: float) -> str:
    if not ts:
        return ""
    return datetime.utcfromtimestamp(ts).strftime("%H:%M:%S")
