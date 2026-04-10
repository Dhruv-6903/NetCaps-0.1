"""Qt model for Hosts tab."""
from __future__ import annotations
from datetime import datetime, timezone
from PySide6.QtCore import Qt, QModelIndex

from ui.models.base_model import BaseTableModel
from core.data_model import Host

_HEADERS = ["IP", "MAC", "Vendor", "Hostnames", "Country",
            "Sent", "Recv", "Packets", "Protocol", "First Seen", "Last Seen"]


class HostsModel(BaseTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(_HEADERS, parent)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        row: Host = self._filtered[index.row()]
        col = index.column()
        if col == 0:
            return row.ip
        if col == 1:
            return row.mac
        if col == 2:
            return row.vendor
        if col == 3:
            return ", ".join(row.hostnames)
        if col == 4:
            return row.country
        if col == 5:
            return _fmt_bytes(row.bytes_sent)
        if col == 6:
            return _fmt_bytes(row.bytes_recv)
        if col == 7:
            return str(row.packets)
        if col == 8:
            return row.top_protocol
        if col == 9:
            return _fmt_ts(row.first_seen)
        if col == 10:
            return _fmt_ts(row.last_seen)
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
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")
