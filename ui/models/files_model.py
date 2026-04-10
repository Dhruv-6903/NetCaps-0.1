"""Qt model for Files tab."""
from __future__ import annotations
from datetime import datetime
from PySide6.QtCore import Qt, QModelIndex

from ui.models.base_model import BaseTableModel
from core.data_model import FileArtifact

_HEADERS = ["Filename", "Type", "Size", "MD5", "SHA256", "Proto",
            "Src IP", "Dst IP", "VT Status", "VT Ratio", "Time"]


class FilesModel(BaseTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(_HEADERS, parent)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        row: FileArtifact = self._filtered[index.row()]
        col = index.column()
        if col == 0:
            return row.filename
        if col == 1:
            return row.file_type
        if col == 2:
            return _fmt_bytes(row.size)
        if col == 3:
            return row.md5
        if col == 4:
            return row.sha256[:16] + "…"
        if col == 5:
            return row.proto
        if col == 6:
            return row.src_ip
        if col == 7:
            return row.dst_ip
        if col == 8:
            return row.vt_status
        if col == 9:
            return row.vt_ratio
        if col == 10:
            return _fmt_ts(row.timestamp)
        return None

    def refresh_row(self, fa: FileArtifact) -> None:
        """Refresh display for a specific file artifact after VT update."""
        for i, item in enumerate(self._filtered):
            if item is fa:
                top_left = self.index(i, 0)
                bottom_right = self.index(i, len(_HEADERS) - 1)
                self.dataChanged.emit(top_left, bottom_right)
                break


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
