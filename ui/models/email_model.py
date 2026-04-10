"""Qt model for Email tab."""
from __future__ import annotations
from datetime import datetime, timezone
from PySide6.QtCore import Qt, QModelIndex

from ui.models.base_model import BaseTableModel
from core.data_model import EmailArtifact

_HEADERS = ["Time", "Src IP", "From", "To", "Subject",
            "Attachments", "URLs", "Body Preview"]


class EmailModel(BaseTableModel):
    def __init__(self, parent=None) -> None:
        super().__init__(_HEADERS, parent)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        row: EmailArtifact = self._filtered[index.row()]
        col = index.column()
        if col == 0:
            return _fmt_ts(row.ts)
        if col == 1:
            return row.src_ip
        if col == 2:
            return row.sender
        if col == 3:
            return row.receiver
        if col == 4:
            return row.subject
        if col == 5:
            return str(row.attachments_count)
        if col == 6:
            return str(len(row.extracted_urls))
        if col == 7:
            return row.body_preview[:80].replace("\n", " ")
        return None


def _fmt_ts(ts: float) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")
