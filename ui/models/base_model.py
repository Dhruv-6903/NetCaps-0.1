"""Base Qt table model with search/filter support."""
from __future__ import annotations
from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex


class BaseTableModel(QAbstractTableModel):
    def __init__(self, headers: list[str], parent=None) -> None:
        super().__init__(parent)
        self._headers = headers
        self._data: list = []
        self._filtered: list = []
        self._filter_term: str = ""

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._filtered)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._headers)

    def headerData(self, section: int, orientation: Qt.Orientation,
                   role: int = Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self._headers[section]
        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable

    def set_data(self, rows: list) -> None:
        self.beginResetModel()
        self._data = rows
        self._apply_filter()
        self.endResetModel()

    def append_rows(self, rows: list) -> None:
        if not rows:
            return
        new_filtered = [r for r in rows
                        if not self._filter_term or self._filter_term in r._search_str]
        if new_filtered:
            start = len(self._filtered)
            self.beginInsertRows(QModelIndex(), start, start + len(new_filtered) - 1)
            self._data.extend(rows)
            self._filtered.extend(new_filtered)
            self.endInsertRows()
        else:
            self._data.extend(rows)

    def set_filter(self, term: str) -> None:
        self._filter_term = term.lower()
        self.beginResetModel()
        self._apply_filter()
        self.endResetModel()

    def _apply_filter(self) -> None:
        if not self._filter_term:
            self._filtered = list(self._data)
        else:
            self._filtered = [r for r in self._data if self._filter_term in r._search_str]

    def get_row(self, index: QModelIndex):
        if index.isValid() and 0 <= index.row() < len(self._filtered):
            return self._filtered[index.row()]
        return None

    def get_row_by_number(self, row: int):
        if 0 <= row < len(self._filtered):
            return self._filtered[row]
        return None
