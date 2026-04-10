"""Sessions tab."""
from __future__ import annotations
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit,
    QTableView, QHeaderView, QMenu, QApplication,
)
from PySide6.QtCore import Qt, QPoint, Signal
from PySide6.QtGui import QAction

from ui.models.sessions_model import SessionsModel


class SessionsTab(QWidget):
    session_selected = Signal(object)  # emits Session

    def __init__(self, case_store, parent=None) -> None:
        super().__init__(parent)
        self._store = case_store
        self._model = SessionsModel(self)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        filter_bar = QLineEdit(placeholderText="Filter sessions…")
        filter_bar.textChanged.connect(self._model.set_filter)
        layout.addWidget(filter_bar)

        self._table = QTableView()
        self._table.setModel(self._model)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setSortingEnabled(True)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)
        self._table.doubleClicked.connect(self._on_double_click)
        layout.addWidget(self._table)

    def append_rows(self, rows: list) -> None:
        self._model.append_rows(rows)

    def refresh(self) -> None:
        self._model.set_data(self._store.snapshot_sessions())

    def _on_double_click(self, index) -> None:
        row = self._model.get_row(index)
        if row:
            self.session_selected.emit(row)

    def _context_menu(self, pos: QPoint) -> None:
        idx = self._table.indexAt(pos)
        if not idx.isValid():
            return
        row = self._model.get_row(idx)
        menu = QMenu(self)
        open_stream = QAction("Open Stream Viewer", self)
        open_stream.triggered.connect(lambda: self.session_selected.emit(row))
        menu.addAction(open_stream)
        copy_id = QAction("Copy Session ID", self)
        copy_id.triggered.connect(lambda: QApplication.clipboard().setText(row.session_id))
        menu.addAction(copy_id)
        menu.exec(self._table.viewport().mapToGlobal(pos))
