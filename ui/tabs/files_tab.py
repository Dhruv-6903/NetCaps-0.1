"""Files tab."""
from __future__ import annotations
import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit,
    QTableView, QHeaderView, QMenu, QApplication, QMessageBox,
)
from PySide6.QtCore import Qt, QPoint, Signal
from PySide6.QtGui import QAction

from ui.models.files_model import FilesModel
from core.data_model import FileArtifact


class FilesTab(QWidget):
    vt_check_requested = Signal(object)  # emits FileArtifact

    def __init__(self, case_store, parent=None) -> None:
        super().__init__(parent)
        self._store = case_store
        self._model = FilesModel(self)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        filter_bar = QLineEdit(placeholderText="Filter files…")
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
        layout.addWidget(self._table)

    def append_rows(self, rows: list) -> None:
        self._model.append_rows(rows)

    def refresh(self) -> None:
        self._model.set_data(self._store.snapshot_files())

    def on_vt_updated(self, fa: FileArtifact) -> None:
        self._model.refresh_row(fa)

    def _context_menu(self, pos: QPoint) -> None:
        idx = self._table.indexAt(pos)
        if not idx.isValid():
            return
        row = self._model.get_row(idx)
        menu = QMenu(self)
        copy_hash = QAction("Copy SHA256", self)
        copy_hash.triggered.connect(lambda: QApplication.clipboard().setText(row.sha256))
        menu.addAction(copy_hash)
        check_vt = QAction("Check on VirusTotal", self)
        check_vt.triggered.connect(lambda: self.vt_check_requested.emit(row))
        menu.addAction(check_vt)
        open_dir = QAction("Open containing folder", self)
        open_dir.triggered.connect(lambda: _open_folder(row.saved_path))
        menu.addAction(open_dir)
        menu.exec(self._table.viewport().mapToGlobal(pos))


def _open_folder(path: str) -> None:
    import subprocess
    import platform
    folder = os.path.dirname(path)
    try:
        system = platform.system()
        if system == "Windows":
            os.startfile(folder)
        elif system == "Darwin":
            subprocess.Popen(["open", folder])
        else:
            subprocess.Popen(["xdg-open", folder])
    except Exception:
        pass
