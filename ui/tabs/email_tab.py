"""Email tab."""
from __future__ import annotations
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QSplitter, QLineEdit,
    QTableView, QHeaderView, QTextBrowser, QMenu, QApplication,
)
from PySide6.QtCore import Qt, QPoint
from PySide6.QtGui import QAction

from ui.models.email_model import EmailModel


class EmailTab(QWidget):
    def __init__(self, case_store, parent=None) -> None:
        super().__init__(parent)
        self._store = case_store
        self._model = EmailModel(self)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        filter_bar = QLineEdit(placeholderText="Filter emails…")
        filter_bar.textChanged.connect(self._model.set_filter)
        layout.addWidget(filter_bar)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self._table = QTableView()
        self._table.setModel(self._model)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setSortingEnabled(True)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)
        self._table.selectionModel().currentRowChanged.connect(self._on_row_changed)
        splitter.addWidget(self._table)

        self._preview = QTextBrowser()
        self._preview.setMaximumHeight(200)
        splitter.addWidget(self._preview)

        layout.addWidget(splitter)

    def append_rows(self, rows: list) -> None:
        self._model.append_rows(rows)

    def refresh(self) -> None:
        self._model.set_data(self._store.snapshot_emails())

    def _on_row_changed(self, current, previous) -> None:
        row = self._model.get_row(current)
        if row:
            text = (
                f"From: {row.sender}\nTo: {row.receiver}\nSubject: {row.subject}\n"
                f"Attachments: {row.attachments_count}\n"
                f"URLs: {len(row.extracted_urls)}\n\n{row.body_preview}"
            )
            self._preview.setPlainText(text)

    def _context_menu(self, pos: QPoint) -> None:
        idx = self._table.indexAt(pos)
        if not idx.isValid():
            return
        row = self._model.get_row(idx)
        menu = QMenu(self)
        copy_subj = QAction("Copy Subject", self)
        copy_subj.triggered.connect(lambda: QApplication.clipboard().setText(row.subject))
        menu.addAction(copy_subj)
        copy_urls = QAction("Copy URLs", self)
        copy_urls.triggered.connect(
            lambda: QApplication.clipboard().setText("\n".join(row.extracted_urls))
        )
        menu.addAction(copy_urls)
        menu.exec(self._table.viewport().mapToGlobal(pos))
