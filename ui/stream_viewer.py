"""Stream viewer dialog showing session payload in hex + ASCII."""
from __future__ import annotations
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTextEdit,
    QPushButton, QLabel, QButtonGroup, QRadioButton,
    QSizePolicy, QScrollBar,
)
from PySide6.QtGui import QFont, QTextCharFormat, QColor, QTextCursor
from PySide6.QtCore import Qt

from core.data_model import Session

_CLIENT_COLOR = QColor("#d0e8ff")
_SERVER_COLOR = QColor("#d0ffd0")


class StreamViewer(QDialog):
    def __init__(self, session: Session, parent=None) -> None:
        super().__init__(parent)
        self._session = session
        self.setWindowTitle(f"Stream: {session.session_id}")
        self.resize(900, 650)
        self._setup_ui()
        self._render("both")

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Info bar
        info = (
            f"{self._session.proto}  "
            f"{self._session.src_ip}:{self._session.src_port} → "
            f"{self._session.dst_ip}:{self._session.dst_port}  "
            f"[{self._session.state}]  "
            f"↑{self._session.bytes_sent} B  ↓{self._session.bytes_recv} B"
        )
        layout.addWidget(QLabel(info))

        if self._session.truncated:
            warn = QLabel("⚠ Payload truncated due to size cap")
            warn.setStyleSheet("color: #cc5500; font-weight: bold;")
            layout.addWidget(warn)

        # Direction selector
        btn_layout = QHBoxLayout()
        self._bg = QButtonGroup(self)
        for label, value in [("Client → Server", "client"),
                              ("Server → Client", "server"),
                              ("Both", "both")]:
            rb = QRadioButton(label)
            self._bg.addButton(rb)
            rb.setProperty("direction", value)
            btn_layout.addWidget(rb)
            if value == "both":
                rb.setChecked(True)
        self._bg.buttonClicked.connect(
            lambda btn: self._render(btn.property("direction"))
        )
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Hex / ASCII view
        self._hex_view = QTextEdit()
        self._hex_view.setReadOnly(True)
        font = QFont("Courier New", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self._hex_view.setFont(font)
        layout.addWidget(self._hex_view)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

    def _render(self, direction: str) -> None:
        self._hex_view.clear()
        cursor = self._hex_view.textCursor()

        def _append(data: bytes, color: QColor, label: str) -> None:
            if not data:
                return
            fmt = QTextCharFormat()
            fmt.setBackground(color)
            cursor.setCharFormat(fmt)
            cursor.insertText(f"── {label} ──\n")
            cursor.insertText(_hexdump(data))
            cursor.insertText("\n")

        if direction in ("client", "both"):
            _append(self._session.payload_client, _CLIENT_COLOR, "Client → Server")
        if direction in ("server", "both"):
            _append(self._session.payload_server, _SERVER_COLOR, "Server → Client")

        self._hex_view.setTextCursor(cursor)
        self._hex_view.moveCursor(QTextCursor.MoveOperation.Start)


def _hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:06x}  {hex_part:<{width*3}}  {asc_part}")
    return "\n".join(lines) + "\n"
