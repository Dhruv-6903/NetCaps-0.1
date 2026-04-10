#!/usr/bin/env python3
"""NetCaps – Desktop Network Forensics Tool."""
import sys
from pathlib import Path

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).parent))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt

import config


def main() -> None:
    cfg = config.load()
    cases_dir = Path(cfg.get("cases_dir", "cases"))
    cases_dir.mkdir(parents=True, exist_ok=True)

    app = QApplication(sys.argv)
    app.setApplicationName("NetCaps")
    app.setApplicationVersion("0.1")
    app.setOrganizationName("NetCaps")

    # Import here so Qt is already initialised
    from ui.main_window import MainWindow
    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
