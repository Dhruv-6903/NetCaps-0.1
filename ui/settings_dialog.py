"""Settings dialog."""
from __future__ import annotations
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit,
    QDialogButtonBox, QGroupBox, QSpinBox, QDoubleSpinBox,
    QPushButton, QFileDialog, QHBoxLayout, QLabel,
)
from PySide6.QtCore import Qt

import config


class SettingsDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("NetCaps Settings")
        self.resize(500, 400)
        self._cfg = dict(config.get())
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # VirusTotal group
        vt_group = QGroupBox("VirusTotal")
        vt_form = QFormLayout(vt_group)
        self._vt_key = QLineEdit(self._cfg.get("vt_api_key", ""))
        self._vt_key.setEchoMode(QLineEdit.EchoMode.Password)
        vt_form.addRow("API Key:", self._vt_key)
        self._vt_delay = QDoubleSpinBox()
        self._vt_delay.setRange(1.0, 60.0)
        self._vt_delay.setValue(self._cfg.get("vt_delay", 15.0))
        vt_form.addRow("Request delay (s):", self._vt_delay)
        layout.addWidget(vt_group)

        # GeoIP group
        geo_group = QGroupBox("GeoIP")
        geo_form = QFormLayout(geo_group)
        geo_row = QHBoxLayout()
        self._geo_path = QLineEdit(self._cfg.get("geoip_db_path", ""))
        geo_row.addWidget(self._geo_path)
        browse_geo = QPushButton("Browse…")
        browse_geo.clicked.connect(self._browse_geo)
        geo_row.addWidget(browse_geo)
        geo_form.addRow("GeoIP DB path:", geo_row)
        layout.addWidget(geo_group)

        # Cases dir
        cases_group = QGroupBox("Storage")
        cases_form = QFormLayout(cases_group)
        cases_row = QHBoxLayout()
        self._cases_dir = QLineEdit(self._cfg.get("cases_dir", "cases"))
        cases_row.addWidget(self._cases_dir)
        browse_cases = QPushButton("Browse…")
        browse_cases.clicked.connect(self._browse_cases)
        cases_row.addWidget(browse_cases)
        cases_form.addRow("Cases directory:", cases_row)
        layout.addWidget(cases_group)

        # Alert thresholds
        alert_group = QGroupBox("Alert Thresholds")
        alert_form = QFormLayout(alert_group)
        self._ps_ports = QSpinBox()
        self._ps_ports.setRange(1, 65535)
        self._ps_ports.setValue(self._cfg.get("alert_port_scan_ports", 20))
        alert_form.addRow("Port scan (ports/window):", self._ps_ports)
        self._bf_attempts = QSpinBox()
        self._bf_attempts.setRange(1, 100)
        self._bf_attempts.setValue(self._cfg.get("alert_brute_force_attempts", 5))
        alert_form.addRow("Brute force (attempts/window):", self._bf_attempts)
        self._large_mb = QSpinBox()
        self._large_mb.setRange(1, 10000)
        self._large_mb.setValue(self._cfg.get("alert_large_transfer_mb", 100))
        alert_form.addRow("Large transfer threshold (MB):", self._large_mb)
        self._icmp_count = QSpinBox()
        self._icmp_count.setRange(1, 10000)
        self._icmp_count.setValue(self._cfg.get("alert_icmp_flood_count", 100))
        alert_form.addRow("ICMP flood count:", self._icmp_count)
        layout.addWidget(alert_group)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _browse_geo(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select GeoIP DB", "",
                                               "MaxMind DB (*.mmdb);;All (*)")
        if path:
            self._geo_path.setText(path)

    def _browse_cases(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select Cases Directory")
        if path:
            self._cases_dir.setText(path)

    def _save(self) -> None:
        self._cfg.update({
            "vt_api_key": self._vt_key.text(),
            "vt_delay": self._vt_delay.value(),
            "geoip_db_path": self._geo_path.text(),
            "cases_dir": self._cases_dir.text(),
            "alert_port_scan_ports": self._ps_ports.value(),
            "alert_brute_force_attempts": self._bf_attempts.value(),
            "alert_large_transfer_mb": self._large_mb.value(),
            "alert_icmp_flood_count": self._icmp_count.value(),
        })
        config.save(self._cfg)
        self.accept()

    def get_config(self) -> dict:
        return self._cfg
