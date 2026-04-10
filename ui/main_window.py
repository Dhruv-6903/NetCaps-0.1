"""Main window and parsing QThread."""
from __future__ import annotations
import os
import time
from pathlib import Path
from datetime import datetime

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QProgressBar, QLabel,
    QTabWidget, QFileDialog, QStatusBar, QMessageBox,
    QToolBar, QMenu,
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QAction

import config
from core.case_store import CaseStore
from core.data_model import (
    Host, build_host_search, build_credential_search,
    build_file_search, build_dns_search, build_alert_search,
    build_email_search, build_timeline_search,
)
from core.pcap_reader import iter_packets
from core.session_engine import SessionEngine
from core.alerts_engine import AlertsEngine
from core.artifacts.dns_parser import parse_dns_payload
from core.artifacts.http_extractor import HTTPExtractor
from core.artifacts.ftp_creds import parse_ftp_payload
from core.artifacts.smtp_parser import parse_smtp_payload
from core.artifacts.file_carver import carve_file
from core.enrichment.geoip import lookup_country
from core.enrichment.oui_lookup import lookup_vendor
from core import timeline as tl
from core.data_model import (
    Credential, FileArtifact, DnsEvent, Alert, EmailArtifact, TimelineEvent,
)
from integrations.virustotal import VTClient
from reporting.exporter import Exporter

from ui.dashboard import Dashboard
from ui.stream_viewer import StreamViewer
from ui.settings_dialog import SettingsDialog
from ui.tabs.hosts_tab import HostsTab
from ui.tabs.sessions_tab import SessionsTab
from ui.tabs.credentials_tab import CredentialsTab
from ui.tabs.files_tab import FilesTab
from ui.tabs.dns_tab import DnsTab
from ui.tabs.alerts_tab import AlertsTab
from ui.tabs.email_tab import EmailTab
from ui.tabs.timeline_tab import TimelineTab

import dpkt


def _ip_str_from_bytes(b: bytes) -> str:
    import socket
    try:
        if len(b) == 4:
            return socket.inet_ntoa(b)
        return socket.inet_ntop(socket.AF_INET6, b)
    except Exception:
        return b.hex()


class ParserThread(QThread):
    batch_ready = Signal(dict)
    progress = Signal(int, int)
    finished = Signal()
    error = Signal(str)

    def __init__(self, filepath: str, case_store: CaseStore,
                 cfg: dict, parent=None) -> None:
        super().__init__(parent)
        self._filepath = filepath
        self._store = case_store
        self._cfg = cfg
        self._stop_requested = False

    def stop(self) -> None:
        self._stop_requested = True

    def run(self) -> None:
        try:
            self._parse()
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            self.finished.emit()

    def _parse(self) -> None:
        cfg = self._cfg
        cases_dir = cfg.get("cases_dir", "cases")
        geoip_path = cfg.get("geoip_db_path", "")

        store = self._store
        session_engine = SessionEngine(cfg)
        alerts_engine = AlertsEngine(cfg)
        http_extractor = HTTPExtractor()

        # Count packets for progress (approximate via file size)
        file_size = Path(self._filepath).stat().st_size
        processed_bytes = 0

        batch: dict = {
            "hosts": [], "sessions": [], "credentials": [],
            "files": [], "dns": [], "alerts": [], "emails": [], "timeline": [],
        }
        last_emit = time.monotonic()

        def _maybe_emit(force: bool = False) -> None:
            nonlocal last_emit
            now = time.monotonic()
            if force or (now - last_emit) >= 0.2:
                if any(batch.values()):
                    self.batch_ready.emit(dict(batch))
                    for k in batch:
                        batch[k] = []
                last_emit = now

        pkt_count = 0
        proto_counts: dict[str, int] = {}

        for ts, raw in iter_packets(self._filepath):
            if self._stop_requested:
                break

            processed_bytes += len(raw) + 16  # rough per-packet overhead
            pkt_count += 1

            if pkt_count % 500 == 0:
                prog = min(int(processed_bytes * 100 / max(file_size, 1)), 99)
                self.progress.emit(prog, 100)
                _maybe_emit()

            # Parse packet with dpkt
            try:
                eth = dpkt.ethernet.Ethernet(raw)
                ip = eth.data
            except Exception:
                try:
                    ip = dpkt.ip.IP(raw)
                except Exception:
                    continue

            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue

            src_ip = _ip_str_from_bytes(ip.src)
            dst_ip = _ip_str_from_bytes(ip.dst)

            # Get or create Host entries
            for ip_addr in (src_ip, dst_ip):
                if ip_addr not in store.hosts:
                    h = Host(ip=ip_addr, first_seen=ts, last_seen=ts)
                    h.country = lookup_country(ip_addr, geoip_path)
                    h._search_str = build_host_search(h)
                    store.upsert_host(h)
                    batch["hosts"].append(h)
                else:
                    h = store.hosts[ip_addr]
                    if ts < h.first_seen:
                        h.first_seen = ts
                    if ts > h.last_seen:
                        h.last_seen = ts

            transport = ip.data
            proto_name = "OTHER"

            if isinstance(transport, dpkt.tcp.TCP):
                proto_name = "TCP"
                src_port = transport.sport
                dst_port = transport.dport
                payload = bytes(transport.data)

                # Update session
                updated = session_engine.process(ts, raw)
                for s in updated:
                    store.upsert_session(s)
                    batch["sessions"].append(s)

                    # Update host stats
                    h_src = store.hosts.get(s.src_ip)
                    if h_src:
                        h_src.bytes_sent += len(raw)
                        h_src.packets += 1
                        h_src.top_protocol = "TCP"

                    # Alert: port scan
                    a = alerts_engine.check_port_scan(ts, src_ip, dst_port)
                    if a:
                        store.add_alert(a)
                        batch["alerts"].append(a)
                        te = tl.from_alert(a)
                        store.add_timeline_event(te)
                        batch["timeline"].append(te)

                    # Alert: large transfer / exfil
                    total = s.bytes_sent + s.bytes_recv
                    a2 = alerts_engine.check_large_transfer(ts, s.src_ip, s.dst_ip, total, s.session_id)
                    if a2:
                        store.add_alert(a2)
                        batch["alerts"].append(a2)
                    a3 = alerts_engine.check_data_exfil(ts, s.src_ip, s.dst_ip, s.bytes_sent, s.session_id)
                    if a3:
                        store.add_alert(a3)
                        batch["alerts"].append(a3)

                # DNS on TCP/53
                if (src_port == 53 or dst_port == 53) and payload:
                    # TCP DNS has 2-byte length prefix
                    dns_payload = payload[2:] if len(payload) > 2 else payload
                    evt = parse_dns_payload(ts, src_ip, dns_payload)
                    if evt:
                        store.add_dns_event(evt)
                        batch["dns"].append(evt)
                        a = alerts_engine.check_suspicious_dns(ts, src_ip, evt.query, evt.status)
                        if a:
                            store.add_alert(a)
                            batch["alerts"].append(a)
                        te = tl.from_dns(evt)
                        store.add_timeline_event(te)
                        batch["timeline"].append(te)

                # HTTP
                if (src_port == 80 or dst_port == 80 or
                        src_port == 8080 or dst_port == 8080) and payload:
                    session = session_engine.sessions.get(
                        next((k for k in session_engine.sessions
                              if src_ip in k and dst_ip in k), ""), None
                    )
                    creds = http_extractor.extract_credentials(
                        payload, src_ip, dst_ip, ts,
                        f"TCP:{src_ip}:{src_port}:{dst_ip}:{dst_port}"
                    )
                    for c in creds:
                        cred = Credential(
                            proto=c["proto"], src_ip=c["src_ip"], dst_ip=c["dst_ip"],
                            username=c["username"], password=c["password"],
                            cred_type=c.get("cred_type", ""),
                            timestamp=c["timestamp"], session_id=c["session_id"],
                        )
                        cred._search_str = build_credential_search(cred)
                        store.add_credential(cred)
                        batch["credentials"].append(cred)
                        a = alerts_engine.check_cred_exposure(ts, src_ip, dst_ip, "HTTP", cred.session_id)
                        if a:
                            store.add_alert(a)
                            batch["alerts"].append(a)
                        a2 = alerts_engine.check_brute_force(ts, src_ip, dst_ip)
                        if a2:
                            store.add_alert(a2)
                            batch["alerts"].append(a2)
                        te = tl.from_credential(cred)
                        store.add_timeline_event(te)
                        batch["timeline"].append(te)

                    files = http_extractor.extract_files(
                        payload, src_ip, dst_ip, ts,
                        f"TCP:{src_ip}:{src_port}:{dst_ip}:{dst_port}"
                    )
                    for fdata in files:
                        fa = carve_file(
                            fdata["data"], fdata["filename"], fdata["file_type"],
                            "HTTP", src_ip, dst_ip, ts, cases_dir,
                        )
                        if fa:
                            store.add_file(fa)
                            batch["files"].append(fa)
                            te = tl.from_file(fa)
                            store.add_timeline_event(te)
                            batch["timeline"].append(te)

                # FTP
                if src_port == 21 or dst_port == 21:
                    session = session_engine.sessions
                    sid = f"TCP:{src_ip}:{src_port}:{dst_ip}:{dst_port}"
                    ftp_session = None
                    for k, s in session_engine.sessions.items():
                        if (s.src_ip == src_ip or s.dst_ip == src_ip) and s.proto == "TCP":
                            if s.src_port == 21 or s.dst_port == 21:
                                ftp_session = s
                                break
                    combined = b""
                    if ftp_session:
                        combined = ftp_session.payload_client + ftp_session.payload_server
                    creds_ftp = parse_ftp_payload(combined or payload, src_ip, dst_ip, ts, sid)
                    for c in creds_ftp:
                        cred = Credential(
                            proto="FTP", src_ip=c["src_ip"], dst_ip=c["dst_ip"],
                            username=c["username"], password=c["password"],
                            cred_type="FTPLogin",
                            timestamp=ts, session_id=sid,
                        )
                        cred._search_str = build_credential_search(cred)
                        store.add_credential(cred)
                        batch["credentials"].append(cred)
                        a = alerts_engine.check_cred_exposure(ts, src_ip, dst_ip, "FTP", sid)
                        if a:
                            store.add_alert(a)
                            batch["alerts"].append(a)
                        te = tl.from_credential(cred)
                        store.add_timeline_event(te)
                        batch["timeline"].append(te)

                # SMTP
                if src_port in (25, 587, 465) or dst_port in (25, 587, 465):
                    sid = f"TCP:{src_ip}:{src_port}:{dst_ip}:{dst_port}"
                    smtp_result = parse_smtp_payload(payload, src_ip, dst_ip, ts, sid)
                    for c in smtp_result.get("creds", []):
                        cred = Credential(
                            proto="SMTP", src_ip=c["src_ip"], dst_ip=c["dst_ip"],
                            username=c["username"], password=c["password"],
                            cred_type="SMTPAuth",
                            timestamp=ts, session_id=sid,
                        )
                        cred._search_str = build_credential_search(cred)
                        store.add_credential(cred)
                        batch["credentials"].append(cred)
                        te = tl.from_credential(cred)
                        store.add_timeline_event(te)
                        batch["timeline"].append(te)

                    email_data = smtp_result.get("email")
                    if email_data:
                        email_art = EmailArtifact(
                            ts=email_data["ts"],
                            src_ip=email_data["src_ip"],
                            sender=email_data["sender"],
                            receiver=email_data["receiver"],
                            subject=email_data["subject"],
                            body_preview=email_data["body_preview"],
                            attachments_count=email_data["attachments_count"],
                            attachment_refs=email_data["attachment_refs"],
                            extracted_urls=email_data["extracted_urls"],
                            related_session_id=email_data["related_session_id"],
                        )
                        email_art._search_str = build_email_search(email_art)
                        store.add_email(email_art)
                        batch["emails"].append(email_art)
                        te = tl.from_email(email_art)
                        store.add_timeline_event(te)
                        batch["timeline"].append(te)

                    for att in smtp_result.get("attachments", []):
                        fa = carve_file(
                            att["data"], att["filename"], "application/octet-stream",
                            "SMTP", src_ip, dst_ip, ts, cases_dir,
                        )
                        if fa:
                            store.add_file(fa)
                            batch["files"].append(fa)

            elif isinstance(transport, dpkt.udp.UDP):
                proto_name = "UDP"
                src_port = transport.sport
                dst_port = transport.dport
                payload = bytes(transport.data)

                updated = session_engine.process(ts, raw)
                for s in updated:
                    store.upsert_session(s)

                # DNS on UDP/53
                if (src_port == 53 or dst_port == 53) and payload:
                    evt = parse_dns_payload(ts, src_ip, payload)
                    if evt:
                        store.add_dns_event(evt)
                        batch["dns"].append(evt)
                        a = alerts_engine.check_suspicious_dns(ts, src_ip, evt.query, evt.status)
                        if a:
                            store.add_alert(a)
                            batch["alerts"].append(a)
                        te = tl.from_dns(evt)
                        store.add_timeline_event(te)
                        batch["timeline"].append(te)

            elif isinstance(transport, dpkt.icmp.ICMP):
                proto_name = "ICMP"
                updated = session_engine.process(ts, raw)
                for s in updated:
                    store.upsert_session(s)
                a = alerts_engine.check_icmp_flood(ts, src_ip)
                if a:
                    store.add_alert(a)
                    batch["alerts"].append(a)
                    te = tl.from_alert(a)
                    store.add_timeline_event(te)
                    batch["timeline"].append(te)

            proto_counts[proto_name] = proto_counts.get(proto_name, 0) + 1

        # Finalize sessions
        session_engine.finalize_all()

        # Add session timeline events (sample: new/closed sessions)
        for s in list(session_engine.sessions.values())[:1000]:
            te = tl.from_session(s)
            store.add_timeline_event(te)
            batch["timeline"].append(te)

        _maybe_emit(force=True)
        self.progress.emit(100, 100)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("NetCaps – Network Forensics")
        self.resize(1400, 900)
        self._store = CaseStore()
        self._cfg = config.get()
        self._parser: ParserThread | None = None
        self._vt_client: VTClient | None = None
        self._exporter = Exporter()
        self._dashboard_timer = QTimer(self)
        self._dashboard_timer.setInterval(2000)
        self._dashboard_timer.timeout.connect(self._refresh_dashboard)
        self._setup_ui()

    def _setup_ui(self) -> None:
        # Toolbar
        toolbar = QToolBar("Main")
        self.addToolBar(toolbar)

        open_action = QAction("📂 Open PCAP", self)
        open_action.triggered.connect(self._open_pcap)
        toolbar.addAction(open_action)

        toolbar.addSeparator()

        self._search_bar = QLineEdit()
        self._search_bar.setPlaceholderText("Global search…")
        self._search_bar.setFixedWidth(300)
        self._search_bar.textChanged.connect(self._global_filter)
        toolbar.addWidget(self._search_bar)

        toolbar.addSeparator()

        self._progress = QProgressBar()
        self._progress.setFixedWidth(200)
        self._progress.setVisible(False)
        toolbar.addWidget(self._progress)

        self._status_label = QLabel("Ready")
        toolbar.addWidget(self._status_label)

        toolbar.addSeparator()

        export_action = QAction("📤 Export", self)
        export_action.triggered.connect(self._show_export_menu)
        toolbar.addAction(export_action)

        settings_action = QAction("⚙ Settings", self)
        settings_action.triggered.connect(self._open_settings)
        toolbar.addAction(settings_action)

        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Dashboard
        self._dashboard = Dashboard(self._store)
        main_layout.addWidget(self._dashboard)

        # Tabs
        self._tabs = QTabWidget()

        self._hosts_tab = HostsTab(self._store)
        self._sessions_tab = SessionsTab(self._store)
        self._sessions_tab.session_selected.connect(self._open_stream_viewer)
        self._creds_tab = CredentialsTab(self._store)
        self._files_tab = FilesTab(self._store)
        self._files_tab.vt_check_requested.connect(self._vt_check)
        self._dns_tab = DnsTab(self._store)
        self._alerts_tab = AlertsTab(self._store)
        self._email_tab = EmailTab(self._store)
        self._timeline_tab = TimelineTab(self._store)

        self._tabs.addTab(self._hosts_tab, "🖥 Hosts")
        self._tabs.addTab(self._sessions_tab, "🔗 Sessions")
        self._tabs.addTab(self._creds_tab, "🔑 Credentials")
        self._tabs.addTab(self._files_tab, "📁 Files")
        self._tabs.addTab(self._dns_tab, "🌐 DNS")
        self._tabs.addTab(self._alerts_tab, "⚠ Alerts")
        self._tabs.addTab(self._email_tab, "✉ Email")
        self._tabs.addTab(self._timeline_tab, "📅 Timeline")

        main_layout.addWidget(self._tabs)

        self.setStatusBar(QStatusBar())

    def _open_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open PCAP/PCAPNG", "",
            "PCAP Files (*.pcap *.pcapng *.cap);;All Files (*)"
        )
        if not path:
            return
        self._start_parsing(path)

    def _start_parsing(self, filepath: str) -> None:
        if self._parser and self._parser.isRunning():
            self._parser.stop()
            self._parser.wait(2000)

        self._store.reset()
        for tab in [self._hosts_tab, self._sessions_tab, self._creds_tab,
                    self._files_tab, self._dns_tab, self._alerts_tab,
                    self._email_tab, self._timeline_tab]:
            tab.refresh()

        self._cfg = config.get()
        cases_dir = Path(self._cfg.get("cases_dir", "cases"))
        cases_dir.mkdir(parents=True, exist_ok=True)

        self._progress.setVisible(True)
        self._progress.setValue(0)
        self._status_label.setText(f"Parsing: {Path(filepath).name}")

        self._parser = ParserThread(filepath, self._store, self._cfg, self)
        self._parser.batch_ready.connect(self._on_batch)
        self._parser.progress.connect(self._on_progress)
        self._parser.finished.connect(self._on_finished)
        self._parser.error.connect(self._on_error)
        self._parser.start()
        self._dashboard_timer.start()

    def _on_batch(self, batch: dict) -> None:
        if batch.get("hosts"):
            self._hosts_tab.append_rows(batch["hosts"])
        if batch.get("sessions"):
            self._sessions_tab.append_rows(batch["sessions"])
        if batch.get("credentials"):
            self._creds_tab.append_rows(batch["credentials"])
        if batch.get("files"):
            self._files_tab.append_rows(batch["files"])
        if batch.get("dns"):
            self._dns_tab.append_rows(batch["dns"])
        if batch.get("alerts"):
            self._alerts_tab.append_rows(batch["alerts"])
        if batch.get("emails"):
            self._email_tab.append_rows(batch["emails"])
        if batch.get("timeline"):
            self._timeline_tab.append_rows(batch["timeline"])

        # Update tab labels with counts
        self._update_tab_counts()

    def _update_tab_counts(self) -> None:
        store = self._store
        counts = [
            len(store.hosts), len(store.sessions), len(store.credentials),
            len(store.files), len(store.dns_events), len(store.alerts),
            len(store.emails), len(store.timeline),
        ]
        labels = ["🖥 Hosts", "🔗 Sessions", "🔑 Credentials", "📁 Files",
                  "🌐 DNS", "⚠ Alerts", "✉ Email", "📅 Timeline"]
        for i, (label, count) in enumerate(zip(labels, counts)):
            self._tabs.setTabText(i, f"{label} ({count})")

    def _on_progress(self, current: int, total: int) -> None:
        self._progress.setValue(current)

    def _on_finished(self) -> None:
        self._progress.setVisible(False)
        store = self._store
        self._status_label.setText(
            f"Done — {len(store.sessions)} sessions, "
            f"{len(store.hosts)} hosts, "
            f"{len(store.alerts)} alerts"
        )
        self._dashboard.refresh()
        self._dashboard_timer.stop()
        # Final refresh to get session timeline events
        self._timeline_tab.refresh()
        self._update_tab_counts()

    def _on_error(self, msg: str) -> None:
        self._progress.setVisible(False)
        self._status_label.setText(f"Error: {msg}")
        QMessageBox.critical(self, "Parse Error", msg)

    def _global_filter(self, term: str) -> None:
        for tab in [self._hosts_tab, self._sessions_tab, self._creds_tab,
                    self._files_tab, self._dns_tab, self._alerts_tab,
                    self._email_tab, self._timeline_tab]:
            tab._model.set_filter(term)

    def set_global_filter(self, term: str) -> None:
        self._search_bar.setText(term)

    def _refresh_dashboard(self) -> None:
        self._dashboard.refresh()

    def _open_stream_viewer(self, session) -> None:
        dlg = StreamViewer(session, self)
        dlg.exec()

    def _open_settings(self) -> None:
        dlg = SettingsDialog(self)
        if dlg.exec():
            self._cfg = config.get()
            vt_key = self._cfg.get("vt_api_key", "")
            if vt_key and self._vt_client is None:
                self._vt_client = VTClient(vt_key, self._cfg.get("vt_delay", 15.0))
                self._vt_client.start()

    def _vt_check(self, fa) -> None:
        if not self._vt_client:
            key = self._cfg.get("vt_api_key", "")
            if not key:
                QMessageBox.warning(self, "No API Key",
                                    "Set a VirusTotal API key in Settings first.")
                return
            self._vt_client = VTClient(key, self._cfg.get("vt_delay", 15.0))
            self._vt_client.start()
        self._vt_client.enqueue(fa, self._files_tab.on_vt_updated)

    def _show_export_menu(self) -> None:
        menu = QMenu(self)
        json_act = QAction("Export JSON", self)
        json_act.triggered.connect(self._export_json)
        menu.addAction(json_act)
        html_act = QAction("Export HTML Report", self)
        html_act.triggered.connect(self._export_html)
        menu.addAction(html_act)
        summary_act = QAction("Attack Summary (text)", self)
        summary_act.triggered.connect(self._export_summary)
        menu.addAction(summary_act)
        menu.exec(self.cursor().pos())

    def _export_json(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save JSON", "report.json",
                                               "JSON (*.json)")
        if path:
            self._exporter.export_json(self._store, path)
            self.statusBar().showMessage(f"Exported JSON: {path}", 3000)

    def _export_html(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save HTML Report", "report.html",
                                               "HTML (*.html)")
        if path:
            self._exporter.export_html(self._store, path)
            self.statusBar().showMessage(f"Exported HTML: {path}", 3000)

    def _export_summary(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save Summary", "summary.md",
                                               "Markdown (*.md);;Text (*.txt)")
        if path:
            summary = self._exporter.generate_attack_summary(self._store)
            Path(path).write_text(summary, encoding="utf-8")
            self.statusBar().showMessage(f"Exported summary: {path}", 3000)

    def closeEvent(self, event) -> None:
        if self._parser and self._parser.isRunning():
            self._parser.stop()
            self._parser.wait(3000)
        if self._vt_client:
            self._vt_client.stop()
        event.accept()
