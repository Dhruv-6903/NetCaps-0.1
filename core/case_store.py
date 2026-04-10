"""Thread-safe central case store with indices."""
from __future__ import annotations
import threading
from collections import defaultdict
from core.data_model import (
    Host, Session, Credential, FileArtifact,
    DnsEvent, Alert, EmailArtifact, TimelineEvent,
)


class CaseStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()

        self.hosts: dict[str, Host] = {}
        self.sessions: dict[str, Session] = {}
        self.credentials: list[Credential] = []
        self.files: list[FileArtifact] = []
        self.dns_events: list[DnsEvent] = []
        self.alerts: list[Alert] = []
        self.emails: list[EmailArtifact] = []
        self.timeline: list[TimelineEvent] = []

        # Indices for fast per-IP filtering
        self.ip_to_sessions: dict[str, list[str]] = defaultdict(list)
        self.ip_to_dns: dict[str, list[int]] = defaultdict(list)
        self.ip_to_files: dict[str, list[int]] = defaultdict(list)
        self.ip_to_creds: dict[str, list[int]] = defaultdict(list)
        self.ip_to_alerts: dict[str, list[int]] = defaultdict(list)
        self.ip_to_emails: dict[str, list[int]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Host
    # ------------------------------------------------------------------
    def upsert_host(self, host: Host) -> None:
        with self._lock:
            self.hosts[host.ip] = host

    def get_host(self, ip: str) -> Host | None:
        with self._lock:
            return self.hosts.get(ip)

    # ------------------------------------------------------------------
    # Session
    # ------------------------------------------------------------------
    def upsert_session(self, session: Session) -> None:
        with self._lock:
            self.sessions[session.session_id] = session
            sid = session.session_id
            for ip in (session.src_ip, session.dst_ip):
                if sid not in self.ip_to_sessions[ip]:
                    self.ip_to_sessions[ip].append(sid)

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            return self.sessions.get(session_id)

    # ------------------------------------------------------------------
    # Credentials
    # ------------------------------------------------------------------
    def add_credential(self, cred: Credential) -> int:
        with self._lock:
            idx = len(self.credentials)
            self.credentials.append(cred)
            self.ip_to_creds[cred.src_ip].append(idx)
            self.ip_to_creds[cred.dst_ip].append(idx)
            return idx

    # ------------------------------------------------------------------
    # Files
    # ------------------------------------------------------------------
    def add_file(self, fa: FileArtifact) -> int:
        with self._lock:
            idx = len(self.files)
            self.files.append(fa)
            self.ip_to_files[fa.src_ip].append(idx)
            self.ip_to_files[fa.dst_ip].append(idx)
            return idx

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------
    def add_dns_event(self, evt: DnsEvent) -> int:
        with self._lock:
            idx = len(self.dns_events)
            self.dns_events.append(evt)
            self.ip_to_dns[evt.src_ip].append(idx)
            return idx

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------
    def add_alert(self, alert: Alert) -> int:
        with self._lock:
            idx = len(self.alerts)
            self.alerts.append(alert)
            self.ip_to_alerts[alert.src_ip].append(idx)
            if alert.dst_ip:
                self.ip_to_alerts[alert.dst_ip].append(idx)
            return idx

    # ------------------------------------------------------------------
    # Emails
    # ------------------------------------------------------------------
    def add_email(self, email: EmailArtifact) -> int:
        with self._lock:
            idx = len(self.emails)
            self.emails.append(email)
            self.ip_to_emails[email.src_ip].append(idx)
            return idx

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------
    def add_timeline_event(self, evt: TimelineEvent) -> int:
        with self._lock:
            idx = len(self.timeline)
            self.timeline.append(evt)
            return idx

    # ------------------------------------------------------------------
    # Bulk snapshot (for UI models)
    # ------------------------------------------------------------------
    def snapshot_hosts(self) -> list[Host]:
        with self._lock:
            return list(self.hosts.values())

    def snapshot_sessions(self) -> list[Session]:
        with self._lock:
            return list(self.sessions.values())

    def snapshot_credentials(self) -> list[Credential]:
        with self._lock:
            return list(self.credentials)

    def snapshot_files(self) -> list[FileArtifact]:
        with self._lock:
            return list(self.files)

    def snapshot_dns(self) -> list[DnsEvent]:
        with self._lock:
            return list(self.dns_events)

    def snapshot_alerts(self) -> list[Alert]:
        with self._lock:
            return list(self.alerts)

    def snapshot_emails(self) -> list[EmailArtifact]:
        with self._lock:
            return list(self.emails)

    def snapshot_timeline(self) -> list[TimelineEvent]:
        with self._lock:
            return list(self.timeline)

    def reset(self) -> None:
        with self._lock:
            self.hosts.clear()
            self.sessions.clear()
            self.credentials.clear()
            self.files.clear()
            self.dns_events.clear()
            self.alerts.clear()
            self.emails.clear()
            self.timeline.clear()
            self.ip_to_sessions.clear()
            self.ip_to_dns.clear()
            self.ip_to_files.clear()
            self.ip_to_creds.clear()
            self.ip_to_alerts.clear()
            self.ip_to_emails.clear()
