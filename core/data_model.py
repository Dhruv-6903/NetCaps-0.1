"""Core data models for NetCaps."""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostnames: list = field(default_factory=list)
    country: str = ""
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets: int = 0
    top_protocol: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    _search_str: str = ""


@dataclass
class Session:
    session_id: str
    proto: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    state: str = "NEW"
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets: int = 0
    duration: float = 0.0
    start_time: float = 0.0
    end_time: float = 0.0
    payload_client: bytes = field(default_factory=bytes)
    payload_server: bytes = field(default_factory=bytes)
    truncated: bool = False
    _search_str: str = ""


@dataclass
class Credential:
    proto: str
    src_ip: str
    dst_ip: str
    username: str
    password: str
    email_id: str = ""
    cred_type: str = ""
    timestamp: float = 0.0
    session_id: str = ""
    _search_str: str = ""


@dataclass
class FileArtifact:
    filename: str
    file_type: str
    size: int
    md5: str
    sha256: str
    proto: str
    src_ip: str
    dst_ip: str
    timestamp: float
    saved_path: str
    vt_status: str = "Unknown"
    vt_ratio: str = ""
    vt_last_checked: float = 0.0
    _search_str: str = ""


@dataclass
class DnsEvent:
    ts: float
    src_ip: str
    query: str
    qtype: str
    responses: list
    status: str
    anomaly_flag: bool = False
    anomaly_reason: str = ""
    _search_str: str = ""


@dataclass
class Alert:
    severity: str  # Low / Medium / High
    rule_id: str
    rule_name: str
    src_ip: str
    dst_ip: str = ""
    description: str = ""
    ts: float = 0.0
    related_session_id: str = ""
    _search_str: str = ""


@dataclass
class EmailArtifact:
    ts: float
    src_ip: str
    sender: str
    receiver: str
    subject: str
    body_preview: str
    attachments_count: int = 0
    attachment_refs: list = field(default_factory=list)
    extracted_urls: list = field(default_factory=list)
    related_session_id: str = ""
    _search_str: str = ""


@dataclass
class TimelineEvent:
    ts: float
    event_type: str  # DNS/Session/File/Credential/Alert/Email
    description: str
    src_ip: str = ""
    dst_ip: str = ""
    link_type: str = ""
    link_id: str = ""
    _search_str: str = ""


def _compute_search(*parts: object) -> str:
    return " ".join(str(p) for p in parts).lower()


def build_host_search(h: Host) -> str:
    return _compute_search(h.ip, h.mac, h.vendor, " ".join(h.hostnames), h.country, h.top_protocol)


def build_session_search(s: Session) -> str:
    return _compute_search(s.session_id, s.proto, s.src_ip, s.src_port, s.dst_ip, s.dst_port, s.state)


def build_credential_search(c: Credential) -> str:
    return _compute_search(c.proto, c.src_ip, c.dst_ip, c.username, c.email_id, c.cred_type)


def build_file_search(f: FileArtifact) -> str:
    return _compute_search(f.filename, f.file_type, f.proto, f.src_ip, f.dst_ip, f.md5, f.sha256, f.vt_status)


def build_dns_search(d: DnsEvent) -> str:
    return _compute_search(d.src_ip, d.query, d.qtype, d.status, d.anomaly_reason, " ".join(str(r) for r in d.responses))


def build_alert_search(a: Alert) -> str:
    return _compute_search(a.severity, a.rule_id, a.rule_name, a.src_ip, a.dst_ip, a.description)


def build_email_search(e: EmailArtifact) -> str:
    return _compute_search(e.src_ip, e.sender, e.receiver, e.subject, e.body_preview)


def build_timeline_search(t: TimelineEvent) -> str:
    return _compute_search(t.event_type, t.description, t.src_ip, t.dst_ip, t.link_type)
