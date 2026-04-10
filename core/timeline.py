"""Unified timeline builder."""
from __future__ import annotations
from core.data_model import (
    TimelineEvent, DnsEvent, Session, Credential, FileArtifact,
    Alert, EmailArtifact, build_timeline_search,
)


def from_dns(evt: DnsEvent) -> TimelineEvent:
    desc = f"DNS {evt.qtype} {evt.query} -> {', '.join(str(r) for r in evt.responses[:3])} [{evt.status}]"
    if evt.anomaly_flag:
        desc += f" ⚠ {evt.anomaly_reason}"
    t = TimelineEvent(
        ts=evt.ts,
        event_type="DNS",
        description=desc,
        src_ip=evt.src_ip,
        link_type="dns",
        link_id=evt.query,
    )
    t._search_str = build_timeline_search(t)
    return t


def from_session(s: Session) -> TimelineEvent:
    size = (s.bytes_sent + s.bytes_recv) / 1024
    unit = "KB"
    if size > 1024:
        size /= 1024
        unit = "MB"
    desc = f"{s.proto} {s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port} [{s.state}] {size:.1f}{unit}"
    t = TimelineEvent(
        ts=s.start_time,
        event_type="Session",
        description=desc,
        src_ip=s.src_ip,
        dst_ip=s.dst_ip,
        link_type="session",
        link_id=s.session_id,
    )
    t._search_str = build_timeline_search(t)
    return t


def from_credential(c: Credential) -> TimelineEvent:
    desc = f"Credential [{c.proto}] {c.username} @ {c.dst_ip}"
    t = TimelineEvent(
        ts=c.timestamp,
        event_type="Credential",
        description=desc,
        src_ip=c.src_ip,
        dst_ip=c.dst_ip,
        link_type="credential",
        link_id=c.session_id,
    )
    t._search_str = build_timeline_search(t)
    return t


def from_file(f: FileArtifact) -> TimelineEvent:
    desc = f"File [{f.proto}] {f.filename} ({f.size} bytes) from {f.src_ip}"
    t = TimelineEvent(
        ts=f.timestamp,
        event_type="File",
        description=desc,
        src_ip=f.src_ip,
        dst_ip=f.dst_ip,
        link_type="file",
        link_id=f.saved_path,
    )
    t._search_str = build_timeline_search(t)
    return t


def from_alert(a: Alert) -> TimelineEvent:
    desc = f"[{a.severity}] {a.rule_name}: {a.description}"
    t = TimelineEvent(
        ts=a.ts,
        event_type="Alert",
        description=desc,
        src_ip=a.src_ip,
        dst_ip=a.dst_ip,
        link_type="alert",
        link_id=a.rule_id,
    )
    t._search_str = build_timeline_search(t)
    return t


def from_email(e: EmailArtifact) -> TimelineEvent:
    desc = f"Email {e.sender} → {e.receiver}: {e.subject}"
    t = TimelineEvent(
        ts=e.ts,
        event_type="Email",
        description=desc,
        src_ip=e.src_ip,
        link_type="email",
        link_id=e.related_session_id,
    )
    t._search_str = build_timeline_search(t)
    return t
