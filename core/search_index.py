"""Global search index using precomputed _search_str fields."""
from __future__ import annotations
from core.data_model import (
    Host, Session, Credential, FileArtifact,
    DnsEvent, Alert, EmailArtifact, TimelineEvent,
)


def filter_list(items: list, term: str) -> list:
    """Return items whose _search_str contains the lowercased term."""
    if not term:
        return list(items)
    low = term.lower()
    return [item for item in items if low in item._search_str]


def filter_hosts(hosts: dict[str, Host], term: str) -> list[Host]:
    if not term:
        return list(hosts.values())
    low = term.lower()
    return [h for h in hosts.values() if low in h._search_str]


def filter_sessions(sessions: dict[str, Session], term: str) -> list[Session]:
    if not term:
        return list(sessions.values())
    low = term.lower()
    return [s for s in sessions.values() if low in s._search_str]
