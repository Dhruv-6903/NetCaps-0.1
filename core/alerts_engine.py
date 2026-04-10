"""Built-in alert rules engine."""
from __future__ import annotations
import math
import time
from collections import defaultdict

import config
from core.data_model import Alert, build_alert_search


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class AlertsEngine:
    def __init__(self, cfg: dict | None = None) -> None:
        self._cfg = cfg or config.get()
        self._alerts: list[Alert] = []

        # Port scan tracking: src_ip -> list of (ts, dst_port)
        self._port_scan: dict[str, list[tuple[float, int]]] = defaultdict(list)
        # Brute force: (src_ip, dst_ip) -> list of ts
        self._brute_force: dict[tuple[str, str], list[float]] = defaultdict(list)
        # ICMP flood: src_ip -> list of ts
        self._icmp_flood: dict[str, list[float]] = defaultdict(list)
        # NXDOMAIN: src_ip -> list of ts
        self._nxdomain: dict[str, list[float]] = defaultdict(list)
        # Emitted alert dedup keys
        self._emitted: set[str] = set()

    @property
    def alerts(self) -> list[Alert]:
        return self._alerts

    def _add_alert(self, alert: Alert) -> Alert | None:
        dedup_key = f"{alert.rule_id}:{alert.src_ip}:{alert.dst_ip}"
        if dedup_key in self._emitted:
            return None
        self._emitted.add(dedup_key)
        alert._search_str = build_alert_search(alert)
        self._alerts.append(alert)
        return alert

    # ------------------------------------------------------------------
    # Rule 1 – PORT_SCAN
    # ------------------------------------------------------------------
    def check_port_scan(self, ts: float, src_ip: str, dst_port: int) -> Alert | None:
        cfg = self._cfg
        window = cfg.get("alert_port_scan_window", 60)
        threshold = cfg.get("alert_port_scan_ports", 20)

        entries = self._port_scan[src_ip]
        entries.append((ts, dst_port))
        # Trim old
        cutoff = ts - window
        self._port_scan[src_ip] = [e for e in entries if e[0] >= cutoff]
        distinct = len(set(e[1] for e in self._port_scan[src_ip]))
        if distinct >= threshold:
            alert = Alert(
                severity="High",
                rule_id="PORT_SCAN",
                rule_name="Port Scan Detected",
                src_ip=src_ip,
                description=f"{distinct} distinct ports scanned in {window}s",
                ts=ts,
            )
            return self._add_alert(alert)
        return None

    # ------------------------------------------------------------------
    # Rule 2 – BRUTE_FORCE
    # ------------------------------------------------------------------
    def check_brute_force(self, ts: float, src_ip: str, dst_ip: str) -> Alert | None:
        cfg = self._cfg
        window = cfg.get("alert_brute_force_window", 60)
        threshold = cfg.get("alert_brute_force_attempts", 5)

        key = (src_ip, dst_ip)
        entries = self._brute_force[key]
        entries.append(ts)
        cutoff = ts - window
        self._brute_force[key] = [t for t in entries if t >= cutoff]
        count = len(self._brute_force[key])
        if count >= threshold:
            alert = Alert(
                severity="High",
                rule_id="BRUTE_FORCE",
                rule_name="Brute Force Attempt",
                src_ip=src_ip,
                dst_ip=dst_ip,
                description=f"{count} credential events in {window}s",
                ts=ts,
            )
            return self._add_alert(alert)
        return None

    # ------------------------------------------------------------------
    # Rule 3 – LARGE_TRANSFER
    # ------------------------------------------------------------------
    def check_large_transfer(self, ts: float, src_ip: str, dst_ip: str,
                              total_bytes: int, session_id: str) -> Alert | None:
        threshold_mb = self._cfg.get("alert_large_transfer_mb", 100)
        if total_bytes >= threshold_mb * 1024 * 1024:
            alert = Alert(
                severity="Medium",
                rule_id="LARGE_TRANSFER",
                rule_name="Large Data Transfer",
                src_ip=src_ip,
                dst_ip=dst_ip,
                description=f"Session transferred {total_bytes // 1024 // 1024} MB",
                ts=ts,
                related_session_id=session_id,
            )
            return self._add_alert(alert)
        return None

    # ------------------------------------------------------------------
    # Rule 4 – SUSPICIOUS_DNS
    # ------------------------------------------------------------------
    def check_suspicious_dns(self, ts: float, src_ip: str, domain: str,
                               status: str) -> Alert | None:
        alerts = []
        # NXDOMAIN spike
        if status == "NXDOMAIN":
            entries = self._nxdomain[src_ip]
            entries.append(ts)
            cutoff = ts - 30
            self._nxdomain[src_ip] = [t for t in entries if t >= cutoff]
            if len(self._nxdomain[src_ip]) > 10:
                label = domain.split(".")[0] if domain else domain
                alert = Alert(
                    severity="Medium",
                    rule_id="SUSPICIOUS_DNS_NXDOMAIN",
                    rule_name="NXDOMAIN Spike",
                    src_ip=src_ip,
                    description=f">{len(self._nxdomain[src_ip])} NXDOMAIN in 30s",
                    ts=ts,
                )
                a = self._add_alert(alert)
                if a:
                    alerts.append(a)

        # High entropy domain
        label = domain.split(".")[0] if domain else ""
        if label and _entropy(label) > 3.5:
            alert = Alert(
                severity="Medium",
                rule_id="SUSPICIOUS_DNS_ENTROPY",
                rule_name="High Entropy Domain",
                src_ip=src_ip,
                description=f"High entropy domain: {domain}",
                ts=ts,
            )
            a = self._add_alert(alert)
            if a:
                alerts.append(a)

        return alerts[0] if alerts else None

    # ------------------------------------------------------------------
    # Rule 5 – CRED_EXPOSURE
    # ------------------------------------------------------------------
    def check_cred_exposure(self, ts: float, src_ip: str, dst_ip: str,
                             proto: str, session_id: str) -> Alert | None:
        alert = Alert(
            severity="Medium",
            rule_id="CRED_EXPOSURE",
            rule_name="Credential Exposure",
            src_ip=src_ip,
            dst_ip=dst_ip,
            description=f"Credentials transmitted in plaintext ({proto})",
            ts=ts,
            related_session_id=session_id,
        )
        return self._add_alert(alert)

    # ------------------------------------------------------------------
    # Rule 6 – ICMP_FLOOD
    # ------------------------------------------------------------------
    def check_icmp_flood(self, ts: float, src_ip: str) -> Alert | None:
        cfg = self._cfg
        window = cfg.get("alert_icmp_flood_window", 10)
        threshold = cfg.get("alert_icmp_flood_count", 100)

        entries = self._icmp_flood[src_ip]
        entries.append(ts)
        cutoff = ts - window
        self._icmp_flood[src_ip] = [t for t in entries if t >= cutoff]
        count = len(self._icmp_flood[src_ip])
        if count >= threshold:
            alert = Alert(
                severity="High",
                rule_id="ICMP_FLOOD",
                rule_name="ICMP Flood",
                src_ip=src_ip,
                description=f"{count} ICMP packets in {window}s",
                ts=ts,
            )
            return self._add_alert(alert)
        return None

    # ------------------------------------------------------------------
    # Rule 7 – DATA_EXFIL
    # ------------------------------------------------------------------
    def check_data_exfil(self, ts: float, src_ip: str, dst_ip: str,
                          bytes_sent: int, session_id: str) -> Alert | None:
        if bytes_sent >= 50 * 1024 * 1024:
            alert = Alert(
                severity="High",
                rule_id="DATA_EXFIL",
                rule_name="Possible Data Exfiltration",
                src_ip=src_ip,
                dst_ip=dst_ip,
                description=f"Large upload: {bytes_sent // 1024 // 1024} MB sent",
                ts=ts,
                related_session_id=session_id,
            )
            return self._add_alert(alert)
        return None
