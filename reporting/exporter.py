"""Report exporter: CSV, JSON, HTML, and attack summary."""
from __future__ import annotations
import csv
import json
import math
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.case_store import CaseStore


def _ts(ts: float) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class Exporter:
    def export_csv(self, tab_name: str, data: list[dict], filepath: str) -> None:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not data:
            path.write_text("")
            return
        keys = list(data[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)

    def export_json(self, case_store: CaseStore, filepath: str) -> None:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        def _serial(obj: Any) -> Any:
            if hasattr(obj, "__dataclass_fields__"):
                return {k: _serial(v) for k, v in vars(obj).items()
                        if not k.startswith("_")}
            if isinstance(obj, bytes):
                return obj.hex()
            if isinstance(obj, list):
                return [_serial(i) for i in obj]
            if isinstance(obj, dict):
                return {k: _serial(v) for k, v in obj.items()}
            return obj

        export = {
            "exported_at": _ts(time.time()),
            "hosts": _serial(case_store.snapshot_hosts()),
            "sessions": _serial(case_store.snapshot_sessions()),
            "credentials": _serial(case_store.snapshot_credentials()),
            "files": _serial(case_store.snapshot_files()),
            "dns_events": _serial(case_store.snapshot_dns()),
            "alerts": _serial(case_store.snapshot_alerts()),
            "emails": _serial(case_store.snapshot_emails()),
            "timeline": _serial(case_store.snapshot_timeline()),
        }
        path.write_text(json.dumps(export, indent=2), encoding="utf-8")

    def export_html(self, case_store: CaseStore, filepath: str) -> None:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        hosts = case_store.snapshot_hosts()
        sessions = case_store.snapshot_sessions()
        alerts = case_store.snapshot_alerts()
        creds = case_store.snapshot_credentials()
        files = case_store.snapshot_files()

        html = [
            "<!DOCTYPE html><html><head><meta charset='utf-8'>",
            "<title>NetCaps Report</title>",
            "<style>body{font-family:sans-serif;margin:20px} "
            "table{border-collapse:collapse;width:100%;margin-bottom:30px} "
            "th,td{border:1px solid #ccc;padding:6px 10px;text-align:left} "
            "th{background:#2c3e50;color:#fff} "
            "tr:nth-child(even){background:#f5f5f5} "
            "h2{color:#2c3e50}</style></head><body>",
            f"<h1>NetCaps Forensics Report</h1>",
            f"<p>Generated: {_ts(time.time())}</p>",
        ]

        def _table(title: str, rows: list, cols: list[str]) -> list[str]:
            out = [f"<h2>{title}</h2><table><tr>"]
            out.append("".join(f"<th>{c}</th>" for c in cols))
            out.append("</tr>")
            for row in rows:
                out.append("<tr>" + "".join(
                    f"<td>{str(getattr(row, c, '')).replace('<','&lt;').replace('>','&gt;')}</td>"
                    for c in cols
                ) + "</tr>")
            out.append("</table>")
            return out

        html += _table("Alerts", alerts,
                       ["severity", "rule_name", "src_ip", "dst_ip", "description"])
        html += _table("Hosts", hosts,
                       ["ip", "mac", "vendor", "country", "bytes_sent", "bytes_recv"])
        html += _table("Sessions", sessions[:500],
                       ["proto", "src_ip", "src_port", "dst_ip", "dst_port", "state",
                        "bytes_sent", "bytes_recv"])
        html += _table("Credentials", creds,
                       ["proto", "src_ip", "dst_ip", "username", "cred_type"])
        html += _table("Files", files,
                       ["filename", "file_type", "size", "md5", "proto", "vt_status"])

        html.append("</body></html>")
        path.write_text("\n".join(html), encoding="utf-8")

    def generate_attack_summary(self, case_store: CaseStore) -> str:
        alerts = case_store.snapshot_alerts()
        sessions = case_store.snapshot_sessions()
        creds = case_store.snapshot_credentials()
        files = case_store.snapshot_files()
        dns = case_store.snapshot_dns()

        high = [a for a in alerts if a.severity == "High"]
        medium = [a for a in alerts if a.severity == "Medium"]

        rule_counts: dict[str, int] = {}
        for a in alerts:
            rule_counts[a.rule_name] = rule_counts.get(a.rule_name, 0) + 1

        top_rules = sorted(rule_counts.items(), key=lambda x: -x[1])[:5]

        attacker_ips: set[str] = set()
        for a in high:
            attacker_ips.add(a.src_ip)

        lines = [
            "# NetCaps Attack Summary",
            f"\nGenerated: {_ts(time.time())}",
            f"\n## Overview",
            f"- Total alerts: {len(alerts)} ({len(high)} High, {len(medium)} Medium)",
            f"- Unique sessions: {len(sessions)}",
            f"- Credentials exposed: {len(creds)}",
            f"- Files extracted: {len(files)}",
            f"- DNS events: {len(dns)}",
        ]

        if top_rules:
            lines.append("\n## Top Alert Rules")
            for rule, count in top_rules:
                lines.append(f"- {rule}: {count}")

        if attacker_ips:
            lines.append(f"\n## Suspicious Source IPs (High-severity alerts)")
            for ip in sorted(attacker_ips):
                lines.append(f"- {ip}")

        if any(a.rule_id == "PORT_SCAN" for a in alerts):
            ps = [a for a in alerts if a.rule_id == "PORT_SCAN"]
            lines.append(f"\n## Port Scanning Activity")
            lines.append(f"Detected {len(ps)} port scan event(s). "
                         f"Source(s): {', '.join(set(a.src_ip for a in ps))}.")

        if any(a.rule_id == "BRUTE_FORCE" for a in alerts):
            bf = [a for a in alerts if a.rule_id == "BRUTE_FORCE"]
            lines.append(f"\n## Brute Force Attempts")
            lines.append(f"Detected {len(bf)} brute force event(s).")

        if any(a.rule_id in ("DATA_EXFIL", "LARGE_TRANSFER") for a in alerts):
            lines.append(f"\n## Data Transfer Anomalies")
            for a in alerts:
                if a.rule_id in ("DATA_EXFIL", "LARGE_TRANSFER"):
                    lines.append(f"- [{a.severity}] {a.description}")

        if creds:
            lines.append(f"\n## Exposed Credentials")
            for c in creds[:20]:
                lines.append(f"- {c.proto}: {c.username}@{c.dst_ip}")

        lines.append("\n---\n*Report generated by NetCaps*")
        return "\n".join(lines)
