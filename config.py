"""Central configuration for NetCaps."""
import json
import os
from pathlib import Path

DEFAULT_CONFIG: dict = {
    "cases_dir": "cases",
    "vt_api_key": "",
    "vt_delay": 15.0,
    "session_payload_cap_mb": 10,
    "global_payload_cap_mb": 200,
    "alert_port_scan_ports": 20,
    "alert_port_scan_window": 60,
    "alert_brute_force_attempts": 5,
    "alert_brute_force_window": 60,
    "alert_large_transfer_mb": 100,
    "alert_icmp_flood_count": 100,
    "alert_icmp_flood_window": 10,
    "geoip_db_path": "",
    "http_cred_fields": [
        "user", "username", "email", "login",
        "pass", "password", "pwd",
    ],
}

_CONFIG_PATH = Path.home() / ".netcaps" / "config.json"
_current: dict = {}


def load() -> dict:
    global _current
    _current = dict(DEFAULT_CONFIG)
    if _CONFIG_PATH.exists():
        try:
            with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
                _current.update(json.load(f))
        except Exception:
            pass
    return _current


def save(cfg: dict) -> None:
    global _current
    _current = cfg
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def get() -> dict:
    if not _current:
        load()
    return _current


load()
