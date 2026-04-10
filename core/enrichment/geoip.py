"""GeoIP country lookup using maxminddb (optional)."""
from __future__ import annotations

_reader = None
_db_path: str = ""


def _load(path: str) -> None:
    global _reader, _db_path
    if path == _db_path and _reader is not None:
        return
    _db_path = path
    _reader = None
    if not path:
        return
    try:
        import maxminddb
        _reader = maxminddb.open_database(path)
    except Exception:
        _reader = None


def lookup_country(ip: str, db_path: str = "") -> str:
    global _reader
    if db_path:
        _load(db_path)
    if _reader is None:
        return "Unknown"
    try:
        rec = _reader.get(ip)
        if rec is None:
            return "Unknown"
        country = rec.get("country") or rec.get("registered_country") or {}
        names = country.get("names", {}) if isinstance(country, dict) else {}
        return names.get("en", "Unknown")
    except Exception:
        return "Unknown"
