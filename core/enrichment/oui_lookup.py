"""Offline OUI vendor lookup with hardcoded common prefixes as fallback."""
from __future__ import annotations

# Top ~80 common vendor OUI prefixes (first 3 bytes of MAC, uppercase, no separators)
_OUI_TABLE: dict[str, str] = {
    "000C29": "VMware",
    "000D3A": "Microsoft",
    "000569": "VMware",
    "001C42": "Parallels",
    "080027": "Oracle VirtualBox",
    "525400": "QEMU/KVM",
    "0A0027": "Oracle VirtualBox",
    "00005E": "IANA",
    "0050C2": "IEEE",
    "001A2B": "Cisco",
    "0013C4": "Cisco",
    "001BD4": "Cisco",
    "002197": "Cisco",
    "0060B9": "Cisco",
    "009027": "Cisco",
    "0000F0": "Samsung",
    "002566": "Apple",
    "001451": "Apple",
    "0017F2": "Apple",
    "001B63": "Apple",
    "001CB3": "Apple",
    "001D4F": "Apple",
    "001EEA": "Apple",
    "001F5B": "Apple",
    "001FF3": "Apple",
    "0021E9": "Apple",
    "0023DF": "Apple",
    "002500": "Apple",
    "0026B9": "Apple",
    "0026BB": "Apple",
    "3C0754": "Apple",
    "A45E60": "Apple",
    "001B21": "Intel",
    "0013E8": "Intel",
    "000E35": "Intel",
    "001101": "Intel",
    "00188B": "Intel",
    "001AAD": "Intel",
    "001C25": "Intel",
    "001D69": "Intel",
    "001E64": "Intel",
    "001F3B": "Intel",
    "002170": "Intel",
    "002255": "Intel",
    "0024D7": "Intel",
    "002619": "Intel",
    "00236C": "Intel",
    "000E08": "Microsoft",
    "001DD8": "Microsoft",
    "002248": "Microsoft",
    "30B5C2": "Microsoft",
    "7845C4": "Microsoft",
    "001422": "Dell",
    "18FB7B": "Dell",
    "00188B": "Dell",
    "0019B9": "Dell",
    "001A4B": "Dell",
    "001DB8": "Dell",
    "001E4F": "Dell",
    "001FB2": "Dell",
    "002564": "Dell",
    "00B0D0": "Dell",
    "001217": "Hewlett-Packard",
    "001708": "Hewlett-Packard",
    "001A4B": "Hewlett-Packard",
    "001CC4": "Hewlett-Packard",
    "001E0B": "Hewlett-Packard",
    "001F29": "Hewlett-Packard",
    "0021F7": "Hewlett-Packard",
    "002264": "Hewlett-Packard",
    "00E0C4": "ASUS",
    "001731": "Netgear",
    "001EEA": "Netgear",
    "00226B": "Netgear",
    "001FE1": "TP-Link",
    "B8F8E1": "TP-Link",
    "EC086B": "TP-Link",
    "001D7E": "Linksys",
    "001E2A": "Linksys",
    "0050F2": "Microsoft (WPS)",
    "ACDE48": "Private",
    "000000": "Xerox",
    "FFFFFFFFFFFF": "Broadcast",
}


def _normalise_mac(mac: str) -> str:
    """Uppercase and remove separators, return first 6 hex chars."""
    cleaned = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    return cleaned[:6]


def lookup_vendor(mac: str, db_path: str = "") -> str:
    """Return vendor name for a MAC address."""
    if not mac:
        return "Unknown"

    prefix = _normalise_mac(mac)
    if not prefix or len(prefix) < 6:
        return "Unknown"

    # Try hardcoded table first
    vendor = _OUI_TABLE.get(prefix, "")
    if vendor:
        return vendor

    # If a path is given, try loading from a text OUI file (wireshark format)
    if db_path:
        try:
            return _lookup_from_file(prefix, db_path)
        except Exception:
            pass

    return "Unknown"


_file_cache: dict[str, dict[str, str]] = {}


def _lookup_from_file(prefix: str, path: str) -> str:
    global _file_cache
    if path not in _file_cache:
        table: dict[str, str] = {}
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 2)
                if len(parts) >= 2:
                    oui = parts[0].upper().replace(":", "").replace("-", "")[:6]
                    vendor = parts[2] if len(parts) > 2 else parts[1]
                    table[oui] = vendor
        _file_cache[path] = table
    return _file_cache[path].get(prefix, "Unknown")
