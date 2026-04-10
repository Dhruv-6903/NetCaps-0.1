"""FTP credential extractor."""
from __future__ import annotations


def parse_ftp_payload(payload: bytes, src_ip: str, dst_ip: str,
                       ts: float, session_id: str) -> list[dict]:
    """Parse FTP control channel and extract USER/PASS credentials."""
    creds = []
    username = None
    lines = payload.replace(b"\r\n", b"\n").split(b"\n")
    for line in lines:
        line = line.strip()
        if line.upper().startswith(b"USER "):
            username = line[5:].decode("utf-8", errors="replace").strip()
        elif line.upper().startswith(b"PASS ") and username is not None:
            password = line[5:].decode("utf-8", errors="replace").strip()
            creds.append({
                "proto": "FTP",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "username": username,
                "password": password,
                "cred_type": "FTPLogin",
                "timestamp": ts,
                "session_id": session_id,
            })
            username = None
    return creds
