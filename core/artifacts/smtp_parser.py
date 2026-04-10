"""SMTP artifact parser: emails, credentials, attachments."""
from __future__ import annotations
import base64
import email
import re
from email.message import Message
from typing import Iterator

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _decode_header_value(value: str) -> str:
    from email.header import decode_header
    parts = decode_header(value)
    result = []
    for part, charset in parts:
        if isinstance(part, bytes):
            result.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            result.append(part)
    return "".join(result)


def parse_smtp_payload(payload: bytes, src_ip: str, dst_ip: str,
                        ts: float, session_id: str) -> dict:
    """Parse SMTP payload. Returns dict with email data and extracted creds."""
    result: dict = {
        "email": None,
        "creds": [],
        "attachments": [],  # list of {filename, data}
    }

    lines = payload.replace(b"\r\n", b"\n").split(b"\n")
    sender = ""
    receiver = ""
    in_data = False
    data_lines: list[bytes] = []
    auth_state = None
    auth_username = None

    for line in lines:
        line_s = line.decode("utf-8", errors="replace").strip()
        line_upper = line_s.upper()

        if line_upper.startswith("MAIL FROM:"):
            m = re.search(r"<([^>]+)>", line_s)
            sender = m.group(1) if m else line_s[10:].strip()

        elif line_upper.startswith("RCPT TO:"):
            m = re.search(r"<([^>]+)>", line_s)
            receiver = m.group(1) if m else line_s[8:].strip()

        elif line_upper.startswith("AUTH LOGIN"):
            auth_state = "user"

        elif auth_state == "user" and not line_upper.startswith("AUTH"):
            try:
                auth_username = base64.b64decode(line_s).decode("utf-8", errors="replace")
            except Exception:
                auth_username = line_s
            auth_state = "pass"

        elif auth_state == "pass":
            try:
                pwd = base64.b64decode(line_s).decode("utf-8", errors="replace")
            except Exception:
                pwd = line_s
            result["creds"].append({
                "proto": "SMTP",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "username": auth_username or "",
                "password": pwd,
                "cred_type": "SMTPAuth",
                "timestamp": ts,
                "session_id": session_id,
            })
            auth_state = None
            auth_username = None

        elif line_upper == "DATA" or line_upper.startswith("354 "):
            in_data = True

        elif in_data:
            if line_s == ".":
                in_data = False
                # Parse collected DATA
                raw_data = b"\n".join(data_lines)
                _parse_email_data(raw_data, sender, receiver, src_ip, dst_ip,
                                  ts, session_id, result)
            else:
                # Remove dot-stuffing
                if line.startswith(b".."):
                    line = line[1:]
                data_lines.append(line)

    return result


def _parse_email_data(raw: bytes, sender: str, receiver: str,
                       src_ip: str, dst_ip: str, ts: float,
                       session_id: str, result: dict) -> None:
    try:
        msg: Message = email.message_from_bytes(raw)
    except Exception:
        return

    subject = _decode_header_value(msg.get("Subject", ""))
    from_hdr = _decode_header_value(msg.get("From", sender))
    to_hdr = _decode_header_value(msg.get("To", receiver))

    body_preview = ""
    extracted_urls: list[str] = []
    attachments_count = 0
    attachment_refs: list[str] = []

    for part in msg.walk():
        ct = part.get_content_type()
        disposition = part.get("Content-Disposition", "")
        if "attachment" in disposition:
            attachments_count += 1
            fn = part.get_filename() or f"attachment_{attachments_count}"
            payload_bytes = part.get_payload(decode=True) or b""
            result["attachments"].append({"filename": fn, "data": payload_bytes})
            attachment_refs.append(fn)
        elif ct in ("text/plain", "text/html") and not body_preview:
            raw_body = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            body_text = raw_body.decode(charset, errors="replace")
            body_preview = body_text[:500]
            extracted_urls = _URL_RE.findall(body_text)

    result["email"] = {
        "ts": ts,
        "src_ip": src_ip,
        "sender": from_hdr or sender,
        "receiver": to_hdr or receiver,
        "subject": subject,
        "body_preview": body_preview,
        "attachments_count": attachments_count,
        "attachment_refs": attachment_refs,
        "extracted_urls": extracted_urls[:50],
        "related_session_id": session_id,
    }
