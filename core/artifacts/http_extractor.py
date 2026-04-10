"""HTTP/1.x stream extractor: files, credentials."""
from __future__ import annotations
import base64
import gzip
import re
import urllib.parse
from typing import Iterator

import config

_CHUNK_RE = re.compile(rb"^([0-9a-fA-F]+)\r\n")


def _unchunk(data: bytes) -> bytes:
    out = bytearray()
    pos = 0
    while pos < len(data):
        m = _CHUNK_RE.match(data, pos)
        if not m:
            break
        size = int(m.group(1), 16)
        if size == 0:
            break
        pos = m.end()
        out.extend(data[pos : pos + size])
        pos += size + 2  # skip CRLF
    return bytes(out)


def _decompress(data: bytes, encoding: str) -> bytes:
    try:
        if "gzip" in encoding:
            return gzip.decompress(data)
        if "deflate" in encoding:
            import zlib
            return zlib.decompress(data)
    except Exception:
        pass
    return data


class HTTPExtractor:
    """Stateless HTTP/1.x extractor operating on reassembled payloads."""

    def extract_credentials(self, payload: bytes, src_ip: str, dst_ip: str,
                             ts: float, session_id: str) -> list[dict]:
        """Extract credentials from HTTP request payloads."""
        creds = []
        cred_fields = config.get().get("http_cred_fields", [])
        try:
            lines = payload.split(b"\r\n")
            headers_done = False
            header_lines = []
            body_start = 0
            for i, line in enumerate(lines):
                if line == b"":
                    headers_done = True
                    body_start = i + 1
                    break
                header_lines.append(line)

            # Authorization: Basic
            for hl in header_lines:
                if hl.lower().startswith(b"authorization: basic "):
                    encoded = hl[len(b"authorization: basic "):]
                    try:
                        decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
                        if ":" in decoded:
                            user, pwd = decoded.split(":", 1)
                            creds.append({
                                "proto": "HTTP",
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "username": user,
                                "password": pwd,
                                "cred_type": "BasicAuth",
                                "timestamp": ts,
                                "session_id": session_id,
                            })
                    except Exception:
                        pass

            # POST body form-urlencoded
            is_post = header_lines and header_lines[0].upper().startswith(b"POST ")
            content_type = b""
            for hl in header_lines:
                if hl.lower().startswith(b"content-type:"):
                    content_type = hl.lower()
            if is_post and b"application/x-www-form-urlencoded" in content_type:
                body = b"\r\n".join(lines[body_start:])
                try:
                    params = urllib.parse.parse_qs(body.decode("utf-8", errors="replace"),
                                                    keep_blank_values=True)
                    username, password = None, None
                    for k, v in params.items():
                        kl = k.lower()
                        for field in cred_fields:
                            if field in kl:
                                if any(x in kl for x in ("pass", "pwd")):
                                    password = v[0] if v else ""
                                else:
                                    username = v[0] if v else ""
                    if username or password:
                        creds.append({
                            "proto": "HTTP",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "username": username or "",
                            "password": password or "",
                            "cred_type": "FormPOST",
                            "timestamp": ts,
                            "session_id": session_id,
                        })
                except Exception:
                    pass
        except Exception:
            pass
        return creds

    def extract_files(self, payload: bytes, src_ip: str, dst_ip: str,
                       ts: float, session_id: str) -> list[dict]:
        """Extract files from HTTP response payloads."""
        results = []
        try:
            # Split header / body
            sep = payload.find(b"\r\n\r\n")
            if sep == -1:
                return results
            header_block = payload[:sep]
            body = payload[sep + 4:]
            header_lines = header_block.split(b"\r\n")

            status_line = header_lines[0] if header_lines else b""
            # Only process 200 responses
            if not status_line.startswith(b"HTTP/") or b" 200 " not in status_line:
                return results

            headers: dict[str, str] = {}
            for hl in header_lines[1:]:
                if b":" in hl:
                    k, _, v = hl.partition(b":")
                    headers[k.strip().lower().decode("utf-8", errors="replace")] = v.strip().decode("utf-8", errors="replace")

            transfer_encoding = headers.get("transfer-encoding", "")
            content_encoding = headers.get("content-encoding", "")
            content_disposition = headers.get("content-disposition", "")
            content_type = headers.get("content-type", "application/octet-stream")

            if "chunked" in transfer_encoding:
                body = _unchunk(body)
            if content_encoding:
                body = _decompress(body, content_encoding)

            filename = ""
            if content_disposition:
                m = re.search(r'filename="?([^";]+)"?', content_disposition, re.IGNORECASE)
                if m:
                    filename = m.group(1).strip()

            if not filename:
                return results

            results.append({
                "filename": filename,
                "file_type": content_type.split(";")[0].strip(),
                "data": body,
                "proto": "HTTP",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "timestamp": ts,
                "session_id": session_id,
            })
        except Exception:
            pass
        return results
