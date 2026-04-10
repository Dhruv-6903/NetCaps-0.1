"""File carver: saves extracted file data to disk, computes hashes."""
from __future__ import annotations
import hashlib
from pathlib import Path

from core.data_model import FileArtifact, build_file_search


def carve_file(data: bytes, filename: str, file_type: str, proto: str,
               src_ip: str, dst_ip: str, ts: float, cases_dir: str,
               session_id: str = "") -> FileArtifact | None:
    if not data:
        return None

    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    out_dir = Path(cases_dir) / "files"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Sanitise filename
    safe_name = "".join(c if c.isalnum() or c in "._- " else "_" for c in filename).strip()
    if not safe_name:
        safe_name = md5[:16]
    out_path = out_dir / f"{md5[:8]}_{safe_name}"

    try:
        out_path.write_bytes(data)
    except Exception:
        return None

    fa = FileArtifact(
        filename=filename,
        file_type=file_type,
        size=len(data),
        md5=md5,
        sha256=sha256,
        proto=proto,
        src_ip=src_ip,
        dst_ip=dst_ip,
        timestamp=ts,
        saved_path=str(out_path),
    )
    fa._search_str = build_file_search(fa)
    return fa
