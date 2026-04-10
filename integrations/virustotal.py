"""VirusTotal API v3 integration with rate-limited queue."""
from __future__ import annotations
import threading
import time
from typing import Callable

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

from core.data_model import FileArtifact


class VTClient:
    _BASE = "https://www.virustotal.com/api/v3/files"

    def __init__(self, api_key: str, delay: float = 15.0) -> None:
        self._api_key = api_key
        self._delay = delay
        self._queue: list[tuple[FileArtifact, Callable]] = []
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def enqueue(self, file_artifact: FileArtifact, callback: Callable) -> None:
        with self._lock:
            self._queue.append((file_artifact, callback))
        if self._thread is None or not self._thread.is_alive():
            self.start()

    def _worker(self) -> None:
        while not self._stop_event.is_set():
            item = None
            with self._lock:
                if self._queue:
                    item = self._queue.pop(0)
            if item is None:
                time.sleep(1.0)
                continue
            fa, callback = item
            self._check_file(fa, callback)
            # Rate-limit: pause between requests
            self._stop_event.wait(self._delay)

    def _check_file(self, fa: FileArtifact, callback: Callable) -> None:
        if not _HAS_REQUESTS or not self._api_key:
            fa.vt_status = "No API Key"
            callback(fa)
            return

        hash_val = fa.sha256 or fa.md5
        if not hash_val:
            fa.vt_status = "No Hash"
            callback(fa)
            return

        try:
            resp = _requests.get(
                f"{self._BASE}/{hash_val}",
                headers={"x-apikey": self._api_key},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get(
                    "last_analysis_stats", {}
                )
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())
                fa.vt_status = "Malicious" if malicious > 0 else "Clean"
                fa.vt_ratio = f"{malicious}/{total}"
                fa.vt_last_checked = time.time()
            elif resp.status_code == 404:
                fa.vt_status = "Not Found"
            elif resp.status_code == 401:
                fa.vt_status = "Unauthorized"
            else:
                fa.vt_status = f"Error {resp.status_code}"
        except Exception as exc:
            fa.vt_status = "Error"
        callback(fa)
