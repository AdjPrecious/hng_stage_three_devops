"""
monitor.py — Continuously tails the Nginx JSON access log line by line.
"""

import json
import os
import time
import queue
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    source_ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    response_size: int
    raw: str = field(repr=False, default="")

    @property
    def is_error(self) -> bool:
        return self.status >= 400


def _resolve_ip(data: dict) -> str:
    """
    Pick the best IP from the log entry.

    Priority:
    1. X-Forwarded-For leftmost IP (real external client)
    2. real_ip / remote_addr (direct Docker connection)
    3. unknown fallback
    """
    xff = data.get("source_ip", "").strip()
    if xff and xff not in ("-", "", "unknown"):
        candidate = xff.split(",")[0].strip()
        if candidate:
            return candidate

    real_ip = data.get("real_ip", "").strip()
    if real_ip and real_ip not in ("-", "", "unknown"):
        return real_ip

    return "unknown"


def parse_log_line(line: str) -> Optional[LogEntry]:
    """
    Parse one JSON log line from Nginx.
    Handles external traffic (X-Forwarded-For)
    and internal Docker traffic (remote_addr).
    """
    line = line.strip()
    if not line:
        return None

    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        logger.debug("Skipping non-JSON log line: %s", line[:120])
        return None

    try:
        ts_raw = data.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_raw)
        except (ValueError, TypeError):
            ts = datetime.utcnow()

        source_ip = _resolve_ip(data)

        if source_ip == "unknown":
            logger.debug("Skipping log entry with no resolvable IP")
            return None

        return LogEntry(
            source_ip=source_ip,
            timestamp=ts,
            method=str(data.get("method", "-")),
            path=str(data.get("path", "/")),
            status=int(data.get("status", 0)),
            response_size=int(data.get("response_size", 0)),
            raw=line,
        )
    except (KeyError, ValueError, TypeError) as exc:
        logger.warning("Malformed log entry (%s): %s", exc, line[:120])
        return None


class LogMonitor:
    """
    Tails a file in real time using seek-to-end then readline loop.
    Handles log rotation by detecting inode changes.
    """

    def __init__(self, log_path: str, out_queue: queue.Queue, poll_interval: float = 0.1):
        self.log_path = log_path
        self.out_queue = out_queue
        self.poll_interval = poll_interval
        self._running = False
        self._lines_processed = 0

    def start(self) -> None:
        """Block and tail the log file until stop() is called."""
        self._running = True
        logger.info("LogMonitor starting — tailing %s", self.log_path)

        while self._running:
            try:
                self._tail()
            except FileNotFoundError:
                logger.warning("Log file not found: %s — retrying in 2s", self.log_path)
                time.sleep(2)
            except Exception as exc:
                logger.error("LogMonitor error: %s — restarting in 1s", exc)
                time.sleep(1)

    def stop(self) -> None:
        self._running = False

    @property
    def lines_processed(self) -> int:
        return self._lines_processed

    def _tail(self) -> None:
        """Open the file and read new lines indefinitely."""
        with open(self.log_path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, os.SEEK_END)
            logger.info("Seeked to EOF (%d bytes) — waiting for new log lines.", fh.tell())

            while self._running:
                line = fh.readline()

                if not line:
                    time.sleep(self.poll_interval)
                    if self._file_rotated(fh):
                        logger.info("Log rotation detected — reopening %s", self.log_path)
                        return
                    continue

                entry = parse_log_line(line)
                if entry is not None:
                    self._lines_processed += 1
                    try:
                        self.out_queue.put_nowait(entry)
                    except queue.Full:
                        logger.warning("Queue full — dropping entry from %s", entry.source_ip)

    def _file_rotated(self, fh) -> bool:
        """Detect log rotation by comparing inodes."""
        try:
            disk_inode = os.stat(self.log_path).st_ino
            open_inode = os.fstat(fh.fileno()).st_ino
            return disk_inode != open_inode
        except OSError:
            return True