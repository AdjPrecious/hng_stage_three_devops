"""
notifier.py — Slack webhook notifications.

All alerts include: condition, current_rate, baseline, timestamp,
and ban duration (for ban events).

We use a background queue so Slack calls never block the detection
hot-path.  If Slack is unreachable the message is dropped with a
warning — we never sacrifice detection latency for alerting.
"""

import json
import logging
import queue
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# Timeout for each Slack HTTP request (seconds)
SLACK_TIMEOUT = 5


class Notifier:
    """
    Sends Slack messages asynchronously via a background worker thread.

    Parameters
    ----------
    webhook_url : Slack Incoming Webhook URL (from config / env)
    """

    def __init__(self, webhook_url: str):
        self._webhook = webhook_url
        self._queue: queue.Queue = queue.Queue(maxsize=200)
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._worker, daemon=True, name="SlackThread")
        self._thread.start()
        logger.info("Notifier started — Slack alerts queued asynchronously.")

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # Public send helpers
    # ------------------------------------------------------------------

    def send_ban(self, record) -> None:
        """Send a Slack message when an IP is banned."""
        duration_str = (
            "permanent" if record.duration == -1
            else self._format_duration(record.duration)
        )
        text = (
            f":rotating_light: *IP BANNED*\n"
            f"• *IP:* `{record.ip}`\n"
            f"• *Reason:* {record.event_condition}\n"
            f"• *Ban duration:* {duration_str}\n"
            f"• *Strike:* #{record.strike}\n"
            f"• *Time:* {self._now_iso()}"
        )
        self._enqueue(text)

    def send_unban(self, record) -> None:
        """Send a Slack message when an IP is unbanned."""
        text = (
            f":white_check_mark: *IP UNBANNED*\n"
            f"• *IP:* `{record.ip}`\n"
            f"• *Strike was:* #{record.strike}\n"
            f"• *Time:* {self._now_iso()}"
        )
        self._enqueue(text)

    def send_ip_anomaly(self, event) -> None:
        """Send a Slack message for an IP anomaly (just before/after ban)."""
        text = (
            f":warning: *IP ANOMALY DETECTED*\n"
            f"• *IP:* `{event.ip}`\n"
            f"• *Condition:* {event.condition}\n"
            f"• *Current rate:* {event.current_rate:.2f} req/s\n"
            f"• *Baseline mean:* {event.baseline.effective_mean:.2f} req/s "
            f"(stddev={event.baseline.effective_stddev:.2f})\n"
            f"• *Z-score:* {event.zscore:.2f}\n"
            f"• *Error surge:* {'yes' if event.error_surge else 'no'}\n"
            f"• *Time:* {self._now_iso()}"
        )
        self._enqueue(text)

    def send_global_anomaly(self, event) -> None:
        """Send a Slack message for a global traffic spike."""
        text = (
            f":globe_with_meridians: *GLOBAL TRAFFIC ANOMALY*\n"
            f"• *Condition:* {event.condition}\n"
            f"• *Current rate:* {event.current_rate:.2f} req/s\n"
            f"• *Baseline mean:* {event.baseline.effective_mean:.2f} req/s "
            f"(stddev={event.baseline.effective_stddev:.2f})\n"
            f"• *Z-score:* {event.zscore:.2f}\n"
            f"• *Time:* {self._now_iso()}"
        )
        self._enqueue(text)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _enqueue(self, text: str) -> None:
        try:
            self._queue.put_nowait({"text": text})
        except queue.Full:
            logger.warning("Slack queue full — dropping alert.")

    def _worker(self) -> None:
        """Drain the queue and POST to Slack."""
        while self._running:
            try:
                payload = self._queue.get(timeout=1)
            except queue.Empty:
                continue

            self._post(payload)
            self._queue.task_done()

    def _post(self, payload: dict) -> None:
        if not self._webhook:
            logger.debug("No Slack webhook configured — skipping alert.")
            return

        try:
            resp = requests.post(
                self._webhook,
                json=payload,
                timeout=SLACK_TIMEOUT,
            )
            if resp.status_code != 200:
                logger.warning(
                    "Slack returned HTTP %d: %s",
                    resp.status_code, resp.text[:200],
                )
        except requests.RequestException as exc:
            logger.warning("Slack POST failed: %s", exc)

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    @staticmethod
    def _format_duration(seconds: int) -> str:
        if seconds < 60:
            return f"{seconds}s"
        if seconds < 3600:
            return f"{seconds // 60}m"
        return f"{seconds // 3600}h"
