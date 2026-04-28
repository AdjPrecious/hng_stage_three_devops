"""
blocker.py — iptables blocking and auto-unban with backoff schedule.

Ban lifecycle
-------------
1. Detector fires → blocker.block(ip, event) is called.
2. We check the IP's strike count to determine the ban duration:
      strike 1 → 10 min
      strike 2 → 30 min
      strike 3 → 2 hours
      strike 4+ → permanent (-1)
3. An iptables DROP rule is inserted (with a 10-second timeout for the
   shell command).
4. The ban is recorded in _bans dict and the Notifier is called.
5. A background thread wakes up every 30 s, checks which bans have
   expired, removes the iptables rule, increments the strike, and notifies.

Thread safety
-------------
All mutations to _bans and _strikes go through self._lock.
The unban thread reads _bans under the lock, releases it before
running iptables (a slow syscall), then re-acquires to delete the entry.
"""

import logging
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BanRecord:
    ip: str
    banned_at: float          # Unix timestamp
    duration: int             # seconds; -1 = permanent
    strike: int               # 1-indexed ban number for this IP
    event_condition: str      # human-readable reason


class Blocker:
    """
    Manages iptables bans with a progressive backoff unban schedule.

    Parameters
    ----------
    cfg          : blocking subsection of config.yaml
    audit_fn     : callable(action, detail) for audit log
    notifier_fn  : callable(action, ban_record) for Slack alerts
    """

    def __init__(
        self,
        cfg: dict,
        audit_fn: Callable = None,
        notifier_fn: Callable = None,
    ):
        raw_durations = cfg.get("ban_durations", [600, 1800, 7200, -1])
        self._durations: List[int] = raw_durations
        self._chain: str = cfg.get("iptables_chain", "INPUT")
        self._block_timeout: int = cfg.get("block_timeout", 10)

        self._audit = audit_fn or (lambda *a, **kw: None)
        self._notify = notifier_fn or (lambda *a, **kw: None)

        self._lock = threading.Lock()
        # ip → BanRecord
        self._bans: Dict[str, BanRecord] = {}
        # ip → number of times this IP has been banned (persists across unbans)
        self._strikes: Dict[str, int] = {}

        self._running = False
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(
            target=self._unban_loop, daemon=True, name="UnbanThread"
        )
        self._thread.start()
        logger.info("Blocker started — unban thread running.")

    def stop(self) -> None:
        self._running = False

    def block(self, ip: str, condition: str) -> bool:
        """
        Add an iptables DROP rule for ip.

        Returns True if the rule was successfully added, False otherwise
        (e.g. already banned, or iptables command failed).
        """
        with self._lock:
            if ip in self._bans:
                logger.debug("IP %s is already banned — skipping.", ip)
                return False

            # Determine ban duration from strike count.
            strike = self._strikes.get(ip, 0) + 1
            self._strikes[ip] = strike
            duration_idx = min(strike - 1, len(self._durations) - 1)
            duration = self._durations[duration_idx]

            record = BanRecord(
                ip=ip,
                banned_at=time.time(),
                duration=duration,
                strike=strike,
                event_condition=condition,
            )
            self._bans[ip] = record

        # Add iptables rule outside the lock — it's a slow syscall.
        success = self._iptables_add(ip)
        if not success:
            with self._lock:
                self._bans.pop(ip, None)
            return False

        duration_str = "permanent" if duration == -1 else f"{duration}s"
        logger.warning(
            "BANNED %s | strike=%d | duration=%s | reason=%s",
            ip, strike, duration_str, condition,
        )

        # Audit
        self._audit(
            "BAN",
            {
                "ip": ip,
                "strike": strike,
                "duration": duration_str,
                "condition": condition,
            }
        )

        # Slack notification
        self._notify("BAN", record)

        return True

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self._bans

    def get_banned_ips(self) -> List[BanRecord]:
        with self._lock:
            return list(self._bans.values())

    # ------------------------------------------------------------------
    # Unban loop
    # ------------------------------------------------------------------

    def _unban_loop(self) -> None:
        """Wake every 30 s and unban any IPs whose duration has expired."""
        while self._running:
            time.sleep(30)
            self._check_unbans()

    def _check_unbans(self) -> None:
        now = time.time()
        to_unban = []

        with self._lock:
            for ip, rec in list(self._bans.items()):
                if rec.duration == -1:
                    continue  # Permanent — never unban automatically.
                if now - rec.banned_at >= rec.duration:
                    to_unban.append(rec)

        for rec in to_unban:
            self._unban(rec)

    def _unban(self, rec: BanRecord) -> None:
        """Remove iptables rule and fire audit/notify."""
        ip = rec.ip
        success = self._iptables_remove(ip)
        if not success:
            logger.error("Failed to remove iptables rule for %s — keeping in ban list.", ip)
            return

        with self._lock:
            self._bans.pop(ip, None)

        logger.info("UNBANNED %s | strike=%d | was banned for %ds", ip, rec.strike, rec.duration)

        self._audit(
            "UNBAN",
            {
                "ip": ip,
                "strike": rec.strike,
                "was_duration": rec.duration,
                "banned_at": datetime.fromtimestamp(rec.banned_at, tz=timezone.utc).isoformat(),
            }
        )
        self._notify("UNBAN", rec)

    # ------------------------------------------------------------------
    # iptables helpers
    # ------------------------------------------------------------------

    def _iptables_add(self, ip: str) -> bool:
        """Insert a DROP rule at the top of the chain."""
        return self._run_iptables([
            "iptables", "-I", self._chain, "1",
            "-s", ip, "-j", "DROP",
            "-m", "comment", "--comment", f"hng-detector-ban"
        ])

    def _iptables_remove(self, ip: str) -> bool:
        """Delete the matching DROP rule."""
        return self._run_iptables([
            "iptables", "-D", self._chain,
            "-s", ip, "-j", "DROP",
            "-m", "comment", "--comment", f"hng-detector-ban"
        ])

    def _run_iptables(self, cmd: list) -> bool:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._block_timeout,
            )
            if result.returncode != 0:
                logger.error("iptables error: %s", result.stderr.strip())
                return False
            return True
        except subprocess.TimeoutExpired:
            logger.error("iptables command timed out after %ds: %s", self._block_timeout, cmd)
            return False
        except FileNotFoundError:
            logger.error("iptables not found — is it installed?")
            return False
        except Exception as exc:  # noqa: BLE001
            logger.error("Unexpected iptables error: %s", exc)
            return False
