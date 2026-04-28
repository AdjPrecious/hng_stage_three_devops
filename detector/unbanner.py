"""
unbanner.py — Thin wrapper that exposes manual unban capability.

The main unban logic lives in blocker.py (_unban_loop / _check_unbans).
This module provides:
  - A function the dashboard can call to manually unban an IP immediately.
  - A helper to query next-unban time for display purposes.
"""

import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)


class Unbanner:
    """
    Provides manual and scheduled unban operations backed by a Blocker instance.
    Blocker already runs its own auto-unban thread; Unbanner just provides
    the manual override surface.
    """

    def __init__(self, blocker):
        self._blocker = blocker

    def manual_unban(self, ip: str) -> bool:
        """
        Immediately unban an IP regardless of the backoff schedule.
        Returns True if the IP was banned and successfully removed.
        """
        from blocker import BanRecord  # avoid circular at module level

        with self._blocker._lock:
            record = self._blocker._bans.get(ip)

        if record is None:
            logger.info("manual_unban: %s is not currently banned.", ip)
            return False

        logger.info("Manual unban requested for %s.", ip)
        self._blocker._unban(record)
        return True

    def time_until_unban(self, ip: str) -> Optional[float]:
        """
        Returns seconds until the IP is auto-unbanned,
        or None if not banned / permanent.
        """
        with self._blocker._lock:
            rec = self._blocker._bans.get(ip)

        if rec is None:
            return None
        if rec.duration == -1:
            return None  # permanent

        elapsed = time.time() - rec.banned_at
        remaining = rec.duration - elapsed
        return max(0.0, remaining)
