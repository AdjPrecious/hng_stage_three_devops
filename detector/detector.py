"""
detector.py — Sliding window anomaly detection.

Sliding window structure
------------------------
Two deque-based windows are maintained simultaneously:

  _ip_windows:  dict[ip_str → deque[float]]
                Each deque holds the Unix timestamps of every request
                from that IP in the last WINDOW_SECONDS seconds.

  _global_window: deque[float]
                  Same idea but for ALL requests regardless of IP.

Eviction logic
--------------
Whenever a new request arrives we first pop timestamps from the LEFT
of the relevant deque(s) while the oldest timestamp is more than
WINDOW_SECONDS seconds ago.  Because timestamps are always appended
to the RIGHT in chronological order, the deque stays sorted and
eviction is O(k) — usually O(1) in practice.

After eviction len(deque) == current request count in the window.

Anomaly criteria (both must be checked; the one that fires first wins)
----------------------------------------------------------------------
  1. Z-score:  z = (rate - mean) / stddev  >  ZSCORE_THRESHOLD (default 3.0)
  2. Rate multiplier: rate  >  RATE_MULTIPLIER_THRESHOLD * mean  (default 5x)

Error surge
-----------
If an IP's 4xx/5xx rate for the current window is >= ERROR_SURGE_MULTIPLIER
x error_baseline_mean, we tighten both thresholds for that IP.
"""

import logging
import threading
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, Optional

from baseline import BaselineEngine, BaselineStats
from monitor import LogEntry

logger = logging.getLogger(__name__)


@dataclass
class AnomalyEvent:
    """Describes a detected anomaly — passed to the blocker and notifier."""
    kind: str
    ip: Optional[str]
    current_rate: float
    baseline: BaselineStats
    zscore: float
    condition: str
    fired_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error_surge: bool = False


class AnomalyDetector:
    """
    Consumes LogEntry objects and fires callbacks when anomalies are detected.
    """

    def __init__(
        self,
        cfg: dict,
        baseline: BaselineEngine,
        on_ip_anomaly: Callable[[AnomalyEvent], None],
        on_global_anomaly: Callable[[AnomalyEvent], None],
    ):
        # Load whitelist from config — these IPs are never banned
        self._whitelist = set(cfg.get("ip_whitelist", [
            "127.0.0.1",
            "::1",
            "172.18.0.1",
            "172.17.0.1",
            "10.0.0.1",
        ]))

        self._window_secs: int = cfg.get("window_seconds", 60)
        self._zscore_thr: float = cfg.get("zscore_threshold", 3.0)
        self._rate_mult_thr: float = cfg.get("rate_multiplier_threshold", 5.0)
        self._error_surge_mult: float = cfg.get("error_surge_multiplier", 3.0)
        self._zscore_tight: float = cfg.get("error_surge_zscore_tighten", 2.0)
        self._rate_tight: float = cfg.get("error_surge_rate_tighten", 3.0)

        self._baseline = baseline
        self._on_ip = on_ip_anomaly
        self._on_global = on_global_anomaly

        self._lock = threading.Lock()
        self._ip_windows: Dict[str, deque] = defaultdict(deque)
        self._ip_error_windows: Dict[str, deque] = defaultdict(deque)
        self._global_window: deque = deque()

        self._current_second: int = 0
        self._second_count: int = 0
        self._second_error_count: int = 0

        self._ip_cooldown_secs: int = 30
        self._ip_last_fired: Dict[str, float] = {}
        self._global_last_fired: float = 0.0
        self._global_cooldown_secs: int = 15

        self.total_events: int = 0
        self.total_anomalies: int = 0

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def process(self, entry: LogEntry) -> None:
        """
        Called for every LogEntry emitted by the LogMonitor.
        Updates sliding windows and checks for anomalies.
        """
        now_ts = entry.timestamp.timestamp()
        ip = entry.source_ip
        is_error = entry.is_error

        with self._lock:
            self.total_events += 1
            cutoff = now_ts - self._window_secs

            # Update global window
            while self._global_window and self._global_window[0] < cutoff:
                self._global_window.popleft()
            self._global_window.append(now_ts)

            # Update per-IP window
            ip_win = self._ip_windows[ip]
            while ip_win and ip_win[0] < cutoff:
                ip_win.popleft()
            ip_win.append(now_ts)

            # Update per-IP error window
            if is_error:
                err_win = self._ip_error_windows[ip]
                while err_win and err_win[0] < cutoff:
                    err_win.popleft()
                err_win.append(now_ts)

            # Accumulate per-second counts for baseline feeding
            sec = int(now_ts)
            if sec != self._current_second:
                self._baseline.record_second(
                    self._current_second,
                    self._second_count,
                    self._second_error_count,
                )
                self._current_second = sec
                self._second_count = 0
                self._second_error_count = 0
            self._second_count += 1
            if is_error:
                self._second_error_count += 1

            global_rate = len(self._global_window) / self._window_secs
            ip_rate = len(ip_win) / self._window_secs
            ip_error_rate = len(self._ip_error_windows[ip]) / self._window_secs

        # Anomaly checks outside the lock
        self._check_ip(ip, ip_rate, ip_error_rate, now_ts)
        self._check_global(global_rate, now_ts)

    # ------------------------------------------------------------------
    # Anomaly checks
    # ------------------------------------------------------------------

    def _check_ip(self, ip: str, rate: float, error_rate: float, now_ts: float) -> None:
        """
        Check whether a single IP's request rate is anomalous.

        Steps
        -----
        1. Skip whitelisted IPs entirely.
        2. Get baseline stats.
        3. Detect error surge — tighten thresholds if triggered.
        4. Compute z-score.
        5. Fire if z-score > threshold OR rate > multiplier * mean.
        6. Respect cooldown to avoid alert storms.
        """
        # Step 1 — never ban whitelisted IPs (Docker gateway, localhost etc)
        if ip in self._whitelist:
            return

        stats = self._baseline.get_stats()
        error_stats = self._baseline.get_error_stats()

        # Detect error surge — tighten thresholds automatically
        error_surge = False
        if error_stats.effective_mean > 0:
            if error_rate >= self._error_surge_mult * error_stats.effective_mean:
                error_surge = True

        zscore_thr = self._zscore_tight if error_surge else self._zscore_thr
        rate_thr = self._rate_tight if error_surge else self._rate_mult_thr

        # Compute z-score
        zscore = (rate - stats.effective_mean) / stats.effective_stddev

        fired = False
        condition = ""

        if zscore > zscore_thr:
            fired = True
            condition = f"z-score {zscore:.2f} > threshold {zscore_thr}"
        elif rate > rate_thr * stats.effective_mean:
            fired = True
            condition = f"rate {rate:.2f} req/s > {rate_thr}x baseline mean {stats.effective_mean:.2f}"

        if not fired:
            return

        # Cooldown check — avoid alert storms for the same IP
        last = self._ip_last_fired.get(ip, 0.0)
        if now_ts - last < self._ip_cooldown_secs:
            return

        self._ip_last_fired[ip] = now_ts
        self.total_anomalies += 1

        event = AnomalyEvent(
            kind="ip",
            ip=ip,
            current_rate=rate,
            baseline=stats,
            zscore=zscore,
            condition=condition,
            error_surge=error_surge,
        )
        logger.warning("IP anomaly detected: %s | %s", ip, condition)
        self._on_ip(event)

    def _check_global(self, rate: float, now_ts: float) -> None:
        """Check whether overall traffic rate is anomalous."""
        stats = self._baseline.get_stats()
        zscore = (rate - stats.effective_mean) / stats.effective_stddev

        fired = False
        condition = ""

        if zscore > self._zscore_thr:
            fired = True
            condition = f"global z-score {zscore:.2f} > threshold {self._zscore_thr}"
        elif rate > self._rate_mult_thr * stats.effective_mean:
            fired = True
            condition = f"global rate {rate:.2f} req/s > {self._rate_mult_thr}x baseline {stats.effective_mean:.2f}"

        if not fired:
            return

        if now_ts - self._global_last_fired < self._global_cooldown_secs:
            return

        self._global_last_fired = now_ts
        self.total_anomalies += 1

        event = AnomalyEvent(
            kind="global",
            ip=None,
            current_rate=rate,
            baseline=stats,
            zscore=zscore,
            condition=condition,
        )
        logger.warning("Global anomaly detected | %s", condition)
        self._on_global(event)

    # ------------------------------------------------------------------
    # Metrics helpers (called by dashboard)
    # ------------------------------------------------------------------

    def get_global_rate(self) -> float:
        """Current global req/s."""
        with self._lock:
            return len(self._global_window) / self._window_secs

    def get_top_ips(self, n: int = 10) -> list[tuple[str, float]]:
        """Return [(ip, rate)] sorted descending by rate."""
        with self._lock:
            rates = [
                (ip, len(win) / self._window_secs)
                for ip, win in self._ip_windows.items()
                if win
            ]
        rates.sort(key=lambda x: x[1], reverse=True)
        return rates[:n]