"""
baseline.py — Rolling baseline computation.

How it works
------------
We maintain a ring of per-second request counts spanning the last
BASELINE_WINDOW_MINUTES (30 min by default).  Every RECALC_INTERVAL
seconds we compute mean and standard deviation from those counts and
cache the result so the detector can read it cheaply.

Per-hour slots
--------------
We also maintain a dict keyed by UTC hour (0-23).  Each slot accumulates
counts only during that calendar hour.  When the detector asks for the
baseline it gets:

  • The current hour's stats if that hour has >= MIN_SAMPLES data points.
  • Otherwise the rolling 30-min window stats (which blends multiple hours).

This means a quiet overnight hour doesn't pollute the busy morning baseline.

Floor values
------------
Mean and stddev are clamped to configured floor values to prevent
division-by-zero and to avoid flagging every single request during
very quiet periods.

Audit log
---------
Every recalculation writes a structured line to the audit log.
"""

import logging
import math
import threading
import time
from collections import deque, defaultdict
from datetime import datetime, timezone
from typing import NamedTuple, Dict, List

logger = logging.getLogger(__name__)


class BaselineStats(NamedTuple):
    """Snapshot of the current baseline at one moment in time."""
    effective_mean: float
    effective_stddev: float
    source: str          # "hourly" or "rolling"
    sample_count: int
    computed_at: datetime


class BaselineEngine:
    """
    Computes and caches rolling mean/stddev for global request rate.

    Thread safety
    -------------
    All public methods are called from different threads (the detector
    calls get_stats() frequently; the background recalculator calls
    _recalculate() periodically).  We protect shared state with a
    threading.Lock() — writes are short so contention is negligible.

    Sliding window structure
    ------------------------
    _second_counts is a deque of (timestamp_second, count) tuples.
    When we push a new count we first evict all tuples older than
    WINDOW_SECONDS from the left end of the deque — O(k) where k is
    the number of expired entries, usually 0 or 1 per tick.
    """

    def __init__(self, cfg: dict, audit_fn=None):
        """
        Parameters
        ----------
        cfg     : the 'detection' subsection of config.yaml
        audit_fn: callable(action, detail_dict) → None, optional
        """
        self._window_minutes: int = cfg.get("baseline_window_minutes", 30)
        self._window_seconds: int = self._window_minutes * 60
        self._recalc_interval: int = cfg.get("baseline_recalc_interval", 60)
        self._min_samples: int = cfg.get("baseline_min_samples", 10)
        self._floor_mean: float = cfg.get("baseline_floor_mean", 1.0)
        self._floor_stddev: float = cfg.get("baseline_floor_stddev", 0.5)

        self._audit = audit_fn or (lambda *a, **kw: None)

        # Rolling 30-min window: deque of (unix_second, count)
        # We store ONE entry per second; the monitor increments a counter
        # and we push it every second via record_second().
        self._lock = threading.Lock()
        self._second_counts: deque = deque()   # (int_second, int_count)

        # Per-hour accumulation: hour_key → list of per-second counts
        # hour_key = datetime.utcnow().hour  (0-23)
        self._hour_slots: Dict[int, List[int]] = defaultdict(list)

        # Cached result — updated by background thread, read by detector.
        self._cached_stats: BaselineStats = BaselineStats(
            effective_mean=self._floor_mean,
            effective_stddev=self._floor_stddev,
            source="init",
            sample_count=0,
            computed_at=datetime.now(timezone.utc),
        )

        # Error baseline (same structure, separate counters)
        self._error_second_counts: deque = deque()
        self._cached_error_stats: BaselineStats = BaselineStats(
            effective_mean=self._floor_mean,
            effective_stddev=self._floor_stddev,
            source="init",
            sample_count=0,
            computed_at=datetime.now(timezone.utc),
        )

        self._running = False
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Data ingestion
    # ------------------------------------------------------------------

    def record_second(self, unix_second: int, count: int, error_count: int = 0) -> None:
        """
        Called once per second by the detector with the number of
        requests (and error requests) seen in that second.

        Eviction logic
        --------------
        Any entry in the deque with timestamp < (now - window_seconds)
        is popped from the left.  The deque stays in chronological order
        because we always append to the right.
        """
        cutoff = unix_second - self._window_seconds
        hour_key = datetime.utcfromtimestamp(unix_second).hour

        with self._lock:
            # Evict stale entries from the rolling window.
            while self._second_counts and self._second_counts[0][0] < cutoff:
                self._second_counts.popleft()

            self._second_counts.append((unix_second, count))

            # Accumulate in the matching hour slot.
            self._hour_slots[hour_key].append(count)
            # Keep hour slots from growing unboundedly: cap at 3600 samples (1 hour).
            if len(self._hour_slots[hour_key]) > 3600:
                self._hour_slots[hour_key] = self._hour_slots[hour_key][-3600:]

            # Error baseline
            cutoff_e = unix_second - self._window_seconds
            while self._error_second_counts and self._error_second_counts[0][0] < cutoff_e:
                self._error_second_counts.popleft()
            self._error_second_counts.append((unix_second, error_count))

    # ------------------------------------------------------------------
    # Stats retrieval
    # ------------------------------------------------------------------

    def get_stats(self) -> BaselineStats:
        """Return the most recently computed baseline stats."""
        with self._lock:
            return self._cached_stats

    def get_error_stats(self) -> BaselineStats:
        """Return error-rate baseline stats."""
        with self._lock:
            return self._cached_error_stats

    # ------------------------------------------------------------------
    # Background recalculation
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Launch the background recalculation thread."""
        self._running = True
        self._thread = threading.Thread(target=self._recalc_loop, daemon=True, name="BaselineThread")
        self._thread.start()
        logger.info("BaselineEngine started (window=%dm, recalc every %ds)",
                    self._window_minutes, self._recalc_interval)

    def stop(self) -> None:
        self._running = False

    def _recalc_loop(self) -> None:
        """Sleep → recalculate → repeat."""
        while self._running:
            time.sleep(self._recalc_interval)
            try:
                self._recalculate()
            except Exception as exc:  # noqa: BLE001
                logger.error("Baseline recalculation error: %s", exc)

    def _recalculate(self) -> None:
        """
        Compute mean and stddev from available data.

        Decision logic
        --------------
        1. Look at the current UTC hour slot.
        2. If it has >= MIN_SAMPLES entries, use it (most recent behaviour).
        3. Otherwise fall back to the full rolling 30-min window.
        4. Apply floor values.
        5. Cache the result and write an audit log entry.
        """
        now = datetime.now(timezone.utc)
        current_hour = now.hour

        with self._lock:
            hour_data = list(self._hour_slots.get(current_hour, []))
            rolling_data = [c for _, c in self._second_counts]
            error_data = [c for _, c in self._error_second_counts]

        # Choose source
        if len(hour_data) >= self._min_samples:
            data = hour_data
            source = "hourly"
        elif len(rolling_data) >= self._min_samples:
            data = rolling_data
            source = "rolling"
        else:
            # Not enough data yet — keep floor values.
            logger.debug("Baseline: insufficient data (%d samples) — keeping floor values.", len(rolling_data))
            return

        mean, stddev = self._compute_stats(data)
        error_mean, error_stddev = self._compute_stats(error_data) if error_data else (self._floor_mean, self._floor_stddev)

        stats = BaselineStats(
            effective_mean=mean,
            effective_stddev=stddev,
            source=source,
            sample_count=len(data),
            computed_at=now,
        )
        error_stats = BaselineStats(
            effective_mean=error_mean,
            effective_stddev=error_stddev,
            source=source,
            sample_count=len(error_data),
            computed_at=now,
        )

        with self._lock:
            self._cached_stats = stats
            self._cached_error_stats = error_stats

        logger.info(
            "Baseline recalculated | source=%s samples=%d mean=%.2f stddev=%.2f",
            source, len(data), mean, stddev,
        )

        # Audit log entry for every recalculation.
        self._audit(
            "BASELINE_RECALC",
            {
                "source": source,
                "sample_count": len(data),
                "effective_mean": round(mean, 4),
                "effective_stddev": round(stddev, 4),
                "hour_slot": current_hour,
            }
        )

    def _compute_stats(self, data: list) -> tuple[float, float]:
        """
        Compute mean and stddev from a list of counts,
        clamping to floor values.
        """
        if not data:
            return self._floor_mean, self._floor_stddev

        n = len(data)
        mean = sum(data) / n
        variance = sum((x - mean) ** 2 for x in data) / n
        stddev = math.sqrt(variance)

        # Apply floors
        mean = max(mean, self._floor_mean)
        stddev = max(stddev, self._floor_stddev)

        return mean, stddev
