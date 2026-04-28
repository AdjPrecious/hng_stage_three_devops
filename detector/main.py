"""
main.py — HNG Anomaly Detection Engine entry point.

Wires together every subsystem:
  LogMonitor → AnomalyDetector → Blocker / Notifier
                                → BaselineEngine (background)
  Dashboard (background Flask thread)
  AuditLogger (file writer)

All subsystems run as daemon threads so the process exits cleanly
if the main thread receives SIGTERM / SIGINT.

Usage
-----
  python main.py [--config /path/to/config.yaml]
"""

import argparse
import logging
import os
import queue
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict

import yaml

# --- Local modules ---
from monitor import LogMonitor
from baseline import BaselineEngine
from detector import AnomalyDetector, AnomalyEvent
from blocker import Blocker, BanRecord
from unbanner import Unbanner
from notifier import Notifier
from dashboard import Dashboard

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("main")


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

class AuditLogger:
    """
    Writes structured audit entries to a dedicated log file.

    Format: [timestamp] ACTION ip | condition | rate | baseline | duration
    """

    def __init__(self, path: str):
        self._path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._lock = threading.Lock()

    def log(self, action: str, details: Dict[str, Any]) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ip = details.get("ip", "-")
        condition = details.get("condition", details.get("source", "-"))
        rate = details.get("rate", details.get("effective_mean", "-"))
        baseline = details.get("baseline", details.get("effective_stddev", "-"))
        duration = details.get("duration", details.get("was_duration", "-"))

        line = (
            f"[{ts}] {action} {ip} | "
            f"condition={condition} | "
            f"rate={rate} | "
            f"baseline={baseline} | "
            f"duration={duration}\n"
        )

        with self._lock:
            try:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(line)
            except OSError as exc:
                logger.warning("Audit log write failed: %s", exc)

        logger.info("AUDIT | %s %s", action, ip)


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    # Expand environment variables in the Slack webhook URL
    slack_url = raw.get("slack", {}).get("webhook_url", "")
    if slack_url.startswith("${") and slack_url.endswith("}"):
        env_var = slack_url[2:-1]
        slack_url = os.environ.get(env_var, "")
        if not slack_url:
            logger.warning("Env var %s not set — Slack alerts disabled.", env_var)
    raw.setdefault("slack", {})["webhook_url"] = slack_url

    return raw


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="HNG Anomaly Detection Engine")
    parser.add_argument(
        "--config",
        default=os.path.join(os.path.dirname(__file__), "config.yaml"),
        help="Path to config.yaml",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    start_time = time.time()

    logger.info("=" * 60)
    logger.info("HNG Anomaly Detection Engine starting...")
    logger.info("Config: %s", args.config)
    logger.info("=" * 60)

    # ------------------------------------------------------------------
    # Audit logger
    # ------------------------------------------------------------------
    audit_path = cfg.get("server", {}).get("audit_log_path", "/var/log/detector/audit.log")
    audit = AuditLogger(audit_path)

    # ------------------------------------------------------------------
    # Notifier (Slack)
    # ------------------------------------------------------------------
    slack_url = cfg.get("slack", {}).get("webhook_url", "")
    notifier = Notifier(slack_url)
    notifier.start()

    # ------------------------------------------------------------------
    # Baseline engine
    # ------------------------------------------------------------------
    detection_cfg = cfg.get("detection", {})
    baseline = BaselineEngine(
        cfg=detection_cfg,
        audit_fn=lambda action, details: audit.log(action, details),
    )
    baseline.start()

    # ------------------------------------------------------------------
    # Blocker
    # ------------------------------------------------------------------
    blocking_cfg = cfg.get("blocking", {})

    def notifier_callback(action: str, record: BanRecord) -> None:
        if action == "BAN":
            notifier.send_ban(record)
        elif action == "UNBAN":
            notifier.send_unban(record)

    blocker = Blocker(
        cfg=blocking_cfg,
        audit_fn=lambda action, details: audit.log(action, details),
        notifier_fn=notifier_callback,
    )
    blocker.start()

    # ------------------------------------------------------------------
    # Unbanner
    # ------------------------------------------------------------------
    unbanner = Unbanner(blocker)

    # ------------------------------------------------------------------
    # Anomaly detector
    # ------------------------------------------------------------------

    def on_ip_anomaly(event: AnomalyEvent) -> None:
        # Send Slack alert first (before iptables, to meet the 10-s window)
        notifier.send_ip_anomaly(event)
        audit.log("ANOMALY_IP", {
            "ip": event.ip,
            "condition": event.condition,
            "rate": round(event.current_rate, 3),
            "baseline": round(event.baseline.effective_mean, 3),
            "duration": "pending-ban",
        })
        # Block the IP
        blocker.block(event.ip, event.condition)

    def on_global_anomaly(event: AnomalyEvent) -> None:
        notifier.send_global_anomaly(event)
        audit.log("ANOMALY_GLOBAL", {
            "ip": "GLOBAL",
            "condition": event.condition,
            "rate": round(event.current_rate, 3),
            "baseline": round(event.baseline.effective_mean, 3),
            "duration": "no-ban",
        })

    detector = AnomalyDetector(
        cfg=detection_cfg,
        baseline=baseline,
        on_ip_anomaly=on_ip_anomaly,
        on_global_anomaly=on_global_anomaly,
    )

    # ------------------------------------------------------------------
    # Log monitor → detector feed loop
    # ------------------------------------------------------------------
    log_path = cfg.get("nginx", {}).get("log_path", "/var/log/nginx/hng-access.log")
    log_queue: queue.Queue = queue.Queue(maxsize=10_000)

    monitor = LogMonitor(log_path=log_path, out_queue=log_queue)

    def monitor_thread_fn():
        monitor.start()

    monitor_thread = threading.Thread(target=monitor_thread_fn, daemon=True, name="MonitorThread")
    monitor_thread.start()

    def consumer_thread_fn():
        """Drain the queue and pass entries to the detector."""
        while True:
            try:
                entry = log_queue.get(timeout=1)
                detector.process(entry)
                log_queue.task_done()
            except queue.Empty:
                continue
            except Exception as exc:  # noqa: BLE001
                logger.error("Consumer error: %s", exc)

    consumer = threading.Thread(target=consumer_thread_fn, daemon=True, name="ConsumerThread")
    consumer.start()

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------
    dashboard = Dashboard(
        cfg=cfg,
        detector=detector,
        baseline=baseline,
        blocker=blocker,
        unbanner=unbanner,
        start_time=start_time,
    )

    dash_thread = threading.Thread(target=dashboard.run, daemon=True, name="DashboardThread")
    dash_thread.start()

    # ------------------------------------------------------------------
    # Signal handling — graceful shutdown
    # ------------------------------------------------------------------
    shutdown_event = threading.Event()

    def _handle_signal(signum, frame):
        logger.info("Signal %d received — shutting down.", signum)
        monitor.stop()
        baseline.stop()
        blocker.stop()
        notifier.stop()
        shutdown_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logger.info("All subsystems running. Ctrl-C to stop.")
    logger.info("Dashboard: http://0.0.0.0:%d", cfg.get("server", {}).get("dashboard_port", 8888))

    # Keep main thread alive
    while not shutdown_event.is_set():
        time.sleep(1)

    logger.info("HNG Anomaly Detection Engine stopped.")


if __name__ == "__main__":
    main()
