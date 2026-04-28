# HNG Anomaly Detection Engine

> Real-time HTTP traffic anomaly detector for cloud.ng (Nextcloud) — built for HNG DevSecOps challenge.

**Language:** Python 3.11  
**Why Python?** The asyncio/threading model is ideal for I/O-bound log tailing; the standard library covers deques, statistics, and subprocess; and Flask gives us a dashboard in ~100 lines. Python's readability also makes the detection logic easy to audit and comment.

---

## Live Links *(fill in after deployment)*

| Resource | URL |
|----------|-----|
| Nextcloud | `http://YOUR_SERVER_IP` |
| Metrics Dashboard | `http://YOUR_DASHBOARD_DOMAIN:8888` |
| GitHub Repo | `https://github.com/YOUR_USERNAME/hng-anomaly-detector` |
| Blog Post | `https://YOUR_BLOG_URL` |

---

## Architecture

```
Internet
    │
    ▼
[Nginx :80]  ──── JSON logs ──▶  HNG-nginx-logs (Docker volume)
    │                                      │
    ▼                                      ▼ (read-only mount)
[Nextcloud]                     [Detector Daemon]
                                    ├── LogMonitor   (tail log)
                                    ├── AnomalyDetector (sliding windows)
                                    ├── BaselineEngine  (rolling stats)
                                    ├── Blocker     (iptables)
                                    ├── Notifier    (Slack)
                                    └── Dashboard   (Flask :8888)
```

---

## How the Sliding Window Works

Two **`collections.deque`** structures are maintained simultaneously:

```
_global_window: deque[float]        # timestamps of ALL requests
_ip_windows:   dict[ip → deque]     # per-IP timestamp deques
```

**Eviction logic:** Every time a new request arrives, before appending its timestamp we pop from the **left** of each deque while:

```python
deque[0] < (now - WINDOW_SECONDS)   # i.e., older than 60 s
```

Because timestamps are always appended to the **right** in chronological order, the deque is always sorted. Popping expired entries from the left is O(k) where k is the number of stale entries — typically 0 or 1 per request, so effectively O(1).

After eviction:

```
rate = len(deque) / WINDOW_SECONDS   # req/s in the last 60 s
```

No per-minute counter. No approximation. Exact sliding count.

---

## How the Baseline Works

| Parameter | Default | Description |
|-----------|---------|-------------|
| `baseline_window_minutes` | 30 | Rolling window of per-second counts |
| `baseline_recalc_interval` | 60 s | How often mean/stddev are recomputed |
| `baseline_min_samples` | 10 | Minimum data points before baseline is trusted |
| `baseline_floor_mean` | 1.0 req/s | Minimum mean (avoids false positives at zero traffic) |
| `baseline_floor_stddev` | 0.5 | Minimum stddev (avoids division sensitivity) |

**Per-hour slots:** In addition to the rolling 30-min window, we keep separate lists of per-second counts indexed by UTC hour (0–23). When the detector asks for baseline stats:

1. If the **current hour's slot** has ≥ `MIN_SAMPLES` data points → use it.  
   This gives each hour its own learned "normal" (quiet night vs. busy morning).
2. Otherwise → fall back to the rolling 30-min window (blends recent hours).

Mean and stddev are clamped to floor values so we never divide by zero or flag every request during silent periods.

The baseline is **never hardcoded**. It is always derived from real observed traffic.

---

## Detection Logic

```
z = (current_rate - effective_mean) / effective_stddev

Fire anomaly if:
  z > ZSCORE_THRESHOLD (3.0)          ← catches statistical outliers
  OR
  rate > 5.0 × effective_mean         ← catches early spikes before stddev grows
```

**Error surge tightening:** If an IP's 4xx/5xx rate ≥ 3× the baseline error rate, we automatically reduce thresholds to `z > 2.0` and `rate > 3×` — making detection more sensitive for IPs already showing bad behaviour.

Both checks run on every log line. The first condition that fires triggers the response.

---

## Quick Start (fresh VPS)

### Prerequisites

- Ubuntu 22.04 LTS (or any modern Linux)
- Docker ≥ 24 + Docker Compose ≥ 2
- `iptables` installed (default on most VPS images)
- 2 vCPU, 2 GB RAM minimum

### 1 — Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/hng-anomaly-detector.git
cd hng-anomaly-detector
```

### 2 — Configure environment

```bash
cp .env.example .env
nano .env   # fill in passwords, SERVER_IP, SLACK_WEBHOOK_URL
```

### 3 — (Optional) Point a domain at the dashboard

Add an A record: `metrics.yourdomain.com → YOUR_SERVER_IP`

Then update `config.yaml`:
```yaml
server:
  dashboard_port: 8888
```

Open the port in your firewall:
```bash
ufw allow 8888/tcp
```

### 4 — Start the stack

```bash
docker compose up -d --build
```

### 5 — Verify everything is running

```bash
# All containers should be healthy
docker compose ps

# Watch the detector logs in real time
docker compose logs -f detector

# Check the named volume exists
docker volume ls | grep HNG-nginx-logs

# View the audit log
docker compose exec detector tail -f /var/log/detector/audit.log
```

### 6 — Access the dashboard

Open `http://YOUR_SERVER_IP:8888` (or your metrics subdomain).

---

## Testing Detection Locally

Generate a burst of traffic to trigger anomaly detection:

```bash
# Install Apache Bench
apt-get install -y apache2-utils

# Send 500 requests concurrently
ab -n 500 -c 50 http://YOUR_SERVER_IP/

# Watch the detector respond
docker compose logs -f detector
```

---

## Slack Alerts

Set `SLACK_WEBHOOK_URL` in your `.env`.  
Create a webhook at: https://api.slack.com/messaging/webhooks

You will receive alerts for:
- 🚨 **IP BANNED** — with IP, reason, strike count, ban duration
- ✅ **IP UNBANNED** — with IP and previous strike
- 🌐 **GLOBAL TRAFFIC ANOMALY** — with global rate and baseline

---

## Repository Structure

```
hng-anomaly-detector/
├── detector/
│   ├── main.py         # Entry point, wires all subsystems
│   ├── monitor.py      # Log tailing and JSON parsing
│   ├── baseline.py     # Rolling mean/stddev with per-hour slots
│   ├── detector.py     # Sliding window anomaly detection
│   ├── blocker.py      # iptables banning + auto-unban backoff
│   ├── unbanner.py     # Manual unban API
│   ├── notifier.py     # Async Slack alerts
│   ├── dashboard.py    # Flask live metrics UI
│   ├── config.yaml     # All thresholds (never hardcoded in logic)
│   ├── requirements.txt
│   └── Dockerfile
├── nginx/
│   └── nginx.conf      # JSON logging, X-Forwarded-For, reverse proxy
├── docs/
│   └── architecture.png
├── screenshots/
│   ├── Tool-running.png
│   ├── Ban-slack.png
│   ├── Unban-slack.png
│   ├── Global-alert-slack.png
│   ├── Iptables-banned.png
│   ├── Audit-log.png
│   └── Baseline-graph.png
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Configuration Reference

All thresholds live in `detector/config.yaml`. Key values:

| Key | Default | Purpose |
|-----|---------|---------|
| `detection.window_seconds` | 60 | Sliding window size |
| `detection.zscore_threshold` | 3.0 | Z-score trigger |
| `detection.rate_multiplier_threshold` | 5.0 | Rate × mean trigger |
| `detection.error_surge_multiplier` | 3.0 | Error rate surge factor |
| `blocking.ban_durations` | [600, 1800, 7200, -1] | Backoff schedule (s) |
| `dashboard.refresh_interval` | 3 | Dashboard poll interval (s) |

---

## Audit Log Format

```
[2024-01-15T14:23:01Z] BAN 1.2.3.4 | condition=z-score 4.2 > 3.0 | rate=45.3 | baseline=8.2 | duration=600s
[2024-01-15T14:33:01Z] UNBAN 1.2.3.4 | condition=- | rate=- | baseline=- | duration=600
[2024-01-15T14:24:00Z] BASELINE_RECALC - | condition=hourly | rate=8.2 | baseline=1.3 | duration=-
```

---

## Blog Post

*Link: https://YOUR_BLOG_URL*
