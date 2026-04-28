"""
dashboard.py — Live metrics web dashboard.

Served at configured host:port.  The frontend polls /api/metrics every
3 seconds (or less) and renders the data.

Endpoints
---------
GET /              → Dashboard HTML page
GET /api/metrics   → JSON metrics snapshot
POST /api/unban    → { "ip": "x.x.x.x" }  →  manual unban
"""

import logging
import os
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import psutil
from flask import Flask, jsonify, request, render_template_string
from flask_cors import CORS

if TYPE_CHECKING:
    from detector import AnomalyDetector
    from baseline import BaselineEngine
    from blocker import Blocker
    from unbanner import Unbanner

logger = logging.getLogger(__name__)

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>HNG Anomaly Detector — Live Dashboard</title>
  <style>
    :root {
      --bg: #0f1117;
      --card: #1a1d27;
      --border: #2a2d3e;
      --accent: #6c63ff;
      --danger: #ff4757;
      --success: #2ed573;
      --warn: #ffa502;
      --text: #e0e0f0;
      --muted: #888;
      --font: 'JetBrains Mono', 'Fira Code', monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: var(--font); font-size: 13px; }
    header {
      background: var(--card);
      border-bottom: 1px solid var(--border);
      padding: 14px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    header h1 { color: var(--accent); font-size: 16px; letter-spacing: 1px; }
    #status-dot { width: 10px; height: 10px; border-radius: 50%; background: var(--success); display: inline-block; margin-right: 6px; animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; padding: 20px 24px 0; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
    .card h3 { color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 10px; }
    .metric { font-size: 28px; font-weight: 700; color: var(--accent); }
    .sub { font-size: 11px; color: var(--muted); margin-top: 4px; }
    .main-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; padding: 16px 24px; }
    @media(max-width:700px){ .main-grid{ grid-template-columns:1fr; } }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th { color: var(--muted); text-align: left; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; padding: 6px 8px; border-bottom: 1px solid var(--border); }
    td { padding: 6px 8px; border-bottom: 1px solid rgba(255,255,255,.04); }
    tr:hover td { background: rgba(108,99,255,.06); }
    .tag { display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 10px; }
    .tag-ban { background: rgba(255,71,87,.2); color: var(--danger); }
    .tag-ok { background: rgba(46,213,115,.15); color: var(--success); }
    .btn-unban { background: none; border: 1px solid var(--danger); color: var(--danger); padding: 2px 8px; border-radius: 4px; cursor: pointer; font-size: 11px; }
    .btn-unban:hover { background: var(--danger); color: #fff; }
    footer { text-align: center; padding: 20px; color: var(--muted); font-size: 11px; }
    #last-update { font-size: 11px; color: var(--muted); }
    .warn-text { color: var(--warn); }
    .danger-text { color: var(--danger); }
  </style>
</head>
<body>
<header>
  <h1><span id="status-dot"></span>HNG ANOMALY DETECTOR</h1>
  <span id="last-update">connecting...</span>
</header>

<div class="grid">
  <div class="card">
    <h3>Global Req/s</h3>
    <div class="metric" id="global-rate">—</div>
    <div class="sub">last 60 seconds</div>
  </div>
  <div class="card">
    <h3>Baseline Mean</h3>
    <div class="metric" id="baseline-mean">—</div>
    <div class="sub" id="baseline-src">—</div>
  </div>
  <div class="card">
    <h3>Baseline Stddev</h3>
    <div class="metric" id="baseline-stddev">—</div>
    <div class="sub">effective deviation</div>
  </div>
  <div class="card">
    <h3>Banned IPs</h3>
    <div class="metric danger-text" id="banned-count">0</div>
    <div class="sub">currently active</div>
  </div>
  <div class="card">
    <h3>CPU Usage</h3>
    <div class="metric" id="cpu">—</div>
    <div class="sub">system-wide</div>
  </div>
  <div class="card">
    <h3>Memory Usage</h3>
    <div class="metric" id="memory">—</div>
    <div class="sub">RSS used</div>
  </div>
  <div class="card">
    <h3>Uptime</h3>
    <div class="metric" id="uptime">—</div>
    <div class="sub">detector daemon</div>
  </div>
  <div class="card">
    <h3>Total Events</h3>
    <div class="metric" id="total-events">—</div>
    <div class="sub">log lines processed</div>
  </div>
</div>

<div class="main-grid">
  <div class="card">
    <h3 style="margin-bottom:12px">Top 10 Source IPs</h3>
    <table>
      <thead><tr><th>IP</th><th>Req/s</th><th>Status</th></tr></thead>
      <tbody id="top-ips"></tbody>
    </table>
  </div>
  <div class="card">
    <h3 style="margin-bottom:12px">Banned IPs</h3>
    <table>
      <thead><tr><th>IP</th><th>Strike</th><th>Duration</th><th></th></tr></thead>
      <tbody id="banned-table"></tbody>
    </table>
  </div>
</div>

<footer>cloud.ng — HNG Anomaly Detection Engine &nbsp;|&nbsp; refreshing every 3s</footer>

<script>
const fmt = (n, d=2) => typeof n === 'number' ? n.toFixed(d) : '—';

async function fetchMetrics() {
  try {
    const r = await fetch('/api/metrics');
    if (!r.ok) throw new Error(r.status);
    const d = await r.json();
    render(d);
    document.getElementById('last-update').textContent = 'updated ' + new Date().toLocaleTimeString();
  } catch(e) {
    document.getElementById('last-update').textContent = 'error: ' + e.message;
  }
}

function fmtDur(s) {
  if (s === -1) return 'permanent';
  if (s < 60) return s + 's';
  if (s < 3600) return (s/60).toFixed(0) + 'm';
  return (s/3600).toFixed(1) + 'h';
}

function fmtUptime(s) {
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = Math.floor(s%60);
  return `${h}h ${m}m ${sec}s`;
}

function render(d) {
  document.getElementById('global-rate').textContent = fmt(d.global_rate) + ' r/s';
  document.getElementById('baseline-mean').textContent = fmt(d.baseline_mean) + ' r/s';
  document.getElementById('baseline-src').textContent = 'source: ' + (d.baseline_source || '—');
  document.getElementById('baseline-stddev').textContent = fmt(d.baseline_stddev);
  document.getElementById('banned-count').textContent = d.banned_count;
  document.getElementById('cpu').textContent = fmt(d.cpu_percent, 1) + '%';
  document.getElementById('memory').textContent = fmt(d.memory_mb, 1) + ' MB';
  document.getElementById('uptime').textContent = fmtUptime(d.uptime_seconds);
  document.getElementById('total-events').textContent = (d.total_events || 0).toLocaleString();

  // Top IPs
  const tbody = document.getElementById('top-ips');
  tbody.innerHTML = '';
  (d.top_ips || []).forEach(([ip, rate]) => {
    const banned = (d.banned_ips || []).some(b => b.ip === ip);
    tbody.innerHTML += `<tr>
      <td>${ip}</td>
      <td>${fmt(rate)} r/s</td>
      <td><span class="tag ${banned ? 'tag-ban':'tag-ok'}">${banned?'BANNED':'OK'}</span></td>
    </tr>`;
  });

  // Banned IPs
  const btbody = document.getElementById('banned-table');
  btbody.innerHTML = '';
  (d.banned_ips || []).forEach(b => {
    btbody.innerHTML += `<tr>
      <td>${b.ip}</td>
      <td>#${b.strike}</td>
      <td>${fmtDur(b.duration)}</td>
      <td><button class="btn-unban" onclick="unban('${b.ip}')">Unban</button></td>
    </tr>`;
  });
}

async function unban(ip) {
  if (!confirm('Unban ' + ip + '?')) return;
  const r = await fetch('/api/unban', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ip})
  });
  const d = await r.json();
  alert(d.message || JSON.stringify(d));
  fetchMetrics();
}

fetchMetrics();
setInterval(fetchMetrics, 3000);
</script>
</body>
</html>
"""


class Dashboard:
    """Flask-based live metrics dashboard."""

    def __init__(self, cfg: dict, detector, baseline, blocker, unbanner, start_time: float):
        self._host = cfg.get("server", {}).get("dashboard_host", "0.0.0.0")
        self._port = cfg.get("server", {}).get("dashboard_port", 8888)
        self._detector = detector
        self._baseline = baseline
        self._blocker = blocker
        self._unbanner = unbanner
        self._start_time = start_time

        self._app = Flask(__name__)
        CORS(self._app)
        self._register_routes()

    def _register_routes(self) -> None:
        app = self._app

        @app.route("/")
        def index():
            return render_template_string(DASHBOARD_HTML)

        @app.route("/api/metrics")
        def metrics():
            return jsonify(self._build_metrics())

        @app.route("/api/unban", methods=["POST"])
        def unban():
            data = request.get_json(silent=True) or {}
            ip = data.get("ip", "").strip()
            if not ip:
                return jsonify({"error": "ip required"}), 400
            ok = self._unbanner.manual_unban(ip)
            return jsonify({"message": f"Unbanned {ip}" if ok else f"{ip} was not banned"})

        @app.route("/health")
        def health():
            return jsonify({"status": "ok"})

    def _build_metrics(self) -> dict:
        stats = self._baseline.get_stats()
        banned = self._blocker.get_banned_ips()

        proc = psutil.Process(os.getpid())
        mem_mb = proc.memory_info().rss / 1024 / 1024
        cpu = psutil.cpu_percent(interval=None)

        return {
            "global_rate": round(self._detector.get_global_rate(), 3),
            "baseline_mean": round(stats.effective_mean, 4),
            "baseline_stddev": round(stats.effective_stddev, 4),
            "baseline_source": stats.source,
            "baseline_sample_count": stats.sample_count,
            "banned_count": len(banned),
            "banned_ips": [
                {
                    "ip": b.ip,
                    "strike": b.strike,
                    "duration": b.duration,
                    "banned_at": datetime.fromtimestamp(b.banned_at, tz=timezone.utc).isoformat(),
                    "condition": b.event_condition,
                }
                for b in banned
            ],
            "top_ips": [[ip, round(r, 3)] for ip, r in self._detector.get_top_ips(10)],
            "cpu_percent": round(cpu, 1),
            "memory_mb": round(mem_mb, 2),
            "uptime_seconds": round(time.time() - self._start_time, 1),
            "total_events": self._detector.total_events,
            "total_anomalies": self._detector.total_anomalies,
            "server_time": datetime.now(timezone.utc).isoformat(),
        }

    def run(self) -> None:
        logger.info("Dashboard starting at http://%s:%d", self._host, self._port)
        self._app.run(
            host=self._host,
            port=self._port,
            debug=False,
            use_reloader=False,
            threaded=True,
        )
