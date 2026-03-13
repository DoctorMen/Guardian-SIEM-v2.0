"""
Guardian SIEM v2.0 — Unified Dashboard & API Server
Fixed: /api/ingest 404 errors, Project-Isolation, and WSL Connectivity.
"""

from flask import Flask, render_template, jsonify, request
from flask_sock import Sock
import sqlite3
import os
import re
import json
import time
import yaml
import secrets
import threading
from datetime import datetime

from event_bus import EventBus
from rules_engine import RulesEngine
from mitre_tagger import MitreTagger
from threat_intel import ThreatIntel
from geoip_lookup import GeoIPLookup
from alert_manager import AlertManager
from sigma_engine import SigmaEngine
from yara_scanner import YaraScanner
from active_response import ActiveResponse
from report_generator import ReportGenerator
from syslog_receiver import SyslogReceiver
from auth import setup_auth

# ---- App Setup ----
app = Flask(__name__)
sock = Sock(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "guardian_events.db")
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yaml")

# Load config
config = {}
try:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}
except Exception:
    pass

app.secret_key = os.environ.get("GUARDIAN_SECRET_KEY") or secrets.token_hex(32)

# ---- Initialize Modules ----
event_bus = EventBus()
rules_engine = RulesEngine()
mitre_tagger = MitreTagger()
threat_intel = ThreatIntel()
geoip = GeoIPLookup()
alert_manager = AlertManager()
sigma_engine = SigmaEngine()
yara_scanner = YaraScanner()
active_response = ActiveResponse()
report_gen = ReportGenerator()
syslog_receiver = SyslogReceiver()

# Setup authentication
user_db = setup_auth(app, config)

# WebSocket clients
ws_clients = set()
ws_lock = threading.Lock()

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ---- Event Processing Pipeline ----
def process_event(event):
    """Pipeline: event → rules → enrichment → dispatch."""
    source = event.get("source", "")
    message = event.get("message", "")
    project = event.get("project", "Wyde")

    ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', message)
    src_ip = ip_match.group(1) if ip_match else ""

    matches = rules_engine.evaluate(source, message)
    
    for match in matches:
        mitre_info = mitre_tagger.enrich(match.get("mitre_id", ""))
        geo_data = geoip.lookup(src_ip) if src_ip else {}

        enrichment = {
            "project": project,
            "rule_matched": match["rule_name"],
            "mitre_id": match.get("mitre_id", ""),
            "threat_score": mitre_info.get("severity_weight", 0) * 10,
            "geo_country": geo_data.get("country", ""),
            "geo_city": geo_data.get("city", ""),
            "geo_lat": geo_data.get("latitude", 0),
            "geo_lon": geo_data.get("longitude", 0),
            "src_ip": src_ip,
        }

        alert_event = event_bus.emit(
            f"Alert_{source}", match["severity"],
            f"[{match['rule_name']}] {message[:300]}",
            enrichment=enrichment
        )
        broadcast_ws({"type": "new_event", "event": alert_event})

# Subscribe to pipeline
event_bus.subscribe(lambda event: threading.Thread(
    target=process_event, args=(event,), daemon=True
).start() if not event.get("source", "").startswith("Alert_") else None)

# ---- WebSocket ----
def broadcast_ws(data):
    with ws_lock:
        dead = set()
        for ws in ws_clients:
            try:
                ws.send(json.dumps(data))
            except:
                dead.add(ws)
        ws_clients -= dead

@sock.route('/ws')
def websocket(ws):
    with ws_lock:
        ws_clients.add(ws)
    try:
        while True:
            ws.receive(timeout=30)
    except:
        pass
    finally:
        with ws_lock:
            ws_clients.discard(ws)

# ---- API ROUTES ----

@app.route('/')
def index():
    project = request.args.get('project', None)
    return render_template('dashboard.html', current_project=project)

@app.route('/api/ingest', methods=['POST'])
def ingest_data():
    """Receiver for logs from external sensors (WSL, Swarm, etc.)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No JSON payload"}), 400

        enrichment = data.get("enrichment", {})
        project = enrichment.get("project", "Wyde")

        event_bus.emit(
            source=data.get("source", "Unknown_Sensor"),
            severity=data.get("severity", "INFO"),
            message=data.get("message", ""),
            enrichment=enrichment
        )
        return jsonify({"status": "success", "project": project}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/events')
def get_events():
    project = request.args.get('project', None)
    events = event_bus.query(
        limit=50,
        severity=request.args.get('severity'),
        project=project
    )
    return jsonify(events)

@app.route('/api/stats')
def get_stats():
    project = request.args.get('project', None)
    return jsonify(event_bus.get_stats(project=project))

@app.route('/api/geo')
def get_geo():
    project = request.args.get('project', None)
    conn = get_db_connection()
    try:
        query = "SELECT src_ip, geo_country, geo_city, geo_lat, geo_lon, COUNT(*) as count FROM events WHERE src_ip != ''"
        params = []
        if project:
            query += " AND project = ?"
            params.append(project)
        query += " GROUP BY src_ip ORDER BY count DESC LIMIT 100"
        rows = conn.execute(query, params).fetchall()
        return jsonify([dict(row) for row in rows])
    finally:
        conn.close()

@app.route('/api/mitre')
def get_mitre():
    """Serve MITRE ATT&CK technique data for the dashboard heatmap."""
    project = request.args.get('project', None)
    techniques = mitre_tagger.get_all_techniques()

    # Build top-triggered counts from DB
    conn = get_db_connection()
    try:
        query = "SELECT mitre_id, COUNT(*) as cnt FROM events WHERE mitre_id != ''"
        params = []
        if project:
            query += " AND project = ?"
            params.append(project)
        query += " GROUP BY mitre_id"
        rows = conn.execute(query, params).fetchall()
        top_triggered = {row["mitre_id"]: row["cnt"] for row in rows}
    finally:
        conn.close()

    return jsonify({"techniques": techniques, "top_triggered": top_triggered})

@app.route('/api/rules')
def get_rules():
    """Serve detection rules summary for the dashboard rules table."""
    return jsonify(rules_engine.get_rules_summary())

@app.route('/api/health')
def health():
    return jsonify({"status": "operational", "timestamp": datetime.now().isoformat()})

if __name__ == '__main__':
    host = "0.0.0.0"
    # Change port to 5005 right here:
    port = config.get("dashboard", {}).get("port", 5005) 
    
    threading.Thread(target=lambda: (time.sleep(300), active_response.cleanup_expired()), daemon=True).start()

    print(f"\n🛡️  Guardian SIEM v2.0 - Virtual SOC Active")
    print(f"📡 Listening on: http://{host}:{port}")
    app.run(host=host, port=5005, debug=False) # And force it here just to be safe