import sqlite3
import json
import os
from datetime import datetime

class EventBus:
    def __init__(self, db_path="database/guardian_events.db"):
        self.db_path = db_path
        self._init_db()
        self.subscribers = []

    def _init_db(self):
        """Ensure the database and the project column exist."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        # Create table if it doesn't exist
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source TEXT,
                severity TEXT,
                message TEXT,
                rule_matched TEXT,
                mitre_id TEXT,
                mitre_tactic TEXT,
                threat_score REAL,
                geo_country TEXT,
                geo_city TEXT,
                geo_lat REAL,
                geo_lon REAL,
                src_ip TEXT,
                raw_log TEXT,
                project TEXT
            )
        """)
        # Ensure project column exists (for older DB versions)
        try:
            conn.execute("ALTER TABLE events ADD COLUMN project TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        conn.commit()
        conn.close()

    def subscribe(self, callback):
        self.subscribers.append(callback)

    def emit(self, source, severity, message, enrichment=None):
        """Save an event to the DB and notify subscribers."""
        enrichment = enrichment or {}
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        # Pull project from enrichment, default to 'Wyde'
        project = enrichment.get("project", "Wyde")

        event_data = {
            "timestamp": timestamp,
            "source": source,
            "severity": severity,
            "message": message,
            "rule_matched": enrichment.get("rule_matched", ""),
            "mitre_id": enrichment.get("mitre_id", ""),
            "mitre_tactic": enrichment.get("mitre_tactic", ""),
            "threat_score": enrichment.get("threat_score", 0),
            "geo_country": enrichment.get("geo_country", ""),
            "geo_city": enrichment.get("geo_city", ""),
            "geo_lat": enrichment.get("geo_lat", 0),
            "geo_lon": enrichment.get("geo_lon", 0),
            "src_ip": enrichment.get("src_ip", ""),
            "raw_log": enrichment.get("raw_log", ""),
            "project": project
        }

        # Save to SQLite
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO events (
                timestamp, source, severity, message, rule_matched, 
                mitre_id, mitre_tactic, threat_score, geo_country, 
                geo_city, geo_lat, geo_lon, src_ip, raw_log, project
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_data["timestamp"], event_data["source"], event_data["severity"],
            event_data["message"], event_data["rule_matched"], event_data["mitre_id"],
            event_data["mitre_tactic"], event_data["threat_score"], event_data["geo_country"],
            event_data["geo_city"], event_data["geo_lat"], event_data["geo_lon"],
            event_data["src_ip"], event_data["raw_log"], event_data["project"]
        ))
        conn.commit()
        conn.close()

        # Notify real-time listeners (WebSockets)
        for sub in self.subscribers:
            sub(event_data)
        
        return event_data

    def query(self, limit=50, severity=None, source=None, project=None):
        """Fetch historical events with project-aware filtering."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM events WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if source:
            query += " AND source = ?"
            params.append(source)
        if project:
            query += " AND project = ?"
            params.append(project)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = cursor.execute(query, params).fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_stats(self, project=None):
        """Calculate counts for the dashboard cards based on project."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Build WHERE clause that's always valid SQL
        conditions = []
        params = []
        if project:
            conditions.append("project = ?")
            params.append(project)

        where_clause = (" WHERE " + " AND ".join(conditions)) if conditions else ""

        stats = {}
        # Total Events
        stats["total_events"] = cursor.execute(f"SELECT COUNT(*) FROM events{where_clause}", params).fetchone()[0]

        # Severity Breakdown
        sev_rows = cursor.execute(f"SELECT severity, COUNT(*) FROM events{where_clause} GROUP BY severity", params).fetchall()
        stats["by_severity"] = {row[0]: row[1] for row in sev_rows}

        # Unique IPs — always needs src_ip != '' condition
        ip_conditions = conditions + ["src_ip != ''"]
        ip_where = " WHERE " + " AND ".join(ip_conditions)
        stats["unique_ips"] = cursor.execute(f"SELECT COUNT(DISTINCT src_ip) FROM events{ip_where}", params).fetchone()[0]

        # Top Sources
        src_rows = cursor.execute(f"SELECT source, COUNT(*) FROM events{where_clause} GROUP BY source ORDER BY COUNT(*) DESC LIMIT 5", params).fetchall()
        stats["by_source"] = {row[0]: row[1] for row in src_rows}

        conn.close()
        return stats