#!/usr/bin/env python3
"""
SQLite Database Module for Network Traffic History.
- Continuously records network telemetry snapshots (nodes, socket flows, bandwidth, latency, clusters).
- Strictly maintains a rolling 48-hour retention window (older snapshots are automatically purged).
- Provides thread-safe insertion, range queries, single-snapshot retrieval, and aggregated statistics.
"""

import os
import time
import json
import sqlite3
import threading
from typing import Dict, Any, List, Optional

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'network_history.db')
RETENTION_HOURS = 48
RETENTION_SECONDS = RETENTION_HOURS * 3600  # 172,800 seconds

class NetworkHistoryDB:
    """Manages persistent SQLite storage of network traffic snapshots with a 48-hour rolling window."""

    def __init__(self, db_path: str = DB_FILE, retention_seconds: int = RETENTION_SECONDS):
        self.db_path = db_path
        self.retention_seconds = retention_seconds
        self.lock = threading.Lock()
        self.total_purged = 0
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Performance tuning for concurrent reads and writes
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA temp_store = MEMORY;")
        return conn

    def _init_db(self):
        """Initialize database schema with proper indexes."""
        with self.lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS snapshots (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp REAL NOT NULL,
                            iso_time TEXT NOT NULL,
                            time_str TEXT NOT NULL,
                            total_nodes INTEGER NOT NULL,
                            internal_nodes INTEGER NOT NULL,
                            public_nodes INTEGER NOT NULL,
                            total_connections INTEGER NOT NULL,
                            total_sockets INTEGER NOT NULL,
                            rx_rate_kbps REAL NOT NULL,
                            tx_rate_kbps REAL NOT NULL,
                            avg_latency_ms REAL NOT NULL,
                            gateways_k INTEGER NOT NULL,
                            cross_subnet_count INTEGER NOT NULL,
                            active_processes TEXT NOT NULL,
                            topology_json TEXT NOT NULL
                        );
                    """)
                    conn.execute("""
                        CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp 
                        ON snapshots(timestamp);
                    """)
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS threat_events (
                            id TEXT PRIMARY KEY,
                            timestamp REAL NOT NULL,
                            iso_time TEXT NOT NULL,
                            time_str TEXT NOT NULL,
                            severity TEXT NOT NULL,
                            category TEXT NOT NULL,
                            signature TEXT NOT NULL,
                            cve TEXT,
                            sid INTEGER,
                            src_ip TEXT NOT NULL,
                            src_port INTEGER,
                            dest_ip TEXT NOT NULL,
                            dest_port INTEGER,
                            proto TEXT,
                            process TEXT,
                            matched_payload TEXT,
                            hit_count INTEGER DEFAULT 1,
                            recommendation TEXT,
                            details_json TEXT
                        );
                    """)
                    conn.execute("""
                        CREATE INDEX IF NOT EXISTS idx_threats_timestamp 
                        ON threat_events(timestamp DESC);
                    """)
                    conn.execute("""
                        CREATE INDEX IF NOT EXISTS idx_threats_severity 
                        ON threat_events(severity);
                    """)
            finally:
                conn.close()

    def record_snapshot(self, topology: Dict[str, Any]) -> int:
        """
        Record a new network topology snapshot and enforce the 48-hour rolling retention window.
        Returns the new snapshot ID.
        """
        if not topology or not isinstance(topology, dict):
            return -1

        now = time.time()
        iso_time = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now))
        time_str = time.strftime('%H:%M:%S', time.localtime(now))

        nodes = topology.get('nodes', [])
        connections = topology.get('connections', [])
        meta = topology.get('meta', {})
        sockets = topology.get('sockets', [])

        total_nodes = len(nodes)
        internal_nodes = meta.get('internalNodesCount', sum(1 for n in nodes if n.get('isInternal')))
        public_nodes = meta.get('publicNodesCount', sum(1 for n in nodes if not n.get('isInternal')))
        total_connections = len(connections)
        total_sockets = len(sockets)
        rx_rate_kbps = float(meta.get('rxRateKbps', 0.0))
        tx_rate_kbps = float(meta.get('txRateKbps', 0.0))

        # Calculate average latency from active connections
        latencies = [c.get('latencyMs', 0.0) for c in connections if c.get('latencyMs') and c.get('latencyMs') > 0]
        avg_latency_ms = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

        gateways_k = len(topology.get('subnetGateways', []))
        cross_subnet_count = sum(1 for c in connections if c.get('isCrossSubnet'))

        active_processes = json.dumps(meta.get('activeProcesses', []))
        topology_json = json.dumps(topology)

        with self.lock:
            conn = self._get_connection()
            try:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO snapshots (
                            timestamp, iso_time, time_str,
                            total_nodes, internal_nodes, public_nodes,
                            total_connections, total_sockets,
                            rx_rate_kbps, tx_rate_kbps, avg_latency_ms,
                            gateways_k, cross_subnet_count, active_processes,
                            topology_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        now, iso_time, time_str,
                        total_nodes, internal_nodes, public_nodes,
                        total_connections, total_sockets,
                        rx_rate_kbps, tx_rate_kbps, avg_latency_ms,
                        gateways_k, cross_subnet_count, active_processes,
                        topology_json
                    ))
                    snapshot_id = cursor.lastrowid

                    # Enforce strict 48-hour rolling retention window:
                    # Purge any snapshot older than (now - 48 hours)
                    cutoff = now - self.retention_seconds
                    cursor.execute("DELETE FROM snapshots WHERE timestamp < ?", (cutoff,))
                    purged = cursor.rowcount
                    if purged > 0:
                        self.total_purged += purged

                return snapshot_id
            finally:
                conn.close()

    def get_snapshots(self, since: Optional[float] = None, limit: int = 150, summary_only: bool = True) -> List[Dict[str, Any]]:
        """
        Query snapshots within the 48-hour rolling window.
        - since: timestamp or relative seconds in the past (e.g. 3600 for last 1 hour)
        - limit: max number of snapshots to return (defaults to 150)
        - summary_only: if True, omits topology_json for lightweight timeline transfer
        """
        now = time.time()
        earliest_allowed = now - self.retention_seconds

        if since is not None:
            if since < 1_000_000:
                # Relative seconds ago (e.g. since=3600 means last 1 hour)
                min_time = max(earliest_allowed, now - since)
            else:
                # Absolute timestamp
                min_time = max(earliest_allowed, since)
        else:
            min_time = earliest_allowed

        cols = [
            "id", "timestamp", "iso_time", "time_str",
            "total_nodes", "internal_nodes", "public_nodes",
            "total_connections", "total_sockets",
            "rx_rate_kbps", "tx_rate_kbps", "avg_latency_ms",
            "gateways_k", "cross_subnet_count", "active_processes"
        ]
        if not summary_only:
            cols.append("topology_json")

        sql = f"""
            SELECT {', '.join(cols)}
            FROM snapshots
            WHERE timestamp >= ?
            ORDER BY timestamp ASC
            LIMIT ?
        """

        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(sql, (min_time, min(1000, max(1, limit))))
                rows = cursor.fetchall()
                results = []
                for row in rows:
                    item = dict(row)
                    if 'active_processes' in item:
                        try:
                            item['active_processes'] = json.loads(item['active_processes'])
                        except Exception:
                            item['active_processes'] = []
                    if 'topology_json' in item:
                        try:
                            item['topology'] = json.loads(item['topology_json'])
                        except Exception:
                            item['topology'] = None
                        del item['topology_json']
                    results.append(item)
                return results
            finally:
                conn.close()

    def get_snapshot_by_id(self, snapshot_id: int) -> Optional[Dict[str, Any]]:
        """Fetch a single snapshot by ID with full topology for chart rendering."""
        sql = "SELECT * FROM snapshots WHERE id = ? LIMIT 1"
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(sql, (snapshot_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                item = dict(row)
                if 'active_processes' in item:
                    try:
                        item['active_processes'] = json.loads(item['active_processes'])
                    except Exception:
                        item['active_processes'] = []
                if 'topology_json' in item:
                    try:
                        item['topology'] = json.loads(item['topology_json'])
                    except Exception:
                        item['topology'] = None
                    del item['topology_json']
                return item
            finally:
                conn.close()

    def get_stats(self) -> Dict[str, Any]:
        """Get database storage, snapshot count, and 48-hour rolling window metrics."""
        now = time.time()
        earliest_allowed = now - self.retention_seconds

        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_count,
                        MIN(timestamp) as oldest_ts,
                        MAX(timestamp) as newest_ts
                    FROM snapshots
                """)
                row = cursor.fetchone()
                total_count = row['total_count'] if row else 0
                oldest_ts = row['oldest_ts'] if row and row['oldest_ts'] else None
                newest_ts = row['newest_ts'] if row and row['newest_ts'] else None

                timespan_seconds = (newest_ts - oldest_ts) if (newest_ts and oldest_ts) else 0.0
                timespan_hours = round(timespan_seconds / 3600.0, 2)

                # Database file size on disk
                db_size_bytes = 0
                if os.path.exists(self.db_path):
                    db_size_bytes = os.path.getsize(self.db_path)
                wal_path = f"{self.db_path}-wal"
                if os.path.exists(wal_path):
                    db_size_bytes += os.path.getsize(wal_path)

                db_size_mb = round(db_size_bytes / (1024 * 1024), 2)

                coverage_pct = round(min(100.0, (timespan_seconds / self.retention_seconds) * 100), 1) if timespan_seconds else 0.0

                return {
                    'totalSnapshots': total_count,
                    'retentionHours': RETENTION_HOURS,
                    'retentionSeconds': self.retention_seconds,
                    'oldestTimestamp': oldest_ts,
                    'newestTimestamp': newest_ts,
                    'oldestIso': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(oldest_ts)) if oldest_ts else None,
                    'newestIso': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(newest_ts)) if newest_ts else None,
                    'timespanHours': timespan_hours,
                    'coveragePct': coverage_pct,
                    'dbSizeBytes': db_size_bytes,
                    'dbSizeMb': db_size_mb,
                    'totalPurged': self.total_purged,
                    'status': 'active',
                    'rollingWindow': '48 hours'
                }
            finally:
                conn.close()

    def record_threat(self, threat: Dict[str, Any]) -> bool:
        """Record or update a detected threat event in SQLite."""
        if not threat or not isinstance(threat, dict):
            return False
        now = threat.get('timestamp') or time.time()
        iso_time = threat.get('isoTime') or time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now))
        time_str = threat.get('timeStr') or time.strftime('%H:%M:%S', time.localtime(now))
        event_id = threat.get('id') or f"threat_{int(now)}_{hash(threat.get('signature', '')) & 0xFFFFFF:06x}"
        hit_count = threat.get('hitCount', 1)

        with self.lock:
            conn = self._get_connection()
            try:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO threat_events (
                            id, timestamp, iso_time, time_str, severity, category,
                            signature, cve, sid, src_ip, src_port, dest_ip, dest_port,
                            proto, process, matched_payload, hit_count, recommendation, details_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(id) DO UPDATE SET
                            hit_count = hit_count + 1,
                            timestamp = excluded.timestamp,
                            iso_time = excluded.iso_time,
                            time_str = excluded.time_str,
                            matched_payload = excluded.matched_payload,
                            details_json = excluded.details_json;
                    """, (
                        event_id, now, iso_time, time_str,
                        threat.get('severity', 'MEDIUM'),
                        threat.get('category', 'Unknown'),
                        threat.get('signature', 'Unknown Signature'),
                        threat.get('cve'),
                        threat.get('sid'),
                        threat.get('srcIp', '0.0.0.0'),
                        threat.get('srcPort', 0),
                        threat.get('destIp', '0.0.0.0'),
                        threat.get('destPort', 0),
                        threat.get('proto', 'TCP'),
                        threat.get('process'),
                        str(threat.get('matchedPayload', ''))[:256],
                        hit_count,
                        threat.get('recommendation', ''),
                        json.dumps(threat)
                    ))
                    return True
            except Exception as e:
                return False
            finally:
                conn.close()

    def get_threats(self, since: Optional[float] = None, limit: int = 100, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent threat events, optionally filtered by timestamp or severity."""
        query = "SELECT * FROM threat_events"
        params = []
        conditions = []

        if since is not None:
            conditions.append("timestamp >= ?")
            params.append(since)
        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(query, params)
                rows = cursor.fetchall()
                threats = []
                for row in rows:
                    threats.append({
                        'id': row['id'],
                        'timestamp': row['timestamp'],
                        'isoTime': row['iso_time'],
                        'timeStr': row['time_str'],
                        'severity': row['severity'],
                        'category': row['category'],
                        'signature': row['signature'],
                        'cve': row['cve'],
                        'sid': row['sid'],
                        'srcIp': row['src_ip'],
                        'srcPort': row['src_port'],
                        'destIp': row['dest_ip'],
                        'destPort': row['dest_port'],
                        'proto': row['proto'],
                        'process': row['process'],
                        'matchedPayload': row['matched_payload'],
                        'hitCount': row['hit_count'],
                        'recommendation': row['recommendation']
                    })
                return threats
            finally:
                conn.close()

    def get_threat_stats(self) -> Dict[str, Any]:
        """Return aggregated threat metrics and counts from database."""
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) AS total, severity FROM threat_events GROUP BY severity;")
                rows = cursor.fetchall()
                counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'TOTAL': 0}
                for r in rows:
                    sev = r['severity']
                    cnt = r['total']
                    if sev in counts:
                        counts[sev] = cnt
                    counts['TOTAL'] += cnt
                return counts
            finally:
                conn.close()

    def purge_expired(self) -> int:
        """Manually trigger purging of records older than 48 hours."""
        now = time.time()
        cutoff = now - self.retention_seconds
        with self.lock:
            conn = self._get_connection()
            try:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM snapshots WHERE timestamp < ?", (cutoff,))
                    purged = cursor.rowcount
                    cursor.execute("DELETE FROM threat_events WHERE timestamp < ?", (cutoff,))
                    if purged > 0:
                        self.total_purged += purged
                    return purged
            finally:
                conn.close()


# Singleton instance
db = NetworkHistoryDB()

if __name__ == '__main__':
    stats = db.get_stats()
    print("Network History SQLite DB initialized.")
    print("Database path:", db.db_path)
    print("Stats:", json.dumps(stats, indent=2))
