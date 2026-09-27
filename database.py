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
import urllib.request
from typing import Dict, Any, List, Optional

def get_country_flag(country_code: str) -> str:
    """Convert 2-letter ISO country code to emoji flag."""
    if not country_code or len(country_code) != 2:
        return '🌐'
    try:
        return ''.join(chr(127397 + ord(c.upper())) for c in country_code)
    except Exception:
        return '🌐'

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
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS inbound_connections (
                            id TEXT PRIMARY KEY,
                            timestamp REAL NOT NULL,
                            iso_time TEXT NOT NULL,
                            time_str TEXT NOT NULL,
                            remote_ip TEXT NOT NULL,
                            remote_port INTEGER,
                            local_ip TEXT NOT NULL,
                            local_port INTEGER,
                            proto TEXT NOT NULL,
                            service TEXT,
                            state TEXT,
                            country TEXT,
                            country_code TEXT,
                            region TEXT,
                            city TEXT,
                            asn TEXT,
                            org TEXT,
                            isp TEXT,
                            flag TEXT,
                            process TEXT,
                            bytes_received INTEGER DEFAULT 0,
                            bytes_sent INTEGER DEFAULT 0,
                            hit_count INTEGER DEFAULT 1,
                            first_seen REAL NOT NULL,
                            last_seen REAL NOT NULL,
                            threat_severity TEXT,
                            threat_signature TEXT,
                            user_agent TEXT,
                            endpoint TEXT,
                            source_type TEXT
                        );
                    """)
                    conn.execute("""
                        CREATE INDEX IF NOT EXISTS idx_inbound_last_seen 
                        ON inbound_connections(last_seen DESC);
                    """)
                    conn.execute("""
                        CREATE INDEX IF NOT EXISTS idx_inbound_remote_ip 
                        ON inbound_connections(remote_ip);
                    """)
                    conn.execute("""
                        CREATE INDEX IF NOT EXISTS idx_inbound_country 
                        ON inbound_connections(country);
                    """)
                    conn.execute("""
                        CREATE INDEX IF NOT EXISTS idx_inbound_region 
                        ON inbound_connections(region);
                    """)
                    conn.execute("""
                        CREATE INDEX IF NOT EXISTS idx_inbound_local_port 
                        ON inbound_connections(local_port);
                    """)
                    conn.execute("""
                        CREATE INDEX IF NOT EXISTS idx_inbound_threat_severity 
                        ON inbound_connections(threat_severity);
                    """)

                    # Backfill from historical threat events and snapshots if empty
                    try:
                        cursor = conn.cursor()
                        cursor.execute("SELECT COUNT(*) as cnt FROM inbound_connections")
                        row = cursor.fetchone()
                        if row and row['cnt'] == 0:
                            self._backfill_inbound_connections(conn)
                    except Exception as err:
                        print(f"[database.py] Notice during inbound backfill check: {err}")
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

    def _backfill_inbound_connections(self, conn: sqlite3.Connection):
        """Seed initial inbound_connections records from historical threat_events."""
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT src_ip, src_port, dest_ip, dest_port, proto, process, severity, signature, timestamp, iso_time, time_str, hit_count
                FROM threat_events
                ORDER BY timestamp DESC
                LIMIT 500
            """)
            threat_rows = cursor.fetchall()
            if not threat_rows:
                return

            unique_public_ips = set()
            for r in threat_rows:
                s_ip = r['src_ip']
                if s_ip and not s_ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
                                                 '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                                                 '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
                                                 '127.', '0.', '169.254.')):
                    unique_public_ips.add(s_ip)

            geo_map = {}
            pub_list = list(unique_public_ips)[:80]
            if pub_list:
                try:
                    url = 'http://ip-api.com/batch?fields=status,country,countryCode,regionName,city,isp,org,as,query'
                    req_data = json.dumps([{'query': ip} for ip in pub_list]).encode('utf-8')
                    req = urllib.request.Request(url, data=req_data, headers={'Content-Type': 'application/json', 'User-Agent': 'NetworkMonitor/2.0'})
                    with urllib.request.urlopen(req, timeout=3.0) as resp:
                        data = json.loads(resp.read().decode('utf-8'))
                        for item in data:
                            q_ip = item.get('query')
                            if q_ip and item.get('status') == 'success':
                                cc = item.get('countryCode', '')
                                as_val = item.get('as', '')
                                asn_short = as_val.split()[0] if as_val.startswith('AS') else as_val
                                geo_map[q_ip] = {
                                    'country': item.get('country', 'Unknown'),
                                    'country_code': cc,
                                    'region': item.get('regionName', ''),
                                    'city': item.get('city', 'Unknown'),
                                    'isp': item.get('isp', 'Unknown ISP'),
                                    'org': item.get('org', item.get('isp', 'Public Host')),
                                    'asn': asn_short or 'Unknown',
                                    'flag': get_country_flag(cc)
                                }
                except Exception:
                    pass

            for r in threat_rows:
                s_ip = r['src_ip']
                d_port = r['dest_port'] or 8080
                proto = (r['proto'] or 'TCP').upper()
                conn_id = f"{s_ip}:{d_port}:{proto}"
                ts = r['timestamp'] or time.time()
                iso_time = r['iso_time'] or time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ts))
                time_str = r['time_str'] or time.strftime('%H:%M:%S', time.localtime(ts))

                if s_ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
                                    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                                    '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
                                    '127.', '0.')):
                    country = 'Internal'
                    country_code = 'LAN'
                    region = 'Internal LAN'
                    city = 'Local Subnet'
                    flag = '🏠'
                    asn = 'RFC1918'
                    org = 'Private Network'
                    isp = 'Private Network'
                else:
                    g = geo_map.get(s_ip, {})
                    country = g.get('country', 'Public')
                    country_code = g.get('country_code', 'PUB')
                    region = g.get('region', '')
                    city = g.get('city', 'Unknown')
                    flag = g.get('flag', '🌐')
                    asn = g.get('asn', 'Public')
                    org = g.get('org', 'Public Host')
                    isp = g.get('isp', 'Public Internet')

                service = 'HTTP' if d_port == 8080 else 'SSH' if d_port == 22 else 'DNS' if d_port == 53 else f"Port {d_port}"

                cursor.execute("""
                    INSERT OR IGNORE INTO inbound_connections (
                        id, timestamp, iso_time, time_str,
                        remote_ip, remote_port, local_ip, local_port, proto, service,
                        state, country, country_code, region, city,
                        asn, org, isp, flag, process,
                        bytes_received, bytes_sent, hit_count, first_seen, last_seen,
                        threat_severity, threat_signature, user_agent, endpoint, source_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    conn_id, ts, iso_time, time_str,
                    s_ip, r['src_port'] or 0, r['dest_ip'] or '127.0.0.1', d_port, proto, service,
                    'CLOSED', country, country_code, region, city,
                    asn, org, isp, flag, r['process'] or 'Exploit Engine',
                    1024, 256, r['hit_count'] or 1, ts, ts,
                    r['severity'], r['signature'], '', '', 'threat_engine'
                ))
            print(f"[database.py] Successfully backfilled inbound_connections from threat_events.")
        except Exception as e:
            print(f"[database.py] Error during inbound backfill: {e}")

    def record_inbound_connection(self, conn_data: Dict[str, Any]) -> str:
        """
        Record or update an inbound connection flow in SQLite.
        Upserts on (remote_ip, local_port, proto).
        """
        remote_ip = str(conn_data.get('remote_ip') or conn_data.get('remoteIp') or '')
        local_port = int(conn_data.get('local_port') or conn_data.get('localPort') or 0)
        proto = str(conn_data.get('proto') or 'TCP').upper()
        if not remote_ip or not local_port:
            return ""

        conn_id = f"{remote_ip}:{local_port}:{proto}"
        now = time.time()
        iso_time = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now))
        time_str = time.strftime('%H:%M:%S', time.localtime(now))

        remote_port = int(conn_data.get('remote_port') or conn_data.get('remotePort') or 0)
        local_ip = str(conn_data.get('local_ip') or conn_data.get('localIP') or '127.0.0.1')
        service = str(conn_data.get('service') or '')
        state = str(conn_data.get('state') or 'ESTAB')
        country = str(conn_data.get('country') or 'Unknown')
        country_code = str(conn_data.get('country_code') or conn_data.get('countryCode') or '')
        region = str(conn_data.get('region') or conn_data.get('state') or '')
        city = str(conn_data.get('city') or 'Unknown')
        asn = str(conn_data.get('asn') or '')
        org = str(conn_data.get('org') or '')
        isp = str(conn_data.get('isp') or '')
        flag = str(conn_data.get('flag') or (get_country_flag(country_code) if country_code else '🌐'))
        process = str(conn_data.get('process') or '')
        bytes_recv = int(conn_data.get('bytes_received') or conn_data.get('bytesRecv') or 0)
        bytes_sent = int(conn_data.get('bytes_sent') or conn_data.get('bytesSent') or 0)
        threat_severity = str(conn_data.get('threat_severity') or conn_data.get('threatSeverity') or '')
        threat_signature = str(conn_data.get('threat_signature') or conn_data.get('threatSignature') or '')
        user_agent = str(conn_data.get('user_agent') or conn_data.get('userAgent') or '')
        endpoint = str(conn_data.get('endpoint') or '')
        source_type = str(conn_data.get('source_type') or conn_data.get('sourceType') or 'socket')

        with self.lock:
            conn = self._get_connection()
            try:
                with conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT id, hit_count, bytes_received, bytes_sent, first_seen,
                               threat_severity, threat_signature, country, region, city, flag
                        FROM inbound_connections WHERE id = ?
                    """, (conn_id,))
                    row = cursor.fetchone()
                    if row:
                        old_hits = row['hit_count'] or 1
                        old_recv = row['bytes_received'] or 0
                        old_sent = row['bytes_sent'] or 0
                        old_sev = row['threat_severity'] or ''
                        old_sig = row['threat_signature'] or ''
                        old_country = row['country'] or ''
                        old_region = row['region'] or ''
                        old_city = row['city'] or ''
                        old_flag = row['flag'] or '🌐'

                        fin_sev = threat_severity or old_sev
                        fin_sig = threat_signature or old_sig
                        fin_country = country if country != 'Unknown' else (old_country or country)
                        fin_region = region if region else old_region
                        fin_city = city if city != 'Unknown' else (old_city or city)
                        fin_flag = flag if flag != '🌐' else (old_flag or flag)

                        cursor.execute("""
                            UPDATE inbound_connections SET
                                remote_port = ?,
                                local_ip = ?,
                                service = COALESCE(NULLIF(?, ''), service),
                                state = ?,
                                country = ?,
                                country_code = COALESCE(NULLIF(?, ''), country_code),
                                region = ?,
                                city = ?,
                                asn = COALESCE(NULLIF(?, ''), asn),
                                org = COALESCE(NULLIF(?, ''), org),
                                isp = COALESCE(NULLIF(?, ''), isp),
                                flag = ?,
                                process = COALESCE(NULLIF(?, ''), process),
                                bytes_received = ?,
                                bytes_sent = ?,
                                hit_count = ?,
                                last_seen = ?,
                                threat_severity = ?,
                                threat_signature = ?,
                                user_agent = COALESCE(NULLIF(?, ''), user_agent),
                                endpoint = COALESCE(NULLIF(?, ''), endpoint),
                                source_type = ?
                            WHERE id = ?
                        """, (
                            remote_port, local_ip, service, state,
                            fin_country, country_code, fin_region, fin_city,
                            asn, org, isp, fin_flag, process,
                            old_recv + bytes_recv, old_sent + bytes_sent,
                            old_hits + 1, now, fin_sev, fin_sig,
                            user_agent, endpoint, source_type, conn_id
                        ))
                    else:
                        cursor.execute("""
                            INSERT INTO inbound_connections (
                                id, timestamp, iso_time, time_str,
                                remote_ip, remote_port, local_ip, local_port, proto, service,
                                state, country, country_code, region, city,
                                asn, org, isp, flag, process,
                                bytes_received, bytes_sent, hit_count, first_seen, last_seen,
                                threat_severity, threat_signature, user_agent, endpoint, source_type
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            conn_id, now, iso_time, time_str,
                            remote_ip, remote_port, local_ip, local_port, proto, service,
                            state, country, country_code, region, city,
                            asn, org, isp, flag, process,
                            bytes_recv, bytes_sent, 1, now, now,
                            threat_severity, threat_signature, user_agent, endpoint, source_type
                        ))

                    # 48-hour rolling retention pruning
                    cutoff = now - self.retention_seconds
                    cursor.execute("DELETE FROM inbound_connections WHERE last_seen < ?", (cutoff,))
                return conn_id
            finally:
                conn.close()

    def get_inbound_report(self, since: Optional[float] = None, limit: int = 500,
                           search: Optional[str] = None, country: Optional[str] = None,
                           region: Optional[str] = None, ip: Optional[str] = None,
                           port: Optional[int] = None, proto: Optional[str] = None,
                           threat_only: bool = False, source_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Query inbound connections with multi-faceted filtering (Country, State/Region, IP, Port, etc.)
        and generate summary aggregation metrics.
        """
        now = time.time()
        earliest_allowed = now - self.retention_seconds

        if since is not None:
            if since < 1_000_000:
                min_time = max(earliest_allowed, now - since)
            else:
                min_time = max(earliest_allowed, since)
        else:
            min_time = earliest_allowed

        where_clauses = ["last_seen >= ?"]
        params: List[Any] = [min_time]

        if country and country.strip().lower() not in ('all', ''):
            where_clauses.append("LOWER(country) = LOWER(?)")
            params.append(country.strip())

        if region and region.strip().lower() not in ('all', ''):
            where_clauses.append("LOWER(region) = LOWER(?)")
            params.append(region.strip())

        if ip and ip.strip():
            where_clauses.append("remote_ip LIKE ?")
            params.append(f"%{ip.strip()}%")

        if port and port > 0:
            where_clauses.append("local_port = ?")
            params.append(int(port))

        if proto and proto.strip().lower() not in ('all', ''):
            where_clauses.append("LOWER(proto) = LOWER(?)")
            params.append(proto.strip())

        if threat_only:
            where_clauses.append("threat_severity IS NOT NULL AND threat_severity != ''")

        if source_type and source_type.strip().lower() not in ('all', ''):
            where_clauses.append("LOWER(source_type) = LOWER(?)")
            params.append(source_type.strip())

        if search and search.strip():
            term = f"%{search.strip().lower()}%"
            where_clauses.append("""(
                LOWER(remote_ip) LIKE ? OR
                LOWER(country) LIKE ? OR
                LOWER(region) LIKE ? OR
                LOWER(city) LIKE ? OR
                LOWER(org) LIKE ? OR
                LOWER(isp) LIKE ? OR
                LOWER(asn) LIKE ? OR
                LOWER(service) LIKE ? OR
                CAST(local_port AS TEXT) LIKE ? OR
                LOWER(process) LIKE ? OR
                LOWER(threat_signature) LIKE ? OR
                LOWER(threat_severity) LIKE ?
            )""")
            params.extend([term] * 12)

        where_sql = " AND ".join(where_clauses)

        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()

                query = f"""
                    SELECT * FROM inbound_connections
                    WHERE {where_sql}
                    ORDER BY last_seen DESC
                    LIMIT ?
                """
                query_params = list(params)
                query_params.append(min(1000, max(1, limit)))
                cursor.execute(query, query_params)
                rows = cursor.fetchall()

                connections = []
                unique_ips = set()
                total_bytes = 0
                threat_count = 0
                countries_count: Dict[str, Dict[str, Any]] = {}
                states_count: Dict[str, Dict[str, Any]] = {}
                ports_count: Dict[int, Dict[str, Any]] = {}
                sources_count: Dict[str, int] = {}

                for r in rows:
                    rec = dict(r)
                    r_ip = rec['remote_ip']
                    unique_ips.add(r_ip)
                    b_recv = rec['bytes_received'] or 0
                    b_sent = rec['bytes_sent'] or 0
                    rec_bytes = b_recv + b_sent
                    total_bytes += rec_bytes
                    if rec['threat_severity']:
                        threat_count += 1

                    c_name = rec['country'] or 'Unknown'
                    c_code = rec['country_code'] or ''
                    c_flag = rec['flag'] or (get_country_flag(c_code) if c_code else '🌐')
                    if c_name not in countries_count:
                        countries_count[c_name] = {'country': c_name, 'countryCode': c_code, 'flag': c_flag, 'count': 0, 'bytes': 0}
                    countries_count[c_name]['count'] += rec['hit_count'] or 1
                    countries_count[c_name]['bytes'] += rec_bytes

                    r_name = rec['region'] or ''
                    if r_name:
                        state_key = f"{r_name}, {c_code or c_name}"
                        if state_key not in states_count:
                            states_count[state_key] = {'state': r_name, 'country': c_name, 'countryCode': c_code, 'flag': c_flag, 'count': 0, 'bytes': 0}
                        states_count[state_key]['count'] += rec['hit_count'] or 1
                        states_count[state_key]['bytes'] += rec_bytes

                    l_port = rec['local_port'] or 0
                    if l_port not in ports_count:
                        ports_count[l_port] = {'port': l_port, 'service': rec['service'] or f"Port {l_port}", 'proto': rec['proto'], 'count': 0}
                    ports_count[l_port]['count'] += rec['hit_count'] or 1

                    s_type = rec['source_type'] or 'socket'
                    sources_count[s_type] = sources_count.get(s_type, 0) + 1

                    connections.append(rec)

                # Available options for dropdowns across all records in time window
                cursor.execute("""
                    SELECT DISTINCT country, country_code, flag 
                    FROM inbound_connections 
                    WHERE last_seen >= ? AND country IS NOT NULL AND country != '' 
                    ORDER BY country ASC
                """, (min_time,))
                avail_countries = [{'country': row['country'], 'countryCode': row['country_code'], 'flag': row['flag']} for row in cursor.fetchall()]

                cursor.execute("""
                    SELECT DISTINCT region, country, country_code 
                    FROM inbound_connections 
                    WHERE last_seen >= ? AND region IS NOT NULL AND region != '' 
                    ORDER BY region ASC
                """, (min_time,))
                avail_states = [{'region': row['region'], 'country': row['country'], 'countryCode': row['country_code']} for row in cursor.fetchall()]

                cursor.execute("""
                    SELECT DISTINCT local_port, service, proto 
                    FROM inbound_connections 
                    WHERE last_seen >= ? AND local_port > 0 
                    ORDER BY local_port ASC
                """, (min_time,))
                avail_ports = [{'port': row['local_port'], 'service': row['service'], 'proto': row['proto']} for row in cursor.fetchall()]

                total_hits = sum(c['hit_count'] for c in connections) or len(connections) or 1
                top_countries = sorted(countries_count.values(), key=lambda x: x['count'], reverse=True)[:15]
                for tc in top_countries:
                    tc['pct'] = round((tc['count'] / total_hits) * 100, 1)

                top_states = sorted(states_count.values(), key=lambda x: x['count'], reverse=True)[:15]
                for ts in top_states:
                    ts['pct'] = round((ts['count'] / total_hits) * 100, 1)

                top_ports = sorted(ports_count.values(), key=lambda x: x['count'], reverse=True)[:10]

                return {
                    'summary': {
                        'totalConnections': len(connections),
                        'totalHits': total_hits,
                        'uniqueRemoteIps': len(unique_ips),
                        'totalBytes': total_bytes,
                        'threatCount': threat_count,
                        'topCountry': top_countries[0] if top_countries else None,
                        'topState': top_states[0] if top_states else None,
                        'sources': sources_count
                    },
                    'topCountries': top_countries,
                    'topStates': top_states,
                    'topPorts': top_ports,
                    'availableCountries': avail_countries,
                    'availableStates': avail_states,
                    'availablePorts': avail_ports,
                    'connections': connections
                }
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
                    purged += cursor.rowcount
                    cursor.execute("DELETE FROM inbound_connections WHERE last_seen < ?", (cutoff,))
                    purged += cursor.rowcount
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
