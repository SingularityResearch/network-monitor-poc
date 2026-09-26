#!/usr/bin/env python3
"""
Dynamic Threat & Exploit Detection Engine for Network Monitor.
Integrates:
1. Dynamic Deep Packet Inspection (DPI) with Emerging Threats (ET Open) exploit & attack response signatures.
2. CISA Known Exploited Vulnerabilities (KEV) Catalog integration for live CVE intelligence & remediation actions.
3. Real-Time Malicious IP Reputation Feeds (abuse.ch Feodo Tracker C2 blocklist, CINS Army Threat Intelligence).
4. Real-Time Behavioral / Heuristic Anomaly Detectors (Port scan sweeps, TCP Xmas/SYN+FIN scans).
5. Automatic startup ingestion from online feeds with scheduled periodic background updates.
6. Offline disk caching for resilient zero-downtime startup.
7. Deduplication, active alerting, and SQLite persistence.
"""

import re
import time
import json
import socket
import struct
import os
import urllib.request
import threading
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional, Set, Tuple


def parse_suricata_content(val: str) -> bytes:
    """
    Parses Suricata/Snort rule content string handling mixed ascii and hex notation (|xx xx|).
    Example: '|00 01|test|02|' -> b'\\x00\\x01test\\x02'
    """
    parts: List[bytes] = []
    in_hex = False
    cur = ''
    for c in val:
        if c == '|':
            if in_hex:
                hex_str = cur.replace(' ', '')
                if hex_str:
                    try:
                        parts.append(bytes.fromhex(hex_str))
                    except ValueError:
                        pass
                cur = ''
                in_hex = False
            else:
                if cur:
                    parts.append(cur.encode('utf-8', errors='ignore'))
                    cur = ''
                in_hex = True
        else:
            cur += c
    if cur:
        if in_hex:
            hex_str = cur.replace(' ', '')
            if hex_str:
                try:
                    parts.append(bytes.fromhex(hex_str))
                except ValueError:
                    pass
        else:
            parts.append(cur.encode('utf-8', errors='ignore'))
    return b''.join(parts)


def parse_rule_ports(port_str: str) -> Optional[Set[int]]:
    """Parse Suricata/Snort port definition into a set of integer ports, or None for 'any'."""
    if not port_str or port_str.lower() in ('any', '$any'):
        return None
    port_str = port_str.strip('[]')
    ports = set()
    for token in port_str.split(','):
        token = token.strip()
        if token.isdigit():
            ports.add(int(token))
        elif token == '$HTTP_PORTS':
            ports.update([80, 443, 8080, 8443, 8000, 8888, 3000, 5000])
        elif token == '$ORACLE_PORTS':
            ports.update([1521, 2483, 2484])
        elif token == '$SQL_PORTS':
            ports.update([1433, 1521, 3306, 5432])
        elif token == '$TELNET_SERVERS':
            ports.add(23)
        elif token == '$DNS_PORTS':
            ports.add(53)
        elif token == '$FTP_PORTS':
            ports.update([20, 21])
    return ports if ports else None


class ThreatSignature:
    """Represents a compiled packet payload or protocol inspection rule."""
    def __init__(self, sid: int, name: str, severity: str, category: str, 
                 proto: str = 'ANY', ports: Optional[Set[int]] = None,
                 fast_patterns: Optional[List[bytes]] = None,
                 regex_patterns: Optional[List[re.Pattern]] = None,
                 cve: Optional[str] = None,
                 recommendation: str = ""):
        self.sid = sid
        self.name = name
        self.severity = severity.upper()  # CRITICAL, HIGH, MEDIUM, LOW
        self.category = category
        self.proto = proto.upper()
        self.ports = ports
        self.fast_patterns = [p.lower() if isinstance(p, bytes) else p.encode('utf-8').lower() for p in (fast_patterns or [])]
        self.regex_patterns = regex_patterns or []
        self.cve = cve
        self.recommendation = recommendation

    def matches(self, proto: str, src_port: int, dst_port: int, payload: bytes) -> Optional[str]:
        """Fast-path check: protocol -> port -> fast substring -> regex."""
        if self.proto != 'ANY' and self.proto != proto:
            return None
            
        if self.ports:
            if src_port not in self.ports and dst_port not in self.ports:
                return None
                
        if not payload:
            return None

        payload_lower = payload.lower()
        
        # Fast substring check
        if self.fast_patterns:
            matched_fast = False
            for fp in self.fast_patterns:
                if fp in payload_lower:
                    matched_fast = True
                    break
            if not matched_fast:
                return None

        # Regex validation if regex patterns were defined
        if self.regex_patterns:
            for rp in self.regex_patterns:
                match = rp.search(payload)
                if match:
                    matched_bytes = match.group(0)[:96]
                    try:
                        return matched_bytes.decode('utf-8', errors='replace')
                    except Exception:
                        return repr(matched_bytes)
            return None

        # If fast patterns were defined and matched without regex
        if self.fast_patterns:
            idx = payload_lower.find(self.fast_patterns[0])
            snippet = payload[max(0, idx - 8):min(len(payload), idx + len(self.fast_patterns[0]) + 32)]
            try:
                return snippet.decode('utf-8', errors='replace')
            except Exception:
                return repr(snippet)

        return None


class ThreatEngine:
    """
    Central Dynamic Threat Detection & Live Exploit Signature Matching Engine.
    Zero hardcoded signatures: dynamically downloads, parses, indexes, and schedules
    updates for emerging threats, CISA KEV catalog, and IP reputation feeds.
    """

    # Public threat intelligence feeds
    FEED_URLS = {
        'cisa_kev': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        'et_exploit': 'https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-exploit.rules',
        'et_attack': 'https://rules.emergingthreats.net/open/suricata-5.0/rules/emerging-attack_response.rules',
        'feodo_c2': 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
        'cins_army': 'https://cinsscore.com/list/ci-badguys.txt'
    }

    def __init__(self, db_instance=None, update_interval_seconds: float = 21600.0):
        self.db = db_instance
        self.lock = threading.Lock()
        
        # Threat Event Ring Buffers
        self.recent_threats = deque(maxlen=600)
        self.active_threat_map: Dict[Tuple[str, str, str, int], Dict[str, Any]] = {}
        
        # Statistics
        self.total_packets_inspected = 0
        self.total_threats_detected = 0
        self.threat_counts_by_severity = defaultdict(int)
        
        # Behavioral State: Port Scan Tracking: src_ip -> deque of (timestamp, dst_port)
        self.scan_history = defaultdict(lambda: deque(maxlen=100))
        self.last_scan_alert_time = defaultdict(float)
        
        # Threat Intelligence Storage (Dynamic, not hardcoded)
        self.signatures: List[ThreatSignature] = []
        self.rules_by_proto_port = defaultdict(list)
        self.rules_by_proto_anyport = defaultdict(list)
        self.rules_any_proto: List[ThreatSignature] = []
        
        self.cve_catalog: Dict[str, Dict[str, Any]] = {}
        self.tracked_cves: Set[str] = set()
        self.known_c2_ips: Set[str] = set()
        self.known_scanner_ips: Set[str] = set()
        self.ip_reputation_metadata: Dict[str, Dict[str, Any]] = {}
        
        # Feed Update & Scheduling State
        self.last_update_time: float = 0.0
        self.next_update_due: float = 0.0
        self.last_update_status: str = "Initializing"
        self.update_interval: float = update_interval_seconds  # 6 hours default
        self.is_updating: bool = False
        self.update_event = threading.Event()
        
        # Local Cache File for offline / instant warm-start
        self.cache_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'threat_signatures_cache.json')
        
        # 1. Warm-load disk cache if available for immediate packet sniffer readiness
        self._load_cache_from_disk()
        
        # 2. Launch background sync worker which runs an immediate live fetch on startup
        #    and continues recurring updates at the scheduled interval.
        self.feed_thread = threading.Thread(target=self._feed_sync_worker, daemon=True, name="ThreatFeedSync")
        self.feed_thread.start()

    def _rebuild_indexes(self):
        """Rebuild protocol and port indexes for high-speed sub-millisecond matching."""
        by_proto_port = defaultdict(list)
        by_proto_anyport = defaultdict(list)
        any_proto = []

        for sig in self.signatures:
            if sig.proto == 'ANY':
                any_proto.append(sig)
            elif sig.ports:
                for port in sig.ports:
                    by_proto_port[(sig.proto, port)].append(sig)
            else:
                by_proto_anyport[sig.proto].append(sig)

        self.rules_by_proto_port = by_proto_port
        self.rules_by_proto_anyport = by_proto_anyport
        self.rules_any_proto = any_proto

    def _load_cache_from_disk(self) -> bool:
        """Load previously cached signatures, CVEs, and reputation IPs from disk."""
        if not os.path.exists(self.cache_file):
            return False

        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            sigs_data = data.get('signatures', [])
            loaded_sigs: List[ThreatSignature] = []
            tracked_cves: Set[str] = set()

            for item in sigs_data:
                fast_patterns = [bytes.fromhex(h) for h in item.get('fast_patterns_hex', [])]
                regex_patterns = []
                for p in item.get('regex_patterns', []):
                    try:
                        regex_patterns.append(re.compile(p.encode('utf-8'), re.IGNORECASE))
                    except Exception:
                        pass
                
                ports = set(item['ports']) if item.get('ports') else None
                sig = ThreatSignature(
                    sid=item['sid'],
                    name=item['name'],
                    severity=item['severity'],
                    category=item['category'],
                    proto=item.get('proto', 'ANY'),
                    ports=ports,
                    fast_patterns=fast_patterns,
                    regex_patterns=regex_patterns,
                    cve=item.get('cve'),
                    recommendation=item.get('recommendation', '')
                )
                loaded_sigs.append(sig)
                if item.get('cve'):
                    tracked_cves.add(item['cve'].upper())

            with self.lock:
                self.signatures = loaded_sigs
                self.tracked_cves = tracked_cves
                self.cve_catalog = data.get('cve_catalog', {})
                self.known_c2_ips = set(data.get('known_c2_ips', []))
                self.known_scanner_ips = set(data.get('known_scanner_ips', []))
                self.ip_reputation_metadata = data.get('ip_reputation_metadata', {})
                self.last_update_time = data.get('last_update_time', time.time())
                self.next_update_due = self.last_update_time + self.update_interval
                self.last_update_status = "Armed from cache (syncing live feeds...)"
                self._rebuild_indexes()

            print(f"[ThreatEngine] Loaded {len(loaded_sigs)} signatures ({len(tracked_cves)} CVEs) and "
                  f"{len(self.known_c2_ips)} C2 IPs from local cache.")
            return True
        except Exception as e:
            print(f"[ThreatEngine] Notice: Could not read signatures cache ({e}). Will fetch fresh feeds.")
            return False

    def _save_cache_to_disk(self):
        """Persist current compiled signatures, CVEs, and reputation IPs to disk."""
        try:
            with self.lock:
                serializable_sigs = []
                for s in self.signatures:
                    serializable_sigs.append({
                        'sid': s.sid,
                        'name': s.name,
                        'severity': s.severity,
                        'category': s.category,
                        'proto': s.proto,
                        'ports': list(s.ports) if s.ports else None,
                        'fast_patterns_hex': [p.hex() for p in s.fast_patterns],
                        'cve': s.cve,
                        'recommendation': s.recommendation
                    })
                
                cache_payload = {
                    'version': '2.0',
                    'last_update_time': self.last_update_time,
                    'signatures_count': len(self.signatures),
                    'cves_count': len(self.tracked_cves),
                    'cve_catalog': self.cve_catalog,
                    'signatures': serializable_sigs,
                    'known_c2_ips': list(self.known_c2_ips)[:1000],
                    'known_scanner_ips': list(self.known_scanner_ips)[:2000],
                    'ip_reputation_metadata': self.ip_reputation_metadata
                }

            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_payload, f)
        except Exception as e:
            print(f"[ThreatEngine] Warning saving signature cache: {e}")

    def _fetch_url(self, url: str, timeout: float = 14.0) -> bytes:
        """Download raw feed content with standard user agent."""
        req = urllib.request.Request(url, headers={"User-Agent": "NetworkMonitor-ThreatEngine/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()

    def parse_suricata_rules(self, raw_text: str, cve_lookup: Dict[str, Dict[str, Any]]) -> List[ThreatSignature]:
        """Parse raw Suricata/Snort rules into compiled ThreatSignature objects."""
        compiled: List[ThreatSignature] = []
        for line in raw_text.splitlines():
            line = line.strip()
            if not line.startswith('alert'):
                continue
            h_end = line.find('(')
            if h_end == -1 or not line.endswith(')'):
                continue
            header = line[:h_end].strip().split()
            if len(header) < 6:
                continue

            proto = header[1].upper()
            if proto in ('HTTP', 'TLS', 'SSL'):
                proto = 'TCP'

            dst_port_str = header[5]
            ports = parse_rule_ports(dst_port_str)
            opts = line[h_end+1:-1]

            msg_m = re.search(r'msg:\s*\"([^\"]+)\"', opts)
            msg = msg_m.group(1) if msg_m else 'ET Exploit Attempt'

            sid_m = re.search(r'sid:\s*(\d+)', opts)
            sid = int(sid_m.group(1)) if sid_m else 0

            # Extract CVE reference or CVE in rule name
            cve = None
            cve_m = re.search(r'reference:\s*cve,\s*([^;]+)', opts, re.IGNORECASE)
            if cve_m:
                raw_cve = cve_m.group(1).strip()
                cve = raw_cve if raw_cve.upper().startswith('CVE-') else f'CVE-{raw_cve}'
            else:
                cve_in_msg = re.search(r'(CVE-\d{4}-\d{4,7})', msg, re.IGNORECASE)
                if cve_in_msg:
                    cve = cve_in_msg.group(1).upper()

            contents = re.findall(r'content:\s*\"([^\"]+)\"', opts)
            fast_patterns = [parse_suricata_content(c).lower() for c in contents if len(parse_suricata_content(c)) >= 3]
            if not fast_patterns:
                continue

            # Classify severity & category
            classtype_m = re.search(r'classtype:\s*([^;]+)', opts)
            classtype = classtype_m.group(1).strip() if classtype_m else ''

            severity = 'HIGH'
            category = 'Exploit Attempt'
            if any(k in classtype for k in ('attempted-admin', 'shellcode', 'trojan')):
                severity = 'CRITICAL'
                category = 'Remote Code Execution' if 'admin' in classtype else 'Malware Activity'
            elif 'web-application' in classtype:
                category = 'Web Application Attack'
            elif 'attempted-user' in classtype:
                category = 'Unauthorized Access Attempt'
            elif 'denial-of-service' in classtype:
                category = 'Denial of Service'
            elif 'scan' in classtype:
                severity = 'MEDIUM'
                category = 'Network Reconnaissance'

            # Enrich with CISA KEV catalog if matched
            if cve and cve.upper() in cve_lookup:
                severity = 'CRITICAL'
                kev = cve_lookup[cve.upper()]
                category = 'Known Exploited Vulnerability'
                product = kev.get('product') or kev.get('vendorProject') or 'application'
                action = kev.get('requiredAction') or f'Apply vendor security updates for {cve}.'
                recommendation = f"CISA KEV Alert ({product}): {action}"
            else:
                recommendation = f"Isolate endpoint and apply security patches for {cve if cve else msg[:50]}."

            compiled.append(ThreatSignature(
                sid=sid,
                name=msg,
                severity=severity,
                category=category,
                proto=proto,
                ports=ports,
                fast_patterns=fast_patterns,
                cve=cve,
                recommendation=recommendation
            ))

        return compiled

    def sync_all_feeds(self, force: bool = False) -> Dict[str, Any]:
        """
        Download fresh threat intelligence from CISA, Emerging Threats, abuse.ch, and CINS Army.
        Compiles all rules dynamically with zero hardcoded signatures.
        """
        with self.lock:
            if self.is_updating and not force:
                return {'status': 'in_progress', 'message': 'Update already running'}
            self.is_updating = True
            self.last_update_status = "Updating live feeds..."

        t_start = time.time()
        print("[ThreatEngine] Starting live threat intelligence feed synchronization...")

        try:
            # 1. Fetch CISA Known Exploited Vulnerabilities (KEV) Catalog
            cve_catalog = {}
            try:
                raw_cisa = self._fetch_url(self.FEED_URLS['cisa_kev'], timeout=12.0)
                kev_json = json.loads(raw_cisa.decode('utf-8'))
                for vuln in kev_json.get('vulnerabilities', []):
                    cve_id = vuln.get('cveID', '').upper().strip()
                    if cve_id:
                        cve_catalog[cve_id] = vuln
                print(f"[ThreatEngine] Synced {len(cve_catalog)} CISA Known Exploited Vulnerabilities (KEV).")
            except Exception as e:
                print(f"[ThreatEngine] Warning fetching CISA KEV feed: {e}")
                cve_catalog = self.cve_catalog

            # 2. Fetch Emerging Threats (ET Open) Exploit Rules & Attack Response Rules
            new_signatures: List[ThreatSignature] = []
            for feed_key in ('et_exploit', 'et_attack'):
                url = self.FEED_URLS[feed_key]
                try:
                    raw_rules = self._fetch_url(url, timeout=14.0).decode('utf-8', errors='ignore')
                    rules = self.parse_suricata_rules(raw_rules, cve_catalog)
                    new_signatures.extend(rules)
                    print(f"[ThreatEngine] Synced {len(rules)} compiled DPI signatures from {feed_key}.")
                except Exception as e:
                    print(f"[ThreatEngine] Warning fetching {feed_key}: {e}")

            # 3. Fetch abuse.ch Feodo Tracker Botnet C2 blocklist
            new_c2_ips: Set[str] = set()
            new_rep_meta: Dict[str, Dict[str, Any]] = {}
            try:
                raw_feodo = self._fetch_url(self.FEED_URLS['feodo_c2'], timeout=10.0)
                feodo_data = json.loads(raw_feodo.decode('utf-8'))
                for item in feodo_data:
                    ip = item.get('ip_address', '').strip()
                    malware = item.get('malware', 'Botnet C2')
                    if ip and '.' in ip:
                        new_c2_ips.add(ip)
                        new_rep_meta[ip] = {
                            'family': f"{malware} C2",
                            'category': 'Botnet C2',
                            'severity': 'CRITICAL'
                        }
                print(f"[ThreatEngine] Synced {len(new_c2_ips)} active botnet C2 servers from abuse.ch Feodo Tracker.")
            except Exception as e:
                print(f"[ThreatEngine] Warning fetching Feodo Tracker feed: {e}")

            # 4. Fetch CINS Army Hostile Scanner / Malicious IP list
            new_scanner_ips: Set[str] = set()
            try:
                raw_cins = self._fetch_url(self.FEED_URLS['cins_army'], timeout=10.0).decode('utf-8', errors='ignore')
                for line in raw_cins.splitlines():
                    ip = line.strip()
                    if ip and not ip.startswith('#') and '.' in ip:
                        new_scanner_ips.add(ip)
                        if ip not in new_rep_meta:
                            new_rep_meta[ip] = {
                                'name': 'CINS Threat Intelligence Malicious Actor',
                                'category': 'Hostile Recon / Scanner',
                                'severity': 'MEDIUM'
                            }
                print(f"[ThreatEngine] Synced {len(new_scanner_ips)} hostile scanner IPs from CINS Army.")
            except Exception as e:
                print(f"[ThreatEngine] Warning fetching CINS Army feed: {e}")

            # Compile set of unique CVEs tracked
            new_tracked_cves = set(s.cve.upper() for s in new_signatures if s.cve)

            # Atomic swap of active rules & reputation lists
            with self.lock:
                if new_signatures:
                    self.signatures = new_signatures
                    self.tracked_cves = new_tracked_cves
                    self._rebuild_indexes()

                if cve_catalog:
                    self.cve_catalog = cve_catalog

                if new_c2_ips:
                    self.known_c2_ips = new_c2_ips

                if new_scanner_ips:
                    self.known_scanner_ips = new_scanner_ips

                if new_rep_meta:
                    self.ip_reputation_metadata.update(new_rep_meta)

                self.last_update_time = time.time()
                self.next_update_due = self.last_update_time + self.update_interval
                self.last_update_status = "Active (Live Feeds Synced)"
                self.is_updating = False

            # Save to disk cache for future instant boots
            self._save_cache_to_disk()

            elapsed = round(time.time() - t_start, 2)
            print(f"[ThreatEngine] Synchronization complete in {elapsed}s: "
                  f"{len(self.signatures)} rules active, {len(self.tracked_cves)} CVEs monitored, "
                  f"{len(self.known_c2_ips)} C2 IPs, {len(self.known_scanner_ips)} hostile IPs.")

            return {
                'status': 'success',
                'elapsedSeconds': elapsed,
                'totalRulesLoaded': len(self.signatures),
                'totalTrackedCVEs': len(self.tracked_cves),
                'totalKnownC2IPs': len(self.known_c2_ips),
                'totalKnownScanners': len(self.known_scanner_ips)
            }

        except Exception as err:
            with self.lock:
                self.is_updating = False
                self.last_update_status = f"Update failed: {err}"
            print(f"[ThreatEngine] Error in sync_all_feeds: {err}")
            return {'status': 'error', 'message': str(err)}

    def trigger_feed_update(self):
        """Wake up update worker to perform an immediate sync."""
        self.update_event.set()

    def _feed_sync_worker(self):
        """
        Background updater worker:
        Performs an immediate fetch on startup, then sleeps for the update interval
        (default 6 hours) before refreshing rules automatically.
        """
        # Run startup sync immediately (small 1.5s yield so server can bind port)
        time.sleep(1.5)
        self.sync_all_feeds(force=True)

        while True:
            # Wait for next scheduled interval or manual trigger event
            woken_by_event = self.update_event.wait(timeout=self.update_interval)
            self.update_event.clear()

            if woken_by_event:
                print("[ThreatEngine] Manual signature update triggered.")
            else:
                print(f"[ThreatEngine] Scheduled {self.update_interval/3600:.1f}h signature update starting...")

            self.sync_all_feeds(force=True)

    def record_threat_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Record and deduplicate a detected threat event, persisting to SQLite if available."""
        now = time.time()
        event_id = event.get('id') or f"threat_{int(now)}_{hash(event.get('signature', '')) & 0xFFFFFF:06x}"
        event['id'] = event_id
        event['timestamp'] = now
        event['isoTime'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now))
        event['timeStr'] = time.strftime('%H:%M:%S', time.localtime(now))
        
        sig_name = event.get('signature', 'Unknown')
        src_ip = event.get('srcIp', '0.0.0.0')
        dst_ip = event.get('destIp', '0.0.0.0')
        dst_port = event.get('destPort', 0)
        
        dedup_key = (sig_name, src_ip, dst_ip, dst_port)

        with self.lock:
            self.total_threats_detected += 1
            severity = event.get('severity', 'MEDIUM').upper()
            self.threat_counts_by_severity[severity] += 1
            
            if dedup_key in self.active_threat_map:
                existing = self.active_threat_map[dedup_key]
                existing['hitCount'] = existing.get('hitCount', 1) + 1
                existing['lastSeen'] = now
                existing['lastSeenStr'] = event['timeStr']
                return existing
            else:
                event['hitCount'] = 1
                event['firstSeen'] = now
                event['lastSeen'] = now
                event['lastSeenStr'] = event['timeStr']
                self.active_threat_map[dedup_key] = event
                self.recent_threats.appendleft(event)

        # Persist to SQLite database
        if self.db:
            try:
                self.db.record_threat(event)
            except Exception:
                pass

        return event

    def inspect_packet(self, proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int, 
                       payload: bytes, process: Optional[str] = None, tcp_flags: int = 0) -> Optional[Dict[str, Any]]:
        """
        Deep packet inspection hook called by RawPacketSniffer.
        Evaluates payload signatures, TCP flag anomalies, and IP reputation.
        """
        self.total_packets_inspected += 1
        now = time.time()

        # 1. IP Reputation Check (Source or Destination matching known C2 or malicious scanner)
        for target_ip, role in [(src_ip, 'src'), (dst_ip, 'dst')]:
            if target_ip in self.known_c2_ips:
                meta = self.ip_reputation_metadata.get(target_ip, {})
                family = meta.get('family', 'Botnet C2')
                return self.record_threat_event({
                    'severity': 'CRITICAL',
                    'category': 'Malware Command & Control',
                    'signature': f"REPUTATION Malicious Botnet C2 Contact ({family})",
                    'srcIp': src_ip,
                    'srcPort': src_port,
                    'destIp': dst_ip,
                    'destPort': dst_port,
                    'proto': proto,
                    'process': process or 'Unknown',
                    'matchedPayload': f"Flagged IP: {target_ip} ({family})",
                    'recommendation': "Host is communicating with confirmed botnet C2 infrastructure. Isolate immediately."
                })

            if target_ip in self.known_scanner_ips:
                meta = self.ip_reputation_metadata.get(target_ip, {})
                name = meta.get('name', 'Hostile Recon / Scanner')
                return self.record_threat_event({
                    'severity': meta.get('severity', 'LOW'),
                    'category': 'Network Reconnaissance',
                    'signature': f"REPUTATION Recognized Scanner Probe ({name})",
                    'srcIp': src_ip,
                    'srcPort': src_port,
                    'destIp': dst_ip,
                    'destPort': dst_port,
                    'proto': proto,
                    'process': process or 'Unknown',
                    'matchedPayload': f"Scanner IP: {target_ip} ({name})",
                    'recommendation': "Standard reconnaissance activity. Review firewall exposure."
                })

        # 2. TCP Flag Anomaly Heuristics
        if proto == 'TCP' and tcp_flags > 0:
            if tcp_flags == 0x29:  # Xmas scan (FIN=0x01, PSH=0x08, URG=0x20 -> 0x29)
                return self.record_threat_event({
                    'severity': 'MEDIUM',
                    'category': 'Port Scan',
                    'signature': "SCAN Nmap Stealth Xmas Tree Scan Probe (FIN+PSH+URG)",
                    'srcIp': src_ip,
                    'srcPort': src_port,
                    'destIp': dst_ip,
                    'destPort': dst_port,
                    'proto': proto,
                    'process': process,
                    'matchedPayload': "TCP Flags: FIN, PSH, URG set simultaneously",
                    'recommendation': "Hostile reconnaissance tool detected probing open ports."
                })
            elif (tcp_flags & 0x03) == 0x03:  # SYN + FIN simultaneously
                return self.record_threat_event({
                    'severity': 'MEDIUM',
                    'category': 'Protocol Anomaly',
                    'signature': "SCAN Malformed TCP Flag Combination (SYN+FIN)",
                    'srcIp': src_ip,
                    'srcPort': src_port,
                    'destIp': dst_ip,
                    'destPort': dst_port,
                    'proto': proto,
                    'process': process,
                    'matchedPayload': "TCP Flags: SYN and FIN set simultaneously",
                    'recommendation': "Firewall evasion scan detected."
                })

        # 3. Behavioral Port Scan Detection (track distinct ports within 6-second sliding window)
        if dst_port > 0 and not src_ip.startswith('127.'):
            history = self.scan_history[src_ip]
            history.append((now, dst_port))
            
            while history and now - history[0][0] > 6.0:
                history.popleft()
                
            unique_ports = set(p for t, p in history)
            if len(unique_ports) >= 12 and (now - self.last_scan_alert_time[src_ip] > 15.0):
                self.last_scan_alert_time[src_ip] = now
                return self.record_threat_event({
                    'severity': 'HIGH',
                    'category': 'Port Scan',
                    'signature': f"SCAN Horizontal Port Sweep Detected ({len(unique_ports)} ports targeted)",
                    'srcIp': src_ip,
                    'srcPort': src_port,
                    'destIp': dst_ip,
                    'destPort': dst_port,
                    'proto': proto,
                    'process': process,
                    'matchedPayload': f"Probed ports: {sorted(list(unique_ports))[:8]}...",
                    'recommendation': "Source host is scanning multiple ports. Consider blocking source IP on local firewall."
                })

        # 4. Deep Packet Payload Signature Inspection (fast candidate lookup)
        if payload and len(payload) >= 4:
            candidates: List[ThreatSignature] = []
            if dst_port:
                candidates.extend(self.rules_by_proto_port.get((proto, dst_port), []))
            if src_port:
                candidates.extend(self.rules_by_proto_port.get((proto, src_port), []))
            candidates.extend(self.rules_by_proto_anyport.get(proto, []))
            candidates.extend(self.rules_any_proto)

            seen_sids = set()
            for sig in candidates:
                if sig.sid in seen_sids:
                    continue
                seen_sids.add(sig.sid)

                matched_snippet = sig.matches(proto, src_port, dst_port, payload)
                if matched_snippet:
                    return self.record_threat_event({
                        'severity': sig.severity,
                        'category': sig.category,
                        'signature': sig.name,
                        'cve': sig.cve,
                        'sid': sig.sid,
                        'srcIp': src_ip,
                        'srcPort': src_port,
                        'destIp': dst_ip,
                        'destPort': dst_port,
                        'proto': proto,
                        'process': process or 'Unknown',
                        'matchedPayload': matched_snippet,
                        'recommendation': sig.recommendation
                    })

        return None

    def get_threats_summary(self) -> Dict[str, Any]:
        """Return structured summary of active threats and system counts."""
        now = time.time()
        with self.lock:
            recent_list = [t for t in self.recent_threats if now - t.get('lastSeen', t.get('timestamp', 0)) <= 600.0]
            
            critical_count = sum(1 for t in recent_list if t.get('severity') == 'CRITICAL')
            high_count = sum(1 for t in recent_list if t.get('severity') == 'HIGH')
            medium_count = sum(1 for t in recent_list if t.get('severity') == 'MEDIUM')
            low_count = sum(1 for t in recent_list if t.get('severity') == 'LOW')
            
            affected_ips = set()
            for t in recent_list:
                if t.get('srcIp'):
                    affected_ips.add(t['srcIp'])
                if t.get('destIp'):
                    affected_ips.add(t['destIp'])

            return {
                'activeThreatsCount': len(recent_list),
                'criticalCount': critical_count,
                'highCount': high_count,
                'mediumCount': medium_count,
                'lowCount': low_count,
                'affectedHostsCount': len(affected_ips),
                'totalInspectedPackets': self.total_packets_inspected,
                'totalRulesLoaded': len(self.signatures),
                'totalTrackedCVEs': len(self.tracked_cves),
                'totalKnownC2IPs': len(self.known_c2_ips),
                'totalKnownScanners': len(self.known_scanner_ips),
                'feedStatus': self.last_update_status,
                'isUpdating': self.is_updating,
                'lastUpdated': self.last_update_time,
                'lastUpdatedIso': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(self.last_update_time)) if self.last_update_time else None,
                'lastUpdatedStr': time.strftime('%H:%M:%S', time.localtime(self.last_update_time)) if self.last_update_time else "Never",
                'nextUpdateDue': self.next_update_due,
                'nextUpdateStr': time.strftime('%H:%M:%S', time.localtime(self.next_update_due)) if self.next_update_due else "Pending",
                'updateIntervalHours': round(self.update_interval / 3600.0, 1),
                'threats': recent_list[:100]
            }


# Global threat engine singleton
try:
    from database import db
    threat_engine = ThreatEngine(db_instance=db)
except Exception:
    threat_engine = ThreatEngine()
