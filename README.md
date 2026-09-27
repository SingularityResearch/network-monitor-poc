# K-Means Network IP & Port Connection Visualizer

An interactive, high-performance Network Operations Center (NOC) web application monitoring **actual real-time network traffic from your Linux host and local network**.

Every node represents an IP address with **active socket connections and raw packet flows destined for specific ports on other IP addresses**, dynamically clustered into **Subnet Zones** using K-Means centroids as **Virtual Subnet Gateways**.

---

## Table of Contents
1. [Key Features & Capabilities](#key-features--capabilities)
2. [Real Network Telemetry (Internal & Public)](#real-network-telemetry-internal--public)
3. [Network Relationships & Correlation Engine](#network-relationships--correlation-engine)
4. [Interactive 2D Canvas & Focus Spotlight](#interactive-2d-canvas--focus-spotlight)
5. [Deep Socket & Protocol Inspector](#deep-socket--protocol-inspector)
6. [Threshold Latency & Bandwidth Alerts](#threshold-latency--bandwidth-alerts)
7. [SQLite Persistent History & 48-Hour Rolling Window](#sqlite-persistent-history--48-hour-rolling-window)
8. [Raw Packet Capture & Promiscuous Monitoring](#raw-packet-capture--promiscuous-monitoring)
9. [Security Detection, Signature Caching & Real-Time Threat Engine](#security-detection-signature-caching--real-time-threat-engine)
10. [REST API Reference](#rest-api-reference)
11. [Running Locally](#running-locally)

---

## Key Features & Capabilities

- **Live Linux Kernel Telemetry**: Streams real socket stats directly from `/proc/net`, Linux `sock_diag` netlink / `ss`, and ARP neighbor cache via [telemetry.py](file:///home/shivachrome/source/repos/network-monitor/telemetry.py).
- **Embedded Raw Packet Sniffer**: Linux `AF_PACKET` raw socket engine capturing Layer 2 Ethernet, IPv4, TCP, UDP, ICMP, ARP, DHCP, mDNS, and SSDP broadcasts.
- **Deep Packet Inspection (DPI) & Threat Detection**: Real-time packet payload scanner matching 2,300+ dynamic exploit signatures (Log4Shell, Spring4Shell, Shellshock, Apache Path Traversal, SQLi, Web Shells, Redis RCE) and botnet C2 communications in [threat_engine.py](file:///home/shivachrome/source/repos/network-monitor/threat_engine.py).
- **Instant Signature Caching & Offline Warm-Start**: Pre-compiled 5.5 MB local disk cache in [threat_signatures_cache.json](file:///home/shivachrome/source/repos/network-monitor/threat_signatures_cache.json) arming 2,300+ rules, 560+ CISA KEV vulnerability records, and 3,000+ malicious reputation IPs in under 10ms with zero network blocking.
- **Authentic Threat & Exploit Traffic Generator**: Multi-vector traffic simulation engine in [traffic_generator.py](file:///home/shivachrome/source/repos/network-monitor/traffic_generator.py) emitting authentic inbound exploits, stealth port sweeps, and outbound botnet C2 beacons directly into Linux network interfaces.
- **Relational Correlation Engine**: Detects internal peer-to-peer lateral mesh connections, common external destination domains/URLs accessed by multiple hosts, and protocol affinity clusters.
- **Canvas Focus Spotlight**: Isolate relational subgraphs and threat paths on canvas with non-matching node/connection dimming, animated packet stream restriction, glowing halo accents, and crimson hazard vectors.
- **K-Means Subnet Clustering**: Auto-tunes $K$ centroids using Silhouette Score and WCSS Inertia to discover virtual subnet gateways and routing boundaries.
- **Hardware-Accelerated 60 FPS Canvas Engine**: Smooth lerp coordinate interpolation, organic micro-drift motion, interactive mouse-anchored zoom/pan, and pulsing crimson hazard beacons in [chart.js](file:///home/shivachrome/source/repos/network-monitor/chart.js).
- **Deep Socket Inspector**: Interactive sliding drawer inspecting kernel sockets with protocol badges, TCP connection states, local/remote endpoints, process attribution, TCP RTT variance, and CWND queue buffers.
- **Persistent SQLite Storage**: Background recorder storing full topology snapshots and threat events with Write-Ahead Logging (WAL) and automatic rolling 48-hour data retention in [database.py](file:///home/shivachrome/source/repos/network-monitor/database.py).
- **Historical Timeline Scrubber**: Step backward in time, scrub with a timeline slider across `10m`, `1h`, `6h`, `24h`, and `48h`, and run automated replay playback.
- **Active Threshold Alerts**: Real-time notifications and canvas pulse overlays triggered whenever latency or bandwidth exceed custom thresholds.

---

## Real Network Telemetry (Internal & Public)

The visualizer connects directly to your Linux system's networking stack via [serve.py](file:///home/shivachrome/source/repos/network-monitor/serve.py) and [telemetry.py](file:///home/shivachrome/source/repos/network-monitor/telemetry.py):

### 1. Internal Traffic (LAN & Loopback)
- **Local Host IP & Active Interface**: Discovers your primary interface (e.g. `enp2s0`, `eth0`) and local IP address (e.g. `10.0.0.7`, `192.168.0.117`).
- **Default Gateway & LAN Hosts**: Identifies your default router (`10.0.0.1` / `192.168.0.1`), ARP neighbor cache, and local subnet peer devices.
- **Loopback & Local IPC**: Monitors local inter-process communication sockets (`127.0.0.1`) across development servers, IDE services, databases, and microservices.
- **LAN Ping Discovery**: Click **Scan LAN Subnet** to asynchronously ping the local subnet and discover newly connected devices in real time.

### 2. Public Internet Traffic
- **Active Internet Sockets**: Captures live outbound and inbound connections across public cloud and web services (Google, GitHub, Microsoft Azure, AWS, Fastly, Cloudflare, etc.).
- **Provider & Reverse DNS Resolution**: Resolves hostnames, root domains, and ASN organizations with thread-safe caching.
- **Real TCP Metrics**: Tracks true kernel RTT latency in milliseconds, delivery rates, bytes transferred, and socket states.
- **Application & Process Attribution**: Automatically maps connections to running processes (e.g. `chrome`, `antigravity-ide`, `language_server`, `sshd`, `python3`).

### 3. Traffic Scopes
In the dashboard controls, easily filter your view:
- **🌐 All Traffic (Internal & Public)**: Complete holistic view of both internal LAN/IPC and public internet flows.
- **🏠 Internal Only (LAN & Loopback)**: Focuses exclusively on your local subnet, gateway, and local services.
- **☁️ Public Only (External Internet)**: Focuses exclusively on outbound traffic to external internet hosts and cloud providers.

---

## Network Relationships & Correlation Engine

The application includes a specialized analytics engine in [`RealNetworkCollector.extract_relationships()`](file:///home/shivachrome/source/repos/network-monitor/telemetry.py#L1230-L1424) that continuously examines active network flows to discover meaningful relationships:

### 1. Internal Mesh (Peer-to-Peer & Lateral Flows)
- Correlates direct communication occurring between two devices within your local internal network (e.g. `_gateway ↔ shiva-ubuntu` or peer LAN machines).
- Aggregates:
  - Total active socket connections between the two peers
  - Aggregate throughput (KB/s) and average RTT latency (ms)
  - Exchanged destination ports (e.g. `:22` SSH, `:8080`, `:53` DNS, `:67` DHCP)
  - Protocol breakdown (`TCP`, `UDP`, `ICMP`) and communicating system processes

### 2. Common URLs, External Domains & Cloud Providers
- Groups external destination hosts by root domain (e.g. `github.com`, `google.com`, `1e100.net`, `mcast.net`, CDN subdomains, and cloud ASN providers).
- Identifies when multiple internal devices or sockets are accessing the same destination service or provider.
- Displays participating client hosts, unique destination IP pools, combined throughput, and country/organization flags.

### 3. Protocol Affinity & Service Clusters
- Clusters network flows based on shared protocol and service definitions (e.g. `mDNS :5353`, `SSDP-UPnP :1900`, `HTTPS :443`, `DNS :53`, `DHCP :67`).
- Displays the client host pool, server destination pool, active socket count, and data rate for each protocol.

### 4. Relationships Explorer Drawer
- Open via the **Relationships** header button (with glowing cyan border and live counter pill) or the **Relationships** button in the left sidebar under Controls.
- **Summary KPI Grid**: Displays live counters for *Internal Peer Links*, *Shared External Targets*, *Active Protocols*, and the *Top Internal Pair*.
- **Search & Filter Bar**: Filter relationships dynamically by IP, hostname, root domain, service name, port, or process.
- **Interactive Action Buttons**:
  - **Focus Canvas**: Activates the Canvas Focus Spotlight on that specific relationship and closes the drawer.
  - **Inspect Sockets**: Opens the Deep Socket Inspector pre-filtered to the sockets powering that relationship.

---

## Interactive 2D Canvas & Focus Spotlight

The canvas visualizer in [chart.js](file:///home/shivachrome/source/repos/network-monitor/chart.js) renders network topology with rich animations and interactive navigation:

### Canvas Relationship Focus Spotlight
When a relationship is selected via **Focus Canvas**:
- **Connection Vector Dimming**: Non-matching connections are dimmed to `0.06` opacity, while matching connection links are accentuated with full opacity and a neon glow (`lineWidth: 2.6px`, `shadowBlur: 14px`).
- **Packet Flow Restriction**: Animated data packet particles travel exclusively along the matching relationship paths.
- **Node Highlight & Halo Accent**: Non-matching nodes dim to `0.12` opacity; participating nodes receive glowing cyan halo rings (`lineWidth: 2.5px`), expanded radius, and persistent IP/hostname labels.
- **Centroid Spiderweb Suppression**: Subnet gateway spiderwebs are hidden to avoid visual clutter during relational focus.
- **Floating HUD Banner**: A glassmorphic banner appears at the top center of the canvas indicating the focused relationship name and details, with an instant **"✕ Clear Filter"** button (or press <kbd>Esc</kbd>).

### Canvas Navigation & Controls
- **Mouse Wheel Zoom**: Smooth cursor-anchored zooming (keeps the network topology under the cursor invariant).
- **Drag to Pan**: Click and drag anywhere on the canvas to pan across the network space.
- **Double-Click**: Quickly resets zoom and pan back to 100% overview (or double-clicks to zoom into a specific cluster).
- **Floating Glassmorphic HUD Toolbar**:
  - `[+]` Zoom In
  - `[100%]` Dynamic zoom level badge (click to reset)
  - `[-]` Zoom Out
- **Keyboard Shortcuts**:
  - <kbd>+</kbd> or <kbd>=</kbd>: Zoom In
  - <kbd>-</kbd> or <kbd>_</kbd>: Zoom Out
  - <kbd>0</kbd> or <kbd>R</kbd>: Reset Zoom & Pan
  - <kbd>Esc</kbd>: Clear active relationship focus filter
  - <kbd>Space</kbd>: Pause / Resume real-time telemetry animation stream

---

## Deep Socket & Protocol Inspector

Accessible via the header button **`>_ Socket Inspector`** or by clicking any host node, gateway, connection vector, or relationship card:

- **Filter Modes**:
  - `All`: Full list of all active kernel sockets.
  - `Host Sockets (IP)`: Sockets communicating with a specific IP.
  - `Flow (Connection)`: Sockets matching a specific source and destination pair.
  - `Port Drill-Down`: Sockets targeting a specific destination port.
  - `Subnet Cluster`: Sockets associated with a specific K-Means gateway cluster.
  - `Internal Peer Pair`: Sockets exchanged directly between two internal hosts.
  - `Shared Target / Domain`: Sockets connected to a specific external domain or URL.
  - `Protocol Service`: Sockets grouped under a specific protocol service.
- **Inspection Columns**:
  - **Protocol & Service**: Protocol type, port badge, well-known service name.
  - **TCP State**: Color-coded badges for `ESTABLISHED`, `LISTEN`, `TIME_WAIT`, `CLOSE_WAIT`, `SYN_SENT`.
  - **Local & Remote Endpoints**: Local IP:port, Remote IP:port with country flag, reverse DNS, and ASN provider.
  - **Process Attribution**: Running application name and process PID.
  - **RTT Latency**: Real-time round-trip latency in milliseconds and RTT variance (`rttvar`).
  - **TCP Queues & CWND**: Congestion window (`cwnd`), receive queue (`recv-Q`), and send queue (`send-Q`).
- **Live Search**: Instant keyword search across protocol, process name, IP, port, DNS, and organization.

---

## Threshold Latency & Bandwidth Alerts

The visualizer includes real-time threshold monitoring via sliding drawer and canvas overlays:

- **Custom Threshold Sliders**:
  - **Latency Alert Threshold**: Trigger alerts when socket RTT latency exceeds the slider value (default: `50 ms`).
  - **Bandwidth Alert Threshold**: Trigger alerts when flow throughput exceeds the slider value (default: `10 Mbps`).
- **Visual Alert Signals**:
  - **Canvas Overlays**: Pulsing red connection lines and warning tags over nodes experiencing latency spikes or throughput surges.
  - **Header Alert Counter**: Live warning badge displaying total active threshold violations.
  - **Toast Notifications**: Non-intrusive floating toasts with audible/visual alerts on sudden spikes.
  - **Alerts Center Drawer**: Dedicated sliding drawer listing all active alerts with violation metrics and direct inspection links.

---

## SQLite Persistent History & 48-Hour Rolling Window

The application includes an embedded, high-performance SQLite storage engine ([database.py](file:///home/shivachrome/source/repos/network-monitor/database.py)) for long-term historical network telemetry recording and timeline replay:

- **Database Architecture**:
  - File: `network_history.db`
  - Engine: SQLite 3 configured with Write-Ahead Logging (`PRAGMA journal_mode = WAL;`) and synchronous normal mode for zero lock contention during concurrent background recording and timeline querying.
  - Snapshot Capture: The background daemon thread [`SQLiteHistoryRecorder`](file:///home/shivachrome/source/repos/network-monitor/database.py#L90-L157) captures full network topology snapshots, active processes, bandwidth rates, and relational metadata every 5 seconds.
- **Strict 48-Hour Rolling Retention Window**:
  - Automatically prunes records older than 48 hours (`now - 172,800 seconds`):
    ```sql
    DELETE FROM snapshots WHERE timestamp < (strftime('%s', 'now') - 172800);
    ```
  - Keeps storage strictly bounded (never expands indefinitely).
  - Snapshot pruning occurs automatically on every insertion and can be queried or triggered manually.
- **Interactive Historical Timeline & Replay**:
  - **Timeline Scrubber**: Scrub back in time across the 48-hour archive to inspect past network conditions, anomalies, or high-bandwidth flows.
  - **Quick Time-Window Chips**: Filter historical windows by `10m`, `1h`, `6h`, `24h`, and `48h (Max)`.
  - **Replay Playback**: Click **Play Replay** to step through past network topologies sequentially at 1.5-second playback intervals.
  - **Live Return**: Click **LIVE** to immediately return to real-time live telemetry streaming.

---

## Raw Packet Capture & Promiscuous Monitoring

The monitor includes a built-in, pure-Python raw packet capture engine ([`RawPacketSniffer`](file:///home/shivachrome/source/repos/network-monitor/telemetry.py#L65-L270) in [telemetry.py](file:///home/shivachrome/source/repos/network-monitor/telemetry.py)) using Linux `AF_PACKET` raw sockets.

### 1. Pure-Python Packet Capture (Always Active via CAP_NET_RAW)
Raw socket packet capture on Linux uses `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities. The startup script [start.sh](file:///home/shivachrome/source/repos/network-monitor/start.sh) and [serve.py](file:///home/shivachrome/source/repos/network-monitor/serve.py) verify these capabilities on startup so that pure-Python raw packet capture and promiscuous sniffing are **always active** without needing to run as root:
```bash
# Permitted capability applied to Python binary:
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

### 2. Seeing Traffic Between Other Devices on a Home Network
In modern switched Ethernet and WPA-encrypted Wi-Fi networks, network switches and access points do not broadcast unicast packets between device A and device B to device C's port. To capture and visualize traffic flowing between other devices on your home network:

- **Option A: Run on your Router or Gateway (Recommended)**
  Run the server on a Linux-based router (e.g. Raspberry Pi router, OpenWrt device, pfSense/OPNsense machine, or Proxmox gateway). Because all inter-subnet and internet-bound device traffic physically traverses the router, the sniffer will capture all device flows.
- **Option B: Managed Switch Port Mirroring (SPAN Port)**
  Connect your monitoring PC to a managed switch with Port Mirroring (SPAN) configured to duplicate all packets from the router's uplink port to your monitor PC's Ethernet port.
- **Option C: Hardware Network TAP or Transparent Bridge**
  Place a passive hardware Ethernet TAP inline, or configure your Linux host with two network cards as a transparent bridge (`br0`) between your router and switch.
- **Broadcast & Multicast Discovery (Standard Switch Ports)**
  Even on an ordinary unmanaged switch port without mirroring, the raw sniffer automatically captures all local **ARP requests**, **DHCP announcements**, **mDNS / Bonjour (port 5353)**, and **SSDP UPnP (port 1900)** broadcasts, discovering smart home devices, IoT hardware, and local network services automatically.

---

## Security Detection, Signature Caching & Real-Time Threat Engine

The application includes an embedded, high-performance **Intrusion Detection System (IDS)** and **Deep Packet Inspection (DPI)** engine in [threat_engine.py](file:///home/shivachrome/source/repos/network-monitor/threat_engine.py). It operates concurrently with the raw packet sniffer in [telemetry.py](file:///home/shivachrome/source/repos/network-monitor/telemetry.py) and Linux kernel socket telemetry to detect active exploits, malware command-and-control (C2) communications, reconnaissance sweeps, and abnormal TCP flags in real time with sub-millisecond evaluation.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        REAL-TIME SECURITY DETECTION PIPELINE                           │
└────────────────────────────────────────────────────────────────────────────────────────┘
  Linux AF_PACKET Raw Sniffer / SS Sockets 
        │
        ▼ (proto, src_ip, src_port, dst_ip, dst_port, payload, flags)
  ┌────────────────────────────────────────────────────────────────────────────────────┐
  │  ThreatEngine.inspect_packet()                                                     │
  │  ├─ 1. IP Reputation Check (abuse.ch Feodo C2 / CINS Army Scanner Blocklists)      │
  │  ├─ 2. TCP Flag Anomaly Analysis (Nmap Xmas 0x29 / Malformed SYN+FIN 0x03)        │
  │  ├─ 3. Behavioral Port Sweep Heuristics (12+ Ports / 6s Sliding Window)           │
  │  └─ 4. Multi-Stage Fast-Path DPI Inspection (Port & Proto Index -> Fast Pattern)   │
  └────────────────────────┬───────────────────────────────────────────────────────────┘
                           │ Matches
                           ▼
  ┌────────────────────────────────────────────────────────────────────────────────────┐
  │  Threat Event Enrichment & Persistence                                              │
  │  ├─ CISA KEV Catalog Remediation & Due Date Enrichment                             │
  │  ├─ De-duplication on (signature, src, dst, port) with Incremental Hit Counters   │
  │  ├─ SQLite threat_events WAL Persistence & 48-Hour Auto-Pruning                    │
  │  └─ Canvas 60 FPS Visual Alerts: Crimson Halos, Exploit Vectors & Focus Spotlight  │
  └────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 1. Signature Caching Architecture & Instant Warm-Start (`threat_signatures_cache.json`)

To eliminate startup network latency and guarantee zero packet inspection blind spots, the threat engine features a persistent local disk caching system in [threat_signatures_cache.json](file:///home/shivachrome/source/repos/network-monitor/threat_signatures_cache.json):

- **5.5 MB Pre-Compiled Cache Structure**:
  - **Schema Version**: `2.0`
  - **Compiled Signatures**: Over 2,300+ pre-compiled DPI exploit rules complete with rule ID (`sid`), rule name, severity, category, target protocol, port constraints, hex-encoded fast patterns (`fast_patterns_hex`), minimum data sizing (`min_dsize`), CVE references, and vendor remediation actions.
  - **CISA KEV Catalog**: Over 560+ cached Known Exploited Vulnerability records containing vendor names, product classifications, vulnerability descriptions, binding required actions, and CISA remediation due dates.
  - **Malicious Reputation Sets**: Over 1,000+ confirmed botnet C2 IP addresses from abuse.ch Feodo Tracker and 2,000+ hostile scanner IPs from CINS Army with threat metadata.
- **Sub-10ms Instant Warm-Start**:
  - On application startup, [`ThreatEngine._load_cache_from_disk()`](file:///home/shivachrome/source/repos/network-monitor/threat_engine.py#L245-L314) loads the cache synchronously before opening network ports.
  - Reconstructs protocol and port lookup hash indexes instantly in memory, enabling immediate raw packet inspection as soon as the sniffer binds to network interfaces.
- **Atomic Disk Serialization**:
  - Whenever online feeds are synchronized, [`ThreatEngine._save_cache_to_disk()`](file:///home/shivachrome/source/repos/network-monitor/threat_engine.py#L340-L375) serializes the updated rules, CVE catalog, and IP reputation sets back to [threat_signatures_cache.json](file:///home/shivachrome/source/repos/network-monitor/threat_signatures_cache.json) atomically.
- **Air-Gapped & Offline Resilience**:
  - If upstream threat feeds are unreachable, timing out, or the monitor host operates in an air-gapped / offline environment, the engine gracefully falls back to the local cache without errors, ensuring continuous security posture.
- **Non-Blocking Background Update Pipeline**:
  - A dedicated background daemon thread [`_feed_sync_worker`](file:///home/shivachrome/source/repos/network-monitor/threat_engine.py#L632-L652) yields 1.5 seconds on boot to let the server bind ports, then runs an online sync.
  - Automatically schedules periodic updates every 6 hours (`update_interval = 21600.0s`), or triggers instantly upon manual request via the Web UI or API.

---

### 2. Dynamic Packet Signature & CVE Ingestion (ET Open & CISA KEV)

The engine adheres strictly to a **zero hardcoded signatures** design:

- **Suricata & Snort Rule Syntax Parsing**:
  - The [`ThreatEngine.parse_suricata_rules()`](file:///home/shivachrome/source/repos/network-monitor/threat_engine.py#L382-L495) parser ingests raw rule files from Emerging Threats (ET Open):
    - `emerging-exploit.rules`: Active weaponized exploits, path traversals, deserialization attacks, and injection payloads.
    - `emerging-attack_response.rules`: Compromised host indicators, unauthorized command outputs, web shell signatures, and data exfiltration tokens.
  - Handles mixed ASCII and hex byte notation (`|xx xx|`) via [`parse_suricata_content()`](file:///home/shivachrome/source/repos/network-monitor/threat_engine.py#L27-L64).
  - Evaluates rule options including `content:`, `dsize:`, `isdataat:`, `classtype:`, and well-known port aliases (`$HTTP_PORTS`, `$SQL_PORTS`, `$DNS_PORTS`, `$ORACLE_PORTS`, `$FTP_PORTS`, `$TELNET_SERVERS`) via [`parse_rule_ports()`](file:///home/shivachrome/source/repos/network-monitor/threat_engine.py#L66-L89).
- **CISA Known Exploited Vulnerabilities (KEV) Catalog Mapping**:
  - Ingests the official CISA KEV JSON feed directly from `cisa.gov`.
  - Automatically cross-references CVE IDs discovered in rule messages or references against CISA's catalog.
  - Automatically elevates matched exploits to `CRITICAL` severity and enriches threat alerts with vendor project, product name, required mitigation actions, and CISA compliance due dates.

---

### 3. Real-Time Multi-Stage Matching & Fast-Path Pipeline

Deep packet inspection on live Linux network traffic demands microsecond evaluation speeds. [`ThreatEngine.inspect_packet()`](file:///home/shivachrome/source/repos/network-monitor/threat_engine.py#L705-L840) organizes signatures into a multi-tiered lookup hierarchy:

- **Multi-Tiered Index Architecture**:
  1. **Tier 1 (Port & Protocol Hash Map)**: Slices signatures into `rules_by_proto_port[(proto, dst_port)]` and `rules_by_proto_port[(proto, src_port)]`. Incoming packets only evaluate rules targeting their specific port.
  2. **Tier 2 (Protocol Any-Port Rules)**: Evaluates `rules_by_proto_anyport[proto]` for rules with wildcard ports.
  3. **Tier 3 (Any-Protocol Catch-Alls)**: Evaluates universal protocol rules `rules_any_proto`.
- **Fast Substring & Hex Pre-Filtering**:
  - Each rule maintains lower-cased byte patterns (`fast_patterns`).
  - Pre-screens packet payloads with rapid substring containment before evaluating expensive regular expressions.
- **False Positive Elimination**:
  - Filters out generic, low-entropy HTTP verbs (`GET`, `POST`, `HEAD`, `HTTP/1.1`) as standalone match criteria.
  - Enforces minimum pattern lengths (minimum 4 bytes per pattern and 6 bytes total).
  - Implements DNS (port 53) noise filters requiring meaningful ASCII text or payload sizes greater than 512 bytes (`min_dsize`) to eliminate false alarms from binary DNS queries.

---

### 4. Threat Intelligence Feeds & Malicious C2 Reputation

- **abuse.ch Feodo Tracker Integration**:
  - Ingests confirmed botnet Command & Control (C2) server IP addresses targeting banking trojans and info-stealers: **Dridex**, **Emotet**, **QakBot**, **AsyncRAT**, and **TrickBot**.
  - Checks every packet's source and destination IP against the C2 reputation table.
  - Flags matching connections as `CRITICAL` severity with immediate isolation recommendations.
- **CINS Army Threat Intelligence**:
  - Ingests over 15,000+ malicious IP addresses, automated reconnaissance bots, and brute-force scanners from CINSSCore.
  - Flags reconnaissance probes targeting open services and perimeter ports.

---

### 5. Behavioral Heuristics & Anomaly Detectors

Beyond payload signatures, the engine monitors behavioral patterns directly on the packet wire:

- **Horizontal Port Sweep Detection**:
  - Tracks destination ports contacted by each external source IP within a 6-second sliding window (`scan_history`).
  - Flags hosts probing 12 or more distinct destination ports as active network reconnaissance.
  - Incorporates 15-second alert de-bouncing per source IP to prevent log exhaustion.
- **Abnormal TCP Flag Combinations**:
  - **Nmap Stealth Xmas Tree Scan**: Detects TCP packets with `FIN`, `PSH`, and `URG` flags set simultaneously (`0x29`).
  - **Firewall Evasion Scan**: Detects illegal simultaneous `SYN` and `FIN` flags (`0x03`).

---

### 6. Authentic Threat & Exploit Traffic Generator (`traffic_generator.py`)

The visualizer includes an authentic network threat traffic generator in [traffic_generator.py](file:///home/shivachrome/source/repos/network-monitor/traffic_generator.py) to simulate real-world attacks for demonstration, testing, and security drills:

- **Supported Attack Vectors**:
  - **Remote Code Execution (RCE)**:
    - Log4Shell (`CVE-2021-44228`): LDAP JNDI injection (`${jndi:ldap://...}`) targeting port 8080.
    - Spring4Shell (`CVE-2022-22965`): ClassLoader access RCE payloads.
    - Shellshock (`CVE-2014-6271`): GNU Bash environment variable function injection (`() { :; }; /bin/cat /etc/passwd`).
    - Apache Path Traversal (`CVE-2021-41773`): `GET /cgi-bin/.%2e/.%2e/.../etc/passwd` attempts.
    - SQL Injection (`CVE-2022-29464`): WSO2 file upload and SQL injection payloads.
    - PHP Web Shells: Injection attempts referencing `c99.php`, `r57.php`, and `cmd=id`.
    - Redis Unauthorized RCE: Malicious `CONFIG SET dir /var/spool/cron` injections over port 6379.
    - SMB Tree Connect Exploits: Malformed SMB dialect negotiations.
  - **Inbound Reconnaissance & Scans**:
    - Nmap Stealth Xmas Tree scans (FIN+PSH+URG).
    - SYN+FIN evasion scans.
    - Multi-port horizontal sweeps probing ports 21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017.
  - **Inbound Hostile Scanners**:
    - Scanner probes originating from recognized CINS Army and Tor exit node IP addresses.
  - **Outbound Compromised Activity**:
    - C2 Beacons: Internal hosts beaconing out to confirmed Dridex, Qakbot, Emotet, and Cobalt Strike servers.
    - Interactive Reverse Shells: External command callbacks over ports 4444 and 9001 (`/bin/sh -i`).
    - Sensitive Data Exfiltration: Unencrypted transfers of shadow password hashes and credential tokens.
- **Three Ways to Trigger Threats**:
  1. **1-Click Web UI**: Click **Inject Threat Traffic** in the Threat Detection Center drawer to emit an immediate burst.
  2. **REST API**: Send `POST /api/threats/generate` with parameters `count`, `rate`, and `mode` (`burst`, `continuous`, or `stop`).
  3. **Standalone CLI**:
     ```bash
     # Single burst of 60 exploit packets at 15 pkts/sec
     python3 traffic_generator.py --count 60 --rate 15

     # Continuous simulation daemon
     python3 traffic_generator.py --continuous --rate 8
     ```

---

### 7. Persistent Threat Storage & Historical State Recovery

- **SQLite `threat_events` Storage Engine**:
  - Detected threat events are automatically recorded in `network_history.db` using Write-Ahead Logging (WAL) in [database.py](file:///home/shivachrome/source/repos/network-monitor/database.py).
  - High-performance indexed schema:
    ```sql
    CREATE TABLE IF NOT EXISTS threat_events (
        id TEXT PRIMARY KEY,
        timestamp REAL,
        iso_time TEXT,
        time_str TEXT,
        hit_count INTEGER DEFAULT 1,
        severity TEXT,
        category TEXT,
        signature TEXT,
        cve TEXT,
        sid INTEGER,
        src_ip TEXT,
        src_port INTEGER,
        dest_ip TEXT,
        dest_port INTEGER,
        proto TEXT,
        process TEXT,
        matched_payload TEXT,
        recommendation TEXT,
        raw_json TEXT
    );
    CREATE INDEX idx_threats_timestamp ON threat_events(timestamp DESC);
    CREATE INDEX idx_threats_severity ON threat_events(severity);
    ```
- **Stateful De-Duplication**:
  - Repeat packet flows match compound key `(signature, src_ip, dst_ip, dst_port)`.
  - Increments `hitCount` and updates `lastSeen` timestamps while preserving historical `firstSeen` records.
- **Historical Alert Recovery**:
  - On startup, [`ThreatEngine._load_threats_from_db()`](file:///home/shivachrome/source/repos/network-monitor/threat_engine.py#L315-L339) automatically restores up to 500 recent threat events from SQLite into active memory, maintaining continuity across server restarts.
- **48-Hour Rolling Retention**:
  - Automatically purges threat records older than 48 hours in synchronization with topology snapshot pruning.

---

### 8. Canvas Threat Visualizations & Spotlight Isolation

Real-time threats transform the 60 FPS canvas visualizer in [chart.js](file:///home/shivachrome/source/repos/network-monitor/chart.js):

- **Pulsing Crimson Hazard Beacon Halos**: Affected host nodes are wrapped in expanding hazard halos and outer shockwave ripples colored by severity (🔴 Crimson `#ef4444` for Critical, 🟠 Amber `#f59e0b` for High, 🟡 Yellow `#eab308` for Medium).
- **Hazard Exploit Vectors**: Threat flows flash in vibrant crimson (`#ef4444`) with high-glow shadows (`shadowBlur: 16px`).
- **Animated Crimson Packet Particles**: Packet particles traveling between attacker and victim switch to red to highlight the exploit vector path.
- **Threat Spotlight Isolation**: Clicking **Focus on Canvas** on any threat card isolates the attacker and target host, dimming all non-involved nodes and links to `0.06` opacity.
- **Interactive Tooltip Threat Notices**: Hovering over compromised nodes or connections reveals prominent hazard headers displaying the signature, CVE, category, process attribution, and hit count.

---

### 9. Threat & Exploit Detection Drawer (UI & Incident Response)

The sliding drawer provides a full Incident Response console accessible via the header shield button or left sidebar:

- **Glowing Threat Shield Button**: Includes a pulsing heartbeat counter pill displaying active threat totals.
- **Summary KPI Grid**: Displays live metric tiles for *Active Threats*, *Critical Exploits*, *C2 / Scanners*, and *Packets Inspected*.
- **Live Feed Status Bar**: Displays loaded dynamic rule count, active tracked CVEs, sync timestamp, and a **Sync Feeds** button.
- **One-Click Exploit Injection**: The **Inject Threat Traffic** button emits an authentic burst of exploits for verification.
- **Severity Tabs & Search Filter**: Filter threats by `All`, `🔴 Critical`, `🟠 High`, `🟡 Medium / Low`, or search by IP, CVE, port, process, or signature.
- **Actionable Threat Cards**:
  - Displays match evidence, payload snippets, process attribution, and CISA KEV compliance guidance.
  - **1-Click Copy `iptables` Drop Rule**: Copies pre-formatted Linux firewall blocking commands (e.g. `sudo iptables -A INPUT -s <IP> -j DROP`) to the clipboard.
- **Clear All Alerts**: Dismisses active in-memory alerts while retaining SQLite historical records.

---

## REST API Reference

The backend exposes a JSON REST API for frontend streaming, automation, and threat monitoring:

| Endpoint | Method | Description |
|---|---|---|
| `/api/network-telemetry` | `GET` | Fetches live network topology, nodes, connections, clusters, relationships, and threat summary. Parameters: `scope` (`all`, `internal`, `public`), `k` (cluster count), `resolve_dns` (bool), `resolve_geoip` (bool). |
| `/api/relationships` | `GET` | Returns detected relational patterns: `internalMesh` (peer pairs), `sharedDestinations` (common domains/URLs), `commonProtocols` (service clusters), and `summary`. |
| `/api/threats` | `GET` | Returns live threat summary, dynamic feed status, rules/CVE counts, recent database threat events, and severity statistics. Parameters: `limit` (default `200`), `severity` (`critical`, `high`, `medium`, `low`). |
| `/api/threats/update` | `POST` | Asynchronously triggers synchronization of online threat signatures (ET Open, CISA KEV, abuse.ch Feodo Tracker, CINS Army) and rebuilds the disk cache. |
| `/api/threats/clear` | `POST` | Clears active in-memory threat alerts from the dashboard buffer. |
| `/api/threats/generate` | `POST` | Injects authentic exploit and threat packets into the system. Parameters (query or JSON body): `mode` (`burst`, `continuous`, `stop`), `count` (default `60`), `rate` (pkts/sec, default `20.0`). |
| `/api/trigger-scan` | `GET` | Asynchronously triggers a non-blocking LAN ARP/ping sweep across the local `/24` subnet. |
| `/api/history/stats` | `GET` | Returns SQLite database status: total snapshots, database size in MB, oldest/newest timestamps, and 48-hour coverage percentage. |
| `/api/history/snapshots` | `GET` | Returns list of stored snapshot summaries within a time window. Parameters: `since` (seconds ago, default `172800`), `limit`, `summary` (`true`/`false`). |
| `/api/history/snapshot` | `GET` | Returns the complete topology JSON payload for a single historical snapshot by ID. Parameter: `id`. |
| `/api/history/prune` | `POST` | Manually triggers pruning of snapshots older than the 48-hour retention limit. |

---

## Running Locally

### 1. Start the Visualizer Server & Cloudflare Gateway
Run the unified startup script [start.sh](file:///home/shivachrome/source/repos/network-monitor/start.sh) or [serve.py](file:///home/shivachrome/source/repos/network-monitor/serve.py):
```bash
./start.sh
# or directly:
python3 serve.py 8080
```
- **Local Dashboard**: [http://localhost:8080](http://localhost:8080)
- **Public Cloudflare Gateway**: [https://enlarge-disciplines-executive-watches.trycloudflare.com/](https://enlarge-disciplines-executive-watches.trycloudflare.com/)

- **Raw Packet Sniffer**: Always enabled via `CAP_NET_RAW` & `CAP_NET_ADMIN` (verified on startup, no `sudo` required).

### 2. Test Threat Detection & Signature Matching
To test real-time signature matching, C2 reputation alerts, and canvas threat visualizations, launch the exploit traffic generator in a separate terminal:
```bash
# Inject a burst of 60 diverse exploit packets
python3 traffic_generator.py --count 60 --rate 15

# Or run continuous background threat simulation
python3 traffic_generator.py --continuous --rate 8
```
*(Alternatively, simply open the **Threat Center** drawer in the web UI and click **Inject Threat Traffic**).*

