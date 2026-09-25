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
9. [REST API Reference](#rest-api-reference)
10. [Running Locally](#running-locally)

---

## Key Features & Capabilities

- **Live Linux Kernel Telemetry**: Streams real socket stats directly from `/proc/net`, Linux `sock_diag` netlink / `ss`, and ARP neighbor cache via [telemetry.py](file:///home/shivachrome/source/repos/network-monitor/telemetry.py).
- **Embedded Raw Packet Sniffer**: Linux `AF_PACKET` raw socket engine capturing Layer 2 Ethernet, IPv4, TCP, UDP, ICMP, ARP, DHCP, mDNS, and SSDP broadcasts.
- **Relational Correlation Engine**: Detects internal peer-to-peer lateral mesh connections, common external destination domains/URLs accessed by multiple hosts, and protocol affinity clusters.
- **Canvas Focus Spotlight**: Isolate relational subgraphs on canvas with non-matching node/connection dimming, animated packet stream restriction, and glowing halo accents.
- **K-Means Subnet Clustering**: Auto-tunes $K$ centroids using Silhouette Score and WCSS Inertia to discover virtual subnet gateways and routing boundaries.
- **Hardware-Accelerated 60 FPS Canvas Engine**: Smooth lerp coordinate interpolation, organic micro-drift motion, and interactive mouse-anchored zoom and pan in [chart.js](file:///home/shivachrome/source/repos/network-monitor/chart.js).
- **Deep Socket Inspector**: Interactive sliding drawer inspecting kernel sockets with protocol badges, TCP connection states, local/remote endpoints, process attribution, TCP RTT variance, and CWND queue buffers.
- **Persistent SQLite Storage**: Background recorder storing full topology snapshots with Write-Ahead Logging (WAL) and automatic rolling 48-hour data retention in [database.py](file:///home/shivachrome/source/repos/network-monitor/database.py).
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

### 1. Enabling Packet Capture Permissions
Raw socket packet capture on Linux requires `CAP_NET_RAW` capability. You can grant this to your Python binary without needing to run your entire development environment as root:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```
Alternatively, launch the server directly with `sudo`:
```bash
sudo python3 serve.py 8080
```
*(If run unprivileged without capabilities, the server automatically degrades gracefully to kernel socket telemetry via `ss` and `/proc/net` without errors).*

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

## REST API Reference

The backend exposes a JSON REST API for frontend streaming and automation:

| Endpoint | Method | Description |
|---|---|---|
| `/api/network-telemetry` | `GET` | Fetches live network topology, nodes, connections, clusters, and relationships. Parameters: `scope` (`all`, `internal`, `public`), `k` (cluster count), `resolve_dns` (bool), `resolve_geoip` (bool). |
| `/api/relationships` | `GET` | Returns detected relational patterns: `internalMesh` (peer pairs), `sharedDestinations` (common domains/URLs), `commonProtocols` (service clusters), and `summary`. |
| `/api/trigger-scan` | `GET` | Asynchronously triggers a non-blocking LAN ARP/ping sweep across the local `/24` subnet. |
| `/api/history/stats` | `GET` | Returns SQLite database status: total snapshots, database size in MB, oldest/newest timestamps, and 48-hour coverage percentage. |
| `/api/history/snapshots` | `GET` | Returns list of stored snapshot summaries within a time window. Parameters: `since` (seconds ago, default `172800`), `limit`, `summary` (`true`/`false`). |
| `/api/history/snapshot` | `GET` | Returns the complete topology JSON payload for a single historical snapshot by ID. Parameter: `id`. |
| `/api/history/prune` | `POST` | Manually triggers pruning of snapshots older than the 48-hour retention limit. |

---

## Running Locally

Run [serve.py](file:///home/shivachrome/source/repos/network-monitor/serve.py):
```bash
python3 serve.py 8080
```
Then open **[http://localhost:8080](http://localhost:8080)** in your browser.
