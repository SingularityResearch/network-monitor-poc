# K-Means Network IP & Port Connection Visualizer

An interactive, modern Network Operations Center (NOC) web application monitoring **actual real-time network traffic from your Linux host** as well as simulated benchmark topologies.

Every data point represents an IP address with **active socket connections to specific ports on other IP addresses**, clustered into **Subnet Zones** using K-Means centroids as **Virtual Gateways**.

---

## Real Network Telemetry (Internal & Public)

The visualizer connects directly to your Linux system's networking stack via [serve.py](file:///home/shivachrome/source/repos/network-monitor/serve.py) and [telemetry.py](file:///home/shivachrome/source/repos/network-monitor/telemetry.py):

### 1. Internal Traffic
- **Local Host IP & Active NIC**: Discovers your primary interface (`enp2s0`) and local IP address (`192.168.0.117`).
- **Default Gateway & LAN Hosts**: Detects your router (`192.168.0.1`), ARP neighbor cache, and local `/24` subnet hosts (`192.168.0.28`, `192.168.0.21`, etc.).
- **Loopback & Local IPC**: Monitors local inter-process communication sockets (`127.0.0.1`) across development servers, IDEs, and local services.
- **LAN Ping Discovery**: Click **Scan LAN Subnet** to asynchronously ping the local subnet and discover newly connected devices in real time.

### 2. Public Internet Traffic
- **Active Internet Sockets**: Captures live outbound and inbound connections across public cloud and web services (Google, GitHub, Microsoft Azure, Fastly CDN, Cloudflare, etc.).
- **Provider & Reverse DNS Resolution**: Resolves hostnames and organizations (e.g. `github.com`, `google.com`, `fastly-cdn.net`) with thread-safe caching.
- **Real TCP Metrics**: Tracks true kernel RTT latency in milliseconds, delivery rates, bytes transferred, and socket states.
- **Application & Process Attribution**: Automatically maps connections to running processes (e.g., `chrome`, `antigravity-ide`, `language_server`, `sshd`).

### 3. Traffic Scopes
In the dashboard controls, easily filter your view:
- **🌐 All Traffic (Internal & Public)**: Complete holistic view of both internal LAN/IPC and public internet flows.
- **🏠 Internal Only (LAN & Loopback)**: Focuses exclusively on your local subnet, gateway, and local services.
- **☁️ Public Only (External Internet)**: Focuses exclusively on outbound traffic to external internet hosts and cloud providers.

---

## Network Architecture & Clustering Concept

- **IP Host Nodes**:
  - Each point in 2D space represents an IP host.
  - Position reflects natural topological proximity or network latency profiles.
  - Colors represent assigned subnet clusters.
- **Cluster Centroids as Subnet Gateways ($\mu_k$)**:
  - K-Means centroids ($\mu_1, \mu_2, \dots, \mu_k$) act as the **Virtual Subnet Gateways / Nexus Hubs** (`GW-μ1`, `GW-μ2`, etc.).
  - Rendered with traditional high-contrast bold crosshairs (`✕`), cluster bullseye rings, and pulsing radar boundaries.
- **IP-to-IP Socket Connections on Specific Ports**:
  - Each IP node establishes active socket connections to destination IPs on well-known and custom ports (`443` HTTPS, `80` HTTP, `22` SSH, `53` DNS, `67` DHCP, `8080`, `3000`, `5173`, etc.).
  - **Live Animated Packets**: Glowing data pulses flow in real-time along socket connection vectors from Source IP $\rightarrow$ Destination IP:Port.
  - **Cross-Subnet Egress vs Intra-Subnet**: Inter-subnet traffic is highlighted with distinct opacity and latency metrics.

---

## Telemetry Burst & Auto-Refresh Lifecycle

- Configurable interval bursts (5s, 10s, 15s, 20s):
  - Polls `/api/network-telemetry` to pull the latest system socket state, bandwidth rates, and active processes.
  - Re-computes optimal Subnet Gateways, WCSS Inertia, and Silhouette cohesion.
  - Smooth animated countdown bar indicates when the next burst occurs.
  - Controls: **Pause/Resume** (or press <kbd>Space</kbd>) and **Refresh Now**.

---

## Interactive Controls & Telemetry Dashboard

- **Telemetry Source**: Switch anytime between **🟢 Live Real Network (Host & LAN)** and **⚡ Simulated Benchmark Topology**.
- **Traffic Scope**: Toggle between **All Traffic**, **Internal Only**, and **Public Only**.
- **Filter by Port / Protocol**: Isolate specific ports (e.g. view only port 443, 22, 53, or dynamic IPC ports).
- **Layer Toggles**:
  - `IP-to-IP Socket Links`: Show/hide active connection vectors.
  - `Live Flowing Packets`: Toggle particle packet flow animations.
  - `Gateway Centroid Vectors`: Faint spiderweb connecting each IP to its Subnet Gateway.
  - `Subnet Dispersion Halos`: Circular standard deviation spread around each gateway.
  - `Voronoi Subnet Boundaries`: Geometric partitioning dividing subnets.
  - `Display IP Labels`: Show IP address tags over nodes.
- **Hover Inspection**:
  - Hover over any IP to see its zone badge (`[INTERNAL LAN]`, `[PUBLIC INTERNET]`, `[LOOPBACK IPC]`), domain name, process, traffic throughput, and active outbound/inbound socket list with latency.
  - Hover over any Gateway to inspect total subnet hosts and internal traffic volume.

---

## Running Locally

Run [serve.py](file:///home/shivachrome/source/repos/network-monitor/serve.py):
```bash
python3 serve.py 8080
```
Then open **[http://localhost:8080](http://localhost:8080)** in your browser.
