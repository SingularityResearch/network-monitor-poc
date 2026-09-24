# K-Means Network IP & Port Connection Visualizer

An interactive, modern Network Operations Center (NOC) web application where **every data point represents an IP address** with **active socket connections to specific ports on other IP addresses**, clustered into **Subnet Zones** using K-Means centroids as **Virtual Gateways**.

---

## Network Architecture & Clustering Concept

- **IP Host Nodes**:
  - Each point in 2D space represents an IP host (e.g. `10.0.1.42`, `172.16.1.18`, `192.168.1.5`).
  - Position reflects topological proximity or network latency profiles.
  - Colors represent assigned subnet clusters.
- **Cluster Centroids as Subnet Gateways ($\mu_k$)**:
  - The K-Means centroids ($\mu_1, \mu_2, \dots, \mu_k$) act as the **Virtual Subnet Gateways / Nexus Hubs** (`GW-μ1`, `GW-μ2`, etc.).
  - Rendered with traditional high-contrast bold crosshairs (`✕`), cluster bullseye rings, and pulsing radar boundaries.
- **IP-to-IP Socket Connections on Specific Ports**:
  - Each IP node establishes active socket connections to destination IPs on well-known ports:
    - `443` (HTTPS) - Web Secure
    - `80` (HTTP) - Web Ingress
    - `22` (SSH) - Remote Administration
    - `53` (DNS) - Infrastructure Resolvers
    - `3306` (MySQL) - Database Clusters
    - `5432` (PostgreSQL) - Relational Storage
    - `6379` (Redis) - In-Memory Cache
    - `8080` (API Gateway) - Microservices Ingress
  - **Live Animated Packets**: Glowing data pulses flow in real-time along socket connection vectors from Source IP $\rightarrow$ Destination IP:Port.
  - **Cross-Subnet Egress vs Intra-Subnet**: Inter-subnet traffic is highlighted with distinct opacity and latency metrics.

---

## 10-Second Telemetry Burst Lifecycle

- Every 10 seconds, network telemetry automatically bursts:
  - Generates new IP host positions, connection states, and traffic throughput.
  - K-Means algorithm re-computes optimal Subnet Gateways, WCSS Inertia, and Silhouette cohesion.
  - Smooth animated countdown bar indicates when the next burst occurs.
  - Controls: **Pause/Resume** (or press <kbd>Space</kbd>), **Burst Now** (instant re-generation), and configurable interval (5s, 10s, 15s, 20s).

---

## Interactive Controls & Telemetry Dashboard

- **Filter by Port / Protocol**: Isolate specific traffic types (e.g. view only database port 3306, SSH port 22, or HTTPS port 443).
- **Layer Toggles**:
  - `IP-to-IP Socket Links`: Show/hide active connection vectors.
  - `Live Flowing Packets`: Toggle particle packet flow animations.
  - `Gateway Centroid Vectors`: Faint spiderweb connecting each IP to its Subnet Gateway.
  - `Subnet Dispersion Halos`: Circular standard deviation spread around each gateway.
  - `Voronoi Subnet Boundaries`: Geometric partitioning dividing subnets.
  - `Display IP Labels`: Show IP address tags over nodes.
- **Hover Inspection**:
  - Hover over any IP to highlight all its active outbound and inbound sockets, target ports, and hostnames.
  - Hover over any Centroid Gateway to inspect total subnet hosts and internal traffic volume.
- **Telemetry Cards**: IP Host Count, Subnet Gateways ($K$), Active Sockets, Cross-Subnet Egress %, and Port Distribution Breakdown.

---

## Debugging & Running Locally

### 1. In VS Code / Antigravity IDE (Recommended)
- Press <kbd>F5</kbd> or click **Run and Debug** (`Ctrl+Shift+D`) and choose **Launch Web App & Default Browser**.
- It terminates any previous process occupying port 8080, starts the server under the debugger, and automatically opens your default web browser to the index page.

### 2. Standalone Terminal Server
Run the included [serve.py](file:///home/shivachrome/source/repos/network-monitor/serve.py) helper script:
```bash
python3 serve.py 8080
```
or Python's built-in module:
```bash
python3 -m http.server 8080
```
Then open **[http://localhost:8080](http://localhost:8080)** in your browser.
