import { KMeans } from './kmeans.js';
import { NetworkDataGenerator, WELL_KNOWN_PORTS } from './generator.js';
import { NetworkClusterChart } from './chart.js';

class NetworkClusterApp {
  constructor() {
    // Canvas & Tooltip
    this.canvas = document.getElementById('clusterCanvas');
    this.tooltip = document.getElementById('chartTooltip');

    // Controls
    this.dataSourceSelect = document.getElementById('dataSourceSelect');
    this.trafficScopeSelect = document.getElementById('trafficScopeSelect');
    this.scopeCounter = document.getElementById('scopeCounter');
    this.sourceBadge = document.getElementById('sourceBadge');
    this.btnScanLan = document.getElementById('btnScanLan');

    this.kSlider = document.getElementById('kSlider');
    this.kValueBadge = document.getElementById('kValueBadge');
    this.pointSlider = document.getElementById('pointSlider');
    this.pointValueBadge = document.getElementById('pointValueBadge');
    this.intervalSelect = document.getElementById('intervalSelect');
    this.distSelect = document.getElementById('distSelect');
    this.portFilterSelect = document.getElementById('portFilterSelect');

    this.nodeCountControlGroup = document.getElementById('nodeCountControlGroup');
    this.distControlGroup = document.getElementById('distControlGroup');

    // Action Buttons
    this.btnPlayPause = document.getElementById('btnPlayPause');
    this.btnGenerateNow = document.getElementById('btnGenerateNow');
    this.btnPlayPauseIcon = document.getElementById('playPauseIcon');
    this.btnPlayPauseText = document.getElementById('playPauseText');

    // Visualization Layer Toggles
    this.toggleConnections = document.getElementById('toggleConnections');
    this.togglePackets = document.getElementById('togglePackets');
    this.toggleLines = document.getElementById('toggleLines');
    this.toggleHalos = document.getElementById('toggleHalos');
    this.toggleVoronoi = document.getElementById('toggleVoronoi');
    this.toggleIpLabels = document.getElementById('toggleIpLabels');

    // Live Indicators
    this.liveIndicator = document.getElementById('liveIndicator');
    this.liveStatusText = document.getElementById('liveStatusText');
    this.countdownTime = document.getElementById('countdownTime');
    this.countdownFill = document.getElementById('countdownFill');

    // Host Telemetry Elements
    this.hostInterfaceName = document.getElementById('hostInterfaceName');
    this.hostBandwidthRate = document.getElementById('hostBandwidthRate');
    this.hostLocalIP = document.getElementById('hostLocalIP');
    this.hostGatewayIP = document.getElementById('hostGatewayIP');
    this.pillInternalVal = document.getElementById('pillInternalVal');
    this.pillPublicVal = document.getElementById('pillPublicVal');
    this.processChipsContainer = document.getElementById('processChipsContainer');
    this.telemetryStatusBadge = document.getElementById('telemetryStatusBadge');

    // Analytics Metrics
    this.metricIPs = document.getElementById('metricIPs');
    this.metricGateways = document.getElementById('metricGateways');
    this.metricSockets = document.getElementById('metricSockets');
    this.metricCrossSubnet = document.getElementById('metricCrossSubnet');
    this.metricSilhouette = document.getElementById('metricSilhouette');
    this.metricInertia = document.getElementById('metricInertia');
    this.centroidTableBody = document.getElementById('centroidTableBody');
    this.portStatsContainer = document.getElementById('portStatsContainer');
    this.historyList = document.getElementById('historyList');

    // State
    this.dataSource = this.dataSourceSelect ? this.dataSourceSelect.value : 'real';
    this.trafficScope = this.trafficScopeSelect ? this.trafficScopeSelect.value : 'all';
    this.k = parseInt(this.kSlider.value, 10) || 4;
    this.nodeCount = parseInt(this.pointSlider.value, 10) || 140;
    this.intervalSeconds = parseFloat(this.intervalSelect.value) || 10;
    this.distribution = this.distSelect ? this.distSelect.value : 'blobs';

    this.isPlaying = true;
    this.elapsedSeconds = 0;
    this.timerTickMs = 50;
    this.intervalId = null;

    this.currentTopology = null;
    this.currentKMeansResult = null;
    this.runHistory = [];

    // Initialize Canvas Chart
    this.chart = new NetworkClusterChart(this.canvas, this.tooltip);

    // Populate Ports
    this.populatePortDropdown();

    // Event listeners
    this.attachEventListeners();

    // Initial Trigger
    this.generateAndCluster();
    this.startTimer();
  }

  populatePortDropdown(activeConnections = []) {
    const selectedVal = this.portFilterSelect.value || 'all';
    let options = '<option value="all">All Ports / Protocols</option>';

    // Collect all unique ports
    const portMap = new Map();
    WELL_KNOWN_PORTS.forEach(p => portMap.set(p.port, p));

    if (activeConnections && activeConnections.length > 0) {
      activeConnections.forEach(c => {
        if (!portMap.has(c.destPort) && c.destPort > 0) {
          portMap.set(c.destPort, {
            port: c.destPort,
            service: c.service || `Port ${c.destPort}`,
            proto: c.proto || 'TCP',
            color: c.color || '#94a3b8'
          });
        }
      });
    }

    portMap.forEach(p => {
      const isSel = String(p.port) === String(selectedVal) ? 'selected' : '';
      options += `<option value="${p.port}" ${isSel}>:${p.port} (${p.service} - ${p.proto})</option>`;
    });

    this.portFilterSelect.innerHTML = options;
  }

  attachEventListeners() {
    // Data Source Toggle
    if (this.dataSourceSelect) {
      this.dataSourceSelect.addEventListener('change', (e) => {
        this.dataSource = e.target.value;
        const isReal = this.dataSource === 'real';

        if (this.sourceBadge) {
          this.sourceBadge.textContent = isReal ? 'LIVE SYSTEM' : 'BENCHMARK';
          this.sourceBadge.style.color = isReal ? 'var(--accent-cyan)' : 'var(--accent-amber)';
        }

        if (this.nodeCountControlGroup) {
          this.nodeCountControlGroup.style.opacity = isReal ? '0.5' : '1.0';
          this.pointValueBadge.textContent = isReal ? 'Auto' : this.nodeCount;
        }

        if (this.distControlGroup) {
          this.distControlGroup.style.opacity = isReal ? '0.5' : '1.0';
        }

        this.elapsedSeconds = 0;
        this.generateAndCluster();
      });
    }

    // Traffic Scope Selector
    if (this.trafficScopeSelect) {
      this.trafficScopeSelect.addEventListener('change', (e) => {
        this.trafficScope = e.target.value;
        if (this.scopeCounter) {
          if (this.trafficScope === 'all') this.scopeCounter.textContent = 'Internal + Public';
          else if (this.trafficScope === 'internal') this.scopeCounter.textContent = 'LAN & Loopback';
          else this.scopeCounter.textContent = 'Public Internet';
        }
        this.elapsedSeconds = 0;
        this.generateAndCluster();
      });
    }

    // Scan LAN Subnet Button
    if (this.btnScanLan) {
      this.btnScanLan.addEventListener('click', async () => {
        const origText = this.btnScanLan.innerHTML;
        this.btnScanLan.innerHTML = `
          <svg class="spin-anim" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
          <span style="color:#34d399;">Scanning Subnet...</span>
        `;
        try {
          await fetch('/api/trigger-scan');
          setTimeout(() => {
            this.generateAndCluster();
            this.btnScanLan.innerHTML = origText;
          }, 1200);
        } catch {
          this.btnScanLan.innerHTML = origText;
        }
      });
    }

    // K-Means K Slider
    this.kSlider.addEventListener('input', (e) => {
      this.k = parseInt(e.target.value, 10);
      this.kValueBadge.textContent = this.k;
      this.reclusterTopology();
    });

    // IP Nodes Count Slider
    this.pointSlider.addEventListener('input', (e) => {
      this.nodeCount = parseInt(e.target.value, 10);
      if (this.dataSource === 'simulated') {
        this.pointValueBadge.textContent = this.nodeCount;
      }
    });

    // Interval Selector
    this.intervalSelect.addEventListener('change', (e) => {
      this.intervalSeconds = parseFloat(e.target.value);
      this.elapsedSeconds = 0;
    });

    // Topology Distribution
    this.distSelect.addEventListener('change', (e) => {
      this.distribution = e.target.value;
      if (this.dataSource === 'simulated') {
        this.generateAndCluster();
      }
    });

    // Port Filter
    this.portFilterSelect.addEventListener('change', (e) => {
      this.chart.options.filterPort = e.target.value;
      this.chart.render();
      this.updatePortDistributionUI();
    });

    // Play / Pause
    this.btnPlayPause.addEventListener('click', () => this.togglePlayback());

    // Regenerate / Refresh Now
    this.btnGenerateNow.addEventListener('click', () => {
      this.elapsedSeconds = 0;
      this.generateAndCluster();
    });

    // Layer Toggles
    this.toggleConnections.addEventListener('change', (e) => {
      this.chart.options.showConnections = e.target.checked;
      this.chart.render();
    });

    this.togglePackets.addEventListener('change', (e) => {
      this.chart.options.showPackets = e.target.checked;
      this.chart.render();
    });

    this.toggleLines.addEventListener('change', (e) => {
      this.chart.options.showGatewayLines = e.target.checked;
      this.chart.render();
    });

    this.toggleHalos.addEventListener('change', (e) => {
      this.chart.options.showHalos = e.target.checked;
      this.chart.render();
    });

    this.toggleVoronoi.addEventListener('change', (e) => {
      this.chart.options.showVoronoi = e.target.checked;
      this.chart.render();
    });

    this.toggleIpLabels.addEventListener('change', (e) => {
      this.chart.options.showIpLabels = e.target.checked;
      this.chart.render();
    });

    // Spacebar shortcut
    window.addEventListener('keydown', (e) => {
      if (e.code === 'Space' && e.target === document.body) {
        e.preventDefault();
        this.togglePlayback();
      }
    });
  }

  togglePlayback() {
    this.isPlaying = !this.isPlaying;
    if (this.isPlaying) {
      this.liveIndicator.classList.remove('paused');
      this.liveStatusText.textContent = this.dataSource === 'real' ? 'LIVE SYSTEM STREAM' : 'SIMULATED STREAM';
      this.btnPlayPauseText.textContent = 'Pause';
      this.btnPlayPauseIcon.innerHTML = `
        <rect x="6" y="4" width="4" height="16" fill="currentColor"/>
        <rect x="14" y="4" width="4" height="16" fill="currentColor"/>
      `;
    } else {
      this.liveIndicator.classList.add('paused');
      this.liveStatusText.textContent = 'FEED PAUSED';
      this.btnPlayPauseText.textContent = 'Resume';
      this.btnPlayPauseIcon.innerHTML = `
        <polygon points="5,3 19,12 5,21" fill="currentColor"/>
      `;
    }
  }

  startTimer() {
    if (this.intervalId) clearInterval(this.intervalId);

    this.intervalId = setInterval(() => {
      if (!this.isPlaying) return;

      this.elapsedSeconds += this.timerTickMs / 1000;
      const remaining = Math.max(0, this.intervalSeconds - this.elapsedSeconds);
      this.countdownTime.textContent = `${remaining.toFixed(1)}s`;

      const progressPct = Math.min(100, (this.elapsedSeconds / this.intervalSeconds) * 100);
      this.countdownFill.style.width = `${progressPct}%`;

      if (this.elapsedSeconds >= this.intervalSeconds) {
        this.elapsedSeconds = 0;
        this.generateAndCluster();
      }
    }, this.timerTickMs);
  }

  async fetchRealNetworkData() {
    try {
      const url = `/api/network-telemetry?scope=${encodeURIComponent(this.trafficScope)}&k=${this.k}`;
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn('Real network API request failed, falling back:', err);
      return null;
    }
  }

  /**
   * Acquire network topology (Real Linux Telemetry or Simulated) and run K-Means
   */
  async generateAndCluster() {
    if (this.dataSource === 'real') {
      const realData = await this.fetchRealNetworkData();
      if (realData && realData.nodes && realData.nodes.length > 0) {
        this.currentTopology = realData;
        this.updateRealHostUI(realData.meta);
        this.populatePortDropdown(realData.connections);
        this.reclusterTopology();
        this.addToHistory(true);
        return;
      }
    }

    // Simulated benchmark mode fallback
    this.currentTopology = NetworkDataGenerator.generateTopology({
      nodeCount: this.nodeCount,
      numSubnets: this.k,
      connectionDensity: 1.4,
      distribution: this.distribution,
    });

    this.updateSimulatedHostUI();
    this.populatePortDropdown(this.currentTopology.connections);
    this.reclusterTopology();
    this.addToHistory(false);
  }

  updateRealHostUI(meta) {
    if (!meta) return;

    if (this.hostInterfaceName) this.hostInterfaceName.textContent = meta.interface || 'eth0';
    if (this.hostLocalIP) this.hostLocalIP.textContent = meta.localIP || '127.0.0.1';
    if (this.hostGatewayIP) this.hostGatewayIP.textContent = meta.defaultGateway || '192.168.0.1';

    if (this.hostBandwidthRate) {
      const rx = meta.rxRateKbps || 0;
      const tx = meta.txRateKbps || 0;
      this.hostBandwidthRate.textContent = `↓ ${rx.toFixed(1)} KB/s  ↑ ${tx.toFixed(1)} KB/s`;
    }

    if (this.pillInternalVal) {
      this.pillInternalVal.textContent = `${meta.internalNodesCount || 0} IPs (${meta.internalSocketsCount || 0} socks)`;
    }

    if (this.pillPublicVal) {
      this.pillPublicVal.textContent = `${meta.publicNodesCount || 0} IPs (${meta.publicSocketsCount || 0} socks)`;
    }

    if (this.telemetryStatusBadge) {
      this.telemetryStatusBadge.textContent = 'REAL TELEMETRY';
      this.telemetryStatusBadge.style.color = '#38bdf8';
    }

    if (this.processChipsContainer && meta.activeProcesses) {
      if (meta.activeProcesses.length > 0) {
        let chipsHtml = '';
        meta.activeProcesses.forEach(proc => {
          chipsHtml += `
            <span class="process-chip">
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><circle cx="9" cy="9" r="1"/><circle cx="15" cy="15" r="1"/></svg>
              ${proc}
            </span>
          `;
        });
        this.processChipsContainer.innerHTML = chipsHtml;
      } else {
        this.processChipsContainer.innerHTML = '<span style="font-size:0.68rem;color:#64748b;">Idle / No active named processes</span>';
      }
    }
  }

  updateSimulatedHostUI() {
    if (this.hostInterfaceName) this.hostInterfaceName.textContent = 'sim0 (Virtual)';
    if (this.hostLocalIP) this.hostLocalIP.textContent = '10.0.1.25';
    if (this.hostGatewayIP) this.hostGatewayIP.textContent = '10.0.1.1';
    if (this.hostBandwidthRate) this.hostBandwidthRate.textContent = 'Simulated Stream';
    if (this.pillInternalVal) this.pillInternalVal.textContent = 'Benchmark Host Nodes';
    if (this.pillPublicVal) this.pillPublicVal.textContent = 'Synthetic Sockets';
    if (this.telemetryStatusBadge) {
      this.telemetryStatusBadge.textContent = 'SYNTHETIC';
      this.telemetryStatusBadge.style.color = 'var(--accent-amber)';
    }
    if (this.processChipsContainer) {
      this.processChipsContainer.innerHTML = '<span style="font-size:0.68rem;color:#64748b;">Synthetic traffic generator active</span>';
    }
  }

  reclusterTopology() {
    if (!this.currentTopology) return;

    const { nodes, connections } = this.currentTopology;

    // Run K-Means on IP 2D topological positions
    const kmeans = new KMeans({
      k: this.k,
      maxIterations: 50,
      tolerance: 1e-4,
    });

    const result = kmeans.fit(nodes);
    this.currentKMeansResult = result;

    this.chart.updateData({
      nodes,
      connections,
      centroids: result.centroids,
      assignments: result.assignments,
      clusterStats: result.clusterStats,
    });

    this.chart.render();
    this.updateTelemetryUI(result, nodes, connections);
    this.updateGatewayTable(result, nodes, connections);
    this.updatePortDistributionUI();
  }

  updateTelemetryUI(result, nodes, connections) {
    this.metricIPs.textContent = nodes.length;
    this.metricGateways.textContent = result.k;
    this.metricSockets.textContent = connections.length;

    // Cross-subnet traffic ratio
    const crossSubnetCount = connections.filter(c => c.isCrossSubnet).length;
    const crossPct = connections.length > 0 ? ((crossSubnetCount / connections.length) * 100).toFixed(1) : 0;
    this.metricCrossSubnet.textContent = `${crossPct}%`;

    this.metricSilhouette.textContent = result.silhouette >= 0 ? `+${result.silhouette.toFixed(2)}` : result.silhouette.toFixed(2);
    this.metricInertia.textContent = Math.round(result.inertia).toLocaleString();

    if (this.dataSource === 'real' && this.pointValueBadge) {
      this.pointValueBadge.textContent = `${nodes.length} IPs`;
    }
  }

  updateGatewayTable(result, nodes, connections) {
    const palette = NetworkClusterChart.PALETTE;
    let html = '';

    result.clusterStats.forEach((stat, i) => {
      const color = palette[i % palette.length];
      const memberNodes = nodes.filter((_, idx) => result.assignments[idx] === i);

      // Determine dominant zone or subnet CIDR
      const zones = memberNodes.map(n => n.zone).filter(Boolean);
      let zoneLabel = `Cluster Zone ${i + 1}`;
      if (zones.length > 0) {
        const counts = {};
        zones.forEach(z => { counts[z] = (counts[z] || 0) + 1; });
        zoneLabel = Object.keys(counts).sort((a, b) => counts[b] - counts[a])[0];
      }

      // Extract subnet CIDR prefix
      const subnetsInCluster = [...new Set(memberNodes.map(n => n.ip.split('.').slice(0, 3).join('.') + '.*'))];
      const primarySubnet = subnetsInCluster[0] || (memberNodes[0]?.ip || 'Subnet ' + (i+1));

      // Sockets originating from or terminating in this subnet
      const clusterNodeIds = new Set(memberNodes.map(n => n.id));
      const socketCount = connections.filter(c => clusterNodeIds.has(c.srcId) || clusterNodeIds.has(c.destId)).length;

      html += `
        <tr>
          <td>
            <div class="cluster-tag" style="color: ${color.main}">
              <span class="cluster-color-dot" style="background: ${color.main};"></span>
              GW-μ${i + 1}
            </div>
          </td>
          <td>
            <div style="font-weight:600;color:#f1f5f9;font-size:11px;">${zoneLabel}</div>
            <div style="font-size:10px;color:#94a3b8;font-family:monospace;">${primarySubnet} (${stat.centroid.x.toFixed(1)}, ${stat.centroid.y.toFixed(1)})</div>
          </td>
          <td><b>${stat.count}</b> <span style="font-size:10px;color:#64748b;">hosts</span></td>
          <td><span style="color:${color.main};font-weight:700;">${socketCount}</span></td>
        </tr>
      `;
    });

    this.centroidTableBody.innerHTML = html;
  }

  updatePortDistributionUI() {
    if (!this.currentTopology) return;
    const connections = this.currentTopology.connections;

    // Count by port
    const portStats = new Map();

    connections.forEach(c => {
      const p = c.destPort;
      if (!p) return;
      if (!portStats.has(p)) {
        portStats.set(p, {
          port: p,
          service: c.service || `Port ${p}`,
          color: c.color || '#94a3b8',
          proto: c.proto || 'TCP',
          count: 0
        });
      }
      portStats.get(p).count++;
    });

    // Ensure common ports exist with 0 count if none
    WELL_KNOWN_PORTS.slice(0, 4).forEach(p => {
      if (!portStats.has(p.port)) {
        portStats.set(p.port, { ...p, count: 0 });
      }
    });

    // Sort by count descending
    const sortedPorts = Array.from(portStats.values()).sort((a, b) => b.count - a.count).slice(0, 8);

    let html = '';
    sortedPorts.forEach(p => {
      const count = p.count;
      const pct = connections.length > 0 ? ((count / connections.length) * 100).toFixed(0) : 0;
      html += `
        <div class="port-badge-item" style="border-left: 3px solid ${p.color};">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <span style="font-weight:700;color:${p.color};font-family:var(--font-mono);font-size:11px;">
              :${p.port} [${p.service}]
            </span>
            <span style="font-family:var(--font-mono);font-size:11px;color:#cbd5e1;">
              ${count} <span style="color:#64748b;font-size:10px;">(${pct}%)</span>
            </span>
          </div>
          <div class="port-bar-track">
            <div class="port-bar-fill" style="width:${pct}%;background:${p.color};"></div>
          </div>
        </div>
      `;
    });

    this.portStatsContainer.innerHTML = html;
  }

  addToHistory(isReal = true) {
    if (!this.currentKMeansResult) return;
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    this.runHistory.unshift({
      time: timeStr,
      ips: this.currentTopology.nodes.length,
      sockets: this.currentTopology.connections.length,
      k: this.currentKMeansResult.k,
      isReal
    });

    if (this.runHistory.length > 5) this.runHistory.pop();
    this.renderHistory();
  }

  renderHistory() {
    let html = '';
    this.runHistory.forEach(item => {
      const tag = item.isReal ? '<span style="color:#34d399;font-size:0.65rem;margin-left:4px;">● REAL</span>' : '';
      html += `
        <div class="history-item">
          <div>
            <span class="history-time">${item.time}</span>
            ${tag}
            <span style="margin-left:6px;color:var(--text-secondary);font-size:0.7rem;">(K=${item.k} Gateways)</span>
          </div>
          <div class="history-val">
            <span style="color:var(--accent-cyan)">${item.ips} IPs</span>
            <span style="margin-left:6px;color:var(--accent-emerald)">${item.sockets} Sockets</span>
          </div>
        </div>
      `;
    });
    this.historyList.innerHTML = html;
  }
}

window.addEventListener('DOMContentLoaded', () => {
  new NetworkClusterApp();
});
