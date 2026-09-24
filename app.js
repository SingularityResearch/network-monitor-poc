import { KMeans } from './kmeans.js';
import { NetworkDataGenerator, WELL_KNOWN_PORTS } from './generator.js';
import { NetworkClusterChart } from './chart.js';

class NetworkClusterApp {
  constructor() {
    // DOM Elements
    this.canvas = document.getElementById('clusterCanvas');
    this.tooltip = document.getElementById('chartTooltip');

    // Control Elements
    this.kSlider = document.getElementById('kSlider');
    this.kValueBadge = document.getElementById('kValueBadge');
    this.pointSlider = document.getElementById('pointSlider');
    this.pointValueBadge = document.getElementById('pointValueBadge');
    this.intervalSelect = document.getElementById('intervalSelect');
    this.distSelect = document.getElementById('distSelect');
    this.portFilterSelect = document.getElementById('portFilterSelect');

    // Buttons
    this.btnPlayPause = document.getElementById('btnPlayPause');
    this.btnGenerateNow = document.getElementById('btnGenerateNow');
    this.btnPlayPauseIcon = document.getElementById('playPauseIcon');
    this.btnPlayPauseText = document.getElementById('playPauseText');

    // Toggles
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

    // Network Telemetry Elements
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
    this.k = parseInt(this.kSlider.value, 10) || 4;
    this.nodeCount = parseInt(this.pointSlider.value, 10) || 140;
    this.intervalSeconds = parseFloat(this.intervalSelect.value) || 10;
    this.distribution = this.distSelect.value || 'blobs';

    this.isPlaying = true;
    this.elapsedSeconds = 0;
    this.timerTickMs = 50;
    this.intervalId = null;

    this.currentTopology = null;
    this.currentKMeansResult = null;
    this.runHistory = [];

    // Initialize Chart
    this.chart = new NetworkClusterChart(this.canvas, this.tooltip);

    // Populate Port Filter Dropdown
    this.populatePortDropdown();

    // Bind listeners
    this.attachEventListeners();

    // Initial Run
    this.generateAndCluster();
    this.startTimer();
  }

  populatePortDropdown() {
    let options = '<option value="all" selected>All Ports / Protocols</option>';
    WELL_KNOWN_PORTS.forEach(p => {
      options += `<option value="${p.port}">${p.port} (${p.service} - ${p.proto})</option>`;
    });
    this.portFilterSelect.innerHTML = options;
  }

  attachEventListeners() {
    this.kSlider.addEventListener('input', (e) => {
      this.k = parseInt(e.target.value, 10);
      this.kValueBadge.textContent = this.k;
      this.reclusterTopology();
    });

    this.pointSlider.addEventListener('input', (e) => {
      this.nodeCount = parseInt(e.target.value, 10);
      this.pointValueBadge.textContent = this.nodeCount;
    });

    this.intervalSelect.addEventListener('change', (e) => {
      this.intervalSeconds = parseFloat(e.target.value);
      this.elapsedSeconds = 0;
    });

    this.distSelect.addEventListener('change', (e) => {
      this.distribution = e.target.value;
      this.generateAndCluster();
    });

    this.portFilterSelect.addEventListener('change', (e) => {
      this.chart.options.filterPort = e.target.value;
      this.chart.render();
      this.updatePortDistributionUI();
    });

    // Play / Pause
    this.btnPlayPause.addEventListener('click', () => this.togglePlayback());

    // Regenerate Now
    this.btnGenerateNow.addEventListener('click', () => {
      this.elapsedSeconds = 0;
      this.generateAndCluster();
    });

    // Toggles
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
      this.liveStatusText.textContent = 'TELEMETRY LIVE';
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

  /**
   * Generate new network topology (IPs + Sockets) and run K-Means
   */
  generateAndCluster() {
    this.currentTopology = NetworkDataGenerator.generateTopology({
      nodeCount: this.nodeCount,
      numSubnets: this.k,
      connectionDensity: 1.4,
      distribution: this.distribution,
    });

    this.reclusterTopology();
    this.addToHistory();
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
  }

  updateGatewayTable(result, nodes, connections) {
    const palette = NetworkClusterChart.PALETTE;
    let html = '';

    result.clusterStats.forEach((stat, i) => {
      const color = palette[i % palette.length];
      const memberNodes = nodes.filter((_, idx) => result.assignments[idx] === i);
      const subnetsInCluster = [...new Set(memberNodes.map(n => n.ip.split('.').slice(0, 3).join('.') + '.*'))];

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
            <div style="font-weight:600;color:#f1f5f9;">${subnetsInCluster[0] || '10.0.' + (i+1) + '.*'}</div>
            <div style="font-size:10px;color:#64748b;">(${stat.centroid.x.toFixed(1)}, ${stat.centroid.y.toFixed(1)})</div>
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
    const portCounts = {};
    WELL_KNOWN_PORTS.forEach(p => { portCounts[p.port] = 0; });

    connections.forEach(c => {
      if (portCounts[c.destPort] !== undefined) {
        portCounts[c.destPort]++;
      }
    });

    let html = '';
    WELL_KNOWN_PORTS.forEach(p => {
      const count = portCounts[p.port] || 0;
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

  addToHistory() {
    if (!this.currentKMeansResult) return;
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    this.runHistory.unshift({
      time: timeStr,
      ips: this.currentTopology.nodes.length,
      sockets: this.currentTopology.connections.length,
      k: this.currentKMeansResult.k,
    });

    if (this.runHistory.length > 5) this.runHistory.pop();
    this.renderHistory();
  }

  renderHistory() {
    let html = '';
    this.runHistory.forEach(item => {
      html += `
        <div class="history-item">
          <div>
            <span class="history-time">${item.time}</span>
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
