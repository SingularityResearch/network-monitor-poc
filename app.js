import { KMeans } from './kmeans.js';
import { WELL_KNOWN_PORTS } from './generator.js';
import { NetworkClusterChart } from './chart.js';

class NetworkClusterApp {
  constructor() {
    // Canvas & Tooltip
    this.canvas = document.getElementById('clusterCanvas');
    this.tooltip = document.getElementById('chartTooltip');

    // Controls
    this.trafficScopeSelect = document.getElementById('trafficScopeSelect');
    this.scopeCounter = document.getElementById('scopeCounter');
    this.sourceBadge = document.getElementById('sourceBadge');
    this.btnScanLan = document.getElementById('btnScanLan');

    this.autoKBadge = document.getElementById('autoKBadge');
    this.portFilterSelect = document.getElementById('portFilterSelect');
    this.streamStatusBar = document.getElementById('streamStatusBar');
    this.streamFpsBadge = document.getElementById('streamFpsBadge');
    this.streamVisualizer = document.getElementById('streamVisualizer');
    this.toggleOrganicDrift = document.getElementById('toggleOrganicDrift');

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
    this.toggleDnsLookup = document.getElementById('toggleDnsLookup');
    this.toggleGeoip = document.getElementById('toggleGeoip');

    // Threshold Alert Controls
    this.btnToggleAlerts = document.getElementById('btnToggleAlerts');
    this.headerAlertCount = document.getElementById('headerAlertCount');
    this.alertsDrawer = document.getElementById('alertsDrawer');
    this.alertsBackdrop = document.getElementById('alertsBackdrop');
    this.btnCloseAlerts = document.getElementById('btnCloseAlerts');
    this.alertsListContainer = document.getElementById('alertsListContainer');
    this.sliderLatencyAlert = document.getElementById('sliderLatencyAlert');
    this.valLatencyAlert = document.getElementById('valLatencyAlert');
    this.sliderBandwidthAlert = document.getElementById('sliderBandwidthAlert');
    this.valBandwidthAlert = document.getElementById('valBandwidthAlert');
    this.toggleAlertOverlays = document.getElementById('toggleAlertOverlays');
    this.alertsActiveBadge = document.getElementById('alertsActiveBadge');
    this.toastContainer = document.getElementById('toastContainer');

    // Canvas Zoom & Pan HUD Elements
    this.btnZoomIn = document.getElementById('btnZoomIn');
    this.btnZoomOut = document.getElementById('btnZoomOut');
    this.btnZoomReset = document.getElementById('btnZoomReset');
    this.zoomLevelText = document.getElementById('zoomLevelText');

    // Deep Socket Inspector Controls
    this.btnOpenInspector = document.getElementById('btnOpenInspector');
    this.inspectorDrawer = document.getElementById('inspectorDrawer');
    this.inspectorBackdrop = document.getElementById('inspectorBackdrop');
    this.btnCloseInspector = document.getElementById('btnCloseInspector');
    this.inspectorTitle = document.getElementById('inspectorTitle');
    this.inspectorSubtitle = document.getElementById('inspectorSubtitle');
    this.inspectorSearchInput = document.getElementById('inspectorSearchInput');
    this.inspectorTableBody = document.getElementById('inspectorTableBody');
    this.statTotalSockets = document.getElementById('statTotalSockets');
    this.statAvgLatency = document.getElementById('statAvgLatency');
    this.statTotalSent = document.getElementById('statTotalSent');
    this.btnFilterChartToSelection = document.getElementById('btnFilterChartToSelection');

    // Historical Topology Timeline Controls
    this.timelineBar = document.getElementById('timelineBar');
    this.btnTimelineStepBack = document.getElementById('btnTimelineStepBack');
    this.btnTimelinePlay = document.getElementById('btnTimelinePlay');
    this.timelinePlayIcon = document.getElementById('timelinePlayIcon');
    this.timelinePlayText = document.getElementById('timelinePlayText');
    this.btnTimelineStepFwd = document.getElementById('btnTimelineStepFwd');
    this.btnTimelineLive = document.getElementById('btnTimelineLive');
    this.timelineLiveDot = document.getElementById('timelineLiveDot');
    this.timelineSlider = document.getElementById('timelineSlider');
    this.timelineStatusText = document.getElementById('timelineStatusText');
    this.timelineCountText = document.getElementById('timelineCountText');

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
    this.trafficScope = this.trafficScopeSelect ? this.trafficScopeSelect.value : 'all';
    this.resolveDns = this.toggleDnsLookup ? this.toggleDnsLookup.checked : false;
    this.resolveGeoip = this.toggleGeoip ? this.toggleGeoip.checked : true;
    this.alertLatencyMs = parseInt(this.sliderLatencyAlert?.value || '50', 10);
    this.alertThroughputMbps = parseInt(this.sliderBandwidthAlert?.value || '10', 10);
    this.activeAlerts = [];
    this.rawSockets = [];
    this.inspectorFilter = { type: 'all', value: null, search: '' };

    // History Timeline State
    this.historySnapshots = [];
    this.historyIndex = -1; // -1 = live
    this.isTimelinePlaying = false;
    this.timelinePlayInterval = null;

    this.k = 4;

    this.isPlaying = true;
    this.streamPollIntervalMs = 1200;
    this.streamTimerId = null;
    this.isFetching = false;
    this.lastSnapshotRecordTime = 0;
    this.lastHistoryLogTime = 0;
    this.prevMetrics = { ips: 0, gateways: 0, sockets: 0, crossSubnet: 0 };

    this.currentTopology = null;
    this.currentKMeansResult = null;
    this.runHistory = [];

    // Initialize Canvas Chart
    this.chart = new NetworkClusterChart(this.canvas, this.tooltip);
    this.chart.options.resolveDns = this.resolveDns;
    this.chart.options.showGeoip = this.resolveGeoip;
    this.chart.options.alertLatencyMs = this.alertLatencyMs;
    this.chart.options.alertThroughputMbps = this.alertThroughputMbps;
    this.chart.options.showAlertOverlays = this.toggleAlertOverlays ? this.toggleAlertOverlays.checked : true;
    this.chart.options.organicDrift = this.toggleOrganicDrift ? this.toggleOrganicDrift.checked : true;

    // Report Canvas Render FPS to header badge
    this.chart.onFpsUpdate = (fps) => {
      if (this.streamFpsBadge) {
        this.streamFpsBadge.textContent = `${Math.round(fps)} FPS`;
      }
    };

    // Reflect Canvas zoom level in HUD badge
    this.chart.onZoomChange = (zoom) => {
      if (this.zoomLevelText) {
        this.zoomLevelText.textContent = `${Math.round(zoom * 100)}%`;
      }
    };

    // Connect Canvas item click to deep socket inspector
    this.chart.onItemClick = (item) => {
      if (item.type === 'node') {
        this.openSocketInspector('ip', item.data.ip);
      } else if (item.type === 'centroid') {
        this.openSocketInspector('cluster', item.index);
      } else if (item.type === 'connection') {
        this.openSocketInspector('flow', item.data);
      }
    };

    // Populate Ports
    this.populatePortDropdown();

    // Event listeners
    this.attachEventListeners();

    // Initial Trigger & continuous stream start
    this.generateAndCluster();
    this.startContinuousStream();
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
    // Traffic Scope Selector
    if (this.trafficScopeSelect) {
      this.trafficScopeSelect.addEventListener('change', (e) => {
        this.trafficScope = e.target.value;
        if (this.scopeCounter) {
          if (this.trafficScope === 'all') this.scopeCounter.textContent = 'Internal + Public';
          else if (this.trafficScope === 'internal') this.scopeCounter.textContent = 'LAN & Loopback';
          else this.scopeCounter.textContent = 'Public Internet';
        }
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

    // Organic Micro-Motion Toggle
    if (this.toggleOrganicDrift) {
      this.toggleOrganicDrift.addEventListener('change', (e) => {
        this.chart.options.organicDrift = e.target.checked;
      });
    }

    // Port Filter
    this.portFilterSelect.addEventListener('change', (e) => {
      this.chart.options.filterPort = e.target.value;
      this.chart.render();
      this.updatePortDistributionUI();
    });

    // Zoom & Pan Toolbar Controls
    if (this.btnZoomIn) {
      this.btnZoomIn.addEventListener('click', () => this.chart.zoomIn());
    }
    if (this.btnZoomOut) {
      this.btnZoomOut.addEventListener('click', () => this.chart.zoomOut());
    }
    if (this.btnZoomReset) {
      this.btnZoomReset.addEventListener('click', () => this.chart.resetZoom());
    }
    if (this.zoomLevelText) {
      this.zoomLevelText.addEventListener('click', () => this.chart.resetZoom());
    }

    // Keyboard Shortcuts for Zooming (+/- / 0 / r)
    window.addEventListener('keydown', (e) => {
      const activeTag = document.activeElement?.tagName?.toLowerCase();
      if (activeTag === 'input' || activeTag === 'select' || activeTag === 'textarea') return;

      if (e.key === '+' || e.key === '=') {
        e.preventDefault();
        this.chart.zoomIn();
      } else if (e.key === '-' || e.key === '_') {
        e.preventDefault();
        this.chart.zoomOut();
      } else if (e.key === '0' || e.key.toLowerCase() === 'r') {
        if (!e.ctrlKey && !e.metaKey) {
          e.preventDefault();
          this.chart.resetZoom();
        }
      }
    });

    // Play / Pause
    this.btnPlayPause.addEventListener('click', () => this.togglePlayback());

    // Regenerate / Refresh Now
    this.btnGenerateNow.addEventListener('click', () => {
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

    if (this.toggleDnsLookup) {
      this.toggleDnsLookup.addEventListener('change', (e) => {
        this.resolveDns = e.target.checked;
        this.chart.options.resolveDns = this.resolveDns;

        // Automatically activate label display when Resolve DNS is enabled
        if (this.resolveDns) {
          if (this.toggleIpLabels && !this.toggleIpLabels.checked) {
            this.toggleIpLabels.checked = true;
          }
          this.chart.options.showIpLabels = true;
        }

        this.generateAndCluster();
        this.chart.render();
      });
    }

    if (this.toggleGeoip) {
      this.toggleGeoip.addEventListener('change', (e) => {
        this.resolveGeoip = e.target.checked;
        this.chart.options.showGeoip = this.resolveGeoip;
        this.chart.render();
      });
    }

    // Threshold Alert Sliders & Toggles
    if (this.sliderLatencyAlert) {
      this.sliderLatencyAlert.addEventListener('input', (e) => {
        this.alertLatencyMs = parseInt(e.target.value, 10);
        if (this.valLatencyAlert) this.valLatencyAlert.textContent = `> ${this.alertLatencyMs} ms`;
        this.chart.options.alertLatencyMs = this.alertLatencyMs;
        if (this.currentTopology) this.checkThresholdAlerts(this.currentTopology);
        this.chart.render();
      });
    }

    if (this.sliderBandwidthAlert) {
      this.sliderBandwidthAlert.addEventListener('input', (e) => {
        this.alertThroughputMbps = parseInt(e.target.value, 10);
        if (this.valBandwidthAlert) this.valBandwidthAlert.textContent = `> ${this.alertThroughputMbps} Mbps`;
        this.chart.options.alertThroughputMbps = this.alertThroughputMbps;
        if (this.currentTopology) this.checkThresholdAlerts(this.currentTopology);
        this.chart.render();
      });
    }

    if (this.toggleAlertOverlays) {
      this.toggleAlertOverlays.addEventListener('change', (e) => {
        this.chart.options.showAlertOverlays = e.target.checked;
        this.chart.render();
      });
    }

    // Alerts Center Drawer triggers
    if (this.btnToggleAlerts) {
      this.btnToggleAlerts.addEventListener('click', () => {
        this.alertsDrawer?.classList.toggle('open');
        this.alertsBackdrop?.classList.toggle('open');
      });
    }
    this.btnCloseAlerts?.addEventListener('click', () => {
      this.alertsDrawer?.classList.remove('open');
      this.alertsBackdrop?.classList.remove('open');
    });
    this.alertsBackdrop?.addEventListener('click', () => {
      this.alertsDrawer?.classList.remove('open');
      this.alertsBackdrop?.classList.remove('open');
    });

    // Deep Socket Inspector triggers
    if (this.btnOpenInspector) {
      this.btnOpenInspector.addEventListener('click', () => {
        this.openSocketInspector('all', null);
      });
    }
    this.btnCloseInspector?.addEventListener('click', () => this.closeSocketInspector());
    this.inspectorBackdrop?.addEventListener('click', () => this.closeSocketInspector());

    if (this.inspectorSearchInput) {
      this.inspectorSearchInput.addEventListener('input', (e) => {
        this.inspectorFilter.search = e.target.value.trim().toLowerCase();
        this.renderSocketInspector();
      });
    }

    if (this.btnFilterChartToSelection) {
      this.btnFilterChartToSelection.addEventListener('click', () => {
        if (this.inspectorFilter.type === 'port' && this.inspectorFilter.value) {
          this.portFilterSelect.value = String(this.inspectorFilter.value);
          this.chart.options.filterPort = String(this.inspectorFilter.value);
          this.chart.render();
          this.updatePortDistributionUI();
          this.closeSocketInspector();
        }
      });
    }

    // Timeline Scrubber Controls
    this.btnTimelineStepBack?.addEventListener('click', () => this.stepTimeline(-1));
    this.btnTimelineStepFwd?.addEventListener('click', () => this.stepTimeline(1));
    this.btnTimelinePlay?.addEventListener('click', () => this.toggleTimelinePlay());
    this.btnTimelineLive?.addEventListener('click', () => this.snapToLive());

    if (this.timelineSlider) {
      this.timelineSlider.addEventListener('input', (e) => {
        this.scrubToHistory(parseInt(e.target.value, 10));
      });
    }

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
      this.liveIndicator?.classList.remove('paused');
      this.streamStatusBar?.classList.remove('paused');
      this.liveStatusText.textContent = 'LIVE CONTINUOUS STREAM';
      this.btnPlayPauseText.textContent = 'Pause';
      this.btnPlayPauseIcon.innerHTML = `
        <rect x="6" y="4" width="4" height="16" fill="currentColor"/>
        <rect x="14" y="4" width="4" height="16" fill="currentColor"/>
      `;
      this.startContinuousStream();
    } else {
      if (this.streamTimerId) clearTimeout(this.streamTimerId);
      this.liveIndicator?.classList.add('paused');
      this.streamStatusBar?.classList.add('paused');
      this.liveStatusText.textContent = 'STREAM PAUSED';
      this.btnPlayPauseText.textContent = 'Resume';
      this.btnPlayPauseIcon.innerHTML = `
        <polygon points="5,3 19,12 5,21" fill="currentColor"/>
      `;
    }
  }

  startContinuousStream() {
    if (this.streamTimerId) clearTimeout(this.streamTimerId);
    this.runContinuousStreamTick();
  }

  async runContinuousStreamTick() {
    if (!this.isPlaying) return;
    if (this.historyIndex >= 0) return; // In historical replay mode

    if (!this.isFetching) {
      this.isFetching = true;
      try {
        await this.generateAndCluster();
      } catch (err) {
        console.warn('Continuous stream poll error:', err);
      } finally {
        this.isFetching = false;
      }
    }

    if (this.isPlaying && this.historyIndex < 0) {
      this.streamTimerId = setTimeout(() => this.runContinuousStreamTick(), this.streamPollIntervalMs);
    }
  }

  async fetchRealNetworkData() {
    try {
      const url = `/api/network-telemetry?scope=${encodeURIComponent(this.trafficScope)}&k=${this.k}&resolve_dns=${this.resolveDns}&resolve_geoip=${this.resolveGeoip}`;
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn('Real network API request failed, falling back:', err);
      return null;
    }
  }

  /**
   * Acquire live Linux network telemetry and run K-Means clustering
   */
  async generateAndCluster() {
    // If replaying historical snapshot, don't overwrite with live fetch unless forced
    if (this.historyIndex >= 0) return;

    const realData = await this.fetchRealNetworkData();
    if (realData && realData.nodes && realData.nodes.length > 0) {
      this.currentTopology = realData;
      this.rawSockets = realData.sockets || [];
      this.chart.options.resolveDns = this.resolveDns;
      this.chart.options.showGeoip = this.resolveGeoip;
      this.updateRealHostUI(realData.meta);
      this.populatePortDropdown(realData.connections);
      this.reclusterTopology();
      this.checkThresholdAlerts(realData);

      const now = Date.now();
      if (!this.lastSnapshotRecordTime || now - this.lastSnapshotRecordTime >= 4000) {
        this.lastSnapshotRecordTime = now;
        this.recordSnapshot(realData, this.currentKMeansResult);
      }
      if (this.inspectorDrawer?.classList.contains('open')) {
        this.renderSocketInspector();
      }
      if (!this.lastHistoryLogTime || now - this.lastHistoryLogTime >= 8000) {
        this.lastHistoryLogTime = now;
        this.addToHistory();
      }
    }
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
      if (this.resolveDns) {
        const resolvedCount = this.currentTopology?.nodes?.filter(n => n.dnsName).length || 0;
        this.telemetryStatusBadge.textContent = `DNS ACTIVE (${resolvedCount} PTRs)`;
        this.telemetryStatusBadge.style.color = '#34d399';
      } else {
        this.telemetryStatusBadge.textContent = 'REAL TELEMETRY';
        this.telemetryStatusBadge.style.color = '#38bdf8';
      }
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

  reclusterTopology() {
    if (!this.currentTopology || !this.currentTopology.nodes || this.currentTopology.nodes.length === 0) return;

    const { nodes, connections } = this.currentTopology;

    // Automatically determine optimal K based on active network zones & CIDR subnets
    const distinctSubnets = new Set();
    nodes.forEach(n => {
      const key = n.subnetIdx !== undefined ? n.subnetIdx : (n.zone || 'default');
      distinctSubnets.add(key);
    });

    let autoK = distinctSubnets.size;
    if (this.trafficScope === 'internal') {
      autoK = Math.min(nodes.length, Math.max(1, autoK));
    } else if (this.trafficScope === 'public') {
      autoK = Math.min(nodes.length, Math.max(1, autoK));
    } else {
      autoK = Math.min(nodes.length, Math.max(2, autoK));
    }
    this.k = Math.max(1, Math.min(8, autoK));

    if (this.autoKBadge) {
      this.autoKBadge.textContent = `Auto (${this.k})`;
    }

    // Run K-Means with previous centroids to stabilize cluster color identities
    const prevCentroids = this.currentKMeansResult ? this.currentKMeansResult.centroids : null;
    const kmeans = new KMeans({
      k: this.k,
      maxIterations: 50,
      tolerance: 1e-4,
    });

    const result = kmeans.fit(nodes, prevCentroids);
    this.currentKMeansResult = result;

    this.chart.updateData({
      nodes,
      connections,
      centroids: result.centroids,
      assignments: result.assignments,
      clusterStats: result.clusterStats,
    });

    this.updateTelemetryUI(result, nodes, connections);
    this.updateGatewayTable(result, nodes, connections);
    this.updatePortDistributionUI();
  }

  animateMetric(el, currentVal, targetVal, formatFn = (v) => Math.round(v)) {
    if (!el) return targetVal;
    if (isNaN(currentVal) || currentVal === null || currentVal === undefined) {
      el.textContent = formatFn(targetVal);
      return targetVal;
    }
    if (currentVal === targetVal) {
      el.textContent = formatFn(targetVal);
      return targetVal;
    }
    const startTime = performance.now();
    const duration = 320;
    const step = (now) => {
      const p = Math.min(1, (now - startTime) / duration);
      const ease = 1 - Math.pow(1 - p, 2);
      const val = currentVal + (targetVal - currentVal) * ease;
      el.textContent = formatFn(val);
      if (p < 1) {
        requestAnimationFrame(step);
      } else {
        el.textContent = formatFn(targetVal);
      }
    };
    requestAnimationFrame(step);
    return targetVal;
  }

  updateTelemetryUI(result, nodes, connections) {
    this.prevMetrics.ips = this.animateMetric(this.metricIPs, this.prevMetrics.ips, nodes.length, (v) => Math.round(v));
    this.prevMetrics.gateways = this.animateMetric(this.metricGateways, this.prevMetrics.gateways, result.k, (v) => Math.round(v));
    this.prevMetrics.sockets = this.animateMetric(this.metricSockets, this.prevMetrics.sockets, connections.length, (v) => Math.round(v));

    // Cross-subnet traffic ratio
    const crossSubnetCount = connections.filter((c) => c.isCrossSubnet).length;
    const crossPct = connections.length > 0 ? (crossSubnetCount / connections.length) * 100 : 0;
    this.prevMetrics.crossSubnet = this.animateMetric(this.metricCrossSubnet, this.prevMetrics.crossSubnet, crossPct, (v) => `${v.toFixed(1)}%`);

    this.metricSilhouette.textContent = result.silhouette >= 0 ? `+${result.silhouette.toFixed(2)}` : result.silhouette.toFixed(2);
    this.metricInertia.textContent = Math.round(result.inertia).toLocaleString();
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
        <div class="port-badge-item" data-port="${p.port}" style="border-left: 3px solid ${p.color}; cursor: pointer;" title="Click to inspect deep sockets on port :${p.port}">
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

    // Attach click listeners to port badges for protocol drill-down
    this.portStatsContainer.querySelectorAll('.port-badge-item').forEach(el => {
      el.addEventListener('click', () => {
        const port = el.getAttribute('data-port');
        if (port) {
          this.openSocketInspector('port', parseInt(port, 10));
        }
      });
    });
  }

  // ==========================================================================
  // Bandwidth & Latency Threshold Alerts
  // ==========================================================================
  checkThresholdAlerts(topology) {
    if (!topology) return;
    const newAlerts = [];
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    // 1. Latency spikes on connections
    const connections = topology.connections || [];
    connections.forEach(c => {
      if (c.latencyMs && c.latencyMs > this.alertLatencyMs) {
        const isCritical = c.latencyMs > (this.alertLatencyMs * 2);
        newAlerts.push({
          id: `lat-${c.srcIP}-${c.destIP}-${c.destPort}`,
          type: 'latency',
          severity: isCritical ? 'critical' : 'warning',
          title: `Latency Spike (${c.latencyMs.toFixed(1)} ms)`,
          subtitle: `${c.srcIP} → ${c.destIP}:${c.destPort}`,
          metric: `${c.latencyMs.toFixed(1)} ms`,
          threshold: `>${this.alertLatencyMs} ms`,
          service: c.service || `Port ${c.destPort}`,
          serviceColor: c.color || '#f59e0b',
          time: timeStr,
          targetIp: c.destIP,
          targetPort: c.destPort
        });
      }
    });

    // 2. Bandwidth surges on nodes
    const nodes = topology.nodes || [];
    nodes.forEach(n => {
      const mbps = n.trafficMbps || (n.totalBandwidthKbps ? n.totalBandwidthKbps / 1000 : 0);
      if (mbps > this.alertThroughputMbps) {
        const isCritical = mbps > (this.alertThroughputMbps * 2.5);
        newAlerts.push({
          id: `bw-${n.ip}`,
          type: 'bandwidth',
          severity: isCritical ? 'critical' : 'warning',
          title: `Bandwidth Surge (${mbps.toFixed(1)} Mbps)`,
          subtitle: `Node ${n.ip} ${n.dnsName ? '(' + n.dnsName + ')' : (n.city ? 'in ' + n.city : '')}`,
          metric: `${mbps.toFixed(1)} Mbps`,
          threshold: `>${this.alertThroughputMbps} Mbps`,
          service: n.zone || 'Public Host',
          serviceColor: '#ef4444',
          time: timeStr,
          targetIp: n.ip,
          targetPort: null
        });
      }
    });

    // Notify on new high-severity alerts (toast)
    const prevIds = new Set(this.activeAlerts.map(a => a.id));
    const freshAlerts = newAlerts.filter(a => !prevIds.has(a.id));
    if (freshAlerts.length > 0) {
      const first = freshAlerts[0];
      this.showToast(first.title, `${first.subtitle} exceeded threshold (${first.threshold})`, first.severity === 'critical' ? 'danger' : 'warning');
    }

    this.activeAlerts = newAlerts;

    // Update header badge
    if (this.headerAlertCount) {
      if (newAlerts.length > 0) {
        this.headerAlertCount.textContent = newAlerts.length;
        this.headerAlertCount.style.display = 'inline-block';
      } else {
        this.headerAlertCount.style.display = 'none';
      }
    }

    if (this.alertsActiveBadge) {
      this.alertsActiveBadge.textContent = `${newAlerts.length} Active`;
      this.alertsActiveBadge.style.color = newAlerts.length > 0 ? '#ef4444' : '#10b981';
    }

    this.renderAlertsDrawer();
  }

  renderAlertsDrawer() {
    if (!this.alertsListContainer) return;

    if (this.activeAlerts.length === 0) {
      this.alertsListContainer.innerHTML = `
        <div class="alerts-empty">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="1.8" style="margin-bottom:8px;">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
            <polyline points="22 4 12 14.01 9 11.01"/>
          </svg>
          <h4 style="margin:0 0 4px 0;color:#f1f5f9;font-size:0.92rem;">All Telemetry Normal</h4>
          <p style="margin:0;font-size:0.75rem;color:#64748b;line-height:1.4;">
            No sockets exceed the ${this.alertLatencyMs}ms latency threshold or ${this.alertThroughputMbps}Mbps bandwidth limit.
          </p>
        </div>
      `;
      return;
    }

    let html = '';
    this.activeAlerts.forEach(a => {
      const borderCol = a.severity === 'critical' ? '#ef4444' : '#f59e0b';
      const icon = a.type === 'latency' ? '⏱️' : '⚡';
      html += `
        <div class="alert-card-item" style="border-left: 3px solid ${borderCol};">
          <div class="alert-card-header">
            <span class="alert-card-title">
              <span>${icon}</span>
              <span>${a.title}</span>
            </span>
            <span class="alert-card-time">${a.time}</span>
          </div>
          <div class="alert-card-desc">${a.subtitle}</div>
          <div class="alert-card-footer">
            <span class="alert-metric-pill" style="color:${borderCol};">
              Value: <b>${a.metric}</b> (${a.threshold})
            </span>
            <button class="btn btn-secondary btn-sm btn-inspect-alert" data-ip="${a.targetIp || ''}" data-port="${a.targetPort || ''}" style="padding:2px 8px;font-size:0.68rem;">
              Inspect
            </button>
          </div>
        </div>
      `;
    });

    this.alertsListContainer.innerHTML = html;

    this.alertsListContainer.querySelectorAll('.btn-inspect-alert').forEach(btn => {
      btn.addEventListener('click', () => {
        const ip = btn.getAttribute('data-ip');
        const port = btn.getAttribute('data-port');
        if (ip) {
          this.alertsDrawer?.classList.remove('open');
          this.alertsBackdrop?.classList.remove('open');
          this.openSocketInspector('ip', ip);
        } else if (port) {
          this.alertsDrawer?.classList.remove('open');
          this.alertsBackdrop?.classList.remove('open');
          this.openSocketInspector('port', parseInt(port, 10));
        }
      });
    });
  }

  showToast(title, message, type = 'warning') {
    if (!this.toastContainer) return;

    // Max 3 toasts at once
    const existing = this.toastContainer.querySelectorAll('.toast-item');
    if (existing.length >= 3) {
      existing[0].remove();
    }

    const toast = document.createElement('div');
    toast.className = `toast-item toast-${type}`;
    const icon = type === 'danger' ? '🚨' : type === 'warning' ? '⚠️' : 'ℹ️';

    toast.innerHTML = `
      <div class="toast-icon">${icon}</div>
      <div class="toast-body">
        <div class="toast-title">${title}</div>
        <div class="toast-msg">${message}</div>
      </div>
      <button class="toast-close" title="Dismiss">✕</button>
    `;

    toast.querySelector('.toast-close').addEventListener('click', () => {
      toast.classList.add('fade-out');
      setTimeout(() => toast.remove(), 250);
    });

    this.toastContainer.appendChild(toast);

    // Auto-remove after 4.5 seconds
    setTimeout(() => {
      if (toast.parentNode) {
        toast.classList.add('fade-out');
        setTimeout(() => toast.remove(), 250);
      }
    }, 4500);
  }

  // ==========================================================================
  // Deep Socket & Protocol Inspector
  // ==========================================================================
  openSocketInspector(filterType = 'all', filterValue = null) {
    this.inspectorFilter.type = filterType;
    this.inspectorFilter.value = filterValue;
    this.inspectorFilter.search = '';
    if (this.inspectorSearchInput) this.inspectorSearchInput.value = '';

    // Update Header Text & Context
    if (filterType === 'ip') {
      this.inspectorTitle.textContent = `Host Sockets: ${filterValue}`;
      this.inspectorSubtitle.textContent = `Kernel sockets communicating with IP host ${filterValue}`;
      if (this.btnFilterChartToSelection) this.btnFilterChartToSelection.style.display = 'none';
    } else if (filterType === 'flow' || filterType === 'connection') {
      const conn = filterValue;
      this.inspectorTitle.textContent = `Flow: ${conn.srcIP} → ${conn.destIP}:${conn.destPort}`;
      this.inspectorSubtitle.textContent = `Active ${conn.proto || 'TCP'} socket connection • Service :${conn.destPort} (${conn.service || 'Port'}) • Latency: ${conn.latencyMs} ms`;
      if (this.btnFilterChartToSelection) {
        this.btnFilterChartToSelection.style.display = 'inline-flex';
        this.btnFilterChartToSelection.textContent = `Filter Canvas to :${conn.destPort}`;
      }
    } else if (filterType === 'port') {
      this.inspectorTitle.textContent = `Port :${filterValue} Protocol Drill-Down`;
      this.inspectorSubtitle.textContent = `Detailed socket connections destined for port :${filterValue}`;
      if (this.btnFilterChartToSelection) {
        this.btnFilterChartToSelection.style.display = 'inline-flex';
        this.btnFilterChartToSelection.textContent = `Filter Canvas to :${filterValue}`;
      }
    } else if (filterType === 'cluster') {
      this.inspectorTitle.textContent = `Gateway GW-μ${(filterValue || 0) + 1} Sockets`;
      this.inspectorSubtitle.textContent = `All sockets associated with subnet cluster ${filterValue + 1}`;
      if (this.btnFilterChartToSelection) this.btnFilterChartToSelection.style.display = 'none';
    } else {
      this.inspectorTitle.textContent = `Deep Socket & Protocol Inspector`;
      this.inspectorSubtitle.textContent = `Kernel-level TCP/UDP connection state, GeoIP ASN, and queue buffer telemetry`;
      if (this.btnFilterChartToSelection) this.btnFilterChartToSelection.style.display = 'none';
    }

    if (this.inspectorDrawer) this.inspectorDrawer.classList.add('open');
    if (this.inspectorBackdrop) this.inspectorBackdrop.classList.add('open');

    this.renderSocketInspector();
  }

  closeSocketInspector() {
    if (this.inspectorDrawer) this.inspectorDrawer.classList.remove('open');
    if (this.inspectorBackdrop) this.inspectorBackdrop.classList.remove('open');
  }

  renderSocketInspector() {
    if (!this.inspectorTableBody) return;

    let sockets = this.rawSockets || [];

    // Filter by type
    if (this.inspectorFilter.type === 'ip') {
      const targetIp = String(this.inspectorFilter.value);
      sockets = sockets.filter(s => s.localIP === targetIp || s.peerIP === targetIp);
    } else if ((this.inspectorFilter.type === 'flow' || this.inspectorFilter.type === 'connection') && this.inspectorFilter.value) {
      const conn = this.inspectorFilter.value;
      const sPort = parseInt(conn.destPort, 10);
      let matched = sockets.filter(s =>
        ((s.localIP === conn.srcIP && s.peerIP === conn.destIP) || (s.localIP === conn.destIP && s.peerIP === conn.srcIP)) &&
        (!sPort || s.peerPort === sPort || s.localPort === sPort)
      );
      if (matched.length === 0) {
        matched = (this.rawSockets || []).filter(s =>
          (s.peerIP === conn.destIP || s.localIP === conn.destIP || s.peerIP === conn.srcIP || s.localIP === conn.srcIP) &&
          (!sPort || s.peerPort === sPort || s.localPort === sPort)
        );
      }
      if (matched.length === 0) {
        matched = (this.rawSockets || []).filter(s =>
          s.peerIP === conn.destIP || s.localIP === conn.destIP || s.peerIP === conn.srcIP || s.localIP === conn.srcIP
        );
      }
      sockets = matched.length > 0 ? matched : sockets;
    } else if (this.inspectorFilter.type === 'port') {
      const targetPort = parseInt(this.inspectorFilter.value, 10);
      sockets = sockets.filter(s => s.peerPort === targetPort || s.localPort === targetPort);
    } else if (this.inspectorFilter.type === 'cluster' && this.currentKMeansResult) {
      const clusterIdx = parseInt(this.inspectorFilter.value, 10);
      const clusterNodes = (this.currentTopology?.nodes || []).filter((_, idx) => this.currentKMeansResult.assignments[idx] === clusterIdx);
      const clusterIps = new Set(clusterNodes.map(n => n.ip));
      sockets = sockets.filter(s => clusterIps.has(s.localIP) || clusterIps.has(s.peerIP));
    }

    // Filter by search query
    const q = this.inspectorFilter.search;
    if (q) {
      sockets = sockets.filter(s => {
        const text = `${s.proto} ${s.state} ${s.localIP} ${s.localPort} ${s.peerIP} ${s.peerPort} ${s.process} ${s.service} ${s.dnsName || ''} ${s.geo?.city || ''} ${s.geo?.country || ''} ${s.geo?.asn || ''} ${s.geo?.org || ''}`.toLowerCase();
        return text.includes(q);
      });
    }

    // Summary statistics
    const totalCount = sockets.length;
    let rttSum = 0;
    let rttCount = 0;
    let totalSentBytes = 0;

    sockets.forEach(s => {
      if (s.rttMs && s.rttMs > 0) {
        rttSum += s.rttMs;
        rttCount++;
      }
      if (s.bytesSent) totalSentBytes += s.bytesSent;
    });

    const avgRtt = rttCount > 0 ? (rttSum / rttCount).toFixed(1) : '--';
    const totalSentMb = totalSentBytes > 0 ? (totalSentBytes / (1024 * 1024)).toFixed(2) : '0.00';

    if (this.statTotalSockets) this.statTotalSockets.textContent = totalCount;
    if (this.statAvgLatency) this.statAvgLatency.textContent = `${avgRtt} ms`;
    if (this.statTotalSent) this.statTotalSent.textContent = `${totalSentMb} MB`;

    if (sockets.length === 0) {
      this.inspectorTableBody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align:center;padding:2.5rem 1rem;color:#64748b;">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" style="margin-bottom:6px;opacity:0.6;">
              <circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line>
            </svg>
            <div style="font-size:0.85rem;font-weight:600;color:#94a3b8;">No matching sockets found</div>
            <div style="font-size:0.75rem;margin-top:2px;">Try adjusting your filter or search query</div>
          </td>
        </tr>
      `;
      return;
    }

    let rows = '';
    sockets.forEach(s => {
      // Find matching node for GeoIP if socket doesn't have it direct
      let geo = s.geo;
      let dns = s.dnsName;
      if (!geo && this.currentTopology?.nodes) {
        const peerNode = this.currentTopology.nodes.find(n => n.ip === s.peerIP);
        if (peerNode) {
          geo = peerNode;
          dns = dns || peerNode.dnsName;
        }
      }

      const flag = geo?.flag ? `<span style="font-size:14px;margin-right:3px;">${geo.flag}</span>` : '';
      let geoText = '';
      if (geo?.city || geo?.country) {
        geoText = `${geo.city ? geo.city + ', ' : ''}${geo.country || ''}`;
      }
      const asnText = geo?.asn ? `[${geo.asn}]` : (geo?.org ? `[${geo.org}]` : '');

      const isLatSpike = s.rttMs && s.rttMs > this.alertLatencyMs;
      const rttColor = isLatSpike ? '#ef4444' : (s.rttMs > 30 ? '#f59e0b' : '#34d399');
      const rttDisplay = s.rttMs ? `<b style="color:${rttColor}">${s.rttMs.toFixed(1)} ms</b>` : '<span style="color:#64748b;">--</span>';

      const stateColor = s.state === 'ESTAB' || s.state === 'ESTABLISHED' ? '#10b981' : (s.state === 'LISTEN' ? '#38bdf8' : (s.state === 'TIME_WAIT' ? '#f59e0b' : '#94a3b8'));

      rows += `
        <tr>
          <td>
            <span class="socket-proto-pill" style="color:${s.serviceColor || '#38bdf8'};background:rgba(56,189,248,0.1);border:1px solid rgba(56,189,248,0.25);">
              ${s.proto} :${s.peerPort || s.localPort}
            </span>
            <div style="font-size:10px;color:#94a3b8;margin-top:2px;">${s.service || ''}</div>
          </td>
          <td>
            <span class="socket-state-badge" style="color:${stateColor};border-color:${stateColor}33;background:${stateColor}15;">
              ${s.state}
            </span>
          </td>
          <td>
            <div class="socket-endpoint">${s.localIP}:${s.localPort}</div>
          </td>
          <td>
            <div class="socket-endpoint">
              ${flag}<b>${s.peerIP}</b>:${s.peerPort}
            </div>
            ${dns ? `<div style="font-size:10px;color:#38bdf8;font-family:var(--font-mono);">${dns}</div>` : ''}
            ${geoText || asnText ? `<div style="font-size:10px;color:#94a3b8;">${geoText} <span style="color:#64748b;">${asnText}</span></div>` : ''}
          </td>
          <td>
            <div style="font-weight:600;color:#f1f5f9;font-size:11px;">${s.process || 'system'}</div>
            <div style="font-size:10px;color:#64748b;font-family:var(--font-mono);">PID: ${s.pid || '-'}</div>
          </td>
          <td>
            ${rttDisplay}
            ${s.rttvarMs ? `<div style="font-size:10px;color:#64748b;">var: ${s.rttvarMs.toFixed(1)}ms</div>` : ''}
          </td>
          <td>
            <div style="font-size:10px;font-family:var(--font-mono);color:#cbd5e1;">
              cwnd: <b style="color:#38bdf8;">${s.cwnd || '-'}</b>
            </div>
            <div style="font-size:10px;font-family:var(--font-mono);color:#64748b;">
              rq:${s.recvQ || 0} / sq:${s.sendQ || 0}
            </div>
          </td>
        </tr>
      `;
    });

    this.inspectorTableBody.innerHTML = rows;
  }

  // ==========================================================================
  // Historical Topology Timeline & Playback
  // ==========================================================================
  recordSnapshot(topology, kmeansResult) {
    if (!topology || !kmeansResult) return;

    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    const snap = {
      timestamp: now,
      timeStr,
      topology: JSON.parse(JSON.stringify(topology)),
      kmeansResult: JSON.parse(JSON.stringify(kmeansResult)),
      sockets: JSON.parse(JSON.stringify(this.rawSockets || []))
    };

    this.historySnapshots.push(snap);
    // Keep max 30 snapshots in buffer for timeline scrubbing
    if (this.historySnapshots.length > 30) {
      this.historySnapshots.shift();
    }

    if (this.timelineSlider) {
      this.timelineSlider.max = this.historySnapshots.length - 1;
      if (this.historyIndex === -1) {
        this.timelineSlider.value = this.historySnapshots.length - 1;
      }
    }

    if (this.timelineCountText) {
      const c = this.historySnapshots.length;
      this.timelineCountText.textContent = `${c} snapshot${c === 1 ? '' : 's'} recorded`;
    }
  }

  scrubToHistory(index) {
    if (index < 0 || index >= this.historySnapshots.length) return;

    this.historyIndex = index;
    const snap = this.historySnapshots[index];

    if (this.btnTimelineLive) {
      this.btnTimelineLive.classList.remove('live-active');
    }
    if (this.timelineStatusText) {
      this.timelineStatusText.innerHTML = `<span style="color:#f59e0b;font-weight:700;">⏮ REPLAYING [${index + 1}/${this.historySnapshots.length}] ${snap.timeStr}</span>`;
    }
    if (this.timelineSlider) {
      this.timelineSlider.value = index;
    }

    this.renderHistorySnapshot(index);
  }

  stepTimeline(delta) {
    if (this.historySnapshots.length === 0) return;

    if (this.historyIndex === -1) {
      // Currently live, step back into recent history
      if (delta < 0) {
        const target = Math.max(0, this.historySnapshots.length - 2);
        this.scrubToHistory(target);
      }
    } else {
      const nextIdx = this.historyIndex + delta;
      if (nextIdx >= this.historySnapshots.length) {
        this.snapToLive();
      } else if (nextIdx >= 0) {
        this.scrubToHistory(nextIdx);
      }
    }
  }

  snapToLive() {
    if (this.isTimelinePlaying) {
      this.toggleTimelinePlay();
    }

    this.historyIndex = -1;

    if (this.btnTimelineLive) {
      this.btnTimelineLive.classList.add('live-active');
    }
    if (this.timelineStatusText) {
      this.timelineStatusText.innerHTML = `● LIVE TELEMETRY STREAM`;
    }
    if (this.timelineSlider) {
      this.timelineSlider.value = Math.max(0, this.historySnapshots.length - 1);
    }

    // Refresh live & resume continuous stream
    this.generateAndCluster();
    if (this.isPlaying) {
      this.startContinuousStream();
    }
  }

  toggleTimelinePlay() {
    if (this.isTimelinePlaying) {
      clearInterval(this.timelinePlayInterval);
      this.timelinePlayInterval = null;
      this.isTimelinePlaying = false;
      if (this.timelinePlayIcon) {
        this.timelinePlayIcon.innerHTML = '<polygon points="5 3 19 12 5 21 5 3"></polygon>';
      }
      if (this.timelinePlayText) {
        this.timelinePlayText.textContent = 'Play Replay';
      }
    } else {
      if (this.historySnapshots.length < 2) {
        this.showToast('Timeline Playback', 'Wait for at least 2 telemetry snapshots to record.', 'info');
        return;
      }

      this.isTimelinePlaying = true;
      if (this.timelinePlayIcon) {
        this.timelinePlayIcon.innerHTML = '<rect x="6" y="4" width="4" height="16"></rect><rect x="14" y="4" width="4" height="16"></rect>';
      }
      if (this.timelinePlayText) {
        this.timelinePlayText.textContent = 'Pause Replay';
      }

      if (this.historyIndex === -1 || this.historyIndex >= this.historySnapshots.length - 1) {
        this.historyIndex = 0;
      }
      this.scrubToHistory(this.historyIndex);

      this.timelinePlayInterval = setInterval(() => {
        if (!this.isTimelinePlaying) return;
        const next = this.historyIndex + 1;
        if (next >= this.historySnapshots.length) {
          // Loop back to start or snap live
          this.historyIndex = 0;
          this.scrubToHistory(0);
        } else {
          this.scrubToHistory(next);
        }
      }, 1500);
    }
  }

  renderHistorySnapshot(idx) {
    const snap = this.historySnapshots[idx];
    if (!snap) return;

    this.currentTopology = snap.topology;
    this.currentKMeansResult = snap.kmeansResult;
    this.rawSockets = snap.sockets;

    const { nodes, connections } = snap.topology;
    const result = snap.kmeansResult;

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
    this.checkThresholdAlerts(snap.topology);

    if (this.inspectorDrawer?.classList.contains('open')) {
      this.renderSocketInspector();
    }
  }

  addToHistory() {
    if (!this.currentKMeansResult) return;
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    this.runHistory.unshift({
      time: timeStr,
      ips: this.currentTopology.nodes.length,
      sockets: this.currentTopology.connections.length,
      k: this.currentKMeansResult.k
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
            <span style="color:#34d399;font-size:0.65rem;margin-left:4px;">● LIVE</span>
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

function initNetworkMonitorApp() {
  if (window._networkAppInitialized) return;
  window._networkAppInitialized = true;
  window._appInstance = new NetworkClusterApp();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initNetworkMonitorApp);
} else {
  initNetworkMonitorApp();
}
