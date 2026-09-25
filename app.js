import { KMeans } from './kmeans.js?v=20260925_rel';
import { NetworkClusterChart } from './chart.js?v=20260925_rel';

// Comprehensive well-known destination port catalog and service definitions
// Comprehensive well-known destination port catalog and service definitions (ordered ascending by port number)
const WELL_KNOWN_PORTS = [
  { port: 20, service: 'FTP-Data', proto: 'TCP', color: '#ca8a04', category: 'file' },
  { port: 21, service: 'FTP', proto: 'TCP', color: '#eab308', category: 'file' },
  { port: 22, service: 'SSH', proto: 'TCP', color: '#f59e0b', category: 'admin' },
  { port: 23, service: 'Telnet', proto: 'TCP', color: '#ef4444', category: 'admin' },
  { port: 25, service: 'SMTP', proto: 'TCP', color: '#f97316', category: 'mail' },
  { port: 53, service: 'DNS', proto: 'UDP', color: '#3b82f6', category: 'infra' },
  { port: 67, service: 'DHCP-Server', proto: 'UDP', color: '#6366f1', category: 'infra' },
  { port: 68, service: 'DHCP-Client', proto: 'UDP', color: '#6366f1', category: 'infra' },
  { port: 69, service: 'TFTP', proto: 'UDP', color: '#818cf8', category: 'infra' },
  { port: 80, service: 'HTTP', proto: 'TCP', color: '#06b6d4', category: 'web' },
  { port: 88, service: 'Kerberos', proto: 'TCP', color: '#475569', category: 'auth' },
  { port: 110, service: 'POP3', proto: 'TCP', color: '#fb923c', category: 'mail' },
  { port: 123, service: 'NTP', proto: 'UDP', color: '#8b5cf6', category: 'infra' },
  { port: 137, service: 'NetBIOS-NS', proto: 'UDP', color: '#fbbf24', category: 'infra' },
  { port: 138, service: 'NetBIOS-DGM', proto: 'UDP', color: '#f59e0b', category: 'infra' },
  { port: 139, service: 'NetBIOS-SSN', proto: 'TCP', color: '#d97706', category: 'infra' },
  { port: 143, service: 'IMAP', proto: 'TCP', color: '#38bdf8', category: 'mail' },
  { port: 161, service: 'SNMP', proto: 'UDP', color: '#a855f7', category: 'infra' },
  { port: 162, service: 'SNMP-Trap', proto: 'UDP', color: '#9333ea', category: 'infra' },
  { port: 389, service: 'LDAP', proto: 'TCP', color: '#64748b', category: 'directory' },
  { port: 443, service: 'HTTPS', proto: 'TCP', color: '#10b981', category: 'web' },
  { port: 445, service: 'SMB', proto: 'TCP', color: '#f59e0b', category: 'file' },
  { port: 465, service: 'SMTPS', proto: 'TCP', color: '#c2410c', category: 'mail' },
  { port: 587, service: 'SMTP-Sub', proto: 'TCP', color: '#ea580c', category: 'mail' },
  { port: 636, service: 'LDAPS', proto: 'TCP', color: '#475569', category: 'directory' },
  { port: 993, service: 'IMAPS', proto: 'TCP', color: '#0284c7', category: 'mail' },
  { port: 995, service: 'POP3S', proto: 'TCP', color: '#f97316', category: 'mail' },
  { port: 1433, service: 'MSSQL', proto: 'TCP', color: '#0284c7', category: 'db' },
  { port: 1434, service: 'MSSQL-Browser', proto: 'UDP', color: '#0284c7', category: 'db' },
  { port: 1521, service: 'Oracle-DB', proto: 'TCP', color: '#dc2626', category: 'db' },
  { port: 1883, service: 'MQTT', proto: 'TCP', color: '#14b8a6', category: 'iot' },
  { port: 2375, service: 'Docker', proto: 'TCP', color: '#0284c7', category: 'devops' },
  { port: 2376, service: 'Docker-TLS', proto: 'TCP', color: '#0369a1', category: 'devops' },
  { port: 2379, service: 'etcd-Client', proto: 'TCP', color: '#2563eb', category: 'k8s' },
  { port: 2380, service: 'etcd-Peer', proto: 'TCP', color: '#1d4ed8', category: 'k8s' },
  { port: 3000, service: 'Dev-Web', proto: 'TCP', color: '#22d3ee', category: 'dev' },
  { port: 3001, service: 'Grafana', proto: 'TCP', color: '#f97316', category: 'monitor' },
  { port: 3306, service: 'MySQL', proto: 'TCP', color: '#a855f7', category: 'db' },
  { port: 3389, service: 'RDP', proto: 'TCP', color: '#3b82f6', category: 'admin' },
  { port: 4222, service: 'NATS', proto: 'TCP', color: '#06b6d4', category: 'queue' },
  { port: 5000, service: 'Flask/API', proto: 'TCP', color: '#f59e0b', category: 'dev' },
  { port: 5173, service: 'Vite-Dev', proto: 'TCP', color: '#a78bfa', category: 'dev' },
  { port: 5228, service: 'GCM-Push', proto: 'TCP', color: '#f97316', category: 'cloud' },
  { port: 5432, service: 'PostgreSQL', proto: 'TCP', color: '#ec4899', category: 'db' },
  { port: 5672, service: 'RabbitMQ', proto: 'TCP', color: '#ff6600', category: 'queue' },
  { port: 5900, service: 'VNC', proto: 'TCP', color: '#8b5cf6', category: 'admin' },
  { port: 6379, service: 'Redis', proto: 'TCP', color: '#f43f5e', category: 'cache' },
  { port: 6443, service: 'K8s-API', proto: 'TCP', color: '#326ce5', category: 'k8s' },
  { port: 8000, service: 'Web-Dev', proto: 'TCP', color: '#38bdf8', category: 'web' },
  { port: 8080, service: 'HTTP-Alt', proto: 'TCP', color: '#14b8a6', category: 'web' },
  { port: 8443, service: 'HTTPS-Alt', proto: 'TCP', color: '#059669', category: 'web' },
  { port: 8883, service: 'MQTTS', proto: 'TCP', color: '#0d9488', category: 'iot' },
  { port: 9042, service: 'Cassandra', proto: 'TCP', color: '#06b6d4', category: 'db' },
  { port: 9090, service: 'Prometheus', proto: 'TCP', color: '#e11d48', category: 'monitor' },
  { port: 9092, service: 'Kafka', proto: 'TCP', color: '#7c3aed', category: 'streaming' },
  { port: 9100, service: 'NodeExporter', proto: 'TCP', color: '#be123c', category: 'monitor' },
  { port: 9200, service: 'Elasticsearch', proto: 'TCP', color: '#eab308', category: 'search' },
  { port: 9300, service: 'ES-Cluster', proto: 'TCP', color: '#ca8a04', category: 'search' },
  { port: 10250, service: 'Kubelet', proto: 'TCP', color: '#3b82f6', category: 'k8s' },
  { port: 11211, service: 'Memcached', proto: 'TCP', color: '#0ea5e9', category: 'cache' },
  { port: 15672, service: 'RabbitMQ-Mgmt', proto: 'TCP', color: '#ea580c', category: 'queue' },
  { port: 27017, service: 'MongoDB', proto: 'TCP', color: '#10b981', category: 'db' },
];

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

    // Network Relationships & Correlation Controls
    this.btnOpenRelationships = document.getElementById('btnOpenRelationships');
    this.btnSidebarRelationships = document.getElementById('btnSidebarRelationships');
    this.headerRelCount = document.getElementById('headerRelCount');
    this.relDrawer = document.getElementById('relDrawer');
    this.relDrawerBackdrop = document.getElementById('relDrawerBackdrop');
    this.btnCloseRelDrawer = document.getElementById('btnCloseRelDrawer');
    this.canvasFocusBanner = document.getElementById('canvasFocusBanner');
    this.canvasFocusTitle = document.getElementById('canvasFocusTitle');
    this.canvasFocusDetails = document.getElementById('canvasFocusDetails');
    this.btnClearCanvasFocus = document.getElementById('btnClearCanvasFocus');
    this.relKpiMeshVal = document.getElementById('relKpiMeshVal');
    this.relKpiDomainsVal = document.getElementById('relKpiDomainsVal');
    this.relKpiProtosVal = document.getElementById('relKpiProtosVal');
    this.relKpiTopVal = document.getElementById('relKpiTopVal');
    this.countTabMesh = document.getElementById('countTabMesh');
    this.countTabDomains = document.getElementById('countTabDomains');
    this.countTabProtocols = document.getElementById('countTabProtocols');
    this.tabRelMesh = document.getElementById('tabRelMesh');
    this.tabRelDomains = document.getElementById('tabRelDomains');
    this.tabRelProtocols = document.getElementById('tabRelProtocols');
    this.relSearchInput = document.getElementById('relSearchInput');
    this.relContentScroll = document.getElementById('relContentScroll');

    this.relationshipsData = null;
    this.currentRelTab = 'mesh';
    this.relSearchQuery = '';

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
    this.timelineDbPill = document.getElementById('timelineDbPill');
    this.timelineDbText = document.getElementById('timelineDbText');
    this.timelineRangeChips = document.getElementById('timelineRangeChips');

    // Sidebar SQLite Database Elements
    this.sidebarSqliteCount = document.getElementById('sidebarSqliteCount');
    this.sidebarSqliteSize = document.getElementById('sidebarSqliteSize');

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
    this.resolveDns = this.toggleDnsLookup ? this.toggleDnsLookup.checked : true;
    this.resolveGeoip = this.toggleGeoip ? this.toggleGeoip.checked : true;
    this.alertLatencyMs = parseInt(this.sliderLatencyAlert?.value || '50', 10);
    this.alertThroughputMbps = parseInt(this.sliderBandwidthAlert?.value || '10', 10);
    this.activeAlerts = [];
    this.rawSockets = [];
    this.inspectorFilter = { type: 'all', value: null, search: '' };

    // History Timeline State (SQLite 48-Hour Rolling Storage)
    this.sqliteSnapshots = [];
    this.snapshotCache = new Map();
    this.selectedRangeSeconds = 172800; // 48 hours rolling window max
    this.dbStats = null;
    this.statsPollInterval = null;
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

    // Reflect Canvas relationship focus in floating HUD banner
    this.chart.onFocusChange = (focus) => {
      if (focus) {
        if (this.canvasFocusBanner) this.canvasFocusBanner.style.display = 'block';
        if (this.canvasFocusTitle) this.canvasFocusTitle.textContent = focus.title || 'Relationship Focus';
        if (this.canvasFocusDetails) this.canvasFocusDetails.textContent = focus.details || '';
      } else {
        if (this.canvasFocusBanner) this.canvasFocusBanner.style.display = 'none';
      }
    };

    // Populate Ports
    this.populatePortDropdown();

    // Event listeners
    this.attachEventListeners();

    // Start SQLite 48-Hour Rolling History sync
    this.fetchDatabaseStats();
    this.fetchHistorySnapshots(this.selectedRangeSeconds);
    this.statsPollInterval = setInterval(() => {
      this.fetchDatabaseStats();
      if (this.historyIndex === -1) {
        this.fetchHistorySnapshots(this.selectedRangeSeconds, false);
      }
    }, 6000);

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

    // Sort all ports in strictly ascending numerical order (e.g. 20, 21, 22 ... 1433 ... 27017)
    const sortedPorts = Array.from(portMap.values()).sort((a, b) => a.port - b.port);

    sortedPorts.forEach(p => {
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

    // Relationships & Correlation Explorer triggers
    if (this.btnOpenRelationships) {
      this.btnOpenRelationships.addEventListener('click', () => this.openRelationshipsDrawer());
    }
    this.btnSidebarRelationships?.addEventListener('click', () => this.openRelationshipsDrawer());
    this.btnCloseRelDrawer?.addEventListener('click', () => this.closeRelationshipsDrawer());
    this.relDrawerBackdrop?.addEventListener('click', () => this.closeRelationshipsDrawer());

    // Floating Canvas Focus clear button
    this.btnClearCanvasFocus?.addEventListener('click', () => {
      this.chart.clearFocusRelationship();
    });

    // Relationship Explorer Tabs
    const relTabs = [
      { btn: this.tabRelMesh, tab: 'mesh' },
      { btn: this.tabRelDomains, tab: 'domains' },
      { btn: this.tabRelProtocols, tab: 'protocols' }
    ];
    relTabs.forEach(({ btn, tab }) => {
      if (btn) {
        btn.addEventListener('click', () => {
          relTabs.forEach(t => t.btn?.classList.remove('active'));
          btn.classList.add('active');
          this.currentRelTab = tab;
          this.renderRelationships();
        });
      }
    });

    if (this.relSearchInput) {
      this.relSearchInput.addEventListener('input', (e) => {
        this.relSearchQuery = e.target.value.toLowerCase().trim();
        this.renderRelationships();
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

    // Timeline Range Filter Chips (10m, 1h, 6h, 24h, 48h)
    if (this.timelineRangeChips) {
      this.timelineRangeChips.addEventListener('click', (e) => {
        const btn = e.target.closest('.range-chip');
        if (!btn) return;
        this.timelineRangeChips.querySelectorAll('.range-chip').forEach(c => c.classList.remove('active'));
        btn.classList.add('active');
        const range = parseInt(btn.dataset.range, 10);
        this.selectedRangeSeconds = range;
        this.fetchHistorySnapshots(range);
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
      if (realData.relationships) {
        this.updateRelationshipsData(realData.relationships);
      } else if (this.relDrawer?.classList.contains('open')) {
        this.renderRelationships();
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

    if (meta.pcap) {
      const pcap = meta.pcap;
      const tag = document.getElementById('pcapStatusTag');
      const pktEl = document.getElementById('pcapPacketCount');
      const interEl = document.getElementById('pcapInterDeviceCount');
      const helpNotice = document.getElementById('pcapHelpNotice');
      const helpCmd = document.getElementById('pcapHelpCommand');

      if (pktEl) pktEl.textContent = (pcap.packetsCaptured || 0).toLocaleString();
      if (interEl) interEl.textContent = (pcap.interDevicePackets || 0).toLocaleString();

      if (tag) {
        if (pcap.status === 'active') {
          tag.textContent = pcap.promiscuous ? 'PROMISC ACTIVE' : 'ACTIVE';
          tag.style.background = 'rgba(16, 185, 129, 0.15)';
          tag.style.color = '#34d399';
          tag.style.borderColor = 'rgba(16, 185, 129, 0.35)';
          if (helpNotice) helpNotice.style.display = 'none';
        } else if (pcap.status === 'permission_denied') {
          tag.textContent = 'PERMISSION REQUIRED';
          tag.style.background = 'rgba(245, 158, 11, 0.15)';
          tag.style.color = '#fbbf24';
          tag.style.borderColor = 'rgba(245, 158, 11, 0.35)';
          if (helpNotice) {
            helpNotice.style.display = 'block';
            if (helpCmd && pcap.permissionHelp) helpCmd.textContent = pcap.permissionHelp;
          }
        } else {
          tag.textContent = pcap.status ? pcap.status.toUpperCase() : 'OFFLINE';
          tag.style.background = 'rgba(148, 163, 184, 0.15)';
          tag.style.color = '#94a3b8';
          tag.style.borderColor = 'rgba(148, 163, 184, 0.25)';
          if (helpNotice) helpNotice.style.display = 'none';
        }
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
    } else if (filterType === 'pair' && filterValue) {
      this.inspectorTitle.textContent = `Internal Peer Pair: ${filterValue.hostA} ↔ ${filterValue.hostB}`;
      this.inspectorSubtitle.textContent = `Kernel sockets and lateral flows exchanged directly between ${filterValue.hostA} and ${filterValue.hostB}`;
      if (this.btnFilterChartToSelection) this.btnFilterChartToSelection.style.display = 'none';
    } else if (filterType === 'domain' && filterValue) {
      const gKey = filterValue.groupKey || filterValue;
      this.inspectorTitle.textContent = `Shared Target: ${gKey}`;
      this.inspectorSubtitle.textContent = `Kernel sockets connected to external target ${gKey} (${filterValue.org || filterValue.country || 'Public'})`;
      if (this.btnFilterChartToSelection) this.btnFilterChartToSelection.style.display = 'none';
    } else if (filterType === 'proto' && filterValue) {
      const sName = filterValue.service || 'Protocol';
      const sPort = filterValue.port || '';
      this.inspectorTitle.textContent = `Protocol: ${sName} (:${sPort} • ${filterValue.proto || 'TCP'})`;
      this.inspectorSubtitle.textContent = `Sockets grouped under protocol service ${sName} on port :${sPort}`;
      if (this.btnFilterChartToSelection && sPort) {
        this.btnFilterChartToSelection.style.display = 'inline-flex';
        this.btnFilterChartToSelection.textContent = `Filter Canvas to :${sPort}`;
      }
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
    } else if (this.inspectorFilter.type === 'pair' && this.inspectorFilter.value) {
      const { hostA, hostB } = this.inspectorFilter.value;
      sockets = sockets.filter(s =>
        (s.localIP === hostA && s.peerIP === hostB) ||
        (s.localIP === hostB && s.peerIP === hostA) ||
        ((s.localIP === hostA || s.localIP === hostB) && (s.peerIP === hostA || s.peerIP === hostB))
      );
    } else if (this.inspectorFilter.type === 'domain' && this.inspectorFilter.value) {
      const val = this.inspectorFilter.value;
      const destIps = new Set(val.destinationIPs || [val]);
      const groupKey = (val.groupKey || String(val)).toLowerCase();
      sockets = sockets.filter(s => {
        if (destIps.has(s.peerIP) || destIps.has(s.localIP)) return true;
        if (s.dnsName && s.dnsName.toLowerCase().includes(groupKey)) return true;
        if (s.geo?.org && s.geo.org.toLowerCase().includes(groupKey)) return true;
        return false;
      });
    } else if (this.inspectorFilter.type === 'proto' && this.inspectorFilter.value) {
      const val = this.inspectorFilter.value;
      const port = typeof val === 'object' ? val.port : parseInt(val, 10);
      const service = typeof val === 'object' ? (val.service || '').toLowerCase() : '';
      sockets = sockets.filter(s => {
        if (port && (s.peerPort === port || s.localPort === port)) return true;
        if (service && s.service && s.service.toLowerCase() === service) return true;
        return false;
      });
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
  // Network Relationships & Correlation Explorer
  // ==========================================================================
  async openRelationshipsDrawer() {
    if (this.relDrawer) this.relDrawer.classList.add('open');
    if (this.relDrawerBackdrop) this.relDrawerBackdrop.classList.add('open');

    if (!this.relationshipsData) {
      try {
        const res = await fetch('/api/relationships');
        if (res.ok) {
          const data = await res.json();
          this.updateRelationshipsData(data);
        }
      } catch (err) {
        console.warn('Failed to fetch relationships API:', err);
      }
    }
    this.renderRelationships();
  }

  closeRelationshipsDrawer() {
    if (this.relDrawer) this.relDrawer.classList.remove('open');
    if (this.relDrawerBackdrop) this.relDrawerBackdrop.classList.remove('open');
  }

  updateRelationshipsData(relData) {
    if (!relData) return;
    this.relationshipsData = relData;

    const meshCount = relData.internalMesh?.length || 0;
    const domainCount = relData.sharedDestinations?.length || 0;
    const protoCount = relData.commonProtocols?.length || 0;
    const totalRel = meshCount + domainCount;

    if (this.headerRelCount) {
      this.headerRelCount.textContent = totalRel;
    }

    if (this.relKpiMeshVal) this.relKpiMeshVal.textContent = meshCount;
    if (this.relKpiDomainsVal) this.relKpiDomainsVal.textContent = domainCount;
    if (this.relKpiProtosVal) this.relKpiProtosVal.textContent = protoCount;
    if (this.relKpiTopVal) {
      this.relKpiTopVal.textContent = relData.summary?.topInternalPair || (meshCount > 0 ? `${relData.internalMesh[0].hostA} ↔ ${relData.internalMesh[0].hostB}` : '--');
    }

    if (this.countTabMesh) this.countTabMesh.textContent = meshCount;
    if (this.countTabDomains) this.countTabDomains.textContent = domainCount;
    if (this.countTabProtocols) this.countTabProtocols.textContent = protoCount;

    if (this.relDrawer?.classList.contains('open')) {
      this.renderRelationships();
    }
  }

  renderRelationships() {
    if (!this.relContentScroll) return;
    const data = this.relationshipsData;
    if (!data) {
      this.relContentScroll.innerHTML = `
        <div class="rel-empty-msg">
          <p>Analyzing live packet and socket telemetry for relational patterns...</p>
        </div>
      `;
      return;
    }

    const tab = this.currentRelTab || 'mesh';
    const q = (this.relSearchQuery || '').toLowerCase();
    let cardsHtml = '';

    if (tab === 'mesh') {
      const items = (data.internalMesh || []).filter(item => {
        if (!q) return true;
        const text = `${item.hostA} ${item.hostB} ${item.hostAName || ''} ${item.hostBName || ''} ${(item.services || []).join(' ')} ${(item.protocols || []).join(' ')} ${(item.ports || []).join(' ')} ${(item.processes || []).join(' ')}`.toLowerCase();
        return text.includes(q);
      });

      if (items.length === 0) {
        cardsHtml = `<div class="rel-empty-msg">No internal host mesh pairs matching current filters.</div>`;
      } else {
        cardsHtml = items.map((item, idx) => {
          const portsStr = (item.ports || []).map(p => `<span class="rel-chip">:${p}</span>`).join('');
          const servicesStr = (item.services || []).map(s => `<span class="rel-chip" style="color:#38bdf8;border-color:rgba(56,189,248,0.25);">${s}</span>`).join('');
          const protosStr = (item.protocols || []).map(pr => `<span class="rel-chip" style="color:#34d399;">${pr}</span>`).join('');
          const procsStr = (item.processes || []).map(proc => `<span class="rel-chip" style="color:#a78bfa;">⚙ ${proc}</span>`).join('');
          const latencyStr = item.avgLatencyMs !== null && item.avgLatencyMs !== undefined ? `${item.avgLatencyMs} ms` : '< 1 ms';

          return `
            <div class="rel-card" data-id="${item.id}">
              <div class="rel-card-header">
                <div class="rel-card-title">
                  <span style="color:var(--accent-cyan);">🔗</span>
                  <span>${item.hostAName || item.hostA}</span>
                  <span style="color:var(--text-muted);font-weight:400;margin:0 2px;">↔</span>
                  <span>${item.hostBName || item.hostB}</span>
                </div>
                <div class="rel-card-actions">
                  <button class="rel-btn-focus" data-action="focus-mesh" data-index="${idx}">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/></svg>
                    Focus Canvas
                  </button>
                  <button class="rel-btn-inspect" data-action="inspect-mesh" data-index="${idx}">
                    Inspect Sockets
                  </button>
                </div>
              </div>
              <div class="rel-card-meta">
                <span>Active Sockets: <strong>${item.connectionCount}</strong></span>
                <span>Throughput: <strong>${(item.totalThroughputKbps || 0).toFixed(1)}</strong> KB/s</span>
                <span>Latency: <strong>${latencyStr}</strong></span>
              </div>
              <div class="rel-card-pills">
                ${servicesStr}
                ${portsStr}
                ${protosStr}
                ${procsStr}
              </div>
            </div>
          `;
        }).join('');
      }

    } else if (tab === 'domains') {
      const items = (data.sharedDestinations || []).filter(item => {
        if (!q) return true;
        const text = `${item.groupKey} ${item.primaryHost || ''} ${item.org || ''} ${item.country || ''} ${(item.clientIPs || []).join(' ')} ${(item.destinationIPs || []).join(' ')} ${(item.services || []).join(' ')} ${(item.ports || []).join(' ')}`.toLowerCase();
        return text.includes(q);
      });

      if (items.length === 0) {
        cardsHtml = `<div class="rel-empty-msg">No shared external destinations matching current filters.</div>`;
      } else {
        cardsHtml = items.map((item, idx) => {
          const clientPills = (item.clientIPs || []).map(c => `<span class="rel-chip" style="color:#67e8f9;border-color:rgba(103,232,249,0.25);">Client: ${c}</span>`).join('');
          const destPills = (item.destinationIPs || []).map(d => `<span class="rel-chip" style="color:#94a3b8;">IP: ${d}</span>`).join('');
          const servicesStr = (item.services || []).map(s => `<span class="rel-chip" style="color:#38bdf8;">${s}</span>`).join('');
          const portsStr = (item.ports || []).map(p => `<span class="rel-chip">:${p}</span>`).join('');

          return `
            <div class="rel-card" data-id="${item.id}">
              <div class="rel-card-header">
                <div class="rel-card-title">
                  <span>${item.flag || '🌐'}</span>
                  <span>${item.groupKey}</span>
                  ${item.org && item.org !== 'Public Host' ? `<span style="font-size:0.72rem;color:var(--text-muted);font-weight:400;">(${item.org})</span>` : ''}
                </div>
                <div class="rel-card-actions">
                  <button class="rel-btn-focus" data-action="focus-domain" data-index="${idx}">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/></svg>
                    Focus Canvas
                  </button>
                  <button class="rel-btn-inspect" data-action="inspect-domain" data-index="${idx}">
                    Inspect Sockets
                  </button>
                </div>
              </div>
              <div class="rel-card-meta">
                <span>Shared by <strong>${item.clientCount}</strong> client(s)</span>
                <span>Active Sockets: <strong>${item.connectionCount}</strong></span>
                <span>Throughput: <strong>${(item.totalThroughputKbps || 0).toFixed(1)}</strong> KB/s</span>
                ${item.avgLatencyMs !== null && item.avgLatencyMs !== undefined ? `<span>RTT: <strong>${item.avgLatencyMs} ms</strong></span>` : ''}
              </div>
              <div class="rel-card-pills">
                ${clientPills}
                ${destPills}
                ${servicesStr}
                ${portsStr}
              </div>
            </div>
          `;
        }).join('');
      }

    } else if (tab === 'protocols') {
      const items = (data.commonProtocols || []).filter(item => {
        if (!q) return true;
        const text = `${item.service} ${item.port} ${item.proto} ${item.category || ''} ${(item.clients || []).join(' ')} ${(item.destinations || []).join(' ')}`.toLowerCase();
        return text.includes(q);
      });

      if (items.length === 0) {
        cardsHtml = `<div class="rel-empty-msg">No protocol clusters matching current filters.</div>`;
      } else {
        cardsHtml = items.map((item, idx) => {
          const clientPills = (item.clients || []).slice(0, 4).map(c => `<span class="rel-chip" style="color:#67e8f9;">Client: ${c}</span>`).join('');
          const moreClients = (item.clients || []).length > 4 ? `<span class="rel-chip">+${item.clients.length - 4} clients</span>` : '';
          const destPills = (item.destinations || []).slice(0, 4).map(d => `<span class="rel-chip" style="color:#a5b4fc;">Server: ${d}</span>`).join('');
          const moreDests = (item.destinations || []).length > 4 ? `<span class="rel-chip">+${item.destinations.length - 4} servers</span>` : '';

          return `
            <div class="rel-card" data-id="${item.id}">
              <div class="rel-card-header">
                <div class="rel-card-title">
                  <span style="color:${item.color || '#38bdf8'};">⚡</span>
                  <span>${item.service}</span>
                  <span style="font-size:0.75rem;color:var(--text-muted);font-weight:400;">(:${item.port} • ${item.proto})</span>
                </div>
                <div class="rel-card-actions">
                  <button class="rel-btn-focus" data-action="focus-proto" data-index="${idx}">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/></svg>
                    Focus Canvas
                  </button>
                  <button class="rel-btn-inspect" data-action="inspect-proto" data-index="${idx}">
                    Inspect Sockets
                  </button>
                </div>
              </div>
              <div class="rel-card-meta">
                <span>Clients: <strong>${item.clientCount}</strong></span>
                <span>Destinations: <strong>${item.destinationCount}</strong></span>
                <span>Active Sockets: <strong>${item.connectionCount}</strong></span>
                <span>Throughput: <strong>${(item.totalThroughputKbps || 0).toFixed(1)}</strong> KB/s</span>
              </div>
              <div class="rel-card-pills">
                ${clientPills}
                ${moreClients}
                ${destPills}
                ${moreDests}
              </div>
            </div>
          `;
        }).join('');
      }
    }

    this.relContentScroll.innerHTML = cardsHtml;

    // Attach click listeners to Focus and Inspect buttons
    this.relContentScroll.querySelectorAll('button[data-action]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const action = btn.dataset.action;
        const idx = parseInt(btn.dataset.index, 10);

        if (action === 'focus-mesh') {
          const item = (this.relationshipsData?.internalMesh || [])[idx];
          if (!item) return;
          const nodeKeys = new Set([item.hostA, item.hostB]);
          this.chart.setFocusRelationship({
            type: 'mesh',
            title: `Internal Mesh: ${item.hostAName || item.hostA} ↔ ${item.hostBName || item.hostB}`,
            details: `Direct lateral flow • ${item.connectionCount} active sockets • Ports: ${(item.ports || []).map(p => ':' + p).join(', ') || 'Various'}`,
            nodeKeys: nodeKeys,
            matchConn: (conn, animConn) => {
              return (animConn.srcKey === item.hostA && animConn.destKey === item.hostB) ||
                     (animConn.srcKey === item.hostB && animConn.destKey === item.hostA);
            }
          });
          this.closeRelationshipsDrawer();
          this.showToast('Relationship Focus Active', `Spotlight on ${item.hostAName || item.hostA} ↔ ${item.hostBName || item.hostB}. Press Esc to clear.`, 'info');
        } else if (action === 'inspect-mesh') {
          const item = (this.relationshipsData?.internalMesh || [])[idx];
          if (!item) return;
          this.closeRelationshipsDrawer();
          this.openSocketInspector('pair', { hostA: item.hostA, hostB: item.hostB });
        } else if (action === 'focus-domain') {
          const item = (this.relationshipsData?.sharedDestinations || [])[idx];
          if (!item) return;
          const clientSet = new Set(item.clientIPs || []);
          const destSet = new Set(item.destinationIPs || []);
          const nodeKeys = new Set([...clientSet, ...destSet]);
          this.chart.setFocusRelationship({
            type: 'domain',
            title: `Shared Target: ${item.groupKey} (${item.org || item.country || 'External'})`,
            details: `Accessed by ${item.clientCount} internal host(s) • ${item.connectionCount} sockets • ${(item.totalThroughputKbps || 0).toFixed(1)} KB/s`,
            nodeKeys: nodeKeys,
            matchConn: (conn, animConn) => {
              return (clientSet.has(animConn.srcKey) && destSet.has(animConn.destKey)) ||
                     (destSet.has(animConn.srcKey) && clientSet.has(animConn.destKey));
            }
          });
          this.closeRelationshipsDrawer();
          this.showToast('Relationship Focus Active', `Spotlight on shared domain ${item.groupKey}. Press Esc to clear.`, 'info');
        } else if (action === 'inspect-domain') {
          const item = (this.relationshipsData?.sharedDestinations || [])[idx];
          if (!item) return;
          this.closeRelationshipsDrawer();
          this.openSocketInspector('domain', item);
        } else if (action === 'focus-proto') {
          const item = (this.relationshipsData?.commonProtocols || [])[idx];
          if (!item) return;
          const nodeKeys = new Set([...(item.clients || []), ...(item.destinations || [])]);
          this.chart.setFocusRelationship({
            type: 'proto',
            title: `Protocol Affinity: ${item.service} (Port :${item.port})`,
            details: `${item.clientCount} clients • ${item.destinationCount} servers • ${item.connectionCount} active sockets`,
            nodeKeys: nodeKeys,
            matchConn: (conn, animConn) => {
              return conn.destPort === item.port || (conn.service && conn.service.toLowerCase() === item.service.toLowerCase());
            }
          });
          this.closeRelationshipsDrawer();
          this.showToast('Relationship Focus Active', `Spotlight on protocol ${item.service} (:${item.port}). Press Esc to clear.`, 'info');
        } else if (action === 'inspect-proto') {
          const item = (this.relationshipsData?.commonProtocols || [])[idx];
          if (!item) return;
          this.closeRelationshipsDrawer();
          this.openSocketInspector('proto', item);
        }
      });
    });
  }

  // ==========================================================================
  // Historical Topology Timeline & Playback (SQLite 48-Hour Rolling Retention)
  // ==========================================================================
  recordSnapshot(topology, kmeansResult) {
    if (!topology) return;

    // Trigger asynchronous DB stats & snapshot synchronization periodically
    const now = Date.now();
    if (now - this.lastSnapshotRecordTime > 5000) {
      this.lastSnapshotRecordTime = now;
      this.fetchDatabaseStats();
      if (this.historyIndex === -1) {
        this.fetchHistorySnapshots(this.selectedRangeSeconds, false);
      }
    }
  }

  async fetchDatabaseStats() {
    try {
      const res = await fetch('/api/history/stats');
      if (!res.ok) return;
      const data = await res.json();
      if (data && data.stats) {
        this.dbStats = data.stats;
        this.updateDatabaseUI(data.stats);
      }
    } catch (err) {
      console.warn('Failed to fetch SQLite DB stats:', err);
    }
  }

  updateDatabaseUI(stats) {
    if (this.sidebarSqliteCount) {
      const count = stats.totalSnapshots || 0;
      this.sidebarSqliteCount.textContent = `${count} snapshot${count === 1 ? '' : 's'}`;
    }
    if (this.sidebarSqliteSize) {
      this.sidebarSqliteSize.textContent = `${stats.dbSizeMb} MB`;
    }
    if (this.timelineDbText) {
      const count = stats.totalSnapshots || 0;
      this.timelineDbText.textContent = `SQLite 48h: ${count} snap${count === 1 ? '' : 's'} (${stats.dbSizeMb} MB)`;
    }
    if (this.timelineCountText && this.historyIndex === -1) {
      const count = this.sqliteSnapshots.length || stats.totalSnapshots || 0;
      this.timelineCountText.textContent = `${count} in 48h DB`;
    }
  }

  async fetchHistorySnapshots(rangeSeconds = this.selectedRangeSeconds, resetSlider = true) {
    try {
      const url = `/api/history/snapshots?since=${rangeSeconds}&limit=500&summary=true`;
      const res = await fetch(url);
      if (!res.ok) return;
      const data = await res.json();
      if (data && Array.isArray(data.snapshots)) {
        this.sqliteSnapshots = data.snapshots;
        if (data.stats) {
          this.dbStats = data.stats;
          this.updateDatabaseUI(data.stats);
        }

        if (this.timelineSlider) {
          const maxIdx = Math.max(0, this.sqliteSnapshots.length - 1);
          this.timelineSlider.max = maxIdx;
          if (this.historyIndex === -1 && resetSlider) {
            this.timelineSlider.value = maxIdx;
          }
        }

        if (this.timelineCountText && this.historyIndex === -1) {
          const count = this.sqliteSnapshots.length;
          this.timelineCountText.textContent = `${count} snapshot${count === 1 ? '' : 's'} in window`;
        }
      }
    } catch (err) {
      console.warn('Failed to fetch history snapshots:', err);
    }
  }

  async fetchSnapshotTopology(snapshotId) {
    if (this.snapshotCache.has(snapshotId)) {
      return this.snapshotCache.get(snapshotId);
    }
    try {
      const res = await fetch(`/api/history/snapshot?id=${snapshotId}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data && data.snapshot) {
        this.snapshotCache.set(snapshotId, data.snapshot);
        // Keep cache bounded to 150 items to manage browser memory
        if (this.snapshotCache.size > 150) {
          const firstKey = this.snapshotCache.keys().next().value;
          this.snapshotCache.delete(firstKey);
        }
        return data.snapshot;
      }
    } catch (err) {
      console.error(`Error loading snapshot ${snapshotId}:`, err);
    }
    return null;
  }

  clusterNodes(nodes) {
    if (!nodes || nodes.length === 0) {
      return { centroids: [], assignments: [], clusterStats: [] };
    }
    const kmeans = new KMeans({
      k: this.k,
      maxIterations: 50,
      tolerance: 1e-4,
    });
    return kmeans.fit(nodes);
  }

  async scrubToHistory(index) {
    if (!this.sqliteSnapshots || this.sqliteSnapshots.length === 0) return;
    if (index < 0 || index >= this.sqliteSnapshots.length) return;

    this.historyIndex = index;
    const metaSnap = this.sqliteSnapshots[index];

    if (this.btnTimelineLive) {
      this.btnTimelineLive.classList.remove('live-active');
    }
    if (this.timelineStatusText) {
      this.timelineStatusText.innerHTML = `<span style="color:#f59e0b;font-weight:700;">⏮ REPLAYING SQLite #${metaSnap.id} [${index + 1}/${this.sqliteSnapshots.length}] ${metaSnap.time_str} • ${metaSnap.total_nodes} nodes, ${metaSnap.total_connections} flows</span>`;
    }
    if (this.timelineSlider) {
      this.timelineSlider.value = index;
    }
    if (this.timelineCountText) {
      this.timelineCountText.textContent = `Snapshot ${index + 1} of ${this.sqliteSnapshots.length}`;
    }

    await this.renderHistoricalSnapshot(metaSnap, index);
  }

  async renderHistoricalSnapshot(metaSnap, targetIndex) {
    const fullSnap = await this.fetchSnapshotTopology(metaSnap.id);
    if (!fullSnap || this.historyIndex !== targetIndex) return;

    const topology = fullSnap.topology || fullSnap;
    if (!topology || !topology.nodes) return;

    this.currentTopology = topology;
    this.rawSockets = topology.sockets || [];

    // Recompute K-Means clustering for this snapshot
    const kmeansResult = this.clusterNodes(topology.nodes);
    this.currentKMeansResult = kmeansResult;

    const { nodes, connections } = topology;

    this.chart.updateData({
      nodes,
      connections,
      centroids: kmeansResult.centroids,
      assignments: kmeansResult.assignments,
      clusterStats: kmeansResult.clusterStats,
    });
    this.chart.render();

    this.updateTelemetryUI(kmeansResult, nodes, connections);
    this.updateGatewayTable(kmeansResult, nodes, connections);
    this.updatePortDistributionUI();
    this.checkThresholdAlerts(topology);

    if (this.inspectorDrawer?.classList.contains('open')) {
      this.renderSocketInspector();
    }
    if (topology.relationships) {
      this.updateRelationshipsData(topology.relationships);
    }
  }

  stepTimeline(delta) {
    if (!this.sqliteSnapshots || this.sqliteSnapshots.length === 0) return;

    if (this.historyIndex === -1) {
      // Currently live, step back into recent history
      if (delta < 0) {
        const target = Math.max(0, this.sqliteSnapshots.length - 2);
        this.scrubToHistory(target);
      }
    } else {
      const nextIdx = this.historyIndex + delta;
      if (nextIdx >= this.sqliteSnapshots.length) {
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
      this.timelineSlider.value = Math.max(0, this.sqliteSnapshots.length - 1);
    }
    if (this.timelineCountText) {
      const count = this.sqliteSnapshots.length;
      this.timelineCountText.textContent = `${count} snapshot${count === 1 ? '' : 's'} in window`;
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
      if (!this.sqliteSnapshots || this.sqliteSnapshots.length < 2) {
        this.showToast('Timeline Playback', 'Wait for at least 2 SQLite snapshots to accumulate.', 'info');
        return;
      }

      this.isTimelinePlaying = true;
      if (this.timelinePlayIcon) {
        this.timelinePlayIcon.innerHTML = '<rect x="6" y="4" width="4" height="16"></rect><rect x="14" y="4" width="4" height="16"></rect>';
      }
      if (this.timelinePlayText) {
        this.timelinePlayText.textContent = 'Pause Replay';
      }

      if (this.historyIndex === -1 || this.historyIndex >= this.sqliteSnapshots.length - 1) {
        this.historyIndex = 0;
      }
      this.scrubToHistory(this.historyIndex);

      this.timelinePlayInterval = setInterval(() => {
        if (!this.isTimelinePlaying) return;
        const next = this.historyIndex + 1;
        if (next >= this.sqliteSnapshots.length) {
          // Loop back to start
          this.historyIndex = 0;
          this.scrubToHistory(0);
        } else {
          this.scrubToHistory(next);
        }
      }, 1500);
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
