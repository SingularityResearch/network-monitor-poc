/**
 * NetworkClusterChart
 * High-performance Canvas renderer displaying IP addresses as nodes,
 * K-Means cluster centroids as Subnet Gateways, and active IP-to-IP socket connections on specific ports.
 *
 * Implements continuous 60 FPS hardware-accelerated animations with frame-rate independent
 * exponential interpolation (lerp), smooth centroid tracking, organic micro-drift,
 * and seamless alpha fading for joining/leaving nodes and sockets.
 */

export class NetworkClusterChart {
  static PALETTE = [
    { main: '#06b6d4', glow: 'rgba(6, 182, 212, 0.45)', soft: 'rgba(6, 182, 212, 0.15)', name: 'Cyan' },
    { main: '#a855f7', glow: 'rgba(168, 85, 247, 0.45)', soft: 'rgba(168, 85, 247, 0.15)', name: 'Purple' },
    { main: '#f59e0b', glow: 'rgba(245, 158, 11, 0.45)', soft: 'rgba(245, 158, 11, 0.15)', name: 'Amber' },
    { main: '#10b981', glow: 'rgba(16, 185, 129, 0.45)', soft: 'rgba(16, 185, 129, 0.15)', name: 'Emerald' },
    { main: '#ec4899', glow: 'rgba(236, 72, 153, 0.45)', soft: 'rgba(236, 72, 153, 0.15)', name: 'Pink' },
    { main: '#3b82f6', glow: 'rgba(59, 130, 246, 0.45)', soft: 'rgba(59, 130, 246, 0.15)', name: 'Blue' },
    { main: '#f43f5e', glow: 'rgba(244, 63, 94, 0.45)', soft: 'rgba(244, 63, 94, 0.15)', name: 'Rose' },
    { main: '#14b8a6', glow: 'rgba(20, 184, 166, 0.45)', soft: 'rgba(20, 184, 166, 0.15)', name: 'Teal' },
  ];

  constructor(canvasElement, tooltipElement) {
    this.canvas = canvasElement;
    this.ctx = canvasElement.getContext('2d');
    this.tooltip = tooltipElement;

    this.options = {
      showConnections: true,
      showPackets: true,
      showGatewayLines: true,
      showHalos: true,
      showVoronoi: false,
      showIpLabels: false,
      resolveDns: true,
      showGeoip: true,
      showAlertOverlays: true,
      organicDrift: true,
      alertLatencyMs: 50,
      alertThroughputMbps: 10,
      filterPort: 'all', // 'all' or port number e.g. 443
      pointRadius: 5.5,
      centroidRadius: 11,
    };

    this.onItemClick = null;
    this.onFpsUpdate = null;

    this.margin = { top: 40, right: 40, bottom: 50, left: 60 };

    // Raw dataset snapshots for inspection queries
    this.nodes = [];
    this.connections = [];
    this.centroids = [];
    this.assignments = [];
    this.clusterStats = [];

    // Animated state representations (continuous smooth lerp)
    this.animatedNodes = new Map(); // key -> AnimatedNode
    this.animatedCentroids = [];    // Array of AnimatedCentroids
    this.animatedConnections = new Map(); // key -> AnimatedConnection

    this.hoveredItem = null;
    this.pulsePhase = 0;
    this.lastFrameTime = performance.now();
    this.fps = 60;
    this.fpsTimer = 0;

    // Interactive Zoom and Pan state
    this.zoom = 1.0;
    this.targetZoom = 1.0;
    this.minZoom = 0.5;
    this.maxZoom = 8.0;

    this.pan = { x: 0, y: 0 };
    this.targetPan = { x: 0, y: 0 };

    this.isDragging = false;
    this.dragStart = { x: 0, y: 0 };
    this.panStart = { x: 0, y: 0 };
    this.hasDragged = false;

    this.onZoomChange = null;

    // Relational focus filter state (focuses on specific host pairs, shared domains, or protocols)
    this.focusFilter = null;
    this.onFocusChange = null;

    this.setupEvents();
    this.resize();

    this.animate = this.animate.bind(this);
    requestAnimationFrame(this.animate);
  }

  setFocusRelationship(focus) {
    this.focusFilter = focus;
    if (this.onFocusChange) {
      this.onFocusChange(this.focusFilter);
    }
  }

  clearFocusRelationship() {
    this.focusFilter = null;
    if (this.onFocusChange) {
      this.onFocusChange(null);
    }
  }


  resize() {
    const rect = this.canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    this.width = rect.width;
    this.height = rect.height;

    this.canvas.width = Math.floor(rect.width * dpr);
    this.canvas.height = Math.floor(rect.height * dpr);

    this.ctx.resetTransform?.();
    this.ctx.scale(dpr, dpr);
  }

  setupEvents() {
    window.addEventListener('resize', () => this.resize());

    // Wheel Zoom anchored at mouse pointer
    this.canvas.addEventListener(
      'wheel',
      (e) => {
        e.preventDefault();
        const rect = this.canvas.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;

        // Exponential zoom stepping: wheel up zooms in, wheel down zooms out
        const factor = e.deltaY < 0 ? 1.15 : 0.87;
        this.zoomAt(mouseX, mouseY, factor);
      },
      { passive: false }
    );

    // Mouse drag-to-pan handling
    this.canvas.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return; // Primary left button only
      this.isDragging = true;
      this.hasDragged = false;
      this.dragStart = { x: e.clientX, y: e.clientY };
      this.panStart = { x: this.targetPan.x, y: this.targetPan.y };
    });

    window.addEventListener('mousemove', (e) => {
      if (!this.isDragging) return;
      const dx = e.clientX - this.dragStart.x;
      const dy = e.clientY - this.dragStart.y;
      if (Math.hypot(dx, dy) > 4) {
        this.hasDragged = true;
        this.canvas.style.cursor = 'grabbing';
        this.targetPan.x = this.panStart.x + dx;
        this.targetPan.y = this.panStart.y + dy;
        this.pan.x = this.targetPan.x;
        this.pan.y = this.targetPan.y;
        this.clearHover();
      }
    });

    window.addEventListener('mouseup', () => {
      if (this.isDragging) {
        this.isDragging = false;
        this.canvas.style.cursor = this.hoveredItem ? 'pointer' : 'grab';
      }
    });

    this.canvas.addEventListener('mousemove', (e) => {
      if (this.isDragging && this.hasDragged) return;
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      this.handleHover(mouseX, mouseY, e.clientX, e.clientY);
      this.canvas.style.cursor = this.hoveredItem ? 'pointer' : 'grab';
    });

    this.canvas.addEventListener('mouseleave', () => {
      if (!this.isDragging) {
        this.clearHover();
      }
    });

    this.canvas.addEventListener('click', (e) => {
      if (this.hasDragged) {
        this.hasDragged = false;
        return;
      }
      if (this.hoveredItem && this.onItemClick) {
        this.onItemClick(this.hoveredItem);
      }
    });

    // Double-click resets zoom or zooms 2x into cursor
    this.canvas.addEventListener('dblclick', (e) => {
      e.preventDefault();
      if (
        Math.abs(this.targetZoom - 1.0) > 0.05 ||
        Math.abs(this.targetPan.x) > 5 ||
        Math.abs(this.targetPan.y) > 5
      ) {
        this.resetZoom();
      } else {
        const rect = this.canvas.getBoundingClientRect();
        this.zoomAt(e.clientX - rect.left, e.clientY - rect.top, 2.0);
      }
    });

    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.focusFilter) {
        this.clearFocusRelationship();
      }
    });
  }


  zoomAt(canvasX, canvasY, factor) {
    const oldZoom = this.targetZoom;
    const newZoom = Math.min(this.maxZoom, Math.max(this.minZoom, oldZoom * factor));
    if (Math.abs(newZoom - oldZoom) < 0.0001) return;

    const plotWidth = this.width - this.margin.left - this.margin.right;
    const plotHeight = this.height - this.margin.top - this.margin.bottom;
    const plotCenterX = this.margin.left + plotWidth / 2;
    const plotCenterY = this.margin.top + plotHeight / 2;

    // Anchor: Keep data coordinate under canvasX, canvasY invariant
    const baseX0 = (canvasX - this.targetPan.x - plotCenterX) / oldZoom + plotCenterX;
    const baseY0 = (canvasY - this.targetPan.y - plotCenterY) / oldZoom + plotCenterY;

    const newPanX = canvasX - plotCenterX - (baseX0 - plotCenterX) * newZoom;
    const newPanY = canvasY - plotCenterY - (baseY0 - plotCenterY) * newZoom;

    this.targetZoom = newZoom;
    this.targetPan.x = newPanX;
    this.targetPan.y = newPanY;

    if (this.onZoomChange) {
      this.onZoomChange(this.targetZoom);
    }
  }

  zoomIn() {
    const plotWidth = this.width - this.margin.left - this.margin.right;
    const plotHeight = this.height - this.margin.top - this.margin.bottom;
    const centerX = this.margin.left + plotWidth / 2;
    const centerY = this.margin.top + plotHeight / 2;
    this.zoomAt(centerX, centerY, 1.3);
  }

  zoomOut() {
    const plotWidth = this.width - this.margin.left - this.margin.right;
    const plotHeight = this.height - this.margin.top - this.margin.bottom;
    const centerX = this.margin.left + plotWidth / 2;
    const centerY = this.margin.top + plotHeight / 2;
    this.zoomAt(centerX, centerY, 1 / 1.3);
  }

  resetZoom() {
    this.targetZoom = 1.0;
    this.targetPan = { x: 0, y: 0 };
    if (this.onZoomChange) {
      this.onZoomChange(this.targetZoom);
    }
  }

  toCanvasCoords(x, y) {
    const plotWidth = this.width - this.margin.left - this.margin.right;
    const plotHeight = this.height - this.margin.top - this.margin.bottom;
    const plotCenterX = this.margin.left + plotWidth / 2;
    const plotCenterY = this.margin.top + plotHeight / 2;

    const baseX = this.margin.left + (x / 100) * plotWidth;
    const baseY = this.margin.top + (1 - y / 100) * plotHeight;

    const px = plotCenterX + (baseX - plotCenterX) * this.zoom + this.pan.x;
    const py = plotCenterY + (baseY - plotCenterY) * this.zoom + this.pan.y;
    return { x: px, y: py };
  }

  toDataCoords(px, py) {
    const plotWidth = this.width - this.margin.left - this.margin.right;
    const plotHeight = this.height - this.margin.top - this.margin.bottom;
    const plotCenterX = this.margin.left + plotWidth / 2;
    const plotCenterY = this.margin.top + plotHeight / 2;

    const baseX = (px - this.pan.x - plotCenterX) / this.zoom + plotCenterX;
    const baseY = (py - this.pan.y - plotCenterY) / this.zoom + plotCenterY;

    const x = ((baseX - this.margin.left) / plotWidth) * 100;
    const y = (1 - (baseY - this.margin.top) / plotHeight) * 100;
    return { x, y };
  }

  /**
   * Compute shortest perpendicular distance from point (px, py) to line segment (x1, y1)-(x2, y2)
   */
  distToSegment(px, py, x1, y1, x2, y2) {
    const dx = x2 - x1;
    const dy = y2 - y1;
    const lenSq = dx * dx + dy * dy;
    if (lenSq === 0) return Math.hypot(px - x1, py - y1);
    let t = ((px - x1) * dx + (py - y1) * dy) / lenSq;
    t = Math.max(0, Math.min(1, t));
    const projX = x1 + t * dx;
    const projY = y1 + t * dy;
    return Math.hypot(px - projX, py - projY);
  }

  /**
   * Seamlessly transition to new topology & clustering state.
   * Instead of clearing or popping, existing nodes and centroids glide to new positions,
   * newly added elements smoothly fade in, and removed elements smoothly fade out.
   */
  updateData({ nodes, connections, centroids, assignments, clusterStats }) {
    this.nodes = nodes || [];
    this.connections = connections || [];
    this.centroids = centroids || [];
    this.assignments = assignments || [];
    this.clusterStats = clusterStats || [];

    const incomingNodes = this.nodes;
    const incomingCentroids = this.centroids;
    const incomingConnections = this.connections;

    // 1. Update Centroids with Euclidean matching to avoid index/color swaps
    const newK = incomingCentroids.length;
    if (this.animatedCentroids.length === 0) {
      // First initialization
      this.animatedCentroids = incomingCentroids.map((c, i) => ({
        index: i,
        currentX: c.x,
        currentY: c.y,
        targetX: c.x,
        targetY: c.y,
        currentRadius: clusterStats[i]?.stdDev || 10,
        targetRadius: clusterStats[i]?.stdDev || 10,
        alpha: 1.0,
        targetAlpha: 1.0,
        stats: clusterStats[i] || {},
      }));
    } else {
      // Align incoming centroids with animated centroids
      const availableIncoming = new Set(incomingCentroids.map((_, i) => i));
      const paired = new Set();

      // Greedy nearest assignment
      this.animatedCentroids.forEach((animC) => {
        let bestDist = Infinity;
        let bestIdx = -1;
        for (const incIdx of availableIncoming) {
          const incC = incomingCentroids[incIdx];
          const d = Math.hypot(animC.targetX - incC.x, animC.targetY - incC.y);
          if (d < bestDist) {
            bestDist = d;
            bestIdx = incIdx;
          }
        }

        if (bestIdx >= 0) {
          availableIncoming.delete(bestIdx);
          paired.add(animC);
          const matched = incomingCentroids[bestIdx];
          animC.targetX = matched.x;
          animC.targetY = matched.y;
          animC.targetRadius = clusterStats[bestIdx]?.stdDev || 10;
          animC.targetAlpha = 1.0;
          animC.stats = clusterStats[bestIdx] || {};
        } else {
          // Centroid count decreased: fade out excess
          animC.targetAlpha = 0.0;
        }
      });

      // If more centroids than before, add new animated centroids
      for (const remainingIdx of availableIncoming) {
        const c = incomingCentroids[remainingIdx];
        this.animatedCentroids.push({
          index: remainingIdx,
          currentX: c.x,
          currentY: c.y,
          targetX: c.x,
          targetY: c.y,
          currentRadius: 0,
          targetRadius: clusterStats[remainingIdx]?.stdDev || 10,
          alpha: 0.0,
          targetAlpha: 1.0,
          stats: clusterStats[remainingIdx] || {},
        });
      }
    }

    const isFirstLoad = !this.isInitialized;
    this.isInitialized = true;

    // 2. Update Nodes (Track by IP or id for persistent identity)
    const activeNodeKeys = new Set();

    for (let i = 0; i < incomingNodes.length; i++) {
      const node = incomingNodes[i];
      const key = node.ip || String(node.id);
      activeNodeKeys.add(key);

      const clusterIdx = this.assignments[i] ?? 0;
      const targetRadius = this.options.pointRadius;

      if (this.animatedNodes.has(key)) {
        // Existing node: update destination targets
        const animNode = this.animatedNodes.get(key);
        animNode.targetX = node.x;
        animNode.targetY = node.y;
        animNode.targetRadius = targetRadius;
        animNode.targetAlpha = 1.0;
        animNode.clusterIdx = clusterIdx;
        animNode.data = node;
        animNode.isDeparting = false;
      } else {
        // New node: on first load appear immediately; on subsequent updates spawn smoothly from centroid
        const clusterCentroid = incomingCentroids[clusterIdx] || { x: node.x, y: node.y };
        const startX = isFirstLoad ? node.x : clusterCentroid.x;
        const startY = isFirstLoad ? node.y : clusterCentroid.y;
        const animNode = {
          key,
          currentX: startX,
          currentY: startY,
          targetX: node.x,
          targetY: node.y,
          renderX: startX,
          renderY: startY,
          currentRadius: isFirstLoad ? targetRadius : 0.5,
          targetRadius,
          alpha: isFirstLoad ? 1.0 : 0.0,
          targetAlpha: 1.0,
          clusterIdx,
          data: node,
          floatPhase: Math.random() * Math.PI * 2,
          isDeparting: false,
          isHovered: false,
        };
        this.animatedNodes.set(key, animNode);
      }
    }

    // Mark departed nodes for smooth fade out
    for (const [key, animNode] of this.animatedNodes.entries()) {
      if (!activeNodeKeys.has(key)) {
        animNode.targetAlpha = 0.0;
        animNode.targetRadius = 0.0;
        animNode.isDeparting = true;
      }
    }

    // 3. Update Socket Connections
    const activeConnKeys = new Set();

    for (let i = 0; i < incomingConnections.length; i++) {
      const conn = incomingConnections[i];
      const srcKey = conn.srcIP || String(conn.srcId);
      const destKey = conn.destIP || String(conn.destId);
      const connKey = `${srcKey}->${destKey}:${conn.destPort}`;
      activeConnKeys.add(connKey);

      if (this.animatedConnections.has(connKey)) {
        const animConn = this.animatedConnections.get(connKey);
        animConn.data = conn;
        animConn.srcKey = srcKey;
        animConn.destKey = destKey;
        animConn.targetAlpha = 1.0;
        animConn.isDeparting = false;
      } else {
        const animConn = {
          key: connKey,
          data: conn,
          srcKey,
          destKey,
          alpha: isFirstLoad ? 1.0 : 0.0,
          targetAlpha: 1.0,
          packetPhase: conn.packetPhase ?? Math.random(),
          packetSpeed: conn.packetSpeed ?? (0.008 + Math.random() * 0.012),
          isDeparting: false,
        };
        this.animatedConnections.set(connKey, animConn);
      }
    }

    // Mark departed connections for smooth fade out
    for (const [key, animConn] of this.animatedConnections.entries()) {
      if (!activeConnKeys.has(key)) {
        animConn.targetAlpha = 0.0;
        animConn.isDeparting = true;
      }
    }
  }

  handleHover(mouseX, mouseY, clientX, clientY) {
    if (
      mouseX < this.margin.left ||
      mouseX > this.width - this.margin.right ||
      mouseY < this.margin.top ||
      mouseY > this.height - this.margin.bottom
    ) {
      this.clearHover();
      return;
    }

    // Check Centroids first
    let nearestCentroid = null;
    let minCentroidDist = 22;

    for (let i = 0; i < this.animatedCentroids.length; i++) {
      const c = this.animatedCentroids[i];
      if (c.alpha < 0.2) continue;
      const p = this.toCanvasCoords(c.currentX, c.currentY);
      if (
        p.x < this.margin.left - 10 ||
        p.x > this.width - this.margin.right + 10 ||
        p.y < this.margin.top - 10 ||
        p.y > this.height - this.margin.bottom + 10
      ) {
        continue;
      }
      const d = Math.hypot(p.x - mouseX, p.y - mouseY);
      if (d < minCentroidDist) {
        minCentroidDist = d;
        nearestCentroid = {
          type: 'centroid',
          index: i,
          data: { x: c.currentX, y: c.currentY },
          stats: c.stats,
        };
      }
    }

    if (nearestCentroid) {
      this.setHoveredItem(nearestCentroid, clientX, clientY);
      return;
    }

    // Check Animated IP Nodes
    let nearestNode = null;
    let minNodeDist = 15;
    let idx = 0;

    for (const [key, animNode] of this.animatedNodes.entries()) {
      if (animNode.alpha < 0.2) {
        idx++;
        continue;
      }

      const cp = this.toCanvasCoords(animNode.renderX, animNode.renderY);
      if (
        cp.x < this.margin.left - 8 ||
        cp.x > this.width - this.margin.right + 8 ||
        cp.y < this.margin.top - 8 ||
        cp.y > this.height - this.margin.bottom + 8
      ) {
        idx++;
        continue;
      }
      const d = Math.hypot(cp.x - mouseX, cp.y - mouseY);
      if (d < minNodeDist) {
        minNodeDist = d;
        nearestNode = {
          type: 'node',
          key,
          index: idx,
          data: animNode.data,
          cluster: animNode.clusterIdx,
          renderX: animNode.renderX,
          renderY: animNode.renderY,
        };
      }
      idx++;
    }

    if (nearestNode) {
      this.setHoveredItem(nearestNode, clientX, clientY);
      return;
    }

    // Check Animated IP-to-IP Socket Connection Lines (Network Flows)
    if (this.options.showConnections) {
      let nearestConn = null;
      let minConnDist = 14; // Generous 14px hit detection band for effortless clicking
      const filterPort = this.options.filterPort;

      for (const [key, animConn] of this.animatedConnections.entries()) {
        if (animConn.alpha < 0.08 || animConn.isDeparting) continue;
        const conn = animConn.data;

        // Respect active port filter
        if (filterPort !== 'all' && String(conn.destPort) !== String(filterPort)) {
          continue;
        }

        const srcNode = this.animatedNodes.get(animConn.srcKey);
        const destNode = this.animatedNodes.get(animConn.destKey);
        if (!srcNode || !destNode || srcNode.alpha < 0.05 || destNode.alpha < 0.05) continue;

        const p1 = this.toCanvasCoords(srcNode.renderX, srcNode.renderY);
        const p2 = this.toCanvasCoords(destNode.renderX, destNode.renderY);

        const d = this.distToSegment(mouseX, mouseY, p1.x, p1.y, p2.x, p2.y);
        if (d < minConnDist) {
          minConnDist = d;
          nearestConn = {
            type: 'connection',
            key,
            data: conn,
            animConn,
            srcNode,
            destNode,
            p1,
            p2,
          };
        }
      }

      if (nearestConn) {
        this.setHoveredItem(nearestConn, clientX, clientY);
        return;
      }
    }

    this.clearHover();
  }

  setHoveredItem(item, clientX, clientY) {
    // Reset previous hovered node flag
    if (this.hoveredItem && this.hoveredItem.type === 'node') {
      const prev = this.animatedNodes.get(this.hoveredItem.key);
      if (prev) prev.isHovered = false;
    }

    this.hoveredItem = item;
    if (item.type === 'node') {
      const curr = this.animatedNodes.get(item.key);
      if (curr) curr.isHovered = true;
    }

    this.showTooltip(clientX, clientY, item);
  }

  clearHover() {
    if (this.hoveredItem && this.hoveredItem.type === 'node') {
      const prev = this.animatedNodes.get(this.hoveredItem.key);
      if (prev) prev.isHovered = false;
    }
    this.hoveredItem = null;
    if (this.tooltip) {
      this.tooltip.style.opacity = '0';
    }
  }

  showTooltip(clientX, clientY, item) {
    if (!this.tooltip) return;

    if (item.type === 'centroid') {
      const c = item.data;
      const stats = item.stats || this.clusterStats[item.index] || {};
      const color = NetworkClusterChart.PALETTE[item.index % NetworkClusterChart.PALETTE.length];

      const memberNodes = this.nodes.filter((_, idx) => this.assignments[idx] === item.index);
      const zones = memberNodes.map((n) => n.zone).filter(Boolean);
      const dominantZone =
        zones.length > 0
          ? zones.sort((a, b) => zones.filter((v) => v === a).length - zones.filter((v) => v === b).length).pop()
          : `Subnet Zone ${item.index + 1}`;

      this.tooltip.innerHTML = `
        <div style="display:flex;align-items:center;gap:6px;font-weight:700;color:${color.main};margin-bottom:6px;">
          <span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:${color.main}"></span>
          Subnet Gateway μ${item.index + 1}
        </div>
        <div style="font-size:11.5px;color:#cbd5e1;line-height:1.6;">
          <div>Zone: <b style="color:#f1f5f9;">${dominantZone}</b></div>
          <div>Gateway Nexus: <b>(${c.x.toFixed(2)}, ${c.y.toFixed(2)})</b></div>
          <div>Member Hosts: <b>${stats.count || memberNodes.length} IPs</b> (${(((stats.count || memberNodes.length) / (this.nodes.length || 1)) * 100).toFixed(1)}%)</div>
          <div>Cluster Dispersion: <b>${(stats.avgDistance || 0).toFixed(2)}</b></div>
        </div>
      `;
    } else if (item.type === 'node') {
      const node = item.data;
      const clusterIdx = item.cluster;
      const color = NetworkClusterChart.PALETTE[clusterIdx % NetworkClusterChart.PALETTE.length];

      const outConns = this.connections.filter((c) => (c.srcIP ? c.srcIP === node.ip : c.srcId === node.id));
      const inConns = this.connections.filter((c) => (c.destIP ? c.destIP === node.ip : c.destId === node.id));

      const zoneBadge = node.zone
        ? `<span style="font-size:9.5px;padding:2px 6px;border-radius:4px;font-weight:700;background:${
            node.isInternal
              ? 'rgba(16,185,129,0.18);color:#34d399;border:1px solid rgba(16,185,129,0.3)'
              : 'rgba(6,182,212,0.18);color:#38bdf8;border:1px solid rgba(6,182,212,0.3)'
          }">${node.zone.toUpperCase()}</span>`
        : '';

      const processBadge = node.process
        ? `<div style="margin-top:4px;display:flex;align-items:center;gap:4px;font-size:11px;color:#a78bfa;">
             <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><circle cx="9" cy="9" r="1"/><circle cx="15" cy="15" r="1"/></svg>
             <span>Process: <b>${node.process}</b></span>
           </div>`
        : '';

      const outSummary =
        outConns.length > 0
          ? outConns
              .slice(0, 4)
              .map(
                (c) => `
            <div style="display:flex;justify-content:space-between;align-items:center;gap:6px;font-family:monospace;font-size:10.5px;margin-top:2px;">
              <span style="color:#94a3b8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:130px;">↳ ${c.destIP}</span>
              <div style="display:flex;align-items:center;gap:4px;">
                <span style="background:${c.color}22;color:${c.color};padding:1px 4px;border-radius:3px;font-weight:700;">:${c.destPort}</span>
                <span style="color:#64748b;font-size:9.5px;">${c.latencyMs ? c.latencyMs + 'ms' : ''}</span>
              </div>
            </div>
          `
              )
              .join('')
          : '<div style="color:#64748b;font-size:11px;">No outbound sockets</div>';

      let dnsHtml = '';
      if (node.dnsEnabled || this.options.resolveDns) {
        if (node.dnsName) {
          dnsHtml = `
            <div style="display:flex;justify-content:space-between;margin-top:2px;gap:8px;">
              <span style="color:#94a3b8;">DNS (PTR):</span>
              <b style="color:#38bdf8;font-family:monospace;font-size:11px;max-width:180px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${node.dnsName}">${node.dnsName}</b>
            </div>
          `;
        } else {
          dnsHtml = `
            <div style="display:flex;justify-content:space-between;margin-top:2px;gap:8px;">
              <span style="color:#94a3b8;">DNS (PTR):</span>
              <span style="color:#64748b;font-size:10.5px;font-style:italic;">No PTR record found</span>
            </div>
          `;
        }
      } else {
        dnsHtml = `
          <div style="display:flex;justify-content:space-between;margin-top:2px;gap:8px;">
            <span style="color:#94a3b8;">DNS Lookup:</span>
            <span style="color:#64748b;font-size:10.5px;">Off (Enable via sidebar)</span>
          </div>
        `;
      }

      let geoHtml = '';
      if (node.geo && !node.isInternal) {
        const flag = node.geo.flag || '🌐';
        const loc = [node.geo.city, node.geo.country].filter(Boolean).join(', ');
        const asnPill = node.geo.asn
          ? `<span style="background:rgba(168,85,247,0.22);color:#c084fc;padding:1px 5px;border-radius:3px;font-weight:700;font-size:10px;">${node.geo.asn}</span>`
          : '';
        const orgDesc = node.geo.org || node.geo.isp || '';
        geoHtml = `
          <div style="display:flex;justify-content:space-between;align-items:center;margin-top:3px;gap:6px;">
            <span style="color:#94a3b8;">GeoIP Location:</span>
            <span style="color:#f8fafc;font-size:11px;">${flag} <b>${loc || 'Internet'}</b></span>
          </div>
          <div style="display:flex;justify-content:space-between;align-items:center;margin-top:2px;gap:6px;">
            <span style="color:#94a3b8;">ASN / Org:</span>
            <div style="display:flex;align-items:center;gap:4px;">
              ${asnPill}
              <span style="color:#cbd5e1;font-size:10.5px;max-width:130px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${orgDesc}">${orgDesc}</span>
            </div>
          </div>
        `;
      } else if (node.isInternal) {
        geoHtml = `
          <div style="display:flex;justify-content:space-between;align-items:center;margin-top:3px;gap:6px;">
            <span style="color:#94a3b8;">Geo Location:</span>
            <span style="color:#34d399;font-size:11px;">🏠 <b>Internal Subnet (RFC1918)</b></span>
          </div>
        `;
      }

      this.tooltip.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:5px;gap:8px;">
          <div style="font-weight:700;color:${color.main};font-family:monospace;font-size:13px;">
            ${node.ip}
          </div>
          ${zoneBadge}
        </div>
        <div style="font-size:11.5px;color:#cbd5e1;line-height:1.5;">
          <div style="display:flex;justify-content:space-between;">
            <span style="color:#94a3b8;">Host / Domain:</span>
            <b style="color:#f1f5f9;font-family:monospace;font-size:11px;">${node.hostname || node.ip}</b>
          </div>
          ${dnsHtml}
          ${geoHtml}
          ${processBadge}
          <div style="display:flex;justify-content:space-between;margin-top:2px;">
            <span style="color:#94a3b8;">Cluster Centroid:</span>
            <b style="color:${color.main}">Subnet Gateway μ${clusterIdx + 1}</b>
          </div>
          <div style="display:flex;justify-content:space-between;margin-top:2px;">
            <span style="color:#94a3b8;">Throughput:</span>
            <b style="color:#38bdf8">${node.trafficMbps} Mbps</b>
          </div>
          <div style="margin-top:6px;font-weight:600;color:#94a3b8;font-size:11px;border-top:1px dashed rgba(255,255,255,0.08);padding-top:4px;">
            Active Sockets: Outbound (${outConns.length}) • Inbound (${inConns.length})
          </div>
          ${outSummary}
          <div style="margin-top:8px;font-size:10px;color:#38bdf8;text-align:center;background:rgba(6,182,212,0.12);border:1px solid rgba(6,182,212,0.25);padding:4px;border-radius:4px;font-weight:600;">
            🔍 Click host node to inspect active sockets
          </div>
        </div>
      `;
    } else if (item.type === 'connection') {
      const conn = item.data;
      const srcNode = item.srcNode?.data || {};
      const destNode = item.destNode?.data || {};
      const color = conn.color || '#38bdf8';

      const protoBadge = `<span style="font-size:9.5px;padding:2px 6px;border-radius:4px;font-weight:700;background:${color}22;color:${color};border:1px solid ${color}44;">${conn.proto || 'TCP'} :${conn.destPort} [${conn.service || 'PORT'}]</span>`;

      const typeBadge = conn.isCrossSubnet
        ? `<span style="font-size:9.5px;padding:2px 6px;border-radius:4px;font-weight:700;background:rgba(245,158,11,0.18);color:#f59e0b;border:1px solid rgba(245,158,11,0.3)">CROSS-SUBNET</span>`
        : conn.isInternal
        ? `<span style="font-size:9.5px;padding:2px 6px;border-radius:4px;font-weight:700;background:rgba(16,185,129,0.18);color:#34d399;border:1px solid rgba(16,185,129,0.3)">INTERNAL LAN</span>`
        : `<span style="font-size:9.5px;padding:2px 6px;border-radius:4px;font-weight:700;background:rgba(6,182,212,0.18);color:#38bdf8;border:1px solid rgba(6,182,212,0.3)">INTERNET EGRESS</span>`;

      let latencyColor = '#34d399';
      let latencyQuality = 'Ultra-Low Latency';
      if (conn.latencyMs > 50) {
        latencyColor = '#f59e0b';
        latencyQuality = 'Latency Spike Alert';
      } else if (conn.latencyMs > 20) {
        latencyColor = '#38bdf8';
        latencyQuality = 'Normal Network RTT';
      }

      let destGeoHtml = '';
      if (destNode.geo && !destNode.isInternal) {
        const flag = destNode.geo.flag || '🌐';
        const loc = [destNode.geo.city, destNode.geo.country].filter(Boolean).join(', ');
        const orgDesc = destNode.geo.org || destNode.geo.isp || '';
        destGeoHtml = `
          <div style="display:flex;justify-content:space-between;margin-top:2px;">
            <span style="color:#94a3b8;">Destination Geo:</span>
            <span style="color:#f1f5f9;font-size:11px;">${flag} <b>${loc || 'Internet'}</b></span>
          </div>
          ${orgDesc ? `
          <div style="display:flex;justify-content:space-between;margin-top:2px;">
            <span style="color:#94a3b8;">Provider / ASN:</span>
            <span style="color:#c084fc;font-size:10.5px;max-width:140px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${orgDesc}">${orgDesc}</span>
          </div>` : ''}
        `;
      }

      const processHtml = conn.process
        ? `
          <div style="display:flex;justify-content:space-between;align-items:center;margin-top:3px;">
            <span style="color:#94a3b8;">Process:</span>
            <b style="color:#c084fc;font-family:monospace;font-size:11px;">${conn.process}${conn.pid ? ` (PID ${conn.pid})` : ''}</b>
          </div>
        `
        : '';

      const throughputStr =
        conn.throughputKbps > 1000
          ? `${(conn.throughputKbps / 1000).toFixed(2)} Mbps`
          : `${conn.throughputKbps || 0} Kbps`;

      this.tooltip.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:5px;gap:8px;">
          <div style="font-weight:700;color:${color};font-family:monospace;font-size:12.5px;">
            ⚡ Network Socket Flow
          </div>
          ${typeBadge}
        </div>
        <div style="font-size:11.5px;color:#cbd5e1;line-height:1.5;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
            <span style="color:#94a3b8;">Protocol &amp; Port:</span>
            ${protoBadge}
          </div>
          <div style="background:rgba(15,23,42,0.7);padding:5px 8px;border-radius:4px;border:1px solid rgba(255,255,255,0.06);margin-bottom:6px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <span style="color:#64748b;font-size:10px;text-transform:uppercase;">Source Host</span>
              <span style="font-family:monospace;color:#f8fafc;font-size:11px;">${conn.srcIP}</span>
            </div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-top:2px;">
              <span style="color:#64748b;font-size:10px;text-transform:uppercase;">Destination</span>
              <span style="font-family:monospace;color:${color};font-weight:700;font-size:11px;">${conn.destIP}:${conn.destPort}</span>
            </div>
          </div>
          <div style="display:flex;justify-content:space-between;margin-top:2px;">
            <span style="color:#94a3b8;">Kernel RTT Latency:</span>
            <b style="color:${latencyColor}">${conn.latencyMs} ms <span style="font-size:10px;font-weight:400;color:#94a3b8;">(${latencyQuality})</span></b>
          </div>
          <div style="display:flex;justify-content:space-between;margin-top:2px;">
            <span style="color:#94a3b8;">Flow Throughput:</span>
            <b style="color:#38bdf8">${throughputStr}</b>
          </div>
          <div style="display:flex;justify-content:space-between;margin-top:2px;">
            <span style="color:#94a3b8;">Socket State:</span>
            <b style="color:#10b981">${conn.state || 'ESTABLISHED'}</b>
          </div>
          ${processHtml}
          ${destGeoHtml}
          <div style="margin-top:8px;font-size:10.5px;color:#38bdf8;text-align:center;background:rgba(6,182,212,0.12);border:1px solid rgba(6,182,212,0.25);padding:4px;border-radius:4px;font-weight:600;">
            🔍 Click flow line to inspect socket &amp; packet frames
          </div>
        </div>
      `;
    }

    this.tooltip.style.opacity = '1';
    this.tooltip.style.left = `${clientX + 14}px`;
    this.tooltip.style.top = `${clientY + 14}px`;
  }

  /**
   * Continuous 60 FPS Animation Loop
   */
  animate(timestamp) {
    if (!this.lastFrameTime) this.lastFrameTime = timestamp;
    const dt = Math.min(0.1, (timestamp - this.lastFrameTime) / 1000);
    this.lastFrameTime = timestamp;

    // Rolling FPS metric
    if (dt > 0) {
      const instantFps = 1 / dt;
      this.fps = this.fps * 0.92 + instantFps * 0.08;
    }
    this.fpsTimer += dt;
    if (this.fpsTimer >= 0.5) {
      this.fpsTimer = 0;
      if (this.onFpsUpdate) {
        this.onFpsUpdate(this.fps);
      }
    }

    this.pulsePhase = (this.pulsePhase + 0.04) % (Math.PI * 2);

    // Frame-rate independent exponential smoothing
    const lerpSpeed = 1 - Math.exp(-dt * 6.5);
    const fadeSpeed = 1 - Math.exp(-dt * 9.0);
    const zoomLerpSpeed = 1 - Math.exp(-dt * 14.0);

    // Smooth lerp for zoom and pan
    this.zoom += (this.targetZoom - this.zoom) * zoomLerpSpeed;
    this.pan.x += (this.targetPan.x - this.pan.x) * zoomLerpSpeed;
    this.pan.y += (this.targetPan.y - this.pan.y) * zoomLerpSpeed;

    // 1. Interpolate Centroids
    for (let i = 0; i < this.animatedCentroids.length; i++) {
      const c = this.animatedCentroids[i];
      c.currentX += (c.targetX - c.currentX) * lerpSpeed;
      c.currentY += (c.targetY - c.currentY) * lerpSpeed;
      c.currentRadius += (c.targetRadius - c.currentRadius) * lerpSpeed;
      c.alpha += (c.targetAlpha - c.alpha) * fadeSpeed;
    }
    // Remove dead centroids
    this.animatedCentroids = this.animatedCentroids.filter((c) => c.alpha > 0.01 || c.targetAlpha > 0);

    // 2. Interpolate Nodes
    const showDrift = this.options.organicDrift !== false;
    for (const [key, node] of this.animatedNodes.entries()) {
      if (node.isDeparting && node.alpha < 0.02) {
        this.animatedNodes.delete(key);
        continue;
      }

      node.currentX += (node.targetX - node.currentX) * lerpSpeed;
      node.currentY += (node.targetY - node.currentY) * lerpSpeed;
      node.currentRadius += (node.targetRadius - node.currentRadius) * lerpSpeed;
      node.alpha += (node.targetAlpha - node.alpha) * fadeSpeed;

      // Subtle organic floating micro-motion (breathing cluster)
      if (showDrift && !node.isHovered) {
        const drift = 0.32;
        node.renderX = node.currentX + Math.cos(this.pulsePhase * 0.75 + node.floatPhase) * drift;
        node.renderY = node.currentY + Math.sin(this.pulsePhase * 0.75 + node.floatPhase) * drift;
      } else {
        node.renderX = node.currentX;
        node.renderY = node.currentY;
      }
    }

    // 3. Interpolate Socket Connections & Packet Phases
    for (const [key, conn] of this.animatedConnections.entries()) {
      if (conn.isDeparting && conn.alpha < 0.02) {
        this.animatedConnections.delete(key);
        continue;
      }
      conn.alpha += (conn.targetAlpha - conn.alpha) * fadeSpeed;
      conn.packetPhase = (conn.packetPhase + conn.packetSpeed) % 1.0;
    }

    this.render();
    requestAnimationFrame(this.animate);
  }

  render() {
    const ctx = this.ctx;
    const w = this.width;
    const h = this.height;
    const m = this.margin;
    const plotW = w - m.left - m.right;
    const plotH = h - m.top - m.bottom;

    ctx.clearRect(0, 0, w, h);

    // Grid & Background
    this.drawGrid();

    // Clip inner plot area so zoomed/panned topology elements stay strictly within plot boundaries
    ctx.save();
    ctx.beginPath();
    ctx.rect(m.left, m.top, plotW, plotH);
    ctx.clip();

    // Voronoi subnet zones
    if (this.animatedCentroids.length > 0 && this.options.showVoronoi) {
      this.drawVoronoiRegions();
    }

    // Centroid Gateway Spiderweb Lines
    if (this.options.showGatewayLines && this.animatedCentroids.length > 0) {
      this.drawGatewayLines();
    }

    // Centroid Spread Halos
    if (this.options.showHalos && this.animatedCentroids.length > 0) {
      this.drawCentroidHalos();
    }

    // IP-to-IP Socket Connections & Packet Flows
    if (this.options.showConnections && this.animatedConnections.size > 0) {
      this.drawConnectionsAndPackets();
    }

    // IP Host Nodes
    this.drawIPNodes();

    // Traditional Centroids (Subnet Gateways μ)
    if (this.animatedCentroids.length > 0) {
      this.drawCentroids();
    }

    ctx.restore();

    // Axes & Scale
    this.drawAxes();
  }

  drawGrid() {
    const ctx = this.ctx;
    const m = this.margin;
    const plotW = this.width - m.left - m.right;
    const plotH = this.height - m.top - m.bottom;

    ctx.fillStyle = '#0a0f1d';
    ctx.fillRect(m.left, m.top, plotW, plotH);

    // Subtle radar-like coordinate grid
    ctx.strokeStyle = 'rgba(56, 189, 248, 0.05)';
    ctx.lineWidth = 1;

    ctx.save();
    ctx.beginPath();
    ctx.rect(m.left, m.top, plotW, plotH);
    ctx.clip();

    let gridStep = 20;
    if (this.zoom > 4) gridStep = 5;
    else if (this.zoom > 1.8) gridStep = 10;

    const topLeft = this.toDataCoords(m.left, m.top);
    const bottomRight = this.toDataCoords(m.left + plotW, m.top + plotH);
    const minX = Math.floor(Math.min(topLeft.x, bottomRight.x) / gridStep) * gridStep;
    const maxX = Math.ceil(Math.max(topLeft.x, bottomRight.x) / gridStep) * gridStep;
    const minY = Math.floor(Math.min(topLeft.y, bottomRight.y) / gridStep) * gridStep;
    const maxY = Math.ceil(Math.max(topLeft.y, bottomRight.y) / gridStep) * gridStep;

    for (let val = minX; val <= maxX; val += gridStep) {
      const p1 = this.toCanvasCoords(val, minY);
      const p2 = this.toCanvasCoords(val, maxY);
      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);
      ctx.stroke();
    }

    for (let val = minY; val <= maxY; val += gridStep) {
      const h1 = this.toCanvasCoords(minX, val);
      const h2 = this.toCanvasCoords(maxX, val);
      ctx.beginPath();
      ctx.moveTo(h1.x, h1.y);
      ctx.lineTo(h2.x, h2.y);
      ctx.stroke();
    }

    ctx.restore();
  }

  drawAxes() {
    const ctx = this.ctx;
    const m = this.margin;
    const plotW = this.width - m.left - m.right;
    const plotH = this.height - m.top - m.bottom;

    ctx.strokeStyle = 'rgba(148, 163, 184, 0.3)';
    ctx.lineWidth = 1.5;
    ctx.strokeRect(m.left, m.top, plotW, plotH);

    ctx.fillStyle = '#64748b';
    ctx.font = '11px JetBrains Mono, monospace';

    let gridStep = 20;
    if (this.zoom > 4) gridStep = 5;
    else if (this.zoom > 1.8) gridStep = 10;

    const topLeft = this.toDataCoords(m.left, m.top);
    const bottomRight = this.toDataCoords(m.left + plotW, m.top + plotH);
    const minX = Math.floor(Math.min(topLeft.x, bottomRight.x) / gridStep) * gridStep;
    const maxX = Math.ceil(Math.max(topLeft.x, bottomRight.x) / gridStep) * gridStep;
    const minY = Math.floor(Math.min(topLeft.y, bottomRight.y) / gridStep) * gridStep;
    const maxY = Math.ceil(Math.max(topLeft.y, bottomRight.y) / gridStep) * gridStep;

    // X-Axis Numbers & Ticks along bottom edge
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    for (let val = minX; val <= maxX; val += gridStep) {
      const p = this.toCanvasCoords(val, 0);
      if (p.x >= m.left && p.x <= m.left + plotW) {
        ctx.strokeStyle = 'rgba(148, 163, 184, 0.4)';
        ctx.beginPath();
        ctx.moveTo(p.x, m.top + plotH);
        ctx.lineTo(p.x, m.top + plotH + 4);
        ctx.stroke();

        ctx.fillText(`${val}`, p.x, m.top + plotH + 8);
      }
    }

    // Y-Axis Numbers & Ticks along left edge
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (let val = minY; val <= maxY; val += gridStep) {
      const p = this.toCanvasCoords(0, val);
      if (p.y >= m.top && p.y <= m.top + plotH) {
        ctx.strokeStyle = 'rgba(148, 163, 184, 0.4)';
        ctx.beginPath();
        ctx.moveTo(m.left - 4, p.y);
        ctx.lineTo(m.left, p.y);
        ctx.stroke();

        ctx.fillText(`${val}`, m.left - 8, p.y);
      }
    }

    ctx.font = '600 12px Inter, sans-serif';
    ctx.fillStyle = '#94a3b8';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'bottom';
    ctx.fillText('Network Topology Dimension X₁ (Subnet Latency Profile)', m.left + plotW / 2, this.height - 8);

    ctx.save();
    ctx.translate(16, m.top + plotH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('Network Topology Dimension X₂ (Traffic Density Profile)', 0, 0);
    ctx.restore();
  }

  drawGatewayLines() {
    if (this.focusFilter) return; // Hide centroid spiderweb when focusing on a relationship
    const ctx = this.ctx;


    for (const [key, node] of this.animatedNodes.entries()) {
      if (node.alpha < 0.05) continue;
      const centroid = this.animatedCentroids[node.clusterIdx];
      if (!centroid || centroid.alpha < 0.05) continue;

      const palette = NetworkClusterChart.PALETTE[node.clusterIdx % NetworkClusterChart.PALETTE.length];
      const p1 = this.toCanvasCoords(node.renderX, node.renderY);
      const p2 = this.toCanvasCoords(centroid.currentX, centroid.currentY);

      ctx.save();
      ctx.globalAlpha = node.alpha * centroid.alpha;
      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);
      ctx.strokeStyle = palette.soft;
      ctx.lineWidth = 0.6;
      ctx.stroke();
      ctx.restore();
    }
  }

  drawCentroidHalos() {
    const ctx = this.ctx;
    const plotW = this.width - this.margin.left - this.margin.right;
    const scaleFactor = (plotW / 100) * this.zoom;

    for (let i = 0; i < this.animatedCentroids.length; i++) {
      const c = this.animatedCentroids[i];
      if (c.alpha < 0.05) continue;

      const palette = NetworkClusterChart.PALETTE[i % NetworkClusterChart.PALETTE.length];
      const pos = this.toCanvasCoords(c.currentX, c.currentY);
      const pixelRadius = Math.max(18, c.currentRadius * scaleFactor);

      ctx.save();
      ctx.globalAlpha = c.alpha;

      const radialGrad = ctx.createRadialGradient(pos.x, pos.y, 0, pos.x, pos.y, pixelRadius);
      radialGrad.addColorStop(0, palette.glow);
      radialGrad.addColorStop(0.7, palette.soft);
      radialGrad.addColorStop(1, 'rgba(0, 0, 0, 0)');

      ctx.beginPath();
      ctx.arc(pos.x, pos.y, pixelRadius, 0, Math.PI * 2);
      ctx.fillStyle = radialGrad;
      ctx.fill();

      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, pixelRadius, 0, Math.PI * 2);
      ctx.strokeStyle = palette.soft;
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.restore();
    }
  }

  /**
   * Draw IP-to-IP socket connections with port colors and animated packet pulses
   */
  drawConnectionsAndPackets() {
    const ctx = this.ctx;
    const filterPort = this.options.filterPort;

    for (const [key, animConn] of this.animatedConnections.entries()) {
      if (animConn.alpha < 0.04) continue;
      const conn = animConn.data;

      // Port filter
      if (filterPort !== 'all' && String(conn.destPort) !== String(filterPort)) {
        continue;
      }

      const srcNode = this.animatedNodes.get(animConn.srcKey);
      const destNode = this.animatedNodes.get(animConn.destKey);
      if (!srcNode || !destNode || srcNode.alpha < 0.05 || destNode.alpha < 0.05) continue;

      const p1 = this.toCanvasCoords(srcNode.renderX, srcNode.renderY);
      const p2 = this.toCanvasCoords(destNode.renderX, destNode.renderY);

      const isDirectlyHovered =
        this.hoveredItem &&
        this.hoveredItem.type === 'connection' &&
        this.hoveredItem.key === key;

      const isConnectedToHovered =
        (this.hoveredItem &&
          this.hoveredItem.type === 'node' &&
          (this.hoveredItem.key === animConn.srcKey || this.hoveredItem.key === animConn.destKey)) ||
        isDirectlyHovered;

      const hasFocus = !!this.focusFilter;
      let isFocusMatched = false;
      if (hasFocus) {
        if (this.focusFilter.matchConn) {
          isFocusMatched = this.focusFilter.matchConn(conn, animConn);
        } else if (this.focusFilter.nodeKeys) {
          isFocusMatched = this.focusFilter.nodeKeys.has(animConn.srcKey) && this.focusFilter.nodeKeys.has(animConn.destKey);
        }
      }

      const hasHover = !!this.hoveredItem;
      const isLatencyAlert = this.options.showAlertOverlays && conn.latencyMs > this.options.alertLatencyMs;
      const combinedAlpha = animConn.alpha * srcNode.alpha * destNode.alpha;

      ctx.save();
      if (hasFocus) {
        ctx.globalAlpha = isFocusMatched ? (isDirectlyHovered ? 1.0 : 0.95) : combinedAlpha * 0.06;
      } else {
        ctx.globalAlpha = isDirectlyHovered ? 1.0 : (hasHover && !isConnectedToHovered ? combinedAlpha * 0.22 : combinedAlpha);
      }

      // Draw connection line
      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);

      if (isDirectlyHovered || (hasFocus && isFocusMatched)) {
        ctx.strokeStyle = conn.color || '#38bdf8';
        ctx.lineWidth = isDirectlyHovered ? 3.8 : 2.6;
        ctx.shadowColor = conn.color || '#38bdf8';
        ctx.shadowBlur = 14;
      } else if (isLatencyAlert) {
        ctx.strokeStyle = '#f59e0b';
        ctx.lineWidth = 2.2;
        ctx.shadowColor = '#f59e0b';
        ctx.shadowBlur = 10 + Math.sin(this.pulsePhase * 3) * 6;
      } else if (isConnectedToHovered) {
        ctx.strokeStyle = conn.color || '#10b981';
        ctx.lineWidth = 2.2;
        ctx.shadowColor = conn.color || '#10b981';
        ctx.shadowBlur = 8;
      } else if (hasHover) {
        ctx.strokeStyle = `${conn.color || '#94a3b8'}15`;
        ctx.lineWidth = 0.5;
        ctx.shadowBlur = 0;
      } else {
        ctx.strokeStyle = conn.isCrossSubnet ? `${conn.color || '#94a3b8'}66` : `${conn.color || '#94a3b8'}33`;
        ctx.lineWidth = conn.isCrossSubnet ? 1.0 : 0.75;
        ctx.shadowBlur = 0;
      }

      ctx.stroke();
      ctx.shadowBlur = 0;

      // Draw Animated Packet Pulse traveling along the vector
      if (this.options.showPackets && !animConn.isDeparting && (!hasFocus || isFocusMatched)) {

        const t = animConn.packetPhase;
        const packetX = p1.x + (p2.x - p1.x) * t;
        const packetY = p1.y + (p2.y - p1.y) * t;

        ctx.beginPath();
        const pSize = isDirectlyHovered ? 4.8 : isConnectedToHovered ? 3.5 : 2.0;
        ctx.arc(packetX, packetY, pSize, 0, Math.PI * 2);
        ctx.fillStyle = '#ffffff';
        ctx.shadowColor = conn.color || '#38bdf8';
        ctx.shadowBlur = isDirectlyHovered ? 14 : 6;
        ctx.fill();
        ctx.shadowBlur = 0;
      }

      ctx.restore();
    }
  }

  /**
   * Draw IP host nodes
   */
  drawIPNodes() {
    const ctx = this.ctx;

    for (const [key, node] of this.animatedNodes.entries()) {
      if (node.alpha < 0.04) continue;

      const clusterIdx = node.clusterIdx;
      const palette = NetworkClusterChart.PALETTE[clusterIdx % NetworkClusterChart.PALETTE.length];
      const pos = this.toCanvasCoords(node.renderX, node.renderY);
      const radius = Math.max(1, node.currentRadius);

      const isEndpointOfHoveredConn =
        this.hoveredItem &&
        this.hoveredItem.type === 'connection' &&
        (this.hoveredItem.animConn.srcKey === key || this.hoveredItem.animConn.destKey === key);

      const isHovered =
        (this.hoveredItem && this.hoveredItem.type === 'node' && this.hoveredItem.key === key) ||
        isEndpointOfHoveredConn;

      const isPeerOfHovered =
        this.hoveredItem &&
        this.hoveredItem.type === 'node' &&
        this.connections.some(
          (c) =>
            ((c.srcIP || String(c.srcId)) === this.hoveredItem.key && (c.destIP || String(c.destId)) === key) ||
            ((c.destIP || String(c.destId)) === this.hoveredItem.key && (c.srcIP || String(c.srcId)) === key)
        );

      const hasFocus = !!this.focusFilter;
      const isNodeInFocus = hasFocus && this.focusFilter.nodeKeys ? this.focusFilter.nodeKeys.has(key) : false;

      ctx.save();
      if (hasFocus) {
        ctx.globalAlpha = isNodeInFocus ? 1.0 : node.alpha * 0.12;
      } else {
        ctx.globalAlpha = node.alpha;
      }

      ctx.beginPath();
      const nodeR = isHovered ? radius + 3 : (hasFocus && isNodeInFocus ? radius + 2.5 : radius);
      ctx.arc(pos.x, pos.y, nodeR, 0, Math.PI * 2);

      if (isHovered || (hasFocus && isNodeInFocus)) {
        ctx.fillStyle = '#ffffff';
        ctx.shadowColor = (hasFocus && isNodeInFocus) ? '#38bdf8' : palette.main;
        ctx.shadowBlur = 14;
      } else if (isPeerOfHovered) {
        ctx.fillStyle = '#f8fafc';
        ctx.shadowColor = palette.main;
        ctx.shadowBlur = 8;
      } else {
        ctx.fillStyle = palette.main;
        ctx.shadowBlur = 0;
      }

      ctx.fill();

      // Outer host border
      ctx.lineWidth = (hasFocus && isNodeInFocus) ? 2.5 : 1.5;
      ctx.strokeStyle = isHovered ? '#ffffff' : (hasFocus && isNodeInFocus ? '#38bdf8' : 'rgba(10, 15, 29, 0.9)');
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Bandwidth Surge Alert Ripple Halo
      const isBandwidthAlert = this.options.showAlertOverlays && node.data.trafficMbps > this.options.alertThroughputMbps;
      if (isBandwidthAlert) {
        const alertR = radius + 6 + Math.sin(this.pulsePhase * 3) * 3;
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, alertR, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(239, 68, 68, 0.85)';
        ctx.lineWidth = 1.8;
        ctx.stroke();
      }

      // Optional IP / DNS Host Labels
      // Automatically show labels if Display IP Labels is ON, or if Resolve DNS is ON, or if hovered, or if in relationship focus
      const shouldShowLabel =
        this.options.showIpLabels ||
        this.options.resolveDns ||
        isHovered ||
        (hasFocus && isNodeInFocus);


      if (shouldShowLabel) {
        const hasDns = this.options.resolveDns && (node.data.dnsName || (node.data.hostname && node.data.hostname !== node.data.ip));
        ctx.font = isHovered ? 'bold 10px JetBrains Mono, monospace' : '9px JetBrains Mono, monospace';
        ctx.fillStyle = isHovered ? '#ffffff' : (hasDns ? '#38bdf8' : 'rgba(203, 213, 225, 0.85)');
        ctx.textAlign = 'center';

        const flagPrefix =
          this.options.showGeoip && node.data.flag && !node.data.isInternal ? `${node.data.flag} ` : '';
        let label = `${flagPrefix}${node.data.ip}`;

        if (this.options.resolveDns && node.data.dnsName) {
          label = isHovered
            ? `${flagPrefix}${node.data.dnsName} (${node.data.ip})`
            : `${flagPrefix}${node.data.dnsName}`;
        } else if (this.options.resolveDns && node.data.hostname && node.data.hostname !== node.data.ip) {
          label = isHovered
            ? `${flagPrefix}${node.data.hostname} (${node.data.ip})`
            : `${flagPrefix}${node.data.hostname}`;
        } else if (isHovered && node.data.hostname && node.data.hostname !== node.data.ip) {
          label = `${flagPrefix}${node.data.hostname} (${node.data.ip})`;
        }
        ctx.fillText(label, pos.x, pos.y - radius - 4);
      }

      ctx.restore();
    }
  }

  /**
   * Draw Traditional Centroid markers as Subnet Gateways (μ)
   */
  drawCentroids() {
    const ctx = this.ctx;
    const r = this.options.centroidRadius;
    const pulseOffset = Math.sin(this.pulsePhase) * 3;

    for (let i = 0; i < this.animatedCentroids.length; i++) {
      const c = this.animatedCentroids[i];
      if (c.alpha < 0.05) continue;

      const palette = NetworkClusterChart.PALETTE[i % NetworkClusterChart.PALETTE.length];
      const pos = this.toCanvasCoords(c.currentX, c.currentY);

      ctx.save();
      ctx.globalAlpha = c.alpha;

      // Radar pulse ring
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, r + 9 + pulseOffset, 0, Math.PI * 2);
      ctx.strokeStyle = palette.glow;
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Drop shadow ring
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, r + 4, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(10, 15, 29, 0.85)';
      ctx.fill();
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 2.5;
      ctx.stroke();

      // Core bullseye
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, r, 0, Math.PI * 2);
      ctx.fillStyle = palette.main;
      ctx.fill();

      // Bold Crosshair ('X')
      const arm = r - 2;
      ctx.beginPath();
      ctx.moveTo(pos.x - arm, pos.y - arm);
      ctx.lineTo(pos.x + arm, pos.y + arm);
      ctx.moveTo(pos.x + arm, pos.y - arm);
      ctx.lineTo(pos.x - arm, pos.y + arm);
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 2.5;
      ctx.lineCap = 'round';
      ctx.stroke();

      // Gateway Badge Pill
      const label = `GW-μ${i + 1}`;
      ctx.font = 'bold 10px JetBrains Mono, monospace';
      const textMetrics = ctx.measureText(label);
      const badgeW = textMetrics.width + 12;
      const badgeH = 17;
      const badgeX = pos.x - badgeW / 2;
      const badgeY = pos.y - r - badgeH - 6;

      ctx.fillStyle = 'rgba(15, 23, 42, 0.95)';
      ctx.strokeStyle = palette.main;
      ctx.lineWidth = 1.5;
      this.drawRoundedRect(ctx, badgeX, badgeY, badgeW, badgeH, 4);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = '#ffffff';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(label, pos.x, badgeY + badgeH / 2);

      ctx.restore();
    }
  }

  drawRoundedRect(ctx, x, y, width, height, radius) {
    ctx.beginPath();
    ctx.moveTo(x + radius, y);
    ctx.lineTo(x + width - radius, y);
    ctx.quadraticCurveTo(x + width, y, x + width, y + radius);
    ctx.lineTo(x + width, y + height - radius);
    ctx.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
    ctx.lineTo(x + radius, y + height);
    ctx.quadraticCurveTo(x, y + height, x, y + height - radius);
    ctx.lineTo(x, y + radius);
    ctx.quadraticCurveTo(x, y, x + radius, y);
    ctx.closePath();
  }

  drawVoronoiRegions() {
    const activeCentroids = this.animatedCentroids.filter((c) => c.alpha > 0.3);
    if (activeCentroids.length < 2) return;

    const ctx = this.ctx;
    const m = this.margin;
    const plotW = this.width - m.left - m.right;
    const plotH = this.height - m.top - m.bottom;

    const step = 8;
    const cols = Math.ceil(plotW / step);
    const rows = Math.ceil(plotH / step);

    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const px = m.left + c * step;
        const py = m.top + r * step;
        const dataCoord = this.toDataCoords(px + step / 2, py + step / 2);

        let minD = Infinity;
        let nearestIdx = 0;
        for (let i = 0; i < activeCentroids.length; i++) {
          const centroid = activeCentroids[i];
          const d = Math.hypot(dataCoord.x - centroid.currentX, dataCoord.y - centroid.currentY);
          if (d < minD) {
            minD = d;
            nearestIdx = centroid.index;
          }
        }

        const palette = NetworkClusterChart.PALETTE[nearestIdx % NetworkClusterChart.PALETTE.length];
        ctx.fillStyle = palette.soft;
        ctx.fillRect(px, py, step, step);
      }
    }
  }
}
