/**
 * NetworkClusterChart
 * High-performance Canvas renderer displaying IP addresses as nodes,
 * K-Means cluster centroids as Subnet Gateways, and active IP-to-IP socket connections on specific ports.
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
      resolveDns: false,
      filterPort: 'all', // 'all' or port number e.g. 443
      pointRadius: 5.5,
      centroidRadius: 11,
    };

    this.margin = { top: 40, right: 40, bottom: 50, left: 60 };

    this.nodes = [];
    this.connections = [];
    this.centroids = [];
    this.assignments = [];
    this.clusterStats = [];
    this.hoveredItem = null;

    this.pulsePhase = 0;

    this.setupEvents();
    this.resize();

    this.animate = this.animate.bind(this);
    requestAnimationFrame(this.animate);
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
    this.render();
  }

  setupEvents() {
    window.addEventListener('resize', () => this.resize());

    this.canvas.addEventListener('mousemove', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      this.handleHover(mouseX, mouseY, e.clientX, e.clientY);
    });

    this.canvas.addEventListener('mouseleave', () => {
      this.hoveredItem = null;
      if (this.tooltip) {
        this.tooltip.style.opacity = '0';
      }
    });
  }

  toCanvasCoords(x, y) {
    const plotWidth = this.width - this.margin.left - this.margin.right;
    const plotHeight = this.height - this.margin.top - this.margin.bottom;
    const px = this.margin.left + (x / 100) * plotWidth;
    const py = this.margin.top + (1 - y / 100) * plotHeight;
    return { x: px, y: py };
  }

  toDataCoords(px, py) {
    const plotWidth = this.width - this.margin.left - this.margin.right;
    const plotHeight = this.height - this.margin.top - this.margin.bottom;
    const x = ((px - this.margin.left) / plotWidth) * 100;
    const y = (1 - (py - this.margin.top) / plotHeight) * 100;
    return { x, y };
  }

  updateData({ nodes, connections, centroids, assignments, clusterStats }) {
    this.nodes = nodes || [];
    this.connections = connections || [];
    this.centroids = centroids || [];
    this.assignments = assignments || [];
    this.clusterStats = clusterStats || [];
  }

  handleHover(mouseX, mouseY, clientX, clientY) {
    if (
      mouseX < this.margin.left ||
      mouseX > this.width - this.margin.right ||
      mouseY < this.margin.top ||
      mouseY > this.height - this.margin.bottom
    ) {
      this.hoveredItem = null;
      if (this.tooltip) this.tooltip.style.opacity = '0';
      return;
    }

    // Check Centroids first
    let nearestCentroid = null;
    let minCentroidDist = 20;

    for (let i = 0; i < this.centroids.length; i++) {
      const c = this.centroids[i];
      const p = this.toCanvasCoords(c.x, c.y);
      const d = Math.hypot(p.x - mouseX, p.y - mouseY);
      if (d < minCentroidDist) {
        minCentroidDist = d;
        nearestCentroid = { type: 'centroid', index: i, data: c };
      }
    }

    if (nearestCentroid) {
      this.hoveredItem = nearestCentroid;
      this.showTooltip(clientX, clientY, nearestCentroid);
      return;
    }

    // Check IP Nodes
    let nearestNode = null;
    let minNodeDist = 14;

    for (let i = 0; i < this.nodes.length; i++) {
      const node = this.nodes[i];
      const cp = this.toCanvasCoords(node.x, node.y);
      const d = Math.hypot(cp.x - mouseX, cp.y - mouseY);
      if (d < minNodeDist) {
        minNodeDist = d;
        nearestNode = {
          type: 'node',
          index: i,
          data: node,
          cluster: this.assignments[i],
        };
      }
    }

    if (nearestNode) {
      this.hoveredItem = nearestNode;
      this.showTooltip(clientX, clientY, nearestNode);
    } else {
      this.hoveredItem = null;
      if (this.tooltip) this.tooltip.style.opacity = '0';
    }
  }

  showTooltip(clientX, clientY, item) {
    if (!this.tooltip) return;

    if (item.type === 'centroid') {
      const c = item.data;
      const stats = this.clusterStats[item.index] || {};
      const color = NetworkClusterChart.PALETTE[item.index % NetworkClusterChart.PALETTE.length];
      
      // Determine dominant zone in this cluster
      const memberNodes = this.nodes.filter((_, idx) => this.assignments[idx] === item.index);
      const zones = memberNodes.map(n => n.zone).filter(Boolean);
      const dominantZone = zones.length > 0 
        ? zones.sort((a,b) => zones.filter(v => v===a).length - zones.filter(v => v===b).length).pop()
        : `Subnet Zone ${item.index + 1}`;

      this.tooltip.innerHTML = `
        <div style="display:flex;align-items:center;gap:6px;font-weight:700;color:${color.main};margin-bottom:6px;">
          <span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:${color.main}"></span>
          Subnet Gateway μ${item.index + 1}
        </div>
        <div style="font-size:11.5px;color:#cbd5e1;line-height:1.6;">
          <div>Zone: <b style="color:#f1f5f9;">${dominantZone}</b></div>
          <div>Gateway Nexus: <b>(${c.x.toFixed(2)}, ${c.y.toFixed(2)})</b></div>
          <div>Member Hosts: <b>${stats.count || 0} IPs</b> (${(((stats.count || 0) / (this.nodes.length || 1)) * 100).toFixed(1)}%)</div>
          <div>Cluster Dispersion: <b>${(stats.avgDistance || 0).toFixed(2)}</b></div>
        </div>
      `;
    } else if (item.type === 'node') {
      const node = item.data;
      const clusterIdx = item.cluster;
      const color = NetworkClusterChart.PALETTE[clusterIdx % NetworkClusterChart.PALETTE.length];

      // Find outbound & inbound connections
      const outConns = this.connections.filter(c => c.srcId === node.id);
      const inConns = this.connections.filter(c => c.destId === node.id);

      const zoneBadge = node.zone 
        ? `<span style="font-size:9.5px;padding:2px 6px;border-radius:4px;font-weight:700;background:${node.isInternal ? 'rgba(16,185,129,0.18);color:#34d399;border:1px solid rgba(16,185,129,0.3)' : 'rgba(6,182,212,0.18);color:#38bdf8;border:1px solid rgba(6,182,212,0.3)'}">${node.zone.toUpperCase()}</span>`
        : '';

      const processBadge = node.process
        ? `<div style="margin-top:4px;display:flex;align-items:center;gap:4px;font-size:11px;color:#a78bfa;">
             <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><circle cx="9" cy="9" r="1"/><circle cx="15" cy="15" r="1"/></svg>
             <span>Process: <b>${node.process}</b></span>
           </div>`
        : '';

      const outSummary = outConns.length > 0
        ? outConns.slice(0, 4).map(c => `
            <div style="display:flex;justify-content:space-between;align-items:center;gap:6px;font-family:monospace;font-size:10.5px;margin-top:2px;">
              <span style="color:#94a3b8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:130px;">↳ ${c.destIP}</span>
              <div style="display:flex;align-items:center;gap:4px;">
                <span style="background:${c.color}22;color:${c.color};padding:1px 4px;border-radius:3px;font-weight:700;">:${c.destPort}</span>
                <span style="color:#64748b;font-size:9.5px;">${c.latencyMs ? c.latencyMs + 'ms' : ''}</span>
              </div>
            </div>
          `).join('')
        : '<div style="color:#64748b;font-size:11px;">No outbound sockets</div>';

      let dnsHtml = '';
      if (node.dnsEnabled) {
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
        </div>
      `;
    }

    this.tooltip.style.opacity = '1';
    this.tooltip.style.left = `${clientX + 14}px`;
    this.tooltip.style.top = `${clientY + 14}px`;
  }

  animate() {
    this.pulsePhase = (this.pulsePhase + 0.04) % (Math.PI * 2);

    // Update connection packet phases
    for (let i = 0; i < this.connections.length; i++) {
      const conn = this.connections[i];
      conn.packetPhase = (conn.packetPhase + conn.packetSpeed) % 1.0;
    }

    this.render();
    requestAnimationFrame(this.animate);
  }

  render() {
    const ctx = this.ctx;
    const w = this.width;
    const h = this.height;

    ctx.clearRect(0, 0, w, h);

    // Grid & Coordinates
    this.drawGrid();

    // Voronoi subnet zones
    if (this.centroids.length > 0 && this.options.showVoronoi) {
      this.drawVoronoiRegions();
    }

    // Centroid Gateway Spiderweb Lines
    if (this.options.showGatewayLines && this.centroids.length > 0) {
      this.drawGatewayLines();
    }

    // Centroid Spread Halos
    if (this.options.showHalos && this.centroids.length > 0) {
      this.drawCentroidHalos();
    }

    // IP-to-IP Socket Connections & Packet Flows
    if (this.options.showConnections && this.connections.length > 0) {
      this.drawConnectionsAndPackets();
    }

    // IP Host Nodes
    this.drawIPNodes();

    // Traditional Centroids (Subnet Gateways)
    if (this.centroids.length > 0) {
      this.drawCentroids();
    }

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

    for (let val = 0; val <= 100; val += 20) {
      const p1 = this.toCanvasCoords(val, 0);
      const p2 = this.toCanvasCoords(val, 100);
      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);
      ctx.stroke();

      const h1 = this.toCanvasCoords(0, val);
      const h2 = this.toCanvasCoords(100, val);
      ctx.beginPath();
      ctx.moveTo(h1.x, h1.y);
      ctx.lineTo(h2.x, h2.y);
      ctx.stroke();
    }
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
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';

    for (let val = 0; val <= 100; val += 20) {
      const p = this.toCanvasCoords(val, 0);
      ctx.fillText(`${val}`, p.x, p.y + 8);
    }

    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (let val = 0; val <= 100; val += 20) {
      const p = this.toCanvasCoords(0, val);
      ctx.fillText(`${val}`, p.x - 10, p.y);
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
    const ctx = this.ctx;

    for (let i = 0; i < this.nodes.length; i++) {
      const node = this.nodes[i];
      const clusterIdx = this.assignments[i];
      const centroid = this.centroids[clusterIdx];
      if (!centroid) continue;

      const palette = NetworkClusterChart.PALETTE[clusterIdx % NetworkClusterChart.PALETTE.length];
      const p1 = this.toCanvasCoords(node.x, node.y);
      const p2 = this.toCanvasCoords(centroid.x, centroid.y);

      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);
      ctx.strokeStyle = palette.soft;
      ctx.lineWidth = 0.6;
      ctx.stroke();
    }
  }

  drawCentroidHalos() {
    const ctx = this.ctx;
    const plotW = this.width - this.margin.left - this.margin.right;
    const scaleFactor = plotW / 100;

    for (let i = 0; i < this.centroids.length; i++) {
      const c = this.centroids[i];
      const stats = this.clusterStats[i];
      if (!stats || stats.count === 0) continue;

      const palette = NetworkClusterChart.PALETTE[i % NetworkClusterChart.PALETTE.length];
      const pos = this.toCanvasCoords(c.x, c.y);
      const pixelRadius = Math.max(18, stats.stdDev * scaleFactor);

      const radialGrad = ctx.createRadialGradient(pos.x, pos.y, 0, pos.x, pos.y, pixelRadius);
      radialGrad.addColorStop(0, palette.glow);
      radialGrad.addColorStop(0.7, palette.soft);
      radialGrad.addColorStop(1, 'rgba(0, 0, 0, 0)');

      ctx.beginPath();
      ctx.arc(pos.x, pos.y, pixelRadius, 0, Math.PI * 2);
      ctx.fillStyle = radialGrad;
      ctx.fill();

      ctx.save();
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

    for (let i = 0; i < this.connections.length; i++) {
      const conn = this.connections[i];

      // Port filter
      if (filterPort !== 'all' && String(conn.destPort) !== String(filterPort)) {
        continue;
      }

      const srcNode = this.nodes[conn.srcId];
      const destNode = this.nodes[conn.destId];
      if (!srcNode || !destNode) continue;

      const p1 = this.toCanvasCoords(srcNode.x, srcNode.y);
      const p2 = this.toCanvasCoords(destNode.x, destNode.y);

      const isConnectedToHovered =
        this.hoveredItem &&
        this.hoveredItem.type === 'node' &&
        (this.hoveredItem.data.id === conn.srcId || this.hoveredItem.data.id === conn.destId);

      const hasHover = !!this.hoveredItem;

      // Draw connection line
      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);

      if (isConnectedToHovered) {
        ctx.strokeStyle = conn.color;
        ctx.lineWidth = 2.0;
        ctx.shadowColor = conn.color;
        ctx.shadowBlur = 8;
      } else if (hasHover) {
        ctx.strokeStyle = `${conn.color}15`; // dimmed
        ctx.lineWidth = 0.5;
        ctx.shadowBlur = 0;
      } else {
        // Normal state: cross-subnet links are slightly more prominent
        ctx.strokeStyle = conn.isCrossSubnet ? `${conn.color}66` : `${conn.color}33`;
        ctx.lineWidth = conn.isCrossSubnet ? 1.0 : 0.75;
        ctx.shadowBlur = 0;
      }

      ctx.stroke();
      ctx.shadowBlur = 0;

      // Draw Animated Packet Pulse traveling along the vector
      if (this.options.showPackets) {
        const t = conn.packetPhase;
        const packetX = p1.x + (p2.x - p1.x) * t;
        const packetY = p1.y + (p2.y - p1.y) * t;

        ctx.beginPath();
        ctx.arc(packetX, packetY, isConnectedToHovered ? 3.5 : 2.0, 0, Math.PI * 2);
        ctx.fillStyle = '#ffffff';
        ctx.shadowColor = conn.color;
        ctx.shadowBlur = 6;
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    }
  }

  /**
   * Draw IP host nodes
   */
  drawIPNodes() {
    const ctx = this.ctx;
    const radius = this.options.pointRadius;

    for (let i = 0; i < this.nodes.length; i++) {
      const node = this.nodes[i];
      const clusterIdx = this.assignments[i];
      const palette = NetworkClusterChart.PALETTE[clusterIdx % NetworkClusterChart.PALETTE.length];
      const pos = this.toCanvasCoords(node.x, node.y);

      const isHovered =
        this.hoveredItem &&
        this.hoveredItem.type === 'node' &&
        this.hoveredItem.index === i;

      const isPeerOfHovered =
        this.hoveredItem &&
        this.hoveredItem.type === 'node' &&
        this.connections.some(
          c => (c.srcId === this.hoveredItem.data.id && c.destId === node.id) ||
               (c.destId === this.hoveredItem.data.id && c.srcId === node.id)
        );

      ctx.beginPath();
      ctx.arc(pos.x, pos.y, isHovered ? radius + 3 : radius, 0, Math.PI * 2);

      if (isHovered) {
        ctx.fillStyle = '#ffffff';
        ctx.shadowColor = palette.main;
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
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = isHovered ? '#ffffff' : 'rgba(10, 15, 29, 0.9)';
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Optional IP Host Labels
      if (this.options.showIpLabels || isHovered) {
        ctx.font = isHovered ? 'bold 10px JetBrains Mono, monospace' : '9px JetBrains Mono, monospace';
        ctx.fillStyle = isHovered ? '#ffffff' : 'rgba(203, 213, 225, 0.75)';
        ctx.textAlign = 'center';
        let label = node.ip;
        if (this.options.resolveDns && node.dnsName) {
          label = isHovered ? `${node.dnsName} (${node.ip})` : node.dnsName;
        } else if (isHovered && node.hostname && node.hostname !== node.ip) {
          label = `${node.hostname} (${node.ip})`;
        }
        ctx.fillText(label, pos.x, pos.y - radius - 4);
      }
    }
  }

  /**
   * Draw Traditional Centroid markers as Subnet Gateways (μ)
   */
  drawCentroids() {
    const ctx = this.ctx;
    const r = this.options.centroidRadius;
    const pulseOffset = Math.sin(this.pulsePhase) * 3;

    for (let i = 0; i < this.centroids.length; i++) {
      const c = this.centroids[i];
      const palette = NetworkClusterChart.PALETTE[i % NetworkClusterChart.PALETTE.length];
      const pos = this.toCanvasCoords(c.x, c.y);

      // Radar pulse
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

      // Traditional Bold Crosshair ('X' and diamond)
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
    if (this.centroids.length < 2) return;
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
        for (let i = 0; i < this.centroids.length; i++) {
          const centroid = this.centroids[i];
          const d = Math.hypot(dataCoord.x - centroid.x, dataCoord.y - centroid.y);
          if (d < minD) {
            minD = d;
            nearestIdx = i;
          }
        }

        const palette = NetworkClusterChart.PALETTE[nearestIdx % NetworkClusterChart.PALETTE.length];
        ctx.fillStyle = palette.soft;
        ctx.fillRect(px, py, step, step);
      }
    }
  }
}
