/**
 * Network IP and Port Connection Generator
 * Models IP nodes, subnets, hostnames, and socket connections between IPs on specific ports.
 */

export const WELL_KNOWN_PORTS = [
  { port: 443, service: 'HTTPS', proto: 'TCP', color: '#10b981', category: 'web' },
  { port: 80, service: 'HTTP', proto: 'TCP', color: '#06b6d4', category: 'web' },
  { port: 22, service: 'SSH', proto: 'TCP', color: '#f59e0b', category: 'admin' },
  { port: 53, service: 'DNS', proto: 'UDP', color: '#3b82f6', category: 'infra' },
  { port: 3306, service: 'MySQL', proto: 'TCP', color: '#a855f7', category: 'db' },
  { port: 5432, service: 'PostgreSQL', proto: 'TCP', color: '#ec4899', category: 'db' },
  { port: 6379, service: 'Redis', proto: 'TCP', color: '#f43f5e', category: 'cache' },
  { port: 8080, service: 'API-GW', proto: 'TCP', color: '#14b8a6', category: 'web' },
];

export class NetworkDataGenerator {
  /**
   * Box-Muller transform for normal distribution
   */
  static randomGaussian(mean = 0, stdDev = 1) {
    let u1 = 0, u2 = 0;
    while (u1 === 0) u1 = Math.random();
    while (u2 === 0) u2 = Math.random();
    return mean + Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2) * stdDev;
  }

  static clamp(val, min = 4, max = 96) {
    return Math.max(min, Math.min(max, val));
  }

  /**
   * Generate realistic IP address for a subnet index
   */
  static generateIP(subnetIdx, hostNum) {
    const subnets = [
      '10.0.1.',   // DMZ / Web Tier
      '10.0.2.',   // Application Services
      '10.0.3.',   // Database / Storage
      '172.16.1.', // Edge Ingress / Proxies
      '172.16.2.', // Internal Microservices
      '192.168.1.',// Workstations / Clients
      '192.168.2.',// IoT / Field Devices
      '10.100.1.', // Management / Control Plane
    ];
    const prefix = subnets[subnetIdx % subnets.length];
    const host = (hostNum % 250) + 2;
    return `${prefix}${host}`;
  }

  static generateHostname(subnetIdx, hostNum) {
    const prefixes = [
      'web-edge',
      'app-srv',
      'db-node',
      'gw-proxy',
      'k8s-pod',
      'client-wk',
      'iot-sensor',
      'admin-ctl',
    ];
    const p = prefixes[subnetIdx % prefixes.length];
    return `${p}-${String(hostNum).padStart(2, '0')}`;
  }

  /**
   * Generate network topology: IP nodes positioned in 2D space + socket connections to other IPs
   */
  static generateTopology({
    nodeCount = 120,
    numSubnets = 4,
    connectionDensity = 1.3, // average outbound connections per IP
    distribution = 'blobs',
  } = {}) {
    const nodes = [];
    const subnetCenters = [];

    // Define Subnet Gateway positions in coordinate space
    for (let s = 0; s < numSubnets; s++) {
      const angle = (s / numSubnets) * Math.PI * 2 + (Math.random() * 0.4 - 0.2);
      const radius = 24 + Math.random() * 12;
      subnetCenters.push({
        subnetIdx: s,
        gatewayIP: this.generateIP(s, 1),
        x: 50 + radius * Math.cos(angle),
        y: 50 + radius * Math.sin(angle),
        spread: 7 + Math.random() * 3,
      });
    }

    // 1. Generate IP Nodes
    for (let i = 0; i < nodeCount; i++) {
      const subnetIdx = i % numSubnets;
      const center = subnetCenters[subnetIdx];

      let x, y;
      if (distribution === 'uniform') {
        x = 5 + Math.random() * 90;
        y = 5 + Math.random() * 90;
      } else {
        x = this.clamp(this.randomGaussian(center.x, center.spread));
        y = this.clamp(this.randomGaussian(center.y, center.spread));
      }

      nodes.push({
        id: i,
        ip: this.generateIP(subnetIdx, i + 2),
        hostname: this.generateHostname(subnetIdx, i + 1),
        subnetIdx,
        x: Number(x.toFixed(2)),
        y: Number(y.toFixed(2)),
        trafficMbps: Number((1.5 + Math.random() * 45).toFixed(1)),
        connections: [], // outbound sockets
      });
    }

    // 2. Generate Socket Connections between IP Addresses
    const connections = [];
    let connectionId = 0;

    for (let i = 0; i < nodes.length; i++) {
      const srcNode = nodes[i];
      // Number of outbound links for this IP
      const numLinks = Math.random() < 0.2 ? 0 : Math.floor(1 + Math.random() * (connectionDensity * 1.6));

      for (let l = 0; l < numLinks; l++) {
        // Choose destination IP
        let targetIdx = Math.floor(Math.random() * nodes.length);
        if (targetIdx === i) targetIdx = (i + 1) % nodes.length; // avoid self-loop

        const destNode = nodes[targetIdx];

        // Pick port service based on target subnet or common ports
        let portConfig;
        if (destNode.subnetIdx === 2) {
          // Database subnet prefers DB ports
          portConfig = Math.random() > 0.4 ? WELL_KNOWN_PORTS[4] : WELL_KNOWN_PORTS[5]; // MySQL or Postgres
        } else if (destNode.subnetIdx === 0 || destNode.subnetIdx === 3) {
          // Web / Proxies prefer 443 / 80 / 8080
          const webPorts = [WELL_KNOWN_PORTS[0], WELL_KNOWN_PORTS[1], WELL_KNOWN_PORTS[7]];
          portConfig = webPorts[Math.floor(Math.random() * webPorts.length)];
        } else {
          // General random port
          portConfig = WELL_KNOWN_PORTS[Math.floor(Math.random() * WELL_KNOWN_PORTS.length)];
        }

        const isCrossSubnet = srcNode.subnetIdx !== destNode.subnetIdx;
        const latencyMs = Number((isCrossSubnet ? 12 + Math.random() * 35 : 1 + Math.random() * 4).toFixed(1));
        const throughputKbps = Math.floor(50 + Math.random() * 8500);

        const conn = {
          id: connectionId++,
          srcId: srcNode.id,
          destId: destNode.id,
          srcIP: srcNode.ip,
          destIP: destNode.ip,
          destPort: portConfig.port,
          service: portConfig.service,
          proto: portConfig.proto,
          color: portConfig.color,
          category: portConfig.category,
          isCrossSubnet,
          latencyMs,
          throughputKbps,
          // Animated particle progress along vector [0.0 -> 1.0]
          packetPhase: Math.random(),
          packetSpeed: 0.008 + Math.random() * 0.012,
        };

        connections.push(conn);
        srcNode.connections.push(conn);
      }
    }

    return {
      nodes,
      connections,
      subnetGateways: subnetCenters,
    };
  }
}
