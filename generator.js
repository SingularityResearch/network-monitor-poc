/**
 * Network Port Catalog and Protocol Definitions
 * Categorizes common destination ports, services, and color tags for real network traffic.
 */

export const WELL_KNOWN_PORTS = [
  { port: 443, service: 'HTTPS', proto: 'TCP', color: '#10b981', category: 'web' },
  { port: 80, service: 'HTTP', proto: 'TCP', color: '#06b6d4', category: 'web' },
  { port: 22, service: 'SSH', proto: 'TCP', color: '#f59e0b', category: 'admin' },
  { port: 53, service: 'DNS', proto: 'UDP', color: '#3b82f6', category: 'infra' },
  { port: 67, service: 'DHCP', proto: 'UDP', color: '#6366f1', category: 'infra' },
  { port: 68, service: 'DHCP-Client', proto: 'UDP', color: '#6366f1', category: 'infra' },
  { port: 123, service: 'NTP', proto: 'UDP', color: '#8b5cf6', category: 'infra' },
  { port: 3306, service: 'MySQL', proto: 'TCP', color: '#a855f7', category: 'db' },
  { port: 5432, service: 'PostgreSQL', proto: 'TCP', color: '#ec4899', category: 'db' },
  { port: 6379, service: 'Redis', proto: 'TCP', color: '#f43f5e', category: 'cache' },
  { port: 8080, service: 'API-GW', proto: 'TCP', color: '#14b8a6', category: 'web' },
  { port: 3000, service: 'Dev-Web', proto: 'TCP', color: '#22d3ee', category: 'dev' },
  { port: 5173, service: 'Vite-Dev', proto: 'TCP', color: '#a78bfa', category: 'dev' },
  { port: 5228, service: 'GCM-Push', proto: 'TCP', color: '#f97316', category: 'cloud' },
];
