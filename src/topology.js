export function buildTopology(records, currentTime = Infinity) {
  const nodes = new Map();
  const edges = new Map();
  records
    .filter((record) => !Number.isFinite(record.start) || record.start <= currentTime)
    .forEach((record) => {
      if (!record.source || !record.destination || record.source === "-" || record.destination === "-") return;
      ensureNode(nodes, record.source, record);
      ensureNode(nodes, record.destination, record);
      const key = `${record.source}->${record.destination}:${record.dstPort || "*"}`;
      const edge = edges.get(key) || {
        key,
        source: record.source,
        destination: record.destination,
        port: record.dstPort || "*",
        protocol: record.protocol,
        bytes: 0,
        packets: 0,
        count: 0,
        rejected: 0
      };
      edge.bytes += record.bytes || 0;
      edge.packets += record.packets || 0;
      edge.count += 1;
      if (record.action === "REJECT") edge.rejected += 1;
      edges.set(key, edge);
    });
  return {
    nodes: [...nodes.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 40),
    edges: [...edges.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 80)
  };
}

export function renderTopologySvg(topology, { width = 900, height = 420 } = {}) {
  if (!topology.nodes.length) {
    return `<div class="empty-state"><strong>No topology yet</strong><span>Load evidence to map entity paths.</span></div>`;
  }
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.min(width, height) * 0.34;
  const positions = new Map();
  topology.nodes.forEach((node, index) => {
    const angle = (index / topology.nodes.length) * Math.PI * 2 - Math.PI / 2;
    positions.set(node.key, {
      x: centerX + Math.cos(angle) * radius,
      y: centerY + Math.sin(angle) * radius
    });
  });
  const maxBytes = Math.max(...topology.edges.map((edge) => edge.bytes), 1);
  const edgeMarkup = topology.edges
    .map((edge) => {
      const source = positions.get(edge.source);
      const destination = positions.get(edge.destination);
      if (!source || !destination) return "";
      const widthValue = Math.max(1, Math.min(8, (edge.bytes / maxBytes) * 8));
      const color = edge.rejected ? "#b93838" : "#247080";
      return `<line x1="${source.x}" y1="${source.y}" x2="${destination.x}" y2="${destination.y}" stroke="${color}" stroke-width="${widthValue}" stroke-opacity="0.45"><title>${escapeXml(edge.source)} to ${escapeXml(edge.destination)}:${escapeXml(edge.port)} ${formatBytes(edge.bytes)}</title></line>`;
    })
    .join("");
  const nodeMarkup = topology.nodes
    .map((node) => {
      const pos = positions.get(node.key);
      const size = Math.max(7, Math.min(18, Math.sqrt(node.bytes || 1) / 120));
      return `<g>
        <circle cx="${pos.x}" cy="${pos.y}" r="${size}" fill="${node.public ? "#a86114" : "#22745a"}"><title>${escapeXml(node.key)} ${formatBytes(node.bytes)}</title></circle>
        <text x="${pos.x}" y="${pos.y + size + 12}" text-anchor="middle" font-size="10" fill="#1f2520">${escapeXml(truncate(node.key, 18))}</text>
      </g>`;
    })
    .join("");
  return `<svg class="topology-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="Network topology">${edgeMarkup}${nodeMarkup}</svg>`;
}

function ensureNode(nodes, key, record) {
  const node = nodes.get(key) || { key, bytes: 0, packets: 0, count: 0, public: isPublicIp(key) };
  node.bytes += record.bytes || 0;
  node.packets += record.packets || 0;
  node.count += 1;
  nodes.set(key, node);
}

function isPublicIp(ip) {
  const parts = String(ip).split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part))) return false;
  const [a, b] = parts;
  if (a === 0 || a === 127 || a >= 224) return false;
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return false;
  if (a === 169 && b === 254) return false;
  return true;
}

function truncate(value, length) {
  return value.length > length ? `${value.slice(0, length - 1)}...` : value;
}

function escapeXml(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = Number(bytes) || 0;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(index ? 1 : 0)} ${units[index]}`;
}
