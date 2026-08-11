const DEFAULT_ACTIVITY_ROWS = 28;
const DEFAULT_ACTIVITY_COLUMNS = 36;
const DEFAULT_MATRIX_GROUPS = 24;
const MAX_ACTIVITY_ROWS = 40;
const MAX_ACTIVITY_COLUMNS = 60;
const MAX_MATRIX_GROUPS = 32;
const MAX_CELL_EVIDENCE = 200;

export const HEATMAP_MODES = Object.freeze(["graph", "activity", "matrix", "geographic"]);
export const HEATMAP_METRICS = Object.freeze(["events", "bytes", "rejects", "risk", "detections"]);
export const HEATMAP_GROUPS = Object.freeze(["entity", "subnet", "account", "port", "protocol", "source"]);

export function buildActivityHeatmap(records = [], options = {}) {
  const prepared = prepareRecords(records, options);
  const columns = boundedInteger(options.columns, 12, MAX_ACTIVITY_COLUMNS, DEFAULT_ACTIVITY_COLUMNS);
  const maxRows = boundedInteger(options.maxRows, 8, MAX_ACTIVITY_ROWS, DEFAULT_ACTIVITY_ROWS);
  const fullRange = timestampRange(prepared.allRecords);
  const viewport = viewportRange(fullRange, options.zoom, options.panRatio);
  const bucketWidth = Math.max(1, (viewport.end - viewport.start) / columns);
  const rowTotals = new Map();
  const cellMap = new Map();

  prepared.records.forEach((record) => {
    const timestamp = recordTimestamp(record);
    if (!Number.isFinite(timestamp) || timestamp < viewport.start || timestamp > viewport.end) return;
    const bucket = Math.min(columns - 1, Math.max(0, Math.floor((timestamp - viewport.start) / bucketWidth)));
    const keys = groupKeys(record, options.groupBy || "entity");
    keys.forEach((rowKey) => {
      if (!rowKey) return;
      const stats = contributionStats(record, prepared.detectionKeys);
      const value = metricValue(stats, options.metric);
      rowTotals.set(rowKey, (rowTotals.get(rowKey) || 0) + value);
      const cellKey = `${rowKey}\u0000${bucket}`;
      const cell = cellMap.get(cellKey) || emptyCell(rowKey, bucket, viewport.start + bucket * bucketWidth, viewport.start + (bucket + 1) * bucketWidth);
      addCellRecord(cell, record, stats, prepared.recordIndex.get(record));
      cellMap.set(cellKey, cell);
    });
  });

  const rankedRows = [...rowTotals.entries()].sort((left, right) => right[1] - left[1]);
  const visibleRows = rankedRows.slice(0, maxRows).map(([key, value]) => ({ key, label: key, value }));
  const visibleKeys = new Set(visibleRows.map((row) => row.key));
  const cells = [...cellMap.values()]
    .filter((cell) => visibleKeys.has(cell.rowKey))
    .map((cell) => finalizeCell(cell, options.metric));
  const maxValue = Math.max(0, ...cells.map((cell) => cell.value));

  return {
    kind: "activity",
    groupBy: normalizeGroup(options.groupBy),
    metric: normalizeMetric(options.metric),
    scale: options.scale === "linear" ? "linear" : "log",
    evidenceFilter: normalizeEvidenceFilter(options.evidenceFilter),
    rows: visibleRows,
    columns: Array.from({ length: columns }, (_, index) => ({
      index,
      start: viewport.start + index * bucketWidth,
      end: viewport.start + (index + 1) * bucketWidth
    })),
    cells,
    maxValue,
    fullStart: fullRange.start,
    fullEnd: fullRange.end,
    viewStart: viewport.start,
    viewEnd: viewport.end,
    inputRecordCount: records.length,
    matchedRecordCount: prepared.records.length,
    visibleRecordCount: uniqueEvidenceCount(cells),
    omittedRowCount: Math.max(0, rankedRows.length - visibleRows.length),
    truncated: rankedRows.length > visibleRows.length
  };
}

export function buildCommunicationMatrix(records = [], options = {}) {
  const prepared = prepareRecords(records, options);
  const maxGroups = boundedInteger(options.maxGroups, 8, MAX_MATRIX_GROUPS, DEFAULT_MATRIX_GROUPS);
  const groupBy = normalizeMatrixGroup(options.groupBy);
  const totals = new Map();
  const rawCells = new Map();

  prepared.records.forEach((record) => {
    const sourceKey = endpointGroup(record, "source", groupBy);
    const destinationKey = endpointGroup(record, "destination", groupBy);
    if (!sourceKey || !destinationKey) return;
    const stats = contributionStats(record, prepared.detectionKeys);
    const value = metricValue(stats, options.metric);
    totals.set(sourceKey, (totals.get(sourceKey) || 0) + value);
    totals.set(destinationKey, (totals.get(destinationKey) || 0) + value);
    const key = `${sourceKey}\u0000${destinationKey}`;
    const cell = rawCells.get(key) || { sourceKey, destinationKey, count: 0, bytes: 0, rejects: 0, risk: 0, detections: 0, recordIndexes: [] };
    addCellRecord(cell, record, stats, prepared.recordIndex.get(record));
    rawCells.set(key, cell);
  });

  const rankedGroups = [...totals.entries()].sort((left, right) => right[1] - left[1]);
  const groups = rankedGroups.slice(0, maxGroups).map(([key, value]) => ({ key, label: key, value }));
  const visibleKeys = new Set(groups.map((group) => group.key));
  const cells = [...rawCells.values()]
    .filter((cell) => visibleKeys.has(cell.sourceKey) && visibleKeys.has(cell.destinationKey))
    .map((cell) => finalizeCell(cell, options.metric));
  return {
    kind: "matrix",
    groupBy,
    metric: normalizeMetric(options.metric),
    scale: options.scale === "linear" ? "linear" : "log",
    evidenceFilter: normalizeEvidenceFilter(options.evidenceFilter),
    groups,
    cells,
    maxValue: Math.max(0, ...cells.map((cell) => cell.value)),
    inputRecordCount: records.length,
    matchedRecordCount: prepared.records.length,
    visibleRecordCount: uniqueEvidenceCount(cells),
    omittedGroupCount: Math.max(0, rankedGroups.length - groups.length),
    truncated: rankedGroups.length > groups.length
  };
}

export function buildGeographicHeatmap(records = [], options = {}) {
  const prepared = prepareRecords(records, options);
  const enrichment = options.enrichment || {};
  const pointMap = new Map();
  const edgeMap = new Map();
  let unresolvedEndpointCount = 0;

  prepared.records.forEach((record) => {
    const sourceGeo = resolveGeo(record.source, enrichment, options);
    const destinationGeo = resolveGeo(record.destination, enrichment, options);
    const stats = contributionStats(record, prepared.detectionKeys);
    if (!sourceGeo && isRoutableIp(record.source)) unresolvedEndpointCount += 1;
    if (!destinationGeo && isRoutableIp(record.destination)) unresolvedEndpointCount += 1;
    if (sourceGeo) addGeoPoint(pointMap, record.source, sourceGeo, record, stats, prepared.recordIndex.get(record));
    if (destinationGeo) addGeoPoint(pointMap, record.destination, destinationGeo, record, stats, prepared.recordIndex.get(record));
    if (sourceGeo && destinationGeo) {
      const key = `${sourceGeo.latitude},${sourceGeo.longitude}->${destinationGeo.latitude},${destinationGeo.longitude}`;
      const edge = edgeMap.get(key) || {
        source: sourceGeo,
        destination: destinationGeo,
        count: 0,
        bytes: 0,
        rejects: 0,
        risk: 0,
        detections: 0,
        recordIndexes: []
      };
      addCellRecord(edge, record, stats, prepared.recordIndex.get(record));
      edgeMap.set(key, edge);
    }
  });

  const points = [...pointMap.values()].map((point) => finalizeCell(point, options.metric));
  const edges = [...edgeMap.values()].map((edge) => finalizeCell(edge, options.metric));
  return {
    kind: "geographic",
    metric: normalizeMetric(options.metric),
    scale: options.scale === "linear" ? "linear" : "log",
    evidenceFilter: normalizeEvidenceFilter(options.evidenceFilter),
    points,
    edges,
    maxValue: Math.max(0, ...points.map((point) => point.value)),
    inputRecordCount: records.length,
    matchedRecordCount: prepared.records.length,
    visibleRecordCount: uniqueEvidenceCount(points),
    mappedEndpointCount: new Set(points.flatMap((point) => point.ips || [point.ip])).size,
    unresolvedEndpointCount,
    approximateEndpointCount: points.filter((point) => point.approximate).length
  };
}

export function renderActivityHeatmap(model, selection = null) {
  if (!model?.rows?.length || !model?.columns?.length) return emptyView("No activity cells", "Adjust the replay position, evidence filter, or grouping.");
  const cellByKey = new Map(model.cells.map((cell) => [`${cell.rowKey}\u0000${cell.bucket}`, cell]));
  const header = model.columns.map((column, index) => {
    const label = index % Math.max(1, Math.ceil(model.columns.length / 6)) === 0 ? shortTime(column.start) : "";
    return `<th scope="col"><span>${escapeHtml(label)}</span></th>`;
  }).join("");
  const rows = model.rows.map((row) => `<tr>
      <th scope="row" title="${escapeHtml(row.label)}">${escapeHtml(truncate(row.label, 24))}</th>
      ${model.columns.map((column) => {
        const cell = cellByKey.get(`${row.key}\u0000${column.index}`);
        const active = selection?.type === "activity" && selection.rowKey === row.key && rangesOverlap(selection.start, selection.end, column.start, column.end);
        const level = heatLevel(cell?.value || 0, model.maxValue, model.scale);
        const title = cell ? `${row.label}: ${formatMetric(cell.value, model.metric)}, ${cell.count} flows` : `${row.label}: no activity`;
        return `<td><button type="button" class="heat-cell heat-level-${level}${active ? " selected" : ""}" data-heat-kind="activity" data-heat-row="${escapeHtml(row.key)}" data-heat-start="${Math.round(column.start)}" data-heat-end="${Math.round(column.end)}" aria-label="${escapeHtml(title)}" title="${escapeHtml(title)}"></button></td>`;
      }).join("")}
    </tr>`).join("");
  return `<div class="heatmap-table-wrap" data-heatmap-scroll><table class="heatmap-table activity-table"><thead><tr><th scope="col">${escapeHtml(groupLabel(model.groupBy))}</th>${header}</tr></thead><tbody>${rows}</tbody></table></div>`;
}

export function renderCommunicationMatrix(model, selection = null) {
  if (!model?.groups?.length) return emptyView("No communication matrix", "No source-to-destination paths match the current evidence policy.");
  const cellByKey = new Map(model.cells.map((cell) => [`${cell.sourceKey}\u0000${cell.destinationKey}`, cell]));
  const header = model.groups.map((group) => `<th scope="col" title="${escapeHtml(group.label)}"><span>${escapeHtml(truncate(group.label, 12))}</span></th>`).join("");
  const rows = model.groups.map((source) => `<tr>
      <th scope="row" title="${escapeHtml(source.label)}">${escapeHtml(truncate(source.label, 22))}</th>
      ${model.groups.map((destination) => {
        const cell = cellByKey.get(`${source.key}\u0000${destination.key}`);
        const active = selection?.type === "matrix" && selection.sourceKey === source.key && selection.destinationKey === destination.key;
        const level = heatLevel(cell?.value || 0, model.maxValue, model.scale);
        const title = cell ? `${source.label} to ${destination.label}: ${formatMetric(cell.value, model.metric)}, ${cell.count} flows` : `${source.label} to ${destination.label}: no observed traffic`;
        return `<td><button type="button" class="heat-cell heat-level-${level}${active ? " selected" : ""}" data-heat-kind="matrix" data-heat-source="${escapeHtml(source.key)}" data-heat-destination="${escapeHtml(destination.key)}" aria-label="${escapeHtml(title)}" title="${escapeHtml(title)}"></button></td>`;
      }).join("")}
    </tr>`).join("");
  return `<div class="heatmap-table-wrap" data-heatmap-scroll><table class="heatmap-table matrix-table"><thead><tr><th scope="col">Source / destination</th>${header}</tr></thead><tbody>${rows}</tbody></table></div>`;
}

export function renderGeographicHeatmap(model, options = {}) {
  const width = 1000;
  const height = 480;
  const zoom = clamp(Number(options.zoom) || 1, 1, 4);
  const panX = clamp(Number(options.panX) || 0, -1, 1) * (width * 0.22) * (zoom - 1);
  const panY = clamp(Number(options.panY) || 0, -1, 1) * (height * 0.18) * (zoom - 1);
  const transform = `translate(${width / 2 - panX} ${height / 2 - panY}) scale(${zoom}) translate(${-width / 2} ${-height / 2})`;
  const maxEdgeValue = Math.max(1, ...(model?.edges || []).map((edge) => edge.value));
  const edges = (model?.edges || []).slice(0, 120).map((edge) => {
    const source = geoPoint(edge.source.latitude, edge.source.longitude, width, height);
    const destination = geoPoint(edge.destination.latitude, edge.destination.longitude, width, height);
    const strokeWidth = 0.6 + Math.min(3.4, (edge.value / maxEdgeValue) * 3.4);
    const midX = (source.x + destination.x) / 2;
    const midY = Math.min(source.y, destination.y) - Math.min(70, Math.abs(source.x - destination.x) * 0.12);
    return `<path class="geo-edge" d="M ${source.x} ${source.y} Q ${midX} ${midY} ${destination.x} ${destination.y}" stroke-width="${strokeWidth}"><title>${escapeHtml(`${edge.count} correlated flows`)}</title></path>`;
  }).join("");
  const points = (model?.points || []).map((point) => {
    const position = geoPoint(point.latitude, point.longitude, width, height);
    const radius = 4 + heatLevel(point.value, model.maxValue, model.scale) * 0.85;
    const ips = point.ips || [point.ip];
    const selected = options.selection?.type === "geographic" && (options.selection.ips || [options.selection.ip]).some((ip) => ips.includes(ip));
    const endpointLabel = ips.length === 1 ? ips[0] : `${ips.length} endpoints`;
    const title = `${endpointLabel}: ${point.label || "mapped location"}, ${formatMetric(point.value, model.metric)}${point.approximate ? ", approximate location" : ""}`;
    return `<g class="geo-point-button" role="button" tabindex="0" data-heat-kind="geographic" data-heat-ip="${escapeHtml(point.ip)}" data-heat-ips="${escapeHtml(ips.join(","))}" aria-label="${escapeHtml(title)}"><circle class="geo-point${point.approximate ? " approximate" : ""}${selected ? " selected" : ""}" cx="${position.x}" cy="${position.y}" r="${radius}"><title>${escapeHtml(title)}</title></circle></g>`;
  }).join("");
  const content = points || `<text class="geo-empty-label" x="500" y="240" text-anchor="middle">No geolocated public endpoints</text>`;
  return `<div class="geo-map-wrap"><svg class="geo-map" viewBox="0 0 ${width} ${height}" role="img" aria-label="Geographic network activity heatmap"><defs><clipPath id="geo-map-clip"><rect width="${width}" height="${height}" rx="7"/></clipPath></defs><g clip-path="url(#geo-map-clip)"><rect class="geo-ocean" width="${width}" height="${height}"/><g transform="${transform}">${renderMapGrid(width, height)}${renderWorldLand()}${edges}${content}</g></g></svg></div>`;
}

export function recordMatchesHeatmapSelection(record, selection) {
  if (!selection) return true;
  if (selection.type === "activity") {
    const timestamp = recordTimestamp(record);
    if (!Number.isFinite(timestamp) || timestamp < selection.start || timestamp > selection.end) return false;
    return groupKeys(record, selection.groupBy || "entity").includes(selection.rowKey);
  }
  if (selection.type === "matrix") {
    return endpointGroup(record, "source", selection.groupBy) === selection.sourceKey && endpointGroup(record, "destination", selection.groupBy) === selection.destinationKey;
  }
  if (selection.type === "geographic") {
    const ips = selection.ips || [selection.ip];
    return ips.includes(record.source) || ips.includes(record.destination);
  }
  return true;
}

export function recordEvidenceKey(record) {
  return [record.source, record.destination, Number(record.srcPort) || 0, Number(record.dstPort) || 0, recordTimestamp(record)].join("|");
}

export function eventEvidenceKey(event) {
  return [event.sourceIp || event.source, event.destinationIp || event.destination, Number(event.sourcePort || event.srcPort) || 0, Number(event.destinationPort || event.dstPort) || 0, eventTimestamp(event)].join("|");
}

function prepareRecords(records, options) {
  const allRecords = Array.isArray(records) ? records : [];
  const detectionKeys = options.detectionKeys instanceof Set ? options.detectionKeys : new Set(options.detectionKeys || []);
  const stitchedKeys = options.stitchedKeys instanceof Set ? options.stitchedKeys : new Set(options.stitchedKeys || []);
  const evidenceFilter = normalizeEvidenceFilter(options.evidenceFilter);
  const filtered = allRecords.filter((record) => {
    if (evidenceFilter === "detections") return detectionKeys.has(recordEvidenceKey(record));
    if (evidenceFilter === "stitched") return stitchedKeys.has(recordEvidenceKey(record));
    return true;
  });
  return { allRecords, records: filtered, detectionKeys, stitchedKeys, recordIndex: new Map(allRecords.map((record, index) => [record, index])) };
}

function timestampRange(records) {
  const timestamps = records.map(recordTimestamp).filter(Number.isFinite).sort((a, b) => a - b);
  if (!timestamps.length) {
    const now = Date.now();
    return { start: now - 60 * 60 * 1000, end: now };
  }
  const start = timestamps[0];
  const end = timestamps[timestamps.length - 1];
  return { start, end: end > start ? end : start + 60 * 1000 };
}

function viewportRange(fullRange, zoomValue, panValue) {
  const zoom = clamp(Number(zoomValue) || 1, 1, 8);
  const pan = clamp(Number(panValue) || 0, 0, 1);
  const span = fullRange.end - fullRange.start;
  const viewSpan = Math.max(1000, span / zoom);
  const available = Math.max(0, span - viewSpan);
  const start = fullRange.start + available * pan;
  return { start, end: Math.min(fullRange.end, start + viewSpan) };
}

function groupKeys(record, groupBy) {
  const group = normalizeGroup(groupBy);
  if (group === "entity") return unique([record.source, record.destination].filter(validKey));
  if (group === "subnet") return unique([subnet(record.source), subnet(record.destination)].filter(validKey));
  if (group === "account") return [record.accountId || "Unknown account"];
  if (group === "port") return [record.dstPort ? `${record.dstPort}` : "No destination port"];
  if (group === "protocol") return [record.protocol || "Unknown protocol"];
  return [record.evidenceSource || "Unknown source"];
}

function endpointGroup(record, side, groupBy) {
  if (groupBy === "subnet") return subnet(record[side]);
  if (groupBy === "account") return record.accountId || "Unknown account";
  if (groupBy === "source") return record.evidenceSource || "Unknown source";
  return validKey(record[side]) ? record[side] : "";
}

function contributionStats(record, detectionKeys) {
  return {
    count: 1,
    bytes: Math.max(0, Number(record.bytes) || 0),
    rejects: String(record.action).toUpperCase() === "REJECT" ? 1 : 0,
    risk: riskWeight(record),
    detections: detectionKeys.has(recordEvidenceKey(record)) ? 1 : 0
  };
}

function riskWeight(record) {
  let score = 1;
  if (String(record.action).toUpperCase() === "REJECT") score += 2;
  if ([22, 23, 445, 1433, 2375, 3389, 5432, 6379, 9200, 27017].includes(Number(record.dstPort))) score += 3;
  if (isRoutableIp(record.destination) && Number(record.bytes) >= 1_000_000) score += 4;
  return score;
}

function metricValue(stats, metric) {
  const normalized = normalizeMetric(metric);
  return normalized === "events" ? stats.count || 0 : stats[normalized] || 0;
}

function emptyCell(rowKey, bucket, start, end) {
  return { rowKey, bucket, start, end, count: 0, bytes: 0, rejects: 0, risk: 0, detections: 0, recordIndexes: [] };
}

function addCellRecord(cell, record, stats, recordIndex) {
  cell.count += stats.count;
  cell.bytes += stats.bytes;
  cell.rejects += stats.rejects;
  cell.risk += stats.risk;
  cell.detections += stats.detections;
  if (Number.isInteger(recordIndex) && cell.recordIndexes.length < MAX_CELL_EVIDENCE && !cell.recordIndexes.includes(recordIndex)) cell.recordIndexes.push(recordIndex);
}

function finalizeCell(cell, metric) {
  return { ...cell, value: metricValue(cell, metric) };
}

function addGeoPoint(points, ip, geo, record, stats, recordIndex) {
  const locationKey = geo.city || geo.country
    ? `${geo.city || "unknown-city"}|${geo.region || ""}|${geo.country || "unknown-country"}|${geo.approximate ? "approximate" : "exact"}`
    : `${geo.latitude.toFixed(1)}|${geo.longitude.toFixed(1)}|${geo.approximate ? "approximate" : "exact"}`;
  const key = locationKey;
  const point = points.get(key) || {
    ip,
    ips: [],
    latitude: geo.latitude,
    longitude: geo.longitude,
    label: geo.label,
    country: geo.country,
    city: geo.city,
    source: geo.source,
    approximate: Boolean(geo.approximate),
    count: 0,
    bytes: 0,
    rejects: 0,
    risk: 0,
    detections: 0,
    recordIndexes: []
  };
  if (!point.ips.includes(ip)) point.ips.push(ip);
  addCellRecord(point, record, stats, recordIndex);
  points.set(key, point);
}

function resolveGeo(ip, enrichment, options) {
  if (!isRoutableIp(ip)) return null;
  const entry = enrichment[ip] || {};
  const latitude = finiteCoordinate(entry.latitude ?? entry.lat, -90, 90);
  const longitude = finiteCoordinate(entry.longitude ?? entry.lon ?? entry.lng, -180, 180);
  if (latitude !== null && longitude !== null) {
    return {
      latitude,
      longitude,
      country: entry.country || "",
      city: entry.city || "",
      label: [entry.city, entry.region, entry.country].filter(Boolean).join(", ") || "Imported location",
      source: entry.geoSource || entry.source || "analyst enrichment",
      approximate: entry.geoPrecision !== "exact"
    };
  }
  if (options.allowDemoCoordinates !== false) return demoGeo(ip);
  return null;
}

function demoGeo(ip) {
  const last = Number(String(ip).split(".")[3]) || 0;
  if (String(ip).startsWith("192.0.2.")) return { latitude: 37.77 + (last % 5) * 0.12, longitude: -122.42 + (last % 7) * 0.09, country: "US", city: "Demo West", label: "Demonstration location", source: "TEST-NET fixture", approximate: true };
  if (String(ip).startsWith("198.51.100.")) return { latitude: 40.71 + (last % 5) * 0.1, longitude: -74.0 + (last % 7) * 0.08, country: "US", city: "Demo East", label: "Demonstration location", source: "TEST-NET fixture", approximate: true };
  if (String(ip).startsWith("203.0.113.")) return { latitude: 51.5 + (last % 5) * 0.1, longitude: -0.12 + (last % 7) * 0.08, country: "GB", city: "Demo Europe", label: "Demonstration location", source: "TEST-NET fixture", approximate: true };
  return null;
}

function renderMapGrid(width, height) {
  const longitudeLines = Array.from({ length: 11 }, (_, index) => `<line class="geo-grid-line" x1="${index * width / 10}" y1="0" x2="${index * width / 10}" y2="${height}"/>`).join("");
  const latitudeLines = Array.from({ length: 7 }, (_, index) => `<line class="geo-grid-line" x1="0" y1="${index * height / 6}" x2="${width}" y2="${index * height / 6}"/>`).join("");
  return longitudeLines + latitudeLines;
}

function renderWorldLand() {
  return `<g class="geo-land">
    <path d="M55 105 L105 58 190 55 245 95 265 150 228 185 185 178 155 218 115 195 85 153Z"/>
    <path d="M210 220 L262 232 300 290 283 365 245 425 220 360 228 292 195 250Z"/>
    <path d="M423 92 L470 65 530 78 560 115 535 142 480 135 452 160 420 140Z"/>
    <path d="M445 170 L520 160 570 210 552 295 505 372 463 318 435 242Z"/>
    <path d="M535 95 L640 70 745 82 820 125 885 120 930 165 880 205 795 200 735 238 675 210 618 168 560 150Z"/>
    <path d="M785 300 L835 280 900 305 927 350 885 385 820 370 780 337Z"/>
    <path d="M940 405 L962 392 975 410 955 427Z"/>
  </g>`;
}

function geoPoint(latitude, longitude, width, height) {
  return { x: ((longitude + 180) / 360) * width, y: ((90 - latitude) / 180) * height };
}

function heatLevel(value, maxValue, scale) {
  if (!value || !maxValue) return 0;
  const ratio = scale === "linear" ? value / maxValue : Math.log1p(value) / Math.log1p(maxValue);
  return Math.max(1, Math.min(9, Math.ceil(ratio * 9)));
}

function uniqueEvidenceCount(cells) {
  return new Set(cells.flatMap((cell) => cell.recordIndexes || [])).size;
}

function normalizeMetric(metric) {
  return HEATMAP_METRICS.includes(metric) ? metric : "events";
}

function normalizeGroup(group) {
  return HEATMAP_GROUPS.includes(group) ? group : "entity";
}

function normalizeMatrixGroup(group) {
  return ["entity", "subnet", "account", "source"].includes(group) ? group : "entity";
}

function normalizeEvidenceFilter(filter) {
  return ["all", "detections", "stitched"].includes(filter) ? filter : "all";
}

function groupLabel(group) {
  return { entity: "Entity", subnet: "Subnet", account: "Account", port: "Port", protocol: "Protocol", source: "Evidence source" }[group] || "Entity";
}

function subnet(ip) {
  const parts = String(ip || "").split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return validKey(ip) ? ip : "";
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function isRoutableIp(ip) {
  const parts = String(ip || "").split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b, c] = parts;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  if (a === 192 && b === 0 && c === 0) return false;
  return true;
}

function recordTimestamp(record) {
  const value = Number(record?.start ?? record?.timestamp);
  if (!Number.isFinite(value)) return NaN;
  return value < 10_000_000_000 ? value * 1000 : value;
}

function eventTimestamp(event) {
  const value = Number(event?.timestampMs ?? event?.start ?? event?.timestamp);
  if (Number.isFinite(value)) return value < 10_000_000_000 ? value * 1000 : value;
  const parsed = Date.parse(event?.timestamp || event?.createdAt || "");
  return Number.isFinite(parsed) ? parsed : NaN;
}

function shortTime(timestamp) {
  return new Date(timestamp).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function formatMetric(value, metric) {
  if (metric !== "bytes") return `${Math.round(value).toLocaleString()} ${metric}`;
  const units = ["B", "KB", "MB", "GB", "TB"];
  let amount = Number(value) || 0;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  return `${amount.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

function finiteCoordinate(value, minimum, maximum) {
  if (value === "" || value === null || value === undefined) return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= minimum && number <= maximum ? number : null;
}

function boundedInteger(value, minimum, maximum, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.max(minimum, Math.min(maximum, Math.round(parsed))) : fallback;
}

function rangesOverlap(aStart, aEnd, bStart, bEnd) {
  return Number(aStart) <= Number(bEnd) && Number(aEnd) >= Number(bStart);
}

function validKey(value) {
  return Boolean(value && value !== "-");
}

function unique(values) {
  return [...new Set(values)];
}

function truncate(value, length) {
  const text = String(value || "");
  return text.length > length ? `${text.slice(0, length - 1)}...` : text;
}

function clamp(value, minimum, maximum) {
  return Math.max(minimum, Math.min(maximum, value));
}

function escapeHtml(value) {
  return String(value ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function emptyView(title, copy) {
  return `<div class="empty-state"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(copy)}</span></div>`;
}
