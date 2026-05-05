const DB_NAME = "ndr-flow-console";
const DB_VERSION = 1;

let dbPromise;

export async function openNdrDb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("evidenceRuns")) {
        db.createObjectStore("evidenceRuns", { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains("records")) {
        const records = db.createObjectStore("records", { keyPath: "id" });
        records.createIndex("runId", "runId");
        records.createIndex("source", "source");
        records.createIndex("destination", "destination");
      }
      if (!db.objectStoreNames.contains("cases")) {
        const cases = db.createObjectStore("cases", { keyPath: "id" });
        cases.createIndex("status", "status");
        cases.createIndex("severity", "severity");
      }
      if (!db.objectStoreNames.contains("auditLog")) {
        const audit = db.createObjectStore("auditLog", { keyPath: "id" });
        audit.createIndex("caseId", "caseId");
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  return dbPromise;
}

export async function saveEvidenceRun({ fileName, records, analysis }) {
  if (!("indexedDB" in window)) return null;
  const db = await openNdrDb();
  const id = `run-${Date.now()}`;
  const run = {
    id,
    fileName,
    createdAt: new Date().toISOString(),
    recordCount: records.length,
    detectionCount: analysis?.detections?.length || 0,
    highCount: (analysis?.detections || []).filter((detection) => detection.severity === "high").length,
    bytes: analysis?.totals?.bytes || 0
  };
  await txPut(db, "evidenceRuns", run);
  await txBulkPut(
    db,
    "records",
    records.map((record, index) => ({ ...record, id: `${id}-${index}`, runId: id }))
  );
  return run;
}

export async function listEvidenceRuns() {
  if (!("indexedDB" in window)) return [];
  const db = await openNdrDb();
  return txAll(db, "evidenceRuns").then((runs) => runs.sort((a, b) => b.createdAt.localeCompare(a.createdAt)));
}

export async function saveCase(caseRecord) {
  const db = await openNdrDb();
  const now = new Date().toISOString();
  const record = {
    ...caseRecord,
    id: caseRecord.id || `case-${Date.now()}`,
    createdAt: caseRecord.createdAt || now,
    updatedAt: now
  };
  await txPut(db, "cases", record);
  await appendAudit(record.id, caseRecord.auditAction || "Case saved", caseRecord.auditDetail || record.title);
  return record;
}

export async function listCases() {
  const db = await openNdrDb();
  return txAll(db, "cases").then((cases) => cases.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)));
}

export async function deleteCase(id) {
  const db = await openNdrDb();
  await txDelete(db, "cases", id);
  await appendAudit(id, "Case deleted", id);
}

export async function appendAudit(caseId, action, detail = "") {
  const db = await openNdrDb();
  const entry = {
    id: `audit-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    caseId,
    action,
    detail,
    createdAt: new Date().toISOString()
  };
  await txPut(db, "auditLog", entry);
  return entry;
}

export async function listAudit(caseId) {
  const db = await openNdrDb();
  const entries = await txAll(db, "auditLog");
  return entries.filter((entry) => entry.caseId === caseId).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

function txPut(db, storeName, value) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    tx.objectStore(storeName).put(value);
    tx.oncomplete = () => resolve(value);
    tx.onerror = () => reject(tx.error);
  });
}

function txBulkPut(db, storeName, values) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    const store = tx.objectStore(storeName);
    values.forEach((value) => store.put(value));
    tx.oncomplete = () => resolve(values);
    tx.onerror = () => reject(tx.error);
  });
}

function txAll(db, storeName) {
  return new Promise((resolve, reject) => {
    const request = db.transaction(storeName, "readonly").objectStore(storeName).getAll();
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = () => reject(request.error);
  });
}

function txDelete(db, storeName, key) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    tx.objectStore(storeName).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
