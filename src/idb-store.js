const DB_NAME = "ndr-flow-console";
const DB_VERSION = 3;

let dbPromise;
let activeScope = "signed-out";
let activeEncryptionKey = null;
let storagePolicy = { enabled: false, retentionDays: 7, maxRecords: 50_000 };

export async function setStorageScope(scope, sessionBinding = "") {
  activeScope = String(scope || "signed-out").slice(0, 240);
  activeEncryptionKey = sessionBinding ? await deriveStorageKey(activeScope, sessionBinding) : null;
}

export async function setStoragePolicy(policy = {}) {
  storagePolicy = {
    enabled: policy.enabled !== false,
    retentionDays: Math.max(1, Math.min(90, Number(policy.retentionDays || 7))),
    maxRecords: Math.max(1000, Math.min(250_000, Number(policy.maxRecords || 50_000)))
  };
  if (!storagePolicy.enabled) await clearAllStorage();
  else await purgeExpiredStorage();
}

export async function openNdrDb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (event) => {
      const db = request.result;
      if (!db.objectStoreNames.contains("evidenceRuns")) {
        const runs = db.createObjectStore("evidenceRuns", { keyPath: "id" });
        runs.createIndex("scope", "scope");
      }
      if (!db.objectStoreNames.contains("records")) {
        const records = db.createObjectStore("records", { keyPath: "id" });
        records.createIndex("runId", "runId");
        records.createIndex("source", "source");
        records.createIndex("destination", "destination");
        records.createIndex("scope", "scope");
      }
      if (!db.objectStoreNames.contains("cases")) {
        const cases = db.createObjectStore("cases", { keyPath: "id" });
        cases.createIndex("status", "status");
        cases.createIndex("severity", "severity");
        cases.createIndex("scope", "scope");
      }
      if (!db.objectStoreNames.contains("auditLog")) {
        const audit = db.createObjectStore("auditLog", { keyPath: "id" });
        audit.createIndex("caseId", "caseId");
        audit.createIndex("scope", "scope");
      }
      const upgrade = request.transaction;
      ["evidenceRuns", "records", "cases", "auditLog"].forEach((storeName) => {
        const store = upgrade.objectStore(storeName);
        if (!store.indexNames.contains("scope")) store.createIndex("scope", "scope");
        if (event.oldVersion > 0 && event.oldVersion < 3) store.clear();
      });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  return dbPromise;
}

export async function saveEvidenceRun({ fileName, records, analysis }) {
  if (!storagePolicy.enabled || !activeEncryptionKey || !("indexedDB" in window)) return null;
  const db = await openNdrDb();
  const id = scopedId("run");
  const run = {
    id,
    scope: activeScope,
    fileName,
    createdAt: new Date().toISOString(),
    expiresAt: expiresAt(),
    recordCount: records.length,
    detectionCount: analysis?.detections?.length || 0,
    highCount: (analysis?.detections || []).filter((detection) => detection.severity === "high").length,
    bytes: analysis?.totals?.bytes || 0
  };
  await txPut(db, "evidenceRuns", await sealRecord("evidenceRuns", run));
  await txBulkPut(
    db,
    "records",
    await Promise.all(records.slice(0, storagePolicy.maxRecords).map((record, index) => sealRecord("records", { ...record, id: `${id}-${index}`, runId: id, scope: activeScope, expiresAt: expiresAt() })))
  );
  return run;
}

export async function listEvidenceRuns() {
  if (!storagePolicy.enabled || !activeEncryptionKey || !("indexedDB" in window)) return [];
  const db = await openNdrDb();
  const runs = await decryptRecords("evidenceRuns", await txAllByScope(db, "evidenceRuns"));
  return runs.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function saveCase(caseRecord) {
  if (!storagePolicy.enabled || !activeEncryptionKey) throw new Error("Local evidence storage is disabled or not bound to an authenticated session");
  const db = await openNdrDb();
  const now = new Date().toISOString();
  const record = {
    ...caseRecord,
    id: caseRecord.id || scopedId("case"),
    scope: activeScope,
    createdAt: caseRecord.createdAt || now,
    updatedAt: now,
    expiresAt: expiresAt()
  };
  await txPut(db, "cases", await sealRecord("cases", record));
  await appendAudit(record.id, caseRecord.auditAction || "Case saved", caseRecord.auditDetail || record.title);
  return record;
}

export async function listCases() {
  if (!storagePolicy.enabled || !activeEncryptionKey) return [];
  const db = await openNdrDb();
  const cases = await decryptRecords("cases", await txAllByScope(db, "cases"));
  return cases.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

export async function deleteCase(id) {
  const db = await openNdrDb();
  const record = await txGet(db, "cases", id);
  if (!record || record.scope !== activeScope) throw new Error("Case is outside the active storage scope");
  await txDelete(db, "cases", id);
  await appendAudit(id, "Case deleted", id);
}

export async function appendAudit(caseId, action, detail = "") {
  if (!storagePolicy.enabled || !activeEncryptionKey) return null;
  const db = await openNdrDb();
  const entry = {
    id: scopedId("audit"),
    scope: activeScope,
    caseId,
    action,
    detail,
    createdAt: new Date().toISOString(),
    expiresAt: expiresAt()
  };
  await txPut(db, "auditLog", await sealRecord("auditLog", entry));
  return entry;
}

export async function listAudit(caseId) {
  if (!storagePolicy.enabled || !activeEncryptionKey) return [];
  const db = await openNdrDb();
  const entries = await decryptRecords("auditLog", await txAllByScope(db, "auditLog"));
  return entries.filter((entry) => entry.caseId === caseId).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function clearStorageScope() {
  if (!("indexedDB" in window)) return;
  const db = await openNdrDb();
  await Promise.all(["evidenceRuns", "records", "cases", "auditLog"].map((storeName) => txDeleteScope(db, storeName)));
}

export async function clearAllStorage() {
  if (!("indexedDB" in window)) return;
  const db = await openNdrDb();
  await Promise.all(["evidenceRuns", "records", "cases", "auditLog"].map((storeName) => txClear(db, storeName)));
}

async function purgeExpiredStorage() {
  if (!("indexedDB" in window)) return;
  const db = await openNdrDb();
  const cutoff = Date.now();
  for (const storeName of ["evidenceRuns", "records", "cases", "auditLog"]) {
    const values = await txAll(db, storeName);
    const expired = values.filter((value) => value.expiresAt && Date.parse(value.expiresAt) <= cutoff);
    await Promise.all(expired.map((value) => txDelete(db, storeName, value.id)));
  }
}

function expiresAt() {
  return new Date(Date.now() + storagePolicy.retentionDays * 86400_000).toISOString();
}

function scopedId(prefix) {
  const random = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${activeScope}:${prefix}-${random}`;
}

function txPut(db, storeName, value) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    tx.objectStore(storeName).put(value);
    tx.oncomplete = () => resolve(value);
    tx.onerror = () => reject(tx.error);
  });
}

function txClear(db, storeName) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    tx.objectStore(storeName).clear();
    tx.oncomplete = () => resolve();
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

function txGet(db, storeName, key) {
  return new Promise((resolve, reject) => {
    const request = db.transaction(storeName, "readonly").objectStore(storeName).get(key);
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
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

function txAllByScope(db, storeName) {
  return new Promise((resolve, reject) => {
    const request = db.transaction(storeName, "readonly").objectStore(storeName).index("scope").getAll(activeScope);
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = () => reject(request.error);
  });
}

function txDeleteScope(db, storeName) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    const request = tx.objectStore(storeName).index("scope").openKeyCursor(activeScope);
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) return;
      tx.objectStore(storeName).delete(cursor.primaryKey);
      cursor.continue();
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
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

async function deriveStorageKey(scope, sessionBinding) {
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto is required for encrypted browser evidence storage");
  const material = new TextEncoder().encode(`${scope}\0${sessionBinding}`);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", material);
  return globalThis.crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function sealRecord(storeName, value) {
  if (!activeEncryptionKey) throw new Error("Browser evidence encryption key is unavailable");
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(`${storeName}\0${value.scope}\0${value.id}`);
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, activeEncryptionKey, plaintext);
  return { id: value.id, scope: value.scope, expiresAt: value.expiresAt, sealed: true, iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext)) };
}

async function decryptRecords(storeName, records) {
  const decrypted = await Promise.all((records || []).map(async (record) => {
    if (!record.sealed || !activeEncryptionKey) return null;
    try {
      const iv = base64ToBytes(record.iv);
      const aad = new TextEncoder().encode(`${storeName}\0${record.scope}\0${record.id}`);
      const plaintext = await globalThis.crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, activeEncryptionKey, base64ToBytes(record.ciphertext));
      return JSON.parse(new TextDecoder().decode(plaintext));
    } catch {
      return null;
    }
  }));
  return decrypted.filter(Boolean);
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(String(value || "")), (character) => character.charCodeAt(0));
}
