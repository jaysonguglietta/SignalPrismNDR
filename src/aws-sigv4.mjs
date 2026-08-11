import { createHash, createHmac } from "node:crypto";

export function createSignedAwsRequest({
  accessKeyId,
  secretAccessKey,
  sessionToken = "",
  service,
  region,
  method,
  host,
  path,
  query = {},
  headers = {},
  body = "",
  date = new Date()
}) {
  if (!accessKeyId || !secretAccessKey) throw new Error("AWS credentials are required for SigV4 signing");
  const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const bodyBuffer = Buffer.isBuffer(body) ? body : Buffer.from(body);
  const canonicalQuery = Object.entries(query)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${encodeRfc3986(key)}=${encodeRfc3986(value)}`)
    .join("&");
  const normalizedHeaders = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
  const signedHeaders = {
    host,
    "x-amz-content-sha256": sha256(bodyBuffer),
    "x-amz-date": amzDate,
    ...normalizedHeaders
  };
  if (sessionToken) signedHeaders["x-amz-security-token"] = sessionToken;
  const signedHeaderNames = Object.keys(signedHeaders)
    .sort()
    .map((key) => key.toLowerCase())
    .join(";");
  const canonicalHeaders = Object.keys(signedHeaders)
    .sort()
    .map((key) => `${key.toLowerCase()}:${String(signedHeaders[key]).trim()}\n`)
    .join("");
  const canonicalRequest = [method, path, canonicalQuery, canonicalHeaders, signedHeaderNames, sha256(bodyBuffer)].join("\n");
  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonicalRequest)].join("\n");
  const signingKey = getSignatureKey(secretAccessKey, dateStamp, region, service);
  const signature = hmac(signingKey, stringToSign, "hex");
  const authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaderNames}, Signature=${signature}`;
  const url = `https://${host}${path}${canonicalQuery ? `?${canonicalQuery}` : ""}`;
  return {
    url,
    headers: { ...signedHeaders, authorization },
    canonicalRequest,
    stringToSign,
    signature,
    signedHeaderNames
  };
}

export function createPresignedAwsUrl({
  accessKeyId,
  secretAccessKey,
  sessionToken = "",
  service,
  region,
  method = "GET",
  host,
  path,
  query = {},
  headers = {},
  expiresSeconds = 900,
  date = new Date()
}) {
  if (!accessKeyId || !secretAccessKey) throw new Error("AWS credentials are required for SigV4 presigning");
  const expires = Math.max(1, Math.min(604800, Number(expiresSeconds) || 900));
  const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const normalizedHeaders = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), String(value).trim()]));
  const signedHeaders = { host, ...normalizedHeaders };
  const signedHeaderNames = Object.keys(signedHeaders).sort().join(";");
  const signingQuery = {
    ...query,
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Credential": `${accessKeyId}/${scope}`,
    "X-Amz-Date": amzDate,
    "X-Amz-Expires": String(expires),
    "X-Amz-SignedHeaders": signedHeaderNames
  };
  if (sessionToken) signingQuery["X-Amz-Security-Token"] = sessionToken;
  const canonicalQuery = canonicalizeQuery(signingQuery);
  const canonicalHeaders = Object.keys(signedHeaders).sort().map((key) => `${key}:${signedHeaders[key]}\n`).join("");
  const canonicalRequest = [method.toUpperCase(), path, canonicalQuery, canonicalHeaders, signedHeaderNames, "UNSIGNED-PAYLOAD"].join("\n");
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonicalRequest)].join("\n");
  const signature = hmac(getSignatureKey(secretAccessKey, dateStamp, region, service), stringToSign, "hex");
  return {
    url: `https://${host}${path}?${canonicalQuery}&X-Amz-Signature=${signature}`,
    headers: normalizedHeaders,
    expiresAt: new Date(date.getTime() + expires * 1000).toISOString(),
    signature,
    signedHeaderNames
  };
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function encodeRfc3986(value) {
  return encodeURIComponent(String(value)).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
}

function canonicalizeQuery(query) {
  return Object.entries(query)
    .flatMap(([key, value]) => Array.isArray(value) ? value.map((item) => [key, item]) : [[key, value]])
    .sort(([keyA, valueA], [keyB, valueB]) => keyA.localeCompare(keyB) || String(valueA).localeCompare(String(valueB)))
    .map(([key, value]) => `${encodeRfc3986(key)}=${encodeRfc3986(value)}`)
    .join("&");
}

function getSignatureKey(key, dateStamp, region, service) {
  const kDate = hmac(`AWS4${key}`, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, "aws4_request");
}

function hmac(key, value, encoding) {
  return createHmac("sha256", key).update(value).digest(encoding);
}
