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

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function encodeRfc3986(value) {
  return encodeURIComponent(String(value)).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
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
