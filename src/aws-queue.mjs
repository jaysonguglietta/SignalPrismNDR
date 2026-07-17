export function parseSqsQueueUrl(value, fallbackRegion = "") {
  let url;
  try {
    url = new URL(String(value || ""));
  } catch {
    throw new Error("NDR_QUEUE_URL must be a valid SQS HTTPS URL");
  }
  const match = url.hostname.match(/^sqs[.-]([a-z0-9-]+)\.amazonaws\.com$/);
  if (url.protocol !== "https:" || !match || url.username || url.password || url.search || url.hash) {
    throw new Error("NDR_QUEUE_URL must use an AWS SQS HTTPS endpoint without credentials or query parameters");
  }
  const segments = url.pathname.split("/").filter(Boolean);
  if (segments.length !== 2 || !/^\d{12}$/.test(segments[0]) || !/^[A-Za-z0-9_-]{1,80}$/.test(segments[1])) {
    throw new Error("NDR_QUEUE_URL must include an AWS account ID and queue name");
  }
  const region = match[1] || String(fallbackRegion || "");
  if (fallbackRegion && region !== fallbackRegion) throw new Error("NDR_QUEUE_URL region does not match NDR_QUEUE_REGION");
  return { region, host: url.hostname, path: `/${segments.join("/")}`, accountId: segments[0], queueName: segments[1] };
}

export function buildSqsQuery(action, values = {}) {
  const body = new URLSearchParams({ Action: action, Version: "2012-11-05" });
  Object.entries(values).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") body.set(key, String(value));
  });
  return body.toString();
}

export function parseSqsMessages(xml) {
  const messages = [];
  for (const match of String(xml || "").matchAll(/<Message>([\s\S]*?)<\/Message>/g)) {
    const message = match[1];
    messages.push({
      messageId: xmlValue(message, "MessageId"),
      receiptHandle: xmlValue(message, "ReceiptHandle"),
      body: decodeXml(xmlValue(message, "Body")),
      receiveCount: Number(xmlAttributeValue(message, "ApproximateReceiveCount") || 1)
    });
  }
  return messages;
}

function xmlValue(xml, name) {
  const match = String(xml).match(new RegExp(`<${name}>([\\s\\S]*?)<\\/${name}>`));
  return match ? decodeXml(match[1]) : "";
}

function xmlAttributeValue(xml, name) {
  const pattern = new RegExp(`<Attribute>[\\s\\S]*?<Name>${name}<\\/Name>[\\s\\S]*?<Value>([\\s\\S]*?)<\\/Value>[\\s\\S]*?<\\/Attribute>`);
  const match = String(xml).match(pattern);
  return match ? decodeXml(match[1]) : "";
}

function decodeXml(value) {
  return String(value || "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}
