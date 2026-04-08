/**
 * Network utilities — private IP detection, URL validation.
 */

const PRIVATE_RANGES = [
  /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,         // Loopback
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,           // Class A private
  /^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/, // Class B private
  /^192\.168\.\d{1,3}\.\d{1,3}$/,              // Class C private
  /^169\.254\.\d{1,3}\.\d{1,3}$/,              // Link-local
  /^0\.0\.0\.0$/,                               // Unspecified
];

const PRIVATE_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata",
]);

/** AWS/GCP/Azure metadata endpoints */
export const METADATA_IPS = [
  "169.254.169.254",  // AWS & GCP
  "169.254.170.2",    // AWS ECS
  "100.100.100.200",  // Alibaba Cloud
];

export function isPrivateIp(ip: string): boolean {
  return PRIVATE_RANGES.some((r) => r.test(ip));
}

export function isPrivateHost(hostname: string): boolean {
  if (PRIVATE_HOSTNAMES.has(hostname.toLowerCase())) return true;
  if (isPrivateIp(hostname)) return true;
  // IPv6 loopback
  if (hostname === "::1" || hostname === "[::1]") return true;
  return false;
}

export function isMetadataEndpoint(urlStr: string): boolean {
  try {
    const url = new URL(urlStr);
    return (
      METADATA_IPS.includes(url.hostname) ||
      url.hostname === "metadata.google.internal"
    );
  } catch {
    return false;
  }
}

export function extractHostFromUrl(urlStr: string): string | null {
  try {
    return new URL(urlStr).hostname;
  } catch {
    return null;
  }
}
