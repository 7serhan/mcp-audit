/**
 * Sandbox utilities for safe payload testing.
 */

/** Known-safe canary values for injection testing */
export const CANARY = {
  /** Random string unlikely to appear in normal output */
  MARKER: "MCP_AUDIT_CANARY_" + "7f3a2b1c",
  /** Command that echoes canary for shell injection */
  SHELL_ECHO: "; echo MCP_AUDIT_CANARY_7f3a2b1c",
  /** Path traversal canary */
  PATH_TRAVERSAL: "../../../../etc/passwd",
  /** SSRF probe targets */
  SSRF_TARGETS: [
    "http://127.0.0.1:80",
    "http://localhost:80",
    "http://[::1]:80",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://0.0.0.0:80",
  ],
};

/**
 * Check if a response contains our canary marker.
 */
export function containsCanary(text: string): boolean {
  return text.includes(CANARY.MARKER);
}

/**
 * Generate command injection payloads for a given base value.
 */
export function generateCommandInjectionPayloads(baseValue: string): string[] {
  return [
    `${baseValue}; echo ${CANARY.MARKER}`,
    `${baseValue} && echo ${CANARY.MARKER}`,
    `${baseValue} | echo ${CANARY.MARKER}`,
    `${baseValue}\`echo ${CANARY.MARKER}\``,
    `${baseValue}$(echo ${CANARY.MARKER})`,
    `${baseValue}\necho ${CANARY.MARKER}`,
  ];
}

/**
 * Generate SSRF payloads for URL-type parameters.
 */
export function generateSsrfPayloads(): string[] {
  return [
    ...CANARY.SSRF_TARGETS,
    // Decimal IP encoding for 127.0.0.1
    "http://2130706433/",
    // Hex encoding
    "http://0x7f000001/",
    // URL with credentials
    "http://evil@127.0.0.1/",
    // DNS rebinding placeholder
    "http://127.0.0.1.nip.io/",
  ];
}
