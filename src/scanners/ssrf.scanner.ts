/**
 * SSRF Scanner — Server-Side Request Forgery detection.
 *
 * Checks:
 * - Tools with URL parameters that can be directed to internal hosts
 * - Access to cloud metadata endpoints (AWS, GCP, Azure)
 * - IP address bypass techniques (decimal, hex, IPv6)
 * - DNS rebinding potential
 */

import { Severity, type Finding } from "../core/finding.js";
import type { ScannerPlugin } from "../core/plugin.js";
import type { ScanContext, McpTool } from "../core/context.js";
import { isPrivateHost, isMetadataEndpoint, METADATA_IPS } from "../utils/network.js";
import { generateSsrfPayloads } from "../utils/sandbox.js";

/** Patterns that suggest a parameter accepts URLs */
const URL_PARAM_PATTERNS = [
  /url/i, /uri/i, /href/i, /link/i, /endpoint/i,
  /target/i, /host/i, /server/i, /address/i,
  /source/i, /destination/i, /redirect/i, /callback/i,
  /webhook/i, /fetch/i, /proxy/i, /forward/i,
  /image/i, /file/i, /path/i, /location/i,
];

export const ssrfScanner: ScannerPlugin = {
  name: "ssrf",
  description: "Detects Server-Side Request Forgery vulnerabilities in MCP tools",
  version: "1.0.0",

  async run(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const tool of context.tools) {
      const urlParams = findUrlParameters(tool);

      if (urlParams.length === 0) continue;

      context.logger.debug(
        `SSRF: Testing tool "${tool.name}" — ${urlParams.length} URL-like param(s)`,
      );

      for (const param of urlParams) {
        // Test internal host payloads
        const payloads = generateSsrfPayloads();

        for (const payload of payloads) {
          try {
            const result = await context.callTool(tool.name, {
              [param]: payload,
            });

            const responseText = result.content
              .map((c) => c.text ?? "")
              .join("\n");

            // Check if the request was actually made (not just rejected)
            if (result.isError) continue;

            const host = extractHost(payload);

            if (host && isPrivateHost(host)) {
              findings.push({
                id: "SSRF-001",
                scanner: "ssrf",
                title: `SSRF: Tool "${tool.name}" accessed internal host`,
                description:
                  `Tool "${tool.name}" parameter "${param}" successfully made a request to ` +
                  `internal host "${host}". This allows attackers to scan internal networks ` +
                  "and access services not intended to be publicly reachable.",
                severity: Severity.Critical,
                target: tool.name,
                evidence: {
                  payload,
                  request: `callTool("${tool.name}", { "${param}": "${payload}" })`,
                  response: responseText.slice(0, 500),
                },
                remediation:
                  "Validate and sanitize URL inputs. Block requests to private IP ranges " +
                  "(127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16). " +
                  "Use an allowlist of permitted hosts/domains.",
                cwe: "CWE-918",
              });
              break; // One finding per param is enough
            }

            if (isMetadataEndpoint(payload)) {
              findings.push({
                id: "SSRF-002",
                scanner: "ssrf",
                title: `SSRF: Tool "${tool.name}" can reach cloud metadata endpoint`,
                description:
                  `Tool "${tool.name}" parameter "${param}" can reach cloud metadata endpoint ` +
                  `"${payload}". This can expose cloud credentials, instance identity, ` +
                  "and other sensitive configuration.",
                severity: Severity.Critical,
                target: tool.name,
                evidence: {
                  payload,
                  response: responseText.slice(0, 500),
                },
                remediation:
                  `Block access to metadata IPs (${METADATA_IPS.join(", ")}). ` +
                  "Use IMDSv2 (AWS) which requires a PUT request with hop limit. " +
                  "Configure firewall rules to block metadata access from application containers.",
                cwe: "CWE-918",
              });
              break;
            }
          } catch {
            // Request failed — likely blocked or unreachable
          }
        }
      }

      // Static analysis: check if tool description mentions URL fetching
      const desc = (tool.description ?? "").toLowerCase();
      if (
        /fetch|download|request|proxy|forward|redirect|url|http/i.test(desc) &&
        urlParams.length > 0
      ) {
        findings.push({
          id: "SSRF-003",
          scanner: "ssrf",
          title: `Potential SSRF surface in tool "${tool.name}"`,
          description:
            `Tool "${tool.name}" appears to accept URLs and make requests. ` +
            `Description: "${tool.description}". ` +
            "Ensure server-side URL validation blocks internal/metadata endpoints.",
          severity: Severity.Medium,
          target: tool.name,
          remediation:
            "Implement a URL allowlist. Validate that resolved IPs are not in private ranges before making requests.",
          cwe: "CWE-918",
        });
      }
    }

    return findings;
  },
};

function findUrlParameters(tool: McpTool): string[] {
  const schema = tool.inputSchema;
  if (!schema || typeof schema !== "object") return [];

  const properties = (schema as Record<string, unknown>).properties as
    | Record<string, { type?: string; description?: string; format?: string }>
    | undefined;

  if (!properties) return [];

  const params: string[] = [];

  for (const [name, def] of Object.entries(properties)) {
    // Check parameter name
    if (URL_PARAM_PATTERNS.some((p) => p.test(name))) {
      params.push(name);
      continue;
    }
    // Check format
    if (def?.format === "uri" || def?.format === "url") {
      params.push(name);
      continue;
    }
    // Check description
    if (def?.description && /url|uri|endpoint|address/i.test(def.description)) {
      params.push(name);
    }
  }

  return params;
}

function extractHost(urlStr: string): string | null {
  try {
    return new URL(urlStr).hostname;
  } catch {
    return null;
  }
}
