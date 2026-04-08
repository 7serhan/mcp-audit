/**
 * Data Exfiltration Scanner — detects potential data theft chains.
 *
 * Checks:
 * - Tools that can read data + tools that can send data (read+send chains)
 * - File reading tools that can access sensitive paths
 * - Tools that can forward data to external endpoints
 * - Resource leakage through tool combinations
 */

import { Severity, type Finding } from "../core/finding.js";
import type { ScannerPlugin } from "../core/plugin.js";
import type { ScanContext, McpTool } from "../core/context.js";

/** Tools that read/access data */
const DATA_SOURCE_PATTERNS = [
  /read|get|fetch|list|find|search|query|select|load|cat|head|tail/i,
  /file|directory|folder|database|db|table|record|document/i,
  /env|environment|config|setting|secret|credential/i,
];

/** Tools that send/transmit data */
const DATA_SINK_PATTERNS = [
  /send|post|put|push|upload|forward|transmit|notify|email|message|webhook/i,
  /write|create|insert|update|publish|deploy/i,
  /http|request|fetch|curl|api/i,
];

/** Sensitive file paths that should never be accessible */
const SENSITIVE_PATHS = [
  "/etc/passwd",
  "/etc/shadow",
  "/etc/hosts",
  "~/.ssh/id_rsa",
  "~/.ssh/id_ed25519",
  "~/.aws/credentials",
  "~/.env",
  ".env",
  ".env.local",
  ".env.production",
  "credentials.json",
  "service-account.json",
  "~/.kube/config",
  "~/.docker/config.json",
  "~/.npmrc",
  "~/.pypirc",
  "~/.gitconfig",
  "~/.bash_history",
  "~/.zsh_history",
];

export const dataExfiltrationScanner: ScannerPlugin = {
  name: "data-exfiltration",
  description: "Detects potential data exfiltration chains and sensitive data access",
  version: "1.0.0",

  async run(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    const sources = classifyTools(context.tools, DATA_SOURCE_PATTERNS);
    const sinks = classifyTools(context.tools, DATA_SINK_PATTERNS);

    // Check 1: Read + Send chain exists
    if (sources.length > 0 && sinks.length > 0) {
      findings.push({
        id: "EXFIL-001",
        scanner: "data-exfiltration",
        title: "Data exfiltration chain detected: read + send tools",
        description:
          `Server exposes both data-reading tools (${sources.map((t) => t.name).join(", ")}) ` +
          `and data-sending tools (${sinks.map((t) => t.name).join(", ")}). ` +
          "An attacker controlling the LLM could chain these to read sensitive data and exfiltrate it.",
        severity: Severity.High,
        target: context.target.raw,
        evidence: {
          snippet:
            `Sources: ${sources.map((t) => t.name).join(", ")}\n` +
            `Sinks: ${sinks.map((t) => t.name).join(", ")}`,
        },
        remediation:
          "Implement data flow controls between tools. Require human confirmation for " +
          "operations that combine data reading and external sending. " +
          "Use tool-level permissions to prevent unauthorized data combinations.",
        cwe: "CWE-200",
      });
    }

    // Check 2: Try to access sensitive files
    const readTools = context.tools.filter((t) =>
      /read|get|cat|load|open|file/i.test(t.name),
    );

    for (const tool of readTools.slice(0, 2)) {
      // Find the file path parameter
      const pathParam = findPathParameter(tool);
      if (!pathParam) continue;

      for (const sensitivePath of SENSITIVE_PATHS.slice(0, 5)) {
        try {
          const result = await context.callTool(tool.name, {
            [pathParam]: sensitivePath,
          });

          const responseText = result.content.map((c) => c.text ?? "").join("\n");

          if (!result.isError && responseText.length > 0) {
            findings.push({
              id: "EXFIL-002",
              scanner: "data-exfiltration",
              title: `Sensitive file accessible: ${sensitivePath}`,
              description:
                `Tool "${tool.name}" can read sensitive file "${sensitivePath}". ` +
                "This file may contain credentials, keys, or other sensitive configuration.",
              severity: Severity.Critical,
              target: tool.name,
              evidence: {
                request: `callTool("${tool.name}", { "${pathParam}": "${sensitivePath}" })`,
                response: responseText.slice(0, 200) + (responseText.length > 200 ? "..." : ""),
              },
              remediation:
                "Implement a file access allowlist. Block access to sensitive system files, " +
                "credential files, and configuration files containing secrets. " +
                "Use chroot or sandboxed file system access.",
              cwe: "CWE-552",
            });
            break; // One file per tool is enough
          }
        } catch {
          // Access denied or tool error — good
        }
      }
    }

    // Check 3: Resources that expose sensitive data
    for (const resource of context.resources) {
      const uri = resource.uri.toLowerCase();
      if (/env|secret|credential|config|key|token|password|auth/i.test(uri)) {
        findings.push({
          id: "EXFIL-003",
          scanner: "data-exfiltration",
          title: `Resource may expose sensitive data: ${resource.uri}`,
          description:
            `Resource "${resource.uri}" (${resource.description ?? "no description"}) ` +
            "has a name suggesting it contains sensitive data.",
          severity: Severity.Medium,
          target: resource.uri,
          remediation:
            "Review resource access controls. Don't expose sensitive data as MCP resources " +
            "unless access is properly authenticated and authorized.",
          cwe: "CWE-200",
        });
      }
    }

    return findings;
  },
};

function classifyTools(tools: McpTool[], patterns: RegExp[]): McpTool[] {
  return tools.filter((t) => {
    const text = `${t.name} ${t.description ?? ""}`;
    return patterns.some((p) => p.test(text));
  });
}

function findPathParameter(tool: McpTool): string | null {
  const schema = tool.inputSchema;
  if (!schema || typeof schema !== "object") return null;

  const properties = (schema as Record<string, unknown>).properties as
    | Record<string, { type?: string }>
    | undefined;

  if (!properties) return null;

  for (const [name, def] of Object.entries(properties)) {
    if (def?.type === "string" && /path|file|filename|filepath|dir|uri|location/i.test(name)) {
      return name;
    }
  }

  // Fallback: first string param
  for (const [name, def] of Object.entries(properties)) {
    if (def?.type === "string") return name;
  }

  return null;
}
