/**
 * Info Disclosure Scanner — detects information leakage.
 *
 * Checks:
 * - Server version/name disclosure
 * - Stack traces in error responses
 * - Internal paths in tool descriptions or errors
 * - Verbose error messages
 */

import { Severity, type Finding } from "../core/finding.js";
import type { ScannerPlugin } from "../core/plugin.js";
import type { ScanContext } from "../core/context.js";

const PATH_PATTERNS = [
  /\/home\/\w+/i,
  /\/Users\/\w+/i,
  /C:\\Users\\\w+/i,
  /\/var\/www/i,
  /\/opt\//i,
  /\/etc\//i,
  /\/tmp\//i,
  /node_modules/i,
];

const STACK_TRACE_PATTERNS = [
  /at\s+\S+\s+\(.*:\d+:\d+\)/,       // V8 stack trace
  /Traceback \(most recent call last\)/,  // Python
  /\.py", line \d+/,                    // Python file reference
  /Error:.*\n\s+at\s/,                 // Node.js error
];

const VERSION_PATTERNS = [
  /node[/\s]v?\d+\.\d+/i,
  /python[/\s]v?\d+\.\d+/i,
  /express[/\s]v?\d+/i,
  /nginx[/\s]v?\d+/i,
];

export const infoDisclosureScanner: ScannerPlugin = {
  name: "info-disclosure",
  description: "Detects information leakage in tool descriptions and error responses",
  version: "1.0.0",

  async run(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check 1: Server name/version disclosure
    if (context.serverInfo?.version) {
      findings.push({
        id: "INFO-001",
        scanner: "info-disclosure",
        title: "Server version disclosed",
        description:
          `Server identifies as "${context.serverInfo.name ?? "unknown"}" ` +
          `version "${context.serverInfo.version}". Version disclosure helps ` +
          "attackers identify known vulnerabilities for specific versions.",
        severity: Severity.Low,
        target: context.target.raw,
        evidence: {
          snippet: `Server: ${context.serverInfo.name}/${context.serverInfo.version}`,
        },
        remediation: "Consider hiding or generalizing version information in production.",
        cwe: "CWE-200",
      });
    }

    // Check 2: Internal paths in tool descriptions
    for (const tool of context.tools) {
      const text = `${tool.name} ${tool.description ?? ""} ${JSON.stringify(tool.inputSchema ?? {})}`;

      for (const pattern of PATH_PATTERNS) {
        const match = text.match(pattern);
        if (match) {
          findings.push({
            id: "INFO-002",
            scanner: "info-disclosure",
            title: `Internal path leaked in tool "${tool.name}"`,
            description:
              `Tool "${tool.name}" exposes an internal file path: "${match[0]}". ` +
              "This reveals server directory structure to potential attackers.",
            severity: Severity.Low,
            target: tool.name,
            evidence: { snippet: match[0] },
            remediation: "Remove internal paths from tool descriptions and schemas.",
            cwe: "CWE-200",
          });
          break;
        }
      }
    }

    // Check 3: Trigger error responses and check for leaks
    for (const tool of context.tools.slice(0, 3)) {
      try {
        // Send deliberately invalid input to trigger error
        const result = await context.callTool(tool.name, {
          __invalid__: "mcp-audit-probe",
        });

        const responseText = result.content
          .map((c) => c.text ?? "")
          .join("\n");

        // Check for stack traces
        for (const pattern of STACK_TRACE_PATTERNS) {
          if (pattern.test(responseText)) {
            findings.push({
              id: "INFO-003",
              scanner: "info-disclosure",
              title: `Stack trace leaked in error from "${tool.name}"`,
              description:
                `Tool "${tool.name}" returns stack traces in error responses. ` +
                "Stack traces expose internal code structure, file paths, and dependencies.",
              severity: Severity.Medium,
              target: tool.name,
              evidence: {
                request: `callTool("${tool.name}", { __invalid__: "mcp-audit-probe" })`,
                response: responseText.slice(0, 500),
              },
              remediation:
                "Implement proper error handling that returns user-friendly messages " +
                "without exposing internal details. Log full errors server-side only.",
              cwe: "CWE-209",
            });
            break;
          }
        }

        // Check for internal paths in error
        for (const pattern of PATH_PATTERNS) {
          const match = responseText.match(pattern);
          if (match) {
            findings.push({
              id: "INFO-004",
              scanner: "info-disclosure",
              title: `Internal path leaked in error from "${tool.name}"`,
              description:
                `Error response from "${tool.name}" contains internal path: "${match[0]}".`,
              severity: Severity.Low,
              target: tool.name,
              evidence: {
                response: responseText.slice(0, 500),
              },
              remediation: "Sanitize error messages to remove internal file paths.",
              cwe: "CWE-200",
            });
            break;
          }
        }

        // Check for version info in error
        for (const pattern of VERSION_PATTERNS) {
          const match = responseText.match(pattern);
          if (match) {
            findings.push({
              id: "INFO-005",
              scanner: "info-disclosure",
              title: `Technology version leaked in error from "${tool.name}"`,
              description:
                `Error response reveals technology version: "${match[0]}".`,
              severity: Severity.Low,
              target: tool.name,
              evidence: { snippet: match[0] },
              remediation: "Remove technology version details from error responses.",
              cwe: "CWE-200",
            });
            break;
          }
        }
      } catch {
        // Tool call threw — that's fine, we're probing
      }
    }

    return findings;
  },
};
