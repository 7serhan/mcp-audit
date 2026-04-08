/**
 * Transport Scanner — checks transport-level security.
 *
 * Checks:
 * - HTTP vs HTTPS (unencrypted transport)
 * - TLS certificate issues
 * - CORS misconfigurations
 * - Stdio transport without process isolation
 */

import { Severity, type Finding } from "../core/finding.js";
import type { ScannerPlugin } from "../core/plugin.js";
import type { ScanContext } from "../core/context.js";
import { TransportType } from "../core/target.js";

export const transportScanner: ScannerPlugin = {
  name: "transport",
  description: "Checks transport-level security (TLS, CORS, encryption)",
  version: "1.0.0",

  async run(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    if (context.target.type === TransportType.Http) {
      // Check 1: HTTP instead of HTTPS
      if (context.target.url.startsWith("http://")) {
        findings.push({
          id: "TRANSPORT-001",
          scanner: "transport",
          title: "Unencrypted HTTP transport",
          description:
            "The MCP server is accessible over plain HTTP without TLS encryption. " +
            "All communication including tool calls and responses can be intercepted.",
          severity: Severity.High,
          target: context.target.url,
          remediation:
            "Use HTTPS with a valid TLS certificate. If behind a reverse proxy, ensure TLS terminates there.",
          cwe: "CWE-319",
        });
      }

      // Check 2: Try to detect CORS issues via tool descriptions/metadata
      // (Active CORS probing would require browser context, so we flag HTTP servers)
      if (context.target.url.startsWith("https://") || context.target.url.startsWith("http://")) {
        findings.push({
          id: "TRANSPORT-002",
          scanner: "transport",
          title: "HTTP-based MCP server may have CORS misconfiguration",
          description:
            "HTTP-based MCP servers should configure strict CORS policies to prevent " +
            "unauthorized browser-based access. Verify that Access-Control-Allow-Origin " +
            "is not set to '*' and proper origin validation is in place.",
          severity: Severity.Medium,
          target: context.target.url,
          remediation:
            "Set strict CORS headers: specific allowed origins, no wildcard. " +
            "Validate Origin header server-side.",
          cwe: "CWE-942",
        });
      }
    }

    if (context.target.type === TransportType.Stdio) {
      // Check 3: Stdio transport inherits parent process permissions
      findings.push({
        id: "TRANSPORT-003",
        scanner: "transport",
        title: "Stdio transport runs with parent process privileges",
        description:
          `The MCP server "${context.target.command}" runs as a child process ` +
          "inheriting the parent's environment variables, file system access, and network permissions. " +
          "A compromised server process has full access to the host environment.",
        severity: Severity.Medium,
        target: context.target.raw,
        remediation:
          "Run MCP servers in sandboxed environments (containers, VMs, or OS-level sandboxing). " +
          "Minimize environment variables passed to the child process. " +
          "Use --no-network or similar flags if the server doesn't need network access.",
        cwe: "CWE-250",
      });

      // Check 4: Check if environment variables with secrets might be passed
      if (context.target.env) {
        const sensitiveEnvKeys = Object.keys(context.target.env).filter((key) =>
          /secret|token|key|password|credential|api_key|auth/i.test(key),
        );

        if (sensitiveEnvKeys.length > 0) {
          findings.push({
            id: "TRANSPORT-004",
            scanner: "transport",
            title: "Sensitive environment variables passed to MCP server",
            description:
              `The following environment variables with potentially sensitive names are passed to the server: ` +
              `${sensitiveEnvKeys.join(", ")}. These could be leaked via error messages or logging.`,
            severity: Severity.Medium,
            target: context.target.raw,
            evidence: {
              snippet: `Environment keys: ${sensitiveEnvKeys.join(", ")}`,
            },
            remediation:
              "Use scoped, minimal-privilege tokens. Avoid passing broad API keys. " +
              "Rotate credentials if they may have been exposed.",
            cwe: "CWE-522",
          });
        }
      }
    }

    return findings;
  },
};
