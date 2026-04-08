/**
 * Auth Scanner — detects missing or weak authentication on MCP servers.
 *
 * Checks:
 * - Server accessible without any authentication
 * - No auth-related headers or tokens required
 * - Tools callable without credentials
 * - Missing authorization on sensitive operations
 */

import { Severity, type Finding } from "../core/finding.js";
import type { ScannerPlugin } from "../core/plugin.js";
import type { ScanContext } from "../core/context.js";

const SENSITIVE_TOOL_PATTERNS = [
  /exec|execute|run|shell|command|cmd/i,
  /write|create|delete|remove|update|modify|put|patch/i,
  /upload|download|transfer|send/i,
  /admin|config|setting|manage/i,
  /deploy|install|uninstall/i,
  /database|db|sql|query/i,
  /file|directory|folder|path/i,
  /user|account|password|credential|token|key|secret/i,
];

export const authScanner: ScannerPlugin = {
  name: "auth",
  description: "Detects missing or weak authentication on MCP servers",
  version: "1.0.0",

  async run(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check 1: Server accessible without authentication
    // If we got this far, the server accepted our connection without auth
    if (context.tools.length > 0 || context.resources.length > 0) {
      findings.push({
        id: "AUTH-001",
        scanner: "auth",
        title: "Server accessible without authentication",
        description:
          "The MCP server accepted a connection and exposed tools/resources without requiring any authentication. " +
          `Found ${context.tools.length} tool(s) and ${context.resources.length} resource(s) accessible without credentials.`,
        severity: Severity.Critical,
        target: context.target.raw,
        remediation:
          "Implement authentication before exposing server capabilities. " +
          "Use token-based auth, mTLS, or integrate with your identity provider.",
        cwe: "CWE-306",
      });
    }

    // Check 2: Sensitive tools accessible without auth
    for (const tool of context.tools) {
      const isSensitive = SENSITIVE_TOOL_PATTERNS.some((pattern) =>
        pattern.test(tool.name) || pattern.test(tool.description ?? ""),
      );

      if (isSensitive) {
        findings.push({
          id: "AUTH-002",
          scanner: "auth",
          title: `Sensitive tool "${tool.name}" accessible without authorization`,
          description:
            `Tool "${tool.name}" appears to perform sensitive operations ` +
            `(${tool.description ?? "no description"}) but is accessible without authorization checks.`,
          severity: Severity.High,
          target: tool.name,
          remediation:
            "Implement role-based access control (RBAC) for sensitive tools. " +
            "Require elevated permissions for destructive or administrative operations.",
          cwe: "CWE-862",
        });
      }
    }

    // Check 3: Try calling a tool without auth headers to confirm
    if (context.tools.length > 0) {
      const safeTool = findSafestTool(context);
      if (safeTool) {
        try {
          const result = await context.callTool(safeTool.name, {});
          if (!result.isError) {
            findings.push({
              id: "AUTH-003",
              scanner: "auth",
              title: "Tool invocation succeeds without authentication token",
              description:
                `Successfully called tool "${safeTool.name}" without providing any authentication token or API key. ` +
                "This confirms the server does not enforce authentication at the tool execution level.",
              severity: Severity.High,
              target: safeTool.name,
              evidence: {
                request: `callTool("${safeTool.name}", {})`,
                response: JSON.stringify(result.content).slice(0, 500),
              },
              remediation:
                "Enforce authentication for all tool invocations, not just at connection time.",
              cwe: "CWE-306",
            });
          }
        } catch {
          // Tool call failed — might be auth is working or tool needs params
          context.logger.debug(`Auth probe on "${safeTool.name}" threw — possibly auth is enforced`);
        }
      }
    }

    // Check 4: Resources accessible without auth
    if (context.resources.length > 0) {
      const resource = context.resources[0];
      try {
        const result = await context.readResource(resource.uri);
        if (result.contents.length > 0) {
          findings.push({
            id: "AUTH-004",
            scanner: "auth",
            title: "Resources readable without authentication",
            description:
              `Resource "${resource.uri}" is readable without any authentication. ` +
              `${context.resources.length} total resource(s) may be exposed.`,
            severity: Severity.Medium,
            target: resource.uri,
            remediation: "Implement authentication for resource access.",
            cwe: "CWE-306",
          });
        }
      } catch {
        // Resource read failed — auth might be working
      }
    }

    return findings;
  },
};

/** Find the safest tool to probe (prefer read-only, list-type tools) */
function findSafestTool(context: ScanContext) {
  const safePatterns = [/list|get|read|fetch|search|find|show|describe|info|status|health|ping|version/i];
  const safe = context.tools.find((t) =>
    safePatterns.some((p) => p.test(t.name) || p.test(t.description ?? "")),
  );
  return safe ?? context.tools[0];
}
