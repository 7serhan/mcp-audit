/**
 * Permissions Scanner — detects excessive privileges.
 *
 * Checks:
 * - Tools with overly broad capabilities (file system, network, shell)
 * - Dangerous tool combinations (read + send)
 * - No principle of least privilege
 * - Tools that grant access to the entire file system
 */

import { Severity, type Finding } from "../core/finding.js";
import type { ScannerPlugin } from "../core/plugin.js";
import type { ScanContext } from "../core/context.js";

interface CapabilityCategory {
  name: string;
  patterns: RegExp[];
  severity: Severity;
}

const CAPABILITY_CATEGORIES: CapabilityCategory[] = [
  {
    name: "shell-execution",
    patterns: [/exec|execute|run|shell|command|cmd|bash|powershell|terminal/i],
    severity: Severity.Critical,
  },
  {
    name: "file-system-write",
    patterns: [/write_file|create_file|save_file|delete_file|remove_file|mkdir|rmdir/i],
    severity: Severity.High,
  },
  {
    name: "file-system-read",
    patterns: [/read_file|list_dir|list_files|glob|find_files|get_file/i],
    severity: Severity.Medium,
  },
  {
    name: "network-access",
    patterns: [/fetch|http|request|curl|download|upload|api_call|webhook/i],
    severity: Severity.High,
  },
  {
    name: "database-access",
    patterns: [/query|sql|database|db_|mongo|redis|postgres|mysql/i],
    severity: Severity.High,
  },
  {
    name: "credential-management",
    patterns: [/password|credential|token|secret|api_key|auth|oauth/i],
    severity: Severity.Critical,
  },
  {
    name: "process-management",
    patterns: [/kill|spawn|fork|process|pid|signal/i],
    severity: Severity.High,
  },
];

const DANGEROUS_COMBINATIONS = [
  {
    name: "read-and-exfiltrate",
    requires: ["file-system-read", "network-access"],
    description: "Can read local files and send them over the network",
    severity: Severity.High,
  },
  {
    name: "full-system-control",
    requires: ["shell-execution", "file-system-write"],
    description: "Can execute arbitrary commands and modify files",
    severity: Severity.Critical,
  },
  {
    name: "credential-theft",
    requires: ["file-system-read", "credential-management"],
    description: "Can read files and access credential stores",
    severity: Severity.Critical,
  },
  {
    name: "data-modification",
    requires: ["database-access", "file-system-write"],
    description: "Can modify both database and file system data",
    severity: Severity.High,
  },
];

export const permissionsScanner: ScannerPlugin = {
  name: "permissions",
  description: "Detects excessive privileges and dangerous capability combinations",
  version: "1.0.0",

  async run(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    const detectedCapabilities = new Set<string>();

    // Check 1: Categorize tool capabilities
    for (const tool of context.tools) {
      const text = `${tool.name} ${tool.description ?? ""}`;

      for (const category of CAPABILITY_CATEGORIES) {
        const matches = category.patterns.some((p) => p.test(text));
        if (matches) {
          detectedCapabilities.add(category.name);

          if (category.severity === Severity.Critical) {
            findings.push({
              id: "PERM-001",
              scanner: "permissions",
              title: `Critical capability: ${category.name} via "${tool.name}"`,
              description:
                `Tool "${tool.name}" provides ${category.name} capability. ` +
                `Description: ${tool.description ?? "none"}. ` +
                "This is a high-privilege operation that should be carefully controlled.",
              severity: category.severity,
              target: tool.name,
              remediation:
                "Apply principle of least privilege. Restrict tool capabilities to the minimum required. " +
                "Consider sandboxing or requiring explicit user confirmation for dangerous operations.",
              cwe: "CWE-250",
            });
          }
        }
      }
    }

    // Check 2: Detect dangerous combinations
    for (const combo of DANGEROUS_COMBINATIONS) {
      const hasAll = combo.requires.every((r) => detectedCapabilities.has(r));
      if (hasAll) {
        findings.push({
          id: "PERM-002",
          scanner: "permissions",
          title: `Dangerous capability combination: ${combo.name}`,
          description:
            `Server exposes tools that together enable "${combo.name}": ${combo.description}. ` +
            `Required capabilities: ${combo.requires.join(" + ")}.`,
          severity: combo.severity,
          target: context.target.raw,
          evidence: {
            snippet: `Detected capabilities: ${Array.from(detectedCapabilities).join(", ")}`,
          },
          remediation:
            "Separate capabilities into different server instances with isolated permissions. " +
            "Use human-in-the-loop confirmation for sensitive operations.",
          cwe: "CWE-250",
        });
      }
    }

    // Check 3: Total capability count warning
    if (detectedCapabilities.size >= 4) {
      findings.push({
        id: "PERM-003",
        scanner: "permissions",
        title: "Server exposes too many capability categories",
        description:
          `Server exposes ${detectedCapabilities.size} different capability categories: ` +
          `${Array.from(detectedCapabilities).join(", ")}. ` +
          "A server with many capabilities has a large attack surface.",
        severity: Severity.Medium,
        target: context.target.raw,
        remediation:
          "Follow the principle of least privilege. Split into focused servers with minimal capabilities.",
        cwe: "CWE-250",
      });
    }

    // Check 4: Tool count warning
    if (context.tools.length > 20) {
      findings.push({
        id: "PERM-004",
        scanner: "permissions",
        title: `Server exposes excessive number of tools (${context.tools.length})`,
        description:
          `Server exposes ${context.tools.length} tools. Large tool surfaces increase ` +
          "the risk of unintended tool usage by LLMs and make security review harder.",
        severity: Severity.Low,
        target: context.target.raw,
        remediation:
          "Consider splitting into multiple focused servers or implementing tool groups with access control.",
        cwe: "CWE-250",
      });
    }

    return findings;
  },
};
