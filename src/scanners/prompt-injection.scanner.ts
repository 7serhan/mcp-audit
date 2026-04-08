/**
 * Prompt Injection Scanner — detects LLM manipulation surfaces in MCP tools.
 *
 * Checks:
 * - Tool descriptions containing LLM manipulation patterns
 * - Hidden instructions in tool descriptions
 * - Tools that can modify LLM context/behavior
 * - Rug-pull patterns (tools that change behavior after approval)
 */

import { Severity, type Finding } from "../core/finding.js";
import type { ScannerPlugin } from "../core/plugin.js";
import type { ScanContext } from "../core/context.js";

/** Patterns that indicate prompt injection in tool descriptions */
const INJECTION_PATTERNS: Array<{ pattern: RegExp; label: string; severity: Severity }> = [
  {
    pattern: /ignore\s+(previous|above|all|prior)\s+(instructions?|prompts?|rules?|constraints?)/i,
    label: "instruction override attempt",
    severity: Severity.Critical,
  },
  {
    pattern: /you\s+(are|must|should|will|have\s+to)\s+(now|always)/i,
    label: "role reassignment attempt",
    severity: Severity.High,
  },
  {
    pattern: /system\s*:\s*|<\/?system>|<\/?instructions?>/i,
    label: "fake system message delimiters",
    severity: Severity.Critical,
  },
  {
    pattern: /do\s+not\s+(tell|inform|reveal|mention|disclose|show)/i,
    label: "secrecy instruction",
    severity: Severity.High,
  },
  {
    pattern: /pretend|act\s+as|role\s*play|imagine\s+you/i,
    label: "role manipulation",
    severity: Severity.Medium,
  },
  {
    pattern: /IMPORTANT|URGENT|CRITICAL|OVERRIDE|ADMIN/,
    label: "authority escalation keywords (all-caps)",
    severity: Severity.Medium,
  },
  {
    pattern: /\[INST\]|\[\/INST\]|<<SYS>>|<\|im_start\|>/i,
    label: "model-specific prompt delimiters",
    severity: Severity.Critical,
  },
  {
    pattern: /base64|atob|btoa|decode|encode.*secret/i,
    label: "encoded payload indicator",
    severity: Severity.Medium,
  },
  {
    pattern: /instead\s+of|rather\s+than|don't\s+use\s+the|call\s+this\s+tool\s+(first|instead)/i,
    label: "tool redirection attempt",
    severity: Severity.High,
  },
  {
    pattern: /before\s+(calling|using|executing)\s+(any|other|the)/i,
    label: "tool ordering manipulation",
    severity: Severity.Medium,
  },
];

/** Patterns for invisible/hidden characters */
const HIDDEN_CONTENT_PATTERNS = [
  /[\u200b-\u200f]/,     // Zero-width characters
  /[\u2028-\u2029]/,     // Line/paragraph separators
  /[\u00ad]/,            // Soft hyphen
  /[\ufeff]/,            // BOM
  /[\u2060-\u2064]/,     // Invisible operators
  /[\u180e]/,            // Mongolian vowel separator
];

export const promptInjectionScanner: ScannerPlugin = {
  name: "prompt-injection",
  description: "Detects LLM prompt injection patterns in tool descriptions and responses",
  version: "1.0.0",

  async run(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check all tools
    for (const tool of context.tools) {
      const description = tool.description ?? "";
      const schemaStr = JSON.stringify(tool.inputSchema ?? {});
      const fullText = `${tool.name} ${description} ${schemaStr}`;

      // Check 1: Known injection patterns
      for (const { pattern, label, severity } of INJECTION_PATTERNS) {
        const match = fullText.match(pattern);
        if (match) {
          findings.push({
            id: "PROMPT-001",
            scanner: "prompt-injection",
            title: `Prompt injection pattern in tool "${tool.name}": ${label}`,
            description:
              `Tool "${tool.name}" description contains a prompt injection pattern (${label}): ` +
              `"${match[0]}". This could manipulate LLM behavior when the tool is presented to an AI assistant.`,
            severity,
            target: tool.name,
            evidence: {
              snippet: description.slice(0, 500),
              payload: match[0],
            },
            remediation:
              "Remove manipulative language from tool descriptions. " +
              "Tool descriptions should only contain factual information about the tool's purpose and parameters.",
            cwe: "CWE-74",
          });
        }
      }

      // Check 2: Hidden/invisible characters
      for (const pattern of HIDDEN_CONTENT_PATTERNS) {
        if (pattern.test(description)) {
          findings.push({
            id: "PROMPT-002",
            scanner: "prompt-injection",
            title: `Hidden characters in tool "${tool.name}" description`,
            description:
              `Tool "${tool.name}" description contains invisible Unicode characters. ` +
              "These can be used to hide malicious instructions from human reviewers " +
              "while still being processed by LLMs.",
            severity: Severity.Critical,
            target: tool.name,
            evidence: {
              snippet: `Description length: ${description.length}, visible length: ${description.replace(/[\u200b-\u200f\u2028-\u2029\u00ad\ufeff\u2060-\u2064\u180e]/g, "").length}`,
            },
            remediation:
              "Strip invisible Unicode characters from tool descriptions. " +
              "Only allow standard printable characters.",
            cwe: "CWE-116",
          });
          break;
        }
      }

      // Check 3: Unusually long description (might hide injections)
      if (description.length > 1000) {
        findings.push({
          id: "PROMPT-003",
          scanner: "prompt-injection",
          title: `Unusually long description for tool "${tool.name}"`,
          description:
            `Tool "${tool.name}" has a ${description.length}-character description. ` +
            "Excessively long descriptions may hide prompt injection payloads " +
            "that are difficult to notice during human review.",
          severity: Severity.Low,
          target: tool.name,
          evidence: {
            snippet: description.slice(0, 200) + "...",
          },
          remediation:
            "Keep tool descriptions concise and focused on the tool's purpose. " +
            "Review long descriptions carefully for hidden instructions.",
          cwe: "CWE-74",
        });
      }

      // Check 4: Description differs significantly from tool name
      if (description && tool.name) {
        const nameWords = tool.name.toLowerCase().replace(/[_-]/g, " ").split(/\s+/);
        const descLower = description.toLowerCase();
        const overlap = nameWords.filter((w) => w.length > 2 && descLower.includes(w));

        if (nameWords.length > 1 && overlap.length === 0) {
          findings.push({
            id: "PROMPT-004",
            scanner: "prompt-injection",
            title: `Tool "${tool.name}" description doesn't match its name`,
            description:
              `Tool name "${tool.name}" has no keyword overlap with its description. ` +
              "This could indicate a deceptive tool that does something different from what its name suggests (rug-pull pattern).",
            severity: Severity.Medium,
            target: tool.name,
            evidence: {
              snippet: `Name: "${tool.name}", Description: "${description.slice(0, 200)}"`,
            },
            remediation:
              "Ensure tool descriptions accurately reflect the tool's functionality. " +
              "Review tools where name and description are semantically divergent.",
            cwe: "CWE-345",
          });
        }
      }
    }

    // Check prompts too
    for (const prompt of context.prompts) {
      const text = `${prompt.name} ${prompt.description ?? ""}`;

      for (const { pattern, label, severity } of INJECTION_PATTERNS) {
        if (pattern.test(text)) {
          findings.push({
            id: "PROMPT-005",
            scanner: "prompt-injection",
            title: `Prompt injection pattern in MCP prompt "${prompt.name}": ${label}`,
            description:
              `MCP prompt "${prompt.name}" contains injection pattern: ${label}.`,
            severity,
            target: prompt.name,
            remediation: "Review and sanitize prompt templates for injection patterns.",
            cwe: "CWE-74",
          });
        }
      }
    }

    return findings;
  },
};
