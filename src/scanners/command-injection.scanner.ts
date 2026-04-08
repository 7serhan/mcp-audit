/**
 * Command Injection Scanner — detects shell command injection vulnerabilities.
 *
 * Checks:
 * - Tools that execute system commands with user-controlled input
 * - Shell metacharacter injection (;, |, &&, $(), ``)
 * - Argument injection in command parameters
 * - Canary-based detection of command execution
 */

import { Severity, type Finding } from "../core/finding.js";
import type { ScannerPlugin } from "../core/plugin.js";
import type { ScanContext, McpTool } from "../core/context.js";
import { CANARY, containsCanary, generateCommandInjectionPayloads } from "../utils/sandbox.js";

/** Patterns suggesting a tool executes commands */
const COMMAND_TOOL_PATTERNS = [
  /exec|execute|run|shell|command|cmd|bash|sh|terminal|process|spawn/i,
  /script|eval|system|popen|subprocess/i,
];

/** Patterns suggesting a parameter is used in command execution */
const COMMAND_PARAM_PATTERNS = [
  /command|cmd|script|args|arguments|flags|options|params/i,
  /query|expression|filter|pattern|regex|search/i,
  /filename|filepath|path|dir|directory/i,
  /input|value|data|content|body|text/i,
];

export const commandInjectionScanner: ScannerPlugin = {
  name: "command-injection",
  description: "Detects shell command injection vulnerabilities in MCP tools",
  version: "1.0.0",

  async run(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const tool of context.tools) {
      const isCommandTool = COMMAND_TOOL_PATTERNS.some(
        (p) => p.test(tool.name) || p.test(tool.description ?? ""),
      );

      // Static analysis: flag tools that appear to run commands
      if (isCommandTool) {
        findings.push({
          id: "CMDI-001",
          scanner: "command-injection",
          title: `Tool "${tool.name}" appears to execute system commands`,
          description:
            `Tool "${tool.name}" (${tool.description ?? "no description"}) appears to provide ` +
            "command execution capability. If user input is passed to shell commands without " +
            "proper sanitization, this enables arbitrary command execution.",
          severity: Severity.High,
          target: tool.name,
          remediation:
            "Avoid shell execution where possible. Use parameterized APIs instead of shell commands. " +
            "If shell execution is necessary, use an allowlist of permitted commands, " +
            "never concatenate user input into command strings, and use execFile() instead of exec().",
          cwe: "CWE-78",
        });
      }

      // Active probing: inject canary payloads
      const testableParams = findCommandParameters(tool);

      for (const param of testableParams) {
        const payloads = generateCommandInjectionPayloads("test");

        for (const payload of payloads) {
          try {
            const result = await context.callTool(tool.name, {
              [param]: payload,
            });

            const responseText = result.content
              .map((c) => c.text ?? "")
              .join("\n");

            if (containsCanary(responseText)) {
              findings.push({
                id: "CMDI-002",
                scanner: "command-injection",
                title: `Command injection confirmed in tool "${tool.name}"`,
                description:
                  `Tool "${tool.name}" parameter "${param}" is vulnerable to command injection. ` +
                  `Payload "${payload}" resulted in our canary marker appearing in the response, ` +
                  "confirming arbitrary command execution.",
                severity: Severity.Critical,
                target: tool.name,
                evidence: {
                  payload,
                  request: `callTool("${tool.name}", { "${param}": "${payload}" })`,
                  response: responseText.slice(0, 500),
                },
                remediation:
                  "CRITICAL: This tool is vulnerable to command injection. " +
                  "Immediately sanitize all inputs. Use parameterized command execution. " +
                  "Never pass user input to shell interpreters. Use child_process.execFile() " +
                  "with argument arrays instead of child_process.exec().",
                cwe: "CWE-78",
              });

              // One confirmed finding per tool is enough
              return findings;
            }
          } catch {
            // Tool call failed — might have rejected the payload
          }
        }
      }

      // Test for argument injection (-- prefix injection)
      if (isCommandTool && testableParams.length > 0) {
        const param = testableParams[0];
        const argPayloads = [
          `--help`,
          `--version`,
          `-rf /`,
          `--output=/tmp/${CANARY.MARKER}`,
        ];

        for (const payload of argPayloads) {
          try {
            const result = await context.callTool(tool.name, {
              [param]: payload,
            });

            const responseText = result.content
              .map((c) => c.text ?? "")
              .join("\n");

            // If --help or --version returns expected output, argument injection works
            if (
              /usage:|options:|version\s+\d/i.test(responseText) &&
              (payload === "--help" || payload === "--version")
            ) {
              findings.push({
                id: "CMDI-003",
                scanner: "command-injection",
                title: `Argument injection in tool "${tool.name}"`,
                description:
                  `Tool "${tool.name}" parameter "${param}" allows argument injection. ` +
                  `Passing "${payload}" triggered help/version output, indicating that user input ` +
                  "is interpreted as command-line arguments.",
                severity: Severity.High,
                target: tool.name,
                evidence: {
                  payload,
                  response: responseText.slice(0, 500),
                },
                remediation:
                  "Validate inputs against an allowlist. Prepend '--' to separate options from arguments. " +
                  "Don't pass user input as command-line flags.",
                cwe: "CWE-88",
              });
              break;
            }
          } catch {
            // Expected
          }
        }
      }
    }

    return findings;
  },
};

function findCommandParameters(tool: McpTool): string[] {
  const schema = tool.inputSchema;
  if (!schema || typeof schema !== "object") return [];

  const properties = (schema as Record<string, unknown>).properties as
    | Record<string, { type?: string }>
    | undefined;

  if (!properties) return [];

  const params: string[] = [];

  for (const [name, def] of Object.entries(properties)) {
    if (def?.type === "string" && COMMAND_PARAM_PATTERNS.some((p) => p.test(name))) {
      params.push(name);
    }
  }

  // If no params matched by name, use all string params
  if (params.length === 0) {
    for (const [name, def] of Object.entries(properties)) {
      if (def?.type === "string") {
        params.push(name);
      }
    }
  }

  return params.slice(0, 3); // Limit to 3 params to avoid excessive probing
}
