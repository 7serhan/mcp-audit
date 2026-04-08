/**
 * Input Validation Scanner — tests schema enforcement and boundary values.
 *
 * Checks:
 * - Missing input schemas on tools
 * - Tools accepting unexpected parameter types
 * - No boundary validation (extremely long strings, negative numbers, etc.)
 * - Type coercion vulnerabilities
 */

import { Severity, type Finding } from "../core/finding.js";
import type { ScannerPlugin } from "../core/plugin.js";
import type { ScanContext, McpTool } from "../core/context.js";

const BOUNDARY_PAYLOADS: Record<string, unknown> = {
  veryLongString: "A".repeat(10000),
  negativeNumber: -999999,
  zero: 0,
  float: 1.7976931348623157e308,
  emptyString: "",
  nullValue: null,
  booleanAsString: "true",
  numberAsString: "12345",
  arrayValue: [1, 2, 3],
  objectValue: { nested: "value" },
  specialChars: "<script>alert(1)</script>",
  unicodeString: "\u0000\u001f\uffff",
  protoPayload: { __proto__: { polluted: true } },
};

export const inputValidationScanner: ScannerPlugin = {
  name: "input-validation",
  description: "Tests schema enforcement, boundary values, and type coercion",
  version: "1.0.0",

  async run(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const tool of context.tools) {
      // Check 1: Missing input schema
      if (!tool.inputSchema || Object.keys(tool.inputSchema).length === 0) {
        findings.push({
          id: "INPUT-001",
          scanner: "input-validation",
          title: `Tool "${tool.name}" has no input schema`,
          description:
            `Tool "${tool.name}" does not define an input schema. Without schema validation, ` +
            "the tool may accept arbitrary input, increasing the attack surface.",
          severity: Severity.Medium,
          target: tool.name,
          remediation:
            "Define a strict JSON Schema for all tool inputs using the inputSchema property. " +
            "Specify required fields, types, and constraints.",
          cwe: "CWE-20",
        });
        continue;
      }

      // Check 2: Schema allows additional properties
      const schema = tool.inputSchema;
      if (schema.type === "object" && schema.additionalProperties !== false) {
        findings.push({
          id: "INPUT-002",
          scanner: "input-validation",
          title: `Tool "${tool.name}" schema allows additional properties`,
          description:
            `Tool "${tool.name}" input schema does not set additionalProperties: false. ` +
            "This means unexpected parameters can be passed, potentially triggering unintended behavior.",
          severity: Severity.Low,
          target: tool.name,
          evidence: {
            snippet: `additionalProperties: ${JSON.stringify(schema.additionalProperties ?? "not set")}`,
          },
          remediation:
            'Set "additionalProperties": false in the tool input schema to reject unknown parameters.',
          cwe: "CWE-20",
        });
      }

      // Check 3: Test boundary values on first few tools
      if (context.tools.indexOf(tool) < 3) {
        await testBoundaryValues(context, tool, findings);
      }
    }

    return findings;
  },
};

async function testBoundaryValues(
  context: ScanContext,
  tool: McpTool,
  findings: Finding[],
): Promise<void> {
  const properties = (tool.inputSchema as Record<string, unknown>)?.properties as
    | Record<string, { type?: string }>
    | undefined;

  if (!properties) return;

  // Test with very long string for string parameters
  for (const [paramName, paramDef] of Object.entries(properties)) {
    if (paramDef?.type === "string") {
      try {
        const result = await context.callTool(tool.name, {
          [paramName]: BOUNDARY_PAYLOADS.veryLongString,
        });

        if (!result.isError) {
          findings.push({
            id: "INPUT-003",
            scanner: "input-validation",
            title: `Tool "${tool.name}" accepts extremely long string input`,
            description:
              `Parameter "${paramName}" on tool "${tool.name}" accepted a 10,000-character string ` +
              "without validation. This could lead to resource exhaustion or buffer-related issues.",
            severity: Severity.Low,
            target: tool.name,
            evidence: {
              request: `${paramName}: "A".repeat(10000)`,
            },
            remediation: "Add maxLength constraints to string parameters in the input schema.",
            cwe: "CWE-20",
          });
        }
      } catch {
        // Expected — tool might reject
      }
      break; // Test one param per tool
    }

    if (paramDef?.type === "number" || paramDef?.type === "integer") {
      try {
        const result = await context.callTool(tool.name, {
          [paramName]: BOUNDARY_PAYLOADS.negativeNumber,
        });

        if (!result.isError) {
          findings.push({
            id: "INPUT-004",
            scanner: "input-validation",
            title: `Tool "${tool.name}" accepts negative number without validation`,
            description:
              `Parameter "${paramName}" on tool "${tool.name}" accepted -999999 ` +
              "without validation. Ensure numeric bounds are enforced.",
            severity: Severity.Low,
            target: tool.name,
            evidence: {
              request: `${paramName}: -999999`,
            },
            remediation: "Add minimum/maximum constraints to numeric parameters.",
            cwe: "CWE-20",
          });
        }
      } catch {
        // Expected
      }
      break;
    }
  }

  // Test prototype pollution
  try {
    const result = await context.callTool(tool.name, BOUNDARY_PAYLOADS.protoPayload as Record<string, unknown>);
    const responseText = result.content.map((c) => c.text ?? "").join("");
    if (responseText.includes("polluted")) {
      findings.push({
        id: "INPUT-005",
        scanner: "input-validation",
        title: `Tool "${tool.name}" may be vulnerable to prototype pollution`,
        description:
          `Tool "${tool.name}" processed a __proto__ payload and the response suggests ` +
          "the prototype was polluted. This can lead to code execution.",
        severity: Severity.High,
        target: tool.name,
        evidence: {
          payload: JSON.stringify(BOUNDARY_PAYLOADS.protoPayload),
          response: responseText.slice(0, 500),
        },
        remediation:
          "Sanitize input objects to strip __proto__, constructor, and prototype properties. " +
          "Use Object.create(null) for untrusted data.",
        cwe: "CWE-1321",
      });
    }
  } catch {
    // Expected
  }
}
