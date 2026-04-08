/**
 * MCP Server prompt templates.
 */

export interface PromptTemplate {
  name: string;
  description: string;
  arguments?: Array<{
    name: string;
    description: string;
    required?: boolean;
  }>;
  render: (args: Record<string, string>) => string;
}

export const prompts: PromptTemplate[] = [
  {
    name: "security-review",
    description: "Generate a comprehensive security review prompt for an MCP server",
    arguments: [
      {
        name: "target",
        description: "The MCP server target to review",
        required: true,
      },
    ],
    render: (args) =>
      `Please perform a comprehensive security audit of the MCP server at "${args.target}". ` +
      `Use the scan_server tool to run all security scanners, then analyze each finding and provide:\n\n` +
      `1. An executive summary of the security posture\n` +
      `2. Critical findings that need immediate attention\n` +
      `3. A prioritized remediation plan\n` +
      `4. Any patterns or systemic issues observed\n\n` +
      `Format the response as a professional security report.`,
  },
  {
    name: "quick-check",
    description: "Quick security check focusing on critical issues only",
    arguments: [
      {
        name: "target",
        description: "The MCP server target to check",
        required: true,
      },
    ],
    render: (args) =>
      `Run a quick security check on "${args.target}" focusing only on critical and high severity issues. ` +
      `Use scan_server with only these scanners: auth, ssrf, command-injection. ` +
      `Report only actionable findings.`,
  },
  {
    name: "compliance-report",
    description: "Generate a compliance-oriented security report",
    arguments: [
      {
        name: "target",
        description: "The MCP server target",
        required: true,
      },
      {
        name: "framework",
        description: "Compliance framework (e.g., OWASP, SOC2, ISO27001)",
        required: false,
      },
    ],
    render: (args) =>
      `Perform a security audit of "${args.target}" and map findings to ${args.framework ?? "OWASP"} requirements. ` +
      `For each finding, include:\n` +
      `- The relevant compliance requirement\n` +
      `- Current status (compliant/non-compliant)\n` +
      `- Required actions for compliance\n` +
      `- Evidence collected during the scan`,
  },
];
