/**
 * MCP Server tool definitions — 6 tools for mcp-audit.
 */

import { z } from "zod";
import type { ScanResult } from "../core/finding.js";
import { ScanEngine } from "../core/engine.js";
import { createDefaultConfig } from "../core/config.js";
import { resolveTarget, TransportType } from "../core/target.js";
import type { ScanContext } from "../core/context.js";
import { getAllScanners } from "../scanners/index.js";
import { StdioConnector } from "../transport/stdio.js";
import { HttpConnector } from "../transport/http.js";
import { parseConfigFile } from "../transport/config-parser.js";
import { nullLogger } from "../utils/logger.js";
import { renderJson } from "../cli/output/json.js";
import { renderSarif } from "../cli/output/sarif.js";
import { renderMarkdown } from "../cli/output/markdown.js";

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: z.ZodType;
  handler: (args: Record<string, unknown>) => Promise<string>;
}

async function runScan(targetStr: string, scanners?: string[], exclude?: string[]): Promise<ScanResult> {
  const config = createDefaultConfig({
    scanners: scanners ?? [],
    exclude: exclude ?? [],
  });

  const target = resolveTarget(targetStr);

  const connector =
    target.type === TransportType.Stdio
      ? new StdioConnector({ command: target.command, args: target.args, env: target.env })
      : target.type === TransportType.Http
        ? new HttpConnector({ url: target.url })
        : null;

  if (!connector) throw new Error(`Unsupported target: ${target.type}`);

  try {
    await connector.connect();
    const discovery = await connector.discover();

    const context: ScanContext = {
      target,
      config,
      logger: nullLogger,
      tools: discovery.tools,
      resources: discovery.resources,
      prompts: discovery.prompts,
      capabilities: discovery.capabilities,
      serverInfo: discovery.serverInfo,
      callTool: (name, args) => connector.callTool(name, args),
      readResource: (uri) => connector.readResource(uri),
    };

    const engine = new ScanEngine();
    engine.registerAll(getAllScanners());
    return await engine.scan(context);
  } finally {
    await connector.disconnect().catch(() => {});
  }
}

export const tools: ToolDefinition[] = [
  {
    name: "scan_server",
    description: "Run a full security audit against an MCP server. Returns findings with severity, description, and remediation guidance.",
    inputSchema: z.object({
      target: z.string().describe("Target: URL (https://...), stdio command (stdio:npx -y @server), or config file path"),
      scanners: z.array(z.string()).optional().describe("Specific scanners to run (empty = all)"),
      exclude: z.array(z.string()).optional().describe("Scanners to exclude"),
    }),
    handler: async (args) => {
      const result = await runScan(
        args.target as string,
        args.scanners as string[] | undefined,
        args.exclude as string[] | undefined,
      );
      return renderJson(result);
    },
  },
  {
    name: "inspect_server",
    description: "Discover MCP server capabilities (tools, resources, prompts) without running any security scans.",
    inputSchema: z.object({
      target: z.string().describe("Target: URL, stdio command, or config file path"),
    }),
    handler: async (args) => {
      const target = resolveTarget(args.target as string);
      const connector =
        target.type === TransportType.Stdio
          ? new StdioConnector({ command: target.command, args: target.args, env: target.env })
          : target.type === TransportType.Http
            ? new HttpConnector({ url: target.url })
            : null;

      if (!connector) throw new Error(`Unsupported target: ${target.type}`);

      try {
        await connector.connect();
        const discovery = await connector.discover();
        return JSON.stringify(discovery, null, 2);
      } finally {
        await connector.disconnect().catch(() => {});
      }
    },
  },
  {
    name: "scan_config_file",
    description: "Scan all MCP servers defined in a config file (.mcp.json, claude_desktop_config.json).",
    inputSchema: z.object({
      path: z.string().describe("Path to config file"),
      scanners: z.array(z.string()).optional().describe("Specific scanners to run"),
    }),
    handler: async (args) => {
      const servers = await parseConfigFile(args.path as string);
      const results: Record<string, ScanResult> = {};

      for (const { name, target } of servers) {
        try {
          results[name] = await runScan(target.raw, args.scanners as string[] | undefined);
        } catch (err) {
          results[name] = {
            target: target.raw,
            startedAt: new Date(),
            completedAt: new Date(),
            duration: 0,
            findings: [],
            scannersRun: [],
            scannerErrors: [{ scanner: "connection", error: err instanceof Error ? err.message : String(err) }],
            summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
          };
        }
      }

      return JSON.stringify(results, null, 2);
    },
  },
  {
    name: "list_scanners",
    description: "List all available security scanners with their descriptions.",
    inputSchema: z.object({}),
    handler: async () => {
      const scanners = getAllScanners().map((s) => ({
        name: s.name,
        description: s.description,
        version: s.version,
      }));
      return JSON.stringify(scanners, null, 2);
    },
  },
  {
    name: "explain_finding",
    description: "Get detailed explanation and remediation guidance for a specific finding ID.",
    inputSchema: z.object({
      finding_id: z.string().describe("Finding ID, e.g. SSRF-001, AUTH-002"),
    }),
    handler: async (args) => {
      const id = args.finding_id as string;
      const explanations: Record<string, { title: string; detail: string; remediation: string }> = {
        "SSRF-001": {
          title: "Server-Side Request Forgery — Internal Host Access",
          detail: "The MCP tool accepted a URL pointing to an internal network host (127.0.0.1, 10.x.x.x, etc.) and made a request to it. This allows attackers to scan internal networks, access internal services, and potentially steal cloud credentials.",
          remediation: "1. Validate all URL inputs against an allowlist of permitted domains.\n2. Block private IP ranges: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.\n3. Block metadata IPs: 169.254.169.254.\n4. Resolve DNS before checking IPs to prevent DNS rebinding.\n5. Use a proxy with egress filtering.",
        },
        "CMDI-002": {
          title: "Command Injection Confirmed",
          detail: "The MCP tool concatenates user input into shell commands without sanitization. Our canary payload was executed, confirming arbitrary command execution.",
          remediation: "1. Never use child_process.exec() with user input.\n2. Use child_process.execFile() with explicit argument arrays.\n3. Validate input against an allowlist.\n4. Use parameterized APIs instead of shell commands.\n5. Run in a sandboxed environment with minimal privileges.",
        },
        "AUTH-001": {
          title: "No Authentication Required",
          detail: "The MCP server accepted connections and exposed its full capability set without requiring any form of authentication. Any client can connect and use all tools.",
          remediation: "1. Implement token-based authentication (API keys, JWT, OAuth).\n2. Use mTLS for service-to-service auth.\n3. Validate auth on every request, not just connection.\n4. Implement RBAC for different tool access levels.",
        },
      };

      const explanation = explanations[id];
      if (explanation) {
        return JSON.stringify(explanation, null, 2);
      }

      return JSON.stringify({
        title: `Finding ${id}`,
        detail: "Detailed explanation for this finding ID is not yet available. Run a scan to get finding details with remediation guidance.",
        remediation: "Review the finding description and CWE reference for remediation guidance.",
      });
    },
  },
  {
    name: "generate_report",
    description: "Generate a formatted security report from scan results.",
    inputSchema: z.object({
      target: z.string().describe("Target to scan and generate report for"),
      format: z.enum(["json", "sarif", "markdown"]).default("markdown").describe("Report format"),
    }),
    handler: async (args) => {
      const result = await runScan(args.target as string);

      switch (args.format) {
        case "sarif":
          return renderSarif(result);
        case "markdown":
          return renderMarkdown(result);
        default:
          return renderJson(result);
      }
    },
  },
];
