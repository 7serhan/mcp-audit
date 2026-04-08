/**
 * Parse MCP config files (.mcp.json, claude_desktop_config.json etc.)
 * and extract server definitions.
 */

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { ScanTarget } from "../core/target.js";
import { TransportType } from "../core/target.js";

export interface McpServerEntry {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  type?: string;
}

export interface McpConfigFile {
  mcpServers?: Record<string, McpServerEntry>;
}

/**
 * Read and parse a config file, returning individual targets for each server.
 */
export async function parseConfigFile(
  filePath: string,
): Promise<{ name: string; target: ScanTarget }[]> {
  const absPath = resolve(filePath);
  const raw = await readFile(absPath, "utf-8");
  const config: McpConfigFile = JSON.parse(raw);

  if (!config.mcpServers || typeof config.mcpServers !== "object") {
    throw new Error(`No "mcpServers" found in ${absPath}`);
  }

  const targets: { name: string; target: ScanTarget }[] = [];

  for (const [name, entry] of Object.entries(config.mcpServers)) {
    if (entry.url) {
      targets.push({
        name,
        target: {
          type: TransportType.Http,
          url: entry.url,
          headers: undefined,
          raw: entry.url,
        },
      });
    } else if (entry.command) {
      targets.push({
        name,
        target: {
          type: TransportType.Stdio,
          command: entry.command,
          args: entry.args ?? [],
          env: entry.env,
          raw: `stdio:${entry.command} ${(entry.args ?? []).join(" ")}`.trim(),
        },
      });
    }
  }

  return targets;
}
