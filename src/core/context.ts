/**
 * ScanContext — shared state passed to every scanner.
 * Contains the MCP server connection info, discovered tools/resources, and config.
 */

import type { ScanConfig } from "./config.js";
import type { ScanTarget } from "./target.js";
import type { Logger } from "../utils/logger.js";

/** MCP Tool definition as discovered from the server */
export interface McpTool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

/** MCP Resource definition as discovered from the server */
export interface McpResource {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

/** MCP Prompt definition as discovered from the server */
export interface McpPrompt {
  name: string;
  description?: string;
  arguments?: Array<{
    name: string;
    description?: string;
    required?: boolean;
  }>;
}

/** Server capabilities as reported by the server */
export interface ServerCapabilities {
  tools?: boolean;
  resources?: boolean;
  prompts?: boolean;
  logging?: boolean;
}

export interface ScanContext {
  /** The resolved scan target */
  target: ScanTarget;
  /** Scan configuration */
  config: ScanConfig;
  /** Logger instance */
  logger: Logger;
  /** Discovered MCP tools */
  tools: McpTool[];
  /** Discovered MCP resources */
  resources: McpResource[];
  /** Discovered MCP prompts */
  prompts: McpPrompt[];
  /** Server capabilities */
  capabilities: ServerCapabilities;
  /** Call an MCP tool on the target server */
  callTool(name: string, args: Record<string, unknown>): Promise<ToolCallResult>;
  /** Read an MCP resource */
  readResource(uri: string): Promise<ResourceReadResult>;
  /** Server info (name, version) */
  serverInfo?: { name?: string; version?: string };
}

export interface ToolCallResult {
  content: Array<{
    type: string;
    text?: string;
    data?: string;
    mimeType?: string;
  }>;
  isError?: boolean;
}

export interface ResourceReadResult {
  contents: Array<{
    uri: string;
    text?: string;
    blob?: string;
    mimeType?: string;
  }>;
}
