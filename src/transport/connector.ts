/**
 * Abstract connector — wraps MCP client connections to target servers.
 */

import type {
  McpTool,
  McpResource,
  McpPrompt,
  ServerCapabilities,
  ToolCallResult,
  ResourceReadResult,
} from "../core/context.js";

export interface ServerDiscovery {
  tools: McpTool[];
  resources: McpResource[];
  prompts: McpPrompt[];
  capabilities: ServerCapabilities;
  serverInfo?: { name?: string; version?: string };
}

export interface McpConnector {
  /** Connect to the MCP server */
  connect(): Promise<void>;
  /** Discover server capabilities, tools, resources, prompts */
  discover(): Promise<ServerDiscovery>;
  /** Call a tool on the server */
  callTool(name: string, args: Record<string, unknown>): Promise<ToolCallResult>;
  /** Read a resource from the server */
  readResource(uri: string): Promise<ResourceReadResult>;
  /** Disconnect and clean up */
  disconnect(): Promise<void>;
}
