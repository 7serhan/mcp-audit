/**
 * HTTP/SSE transport — connects to MCP servers via HTTP.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import type { McpConnector, ServerDiscovery } from "./connector.js";
import type { ToolCallResult, ResourceReadResult } from "../core/context.js";

export interface HttpConnectorOptions {
  url: string;
  headers?: Record<string, string>;
  timeout?: number;
}

export class HttpConnector implements McpConnector {
  private client: Client;
  private transport: SSEClientTransport;

  constructor(options: HttpConnectorOptions) {
    this.transport = new SSEClientTransport(new URL(options.url));
    this.client = new Client(
      { name: "mcp-audit", version: "0.1.0" },
      { capabilities: {} },
    );
  }

  async connect(): Promise<void> {
    await this.client.connect(this.transport);
  }

  async discover(): Promise<ServerDiscovery> {
    const [toolsResult, resourcesResult, promptsResult] =
      await Promise.allSettled([
        this.client.listTools(),
        this.client.listResources(),
        this.client.listPrompts(),
      ]);

    const tools =
      toolsResult.status === "fulfilled"
        ? toolsResult.value.tools.map((t) => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema as Record<string, unknown> | undefined,
          }))
        : [];

    const resources =
      resourcesResult.status === "fulfilled"
        ? resourcesResult.value.resources.map((r) => ({
            uri: r.uri,
            name: r.name,
            description: r.description,
            mimeType: r.mimeType,
          }))
        : [];

    const prompts =
      promptsResult.status === "fulfilled"
        ? promptsResult.value.prompts.map((p) => ({
            name: p.name,
            description: p.description,
            arguments: p.arguments?.map((a) => ({
              name: a.name,
              description: a.description,
              required: a.required,
            })),
          }))
        : [];

    return {
      tools,
      resources,
      prompts,
      capabilities: {
        tools: tools.length > 0,
        resources: resources.length > 0,
        prompts: prompts.length > 0,
      },
      serverInfo: this.client.getServerVersion()
        ? {
            name: this.client.getServerVersion()?.name,
            version: this.client.getServerVersion()?.version,
          }
        : undefined,
    };
  }

  async callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<ToolCallResult> {
    const result = await this.client.callTool({ name, arguments: args });
    return {
      content: (result.content as ToolCallResult["content"]) ?? [],
      isError: result.isError as boolean | undefined,
    };
  }

  async readResource(uri: string): Promise<ResourceReadResult> {
    const result = await this.client.readResource({ uri });
    return {
      contents: result.contents.map((c) => ({
        uri: c.uri,
        text: "text" in c ? c.text : undefined,
        blob: "blob" in c ? c.blob : undefined,
        mimeType: c.mimeType,
      })),
    };
  }

  async disconnect(): Promise<void> {
    await this.client.close();
  }
}
