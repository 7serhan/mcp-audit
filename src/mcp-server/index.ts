#!/usr/bin/env node
/**
 * mcp-audit MCP server — exposes security scanning as MCP tools.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { tools } from "./tools.js";
import { prompts } from "./prompts.js";

const server = new Server(
  {
    name: "mcp-audit",
    version: "0.1.0",
  },
  {
    capabilities: {
      tools: {},
      prompts: {},
    },
  },
);

// List tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: tools.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: {
      type: "object" as const,
      properties: Object.fromEntries(
        Object.entries(
          (t.inputSchema as unknown as { shape: Record<string, { _def: { typeName: string; description?: string } }> }).shape ?? {},
        ).map(([key, val]) => [
          key,
          {
            type: "string",
            description: val?._def?.description ?? key,
          },
        ]),
      ),
    },
  })),
}));

// Call tool
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const tool = tools.find((t) => t.name === request.params.name);

  if (!tool) {
    return {
      content: [{ type: "text", text: `Unknown tool: ${request.params.name}` }],
      isError: true,
    };
  }

  try {
    const result = await tool.handler(
      (request.params.arguments as Record<string, unknown>) ?? {},
    );
    return {
      content: [{ type: "text", text: result }],
    };
  } catch (err) {
    return {
      content: [
        {
          type: "text",
          text: `Error: ${err instanceof Error ? err.message : String(err)}`,
        },
      ],
      isError: true,
    };
  }
});

// List prompts
server.setRequestHandler(ListPromptsRequestSchema, async () => ({
  prompts: prompts.map((p) => ({
    name: p.name,
    description: p.description,
    arguments: p.arguments,
  })),
}));

// Get prompt
server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const prompt = prompts.find((p) => p.name === request.params.name);

  if (!prompt) {
    throw new Error(`Unknown prompt: ${request.params.name}`);
  }

  const args = (request.params.arguments as Record<string, string>) ?? {};
  const message = prompt.render(args);

  return {
    messages: [
      {
        role: "user" as const,
        content: { type: "text" as const, text: message },
      },
    ],
  };
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
