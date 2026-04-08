#!/usr/bin/env node
/**
 * Well-secured MCP server for testing.
 * Should produce minimal/no findings.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "secure-test-server", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_greeting",
      description: "Returns a greeting message for the given name",
      inputSchema: {
        type: "object",
        properties: {
          name: {
            type: "string",
            description: "Name to greet",
            maxLength: 100,
          },
        },
        required: ["name"],
        additionalProperties: false,
      },
    },
    {
      name: "add_numbers",
      description: "Adds two numbers together and returns the result",
      inputSchema: {
        type: "object",
        properties: {
          a: { type: "number", description: "First number" },
          b: { type: "number", description: "Second number" },
        },
        required: ["a", "b"],
        additionalProperties: false,
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "get_greeting": {
      const nameArg = (args as Record<string, unknown>).name;
      if (typeof nameArg !== "string" || nameArg.length === 0 || nameArg.length > 100) {
        return {
          content: [{ type: "text", text: "Invalid name parameter" }],
          isError: true,
        };
      }
      // Sanitize output
      const safeName = nameArg.replace(/[<>&"']/g, "");
      return { content: [{ type: "text", text: `Hello, ${safeName}!` }] };
    }

    case "add_numbers": {
      const a = (args as Record<string, unknown>).a;
      const b = (args as Record<string, unknown>).b;
      if (typeof a !== "number" || typeof b !== "number") {
        return {
          content: [{ type: "text", text: "Parameters must be numbers" }],
          isError: true,
        };
      }
      return { content: [{ type: "text", text: String(a + b) }] };
    }

    default:
      return {
        content: [{ type: "text", text: "Unknown tool" }],
        isError: true,
      };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(() => process.exit(1));
