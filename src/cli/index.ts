#!/usr/bin/env node
/**
 * mcp-audit CLI entry point.
 */

import { Command } from "commander";
import { scanCommand } from "./commands/scan.js";
import { inspectCommand } from "./commands/inspect.js";

const program = new Command();

program
  .name("mcp-audit")
  .description("Security auditing tool for MCP (Model Context Protocol) servers")
  .version("0.1.0");

program.addCommand(scanCommand);
program.addCommand(inspectCommand);

program.parse();
