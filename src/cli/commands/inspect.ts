/**
 * `mcp-audit inspect` command — discover and list server capabilities without scanning.
 */

import { Command } from "commander";
import chalk from "chalk";
import { resolveTarget, TransportType } from "../../core/target.js";
import { StdioConnector } from "../../transport/stdio.js";
import { HttpConnector } from "../../transport/http.js";
import { parseConfigFile } from "../../transport/config-parser.js";
import { createLogger, LogLevel } from "../../utils/logger.js";

export const inspectCommand = new Command("inspect")
  .description("Discover and list MCP server capabilities (no scanning)")
  .argument("<target>", "Target: file path, URL, or stdio:command")
  .option("-v, --verbose", "Verbose output")
  .option("-o, --output <format>", "Output format: terminal, json", "terminal")
  .action(async (targetStr: string, opts) => {
    const logger = createLogger(opts.verbose ? LogLevel.Debug : LogLevel.Info);
    const target = resolveTarget(targetStr);

    if (target.type === TransportType.ConfigFile) {
      const servers = await parseConfigFile(target.filePath);
      for (const { name, target: serverTarget } of servers) {
        console.log(chalk.bold.cyan(`\n=== ${name} ===`));
        await inspectSingle(serverTarget, logger, opts.output);
      }
    } else {
      await inspectSingle(target, logger, opts.output);
    }
  });

async function inspectSingle(
  target: ReturnType<typeof resolveTarget>,
  logger: ReturnType<typeof createLogger>,
  format: string,
) {
  const connector =
    target.type === TransportType.Stdio
      ? new StdioConnector({
          command: target.command,
          args: target.args,
          env: target.env,
        })
      : target.type === TransportType.Http
        ? new HttpConnector({ url: target.url })
        : null;

  if (!connector) {
    logger.error(`Unsupported target type: ${target.type}`);
    return;
  }

  try {
    await connector.connect();
    const discovery = await connector.discover();

    if (format === "json") {
      console.log(JSON.stringify(discovery, null, 2));
      return;
    }

    // Terminal output
    if (discovery.serverInfo) {
      console.log(
        chalk.bold("Server:"),
        `${discovery.serverInfo.name ?? "unknown"} v${discovery.serverInfo.version ?? "?"}`,
      );
    }

    console.log(chalk.bold("\nTools:"), discovery.tools.length);
    for (const tool of discovery.tools) {
      console.log(`  ${chalk.green("●")} ${chalk.bold(tool.name)}`);
      if (tool.description) {
        console.log(`    ${chalk.dim(tool.description)}`);
      }
      if (tool.inputSchema) {
        const props = (tool.inputSchema as Record<string, unknown>).properties;
        if (props && typeof props === "object") {
          const paramNames = Object.keys(props);
          console.log(`    ${chalk.dim("params:")} ${paramNames.join(", ")}`);
        }
      }
    }

    console.log(chalk.bold("\nResources:"), discovery.resources.length);
    for (const r of discovery.resources) {
      console.log(`  ${chalk.blue("●")} ${r.uri}`);
      if (r.description) console.log(`    ${chalk.dim(r.description)}`);
    }

    console.log(chalk.bold("\nPrompts:"), discovery.prompts.length);
    for (const p of discovery.prompts) {
      console.log(`  ${chalk.yellow("●")} ${p.name}`);
      if (p.description) console.log(`    ${chalk.dim(p.description)}`);
    }
  } catch (err) {
    logger.error(`Inspect failed: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    await connector.disconnect().catch(() => {});
  }
}
