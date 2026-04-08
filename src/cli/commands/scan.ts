/**
 * `mcp-audit scan` command — run security scanners against an MCP target.
 */

import { Command } from "commander";
import { Severity } from "../../core/finding.js";
import { ScanEngine } from "../../core/engine.js";
import { createDefaultConfig, type ScanConfig } from "../../core/config.js";
import { resolveTarget, TransportType } from "../../core/target.js";
import type { ScanContext } from "../../core/context.js";
import { getAllScanners } from "../../scanners/index.js";
import { StdioConnector } from "../../transport/stdio.js";
import { HttpConnector } from "../../transport/http.js";
import { parseConfigFile } from "../../transport/config-parser.js";
import { createLogger, LogLevel } from "../../utils/logger.js";
import { renderTerminal } from "../output/terminal.js";
import { renderJson } from "../output/json.js";
import { renderSarif } from "../output/sarif.js";
import { renderMarkdown } from "../output/markdown.js";
import type { ScanResult } from "../../core/finding.js";

export const scanCommand = new Command("scan")
  .description("Run security audit against an MCP server or config file")
  .argument("<target>", "Target: file path, URL, or stdio:command")
  .option("-s, --scanners <list>", "Comma-separated scanner names to run")
  .option("-x, --exclude <list>", "Comma-separated scanner names to exclude")
  .option("-o, --output <format>", "Output format: terminal, json, sarif, markdown", "terminal")
  .option("--fail-on <severity>", "Exit code 1 if findings at or above severity")
  .option("--timeout <ms>", "Tool call timeout in ms", "30000")
  .option("--concurrency <n>", "Max concurrent scanners", "5")
  .option("-v, --verbose", "Verbose output")
  .action(async (targetStr: string, opts) => {
    const config = createDefaultConfig({
      scanners: opts.scanners ? opts.scanners.split(",") : [],
      exclude: opts.exclude ? opts.exclude.split(",") : [],
      output: opts.output,
      failOn: opts.failOn as Severity | undefined,
      timeout: parseInt(opts.timeout, 10),
      concurrency: parseInt(opts.concurrency, 10),
      verbose: opts.verbose ?? false,
    });

    const logger = createLogger(config.verbose ? LogLevel.Debug : LogLevel.Info);
    const target = resolveTarget(targetStr);

    // If config file, scan each server in it
    if (target.type === TransportType.ConfigFile) {
      const servers = await parseConfigFile(target.filePath);
      logger.info(`Found ${servers.length} server(s) in config file`);

      const allResults: ScanResult[] = [];

      for (const { name, target: serverTarget } of servers) {
        logger.info(`\nScanning server: ${name}`);
        try {
          const result = await scanSingleTarget(serverTarget, config, logger);
          allResults.push(result);
        } catch (err) {
          logger.error(`Failed to scan "${name}": ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      for (const result of allResults) {
        outputResult(result, config);
      }

      const hasFailures = config.failOn
        ? allResults.some((r) =>
            r.findings.some((f) => severityGte(f.severity, config.failOn!)),
          )
        : false;

      process.exit(hasFailures ? 1 : 0);
    } else {
      // Single target
      try {
        const result = await scanSingleTarget(target, config, logger);
        outputResult(result, config);

        const hasFailures = config.failOn
          ? result.findings.some((f) => severityGte(f.severity, config.failOn!))
          : false;

        process.exit(hasFailures ? 1 : 0);
      } catch (err) {
        logger.error(`Scan failed: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(2);
      }
    }
  });

async function scanSingleTarget(
  target: ReturnType<typeof resolveTarget>,
  config: ScanConfig,
  logger: ReturnType<typeof createLogger>,
): Promise<ScanResult> {
  // Create connector based on target type
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
    throw new Error(`Unsupported target type: ${target.type}`);
  }

  try {
    logger.info("Connecting to server...");
    await connector.connect();

    logger.info("Discovering capabilities...");
    const discovery = await connector.discover();

    logger.info(
      `Found ${discovery.tools.length} tool(s), ${discovery.resources.length} resource(s), ${discovery.prompts.length} prompt(s)`,
    );

    // Build scan context
    const context: ScanContext = {
      target,
      config,
      logger,
      tools: discovery.tools,
      resources: discovery.resources,
      prompts: discovery.prompts,
      capabilities: discovery.capabilities,
      serverInfo: discovery.serverInfo,
      callTool: (name, args) => connector.callTool(name, args),
      readResource: (uri) => connector.readResource(uri),
    };

    // Run scanners
    const engine = new ScanEngine();
    engine.registerAll(getAllScanners());

    return await engine.scan(context);
  } finally {
    await connector.disconnect().catch(() => {});
  }
}

function outputResult(result: ScanResult, config: ScanConfig): void {
  switch (config.output) {
    case "json":
      console.log(renderJson(result));
      break;
    case "sarif":
      console.log(renderSarif(result));
      break;
    case "markdown":
      console.log(renderMarkdown(result));
      break;
    default:
      console.log(renderTerminal(result));
  }
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function severityGte(severity: Severity, threshold: Severity): boolean {
  return (SEVERITY_ORDER[severity] ?? 0) >= (SEVERITY_ORDER[threshold] ?? 0);
}
