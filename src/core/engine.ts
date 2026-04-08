/**
 * ScanEngine — orchestrates scanner execution against a target.
 */

import type { ScannerPlugin } from "./plugin.js";
import type { ScanContext } from "./context.js";
import type { ScanConfig } from "./config.js";
import {
  type Finding,
  type ScanResult,
  type ScannerError,
  createSeveritySummary,
  severityMeetsThreshold,
} from "./finding.js";

export class ScanEngine {
  private plugins: Map<string, ScannerPlugin> = new Map();

  register(plugin: ScannerPlugin): void {
    if (this.plugins.has(plugin.name)) {
      throw new Error(`Scanner "${plugin.name}" is already registered`);
    }
    this.plugins.set(plugin.name, plugin);
  }

  registerAll(plugins: ScannerPlugin[]): void {
    for (const p of plugins) {
      this.register(p);
    }
  }

  getScanner(name: string): ScannerPlugin | undefined {
    return this.plugins.get(name);
  }

  listScanners(): ScannerPlugin[] {
    return Array.from(this.plugins.values());
  }

  /**
   * Run selected scanners against the context.
   */
  async scan(context: ScanContext): Promise<ScanResult> {
    const startedAt = new Date();
    const selectedPlugins = this.resolvePlugins(context.config);

    context.logger.info(
      `Running ${selectedPlugins.length} scanner(s) against ${context.target.raw}`,
    );

    const findings: Finding[] = [];
    const scannerErrors: ScannerError[] = [];
    const scannersRun: string[] = [];

    // Run scanners with concurrency limit
    const concurrency = context.config.concurrency;
    const queue = [...selectedPlugins];

    const runNext = async (): Promise<void> => {
      while (queue.length > 0) {
        const plugin = queue.shift()!;
        scannersRun.push(plugin.name);

        try {
          context.logger.debug(`Running scanner: ${plugin.name}`);
          const result = await this.runWithTimeout(
            plugin.run(context),
            context.config.timeout,
            plugin.name,
          );

          // Filter by minSeverity
          const filtered = result.filter((f) =>
            severityMeetsThreshold(f.severity, context.config.minSeverity),
          );

          findings.push(...filtered);
          context.logger.debug(
            `Scanner ${plugin.name}: ${filtered.length} finding(s)`,
          );
        } catch (err) {
          const message =
            err instanceof Error ? err.message : String(err);
          context.logger.error(`Scanner ${plugin.name} failed: ${message}`);
          scannerErrors.push({ scanner: plugin.name, error: message });
        }
      }
    };

    // Launch concurrent workers
    const workers = Array.from(
      { length: Math.min(concurrency, selectedPlugins.length) },
      () => runNext(),
    );
    await Promise.all(workers);

    const completedAt = new Date();

    return {
      target: context.target.raw,
      startedAt,
      completedAt,
      duration: completedAt.getTime() - startedAt.getTime(),
      findings: findings.sort(
        (a, b) =>
          // Sort by severity descending
          (SEVERITY_WEIGHT[b.severity] ?? 0) -
          (SEVERITY_WEIGHT[a.severity] ?? 0),
      ),
      scannersRun,
      scannerErrors,
      summary: createSeveritySummary(findings),
    };
  }

  private resolvePlugins(config: ScanConfig): ScannerPlugin[] {
    let plugins: ScannerPlugin[];

    if (config.scanners.length > 0) {
      // Only run specified scanners
      plugins = config.scanners
        .map((name) => this.plugins.get(name))
        .filter((p): p is ScannerPlugin => {
          if (!p) return false;
          return true;
        });
    } else {
      plugins = Array.from(this.plugins.values());
    }

    // Apply exclusions
    if (config.exclude.length > 0) {
      const excludeSet = new Set(config.exclude);
      plugins = plugins.filter((p) => !excludeSet.has(p.name));
    }

    return plugins;
  }

  private async runWithTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    label: string,
  ): Promise<T> {
    return Promise.race([
      promise,
      new Promise<never>((_, reject) =>
        setTimeout(
          () => reject(new Error(`Scanner "${label}" timed out after ${timeoutMs}ms`)),
          timeoutMs,
        ),
      ),
    ]);
  }
}

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};
