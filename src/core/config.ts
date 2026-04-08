/**
 * Configuration schema for mcp-audit, validated with zod.
 */

import { z } from "zod";
import { Severity } from "./finding.js";

export const ScanConfigSchema = z.object({
  /** Scanners to run (empty = all) */
  scanners: z.array(z.string()).default([]),
  /** Scanners to exclude */
  exclude: z.array(z.string()).default([]),
  /** Minimum severity to report */
  minSeverity: z.nativeEnum(Severity).default(Severity.Info),
  /** Fail threshold for CI — exit code 1 if findings at or above this severity */
  failOn: z.nativeEnum(Severity).optional(),
  /** Output format */
  output: z.enum(["terminal", "json", "sarif", "markdown"]).default("terminal"),
  /** Request timeout in ms for tool calls */
  timeout: z.number().min(1000).max(300000).default(30000),
  /** Max concurrent scanner executions */
  concurrency: z.number().min(1).max(20).default(5),
  /** Verbose logging */
  verbose: z.boolean().default(false),
  /** Custom scanner directories to load */
  pluginDirs: z.array(z.string()).default([]),
});

export type ScanConfig = z.infer<typeof ScanConfigSchema>;

export function createDefaultConfig(
  overrides?: Partial<ScanConfig>,
): ScanConfig {
  return ScanConfigSchema.parse(overrides ?? {});
}
