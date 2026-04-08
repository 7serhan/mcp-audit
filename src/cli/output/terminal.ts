/**
 * Terminal output — colorful, human-readable scan results.
 */

import chalk from "chalk";
import type { ScanResult, Finding } from "../../core/finding.js";
import { Severity } from "../../core/finding.js";

const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  [Severity.Critical]: chalk.bgRed.white.bold,
  [Severity.High]: chalk.red.bold,
  [Severity.Medium]: chalk.yellow.bold,
  [Severity.Low]: chalk.blue,
  [Severity.Info]: chalk.dim,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  [Severity.Critical]: "!!!",
  [Severity.High]: "!!",
  [Severity.Medium]: "!",
  [Severity.Low]: "-",
  [Severity.Info]: "i",
};

export function renderTerminal(result: ScanResult): string {
  const lines: string[] = [];

  // Header
  lines.push("");
  lines.push(chalk.bold.cyan("  mcp-audit Security Report"));
  lines.push(chalk.dim(`  Target: ${result.target}`));
  lines.push(chalk.dim(`  Duration: ${result.duration}ms`));
  lines.push(chalk.dim(`  Scanners: ${result.scannersRun.join(", ")}`));
  lines.push("");

  // Summary
  const s = result.summary;
  lines.push(chalk.bold("  Summary:"));
  if (s.critical > 0) lines.push(`    ${chalk.bgRed.white.bold(` ${s.critical} CRITICAL `)}`);
  if (s.high > 0) lines.push(`    ${chalk.red.bold(`${s.high} High`)}`);
  if (s.medium > 0) lines.push(`    ${chalk.yellow.bold(`${s.medium} Medium`)}`);
  if (s.low > 0) lines.push(`    ${chalk.blue(`${s.low} Low`)}`);
  if (s.info > 0) lines.push(`    ${chalk.dim(`${s.info} Info`)}`);
  lines.push(`    ${chalk.bold(`${s.total} Total`)}`);
  lines.push("");

  if (s.total === 0) {
    lines.push(chalk.green.bold("  No security findings detected."));
    lines.push("");
    return lines.join("\n");
  }

  // Findings
  lines.push(chalk.bold("  Findings:"));
  lines.push(chalk.dim("  " + "─".repeat(70)));

  for (const finding of result.findings) {
    lines.push(renderFinding(finding));
  }

  // Scanner errors
  if (result.scannerErrors.length > 0) {
    lines.push("");
    lines.push(chalk.bold.red("  Scanner Errors:"));
    for (const err of result.scannerErrors) {
      lines.push(`    ${chalk.red("x")} ${err.scanner}: ${err.error}`);
    }
  }

  lines.push("");
  return lines.join("\n");
}

function renderFinding(f: Finding): string {
  const lines: string[] = [];
  const color = SEVERITY_COLORS[f.severity];
  const icon = SEVERITY_ICONS[f.severity];

  lines.push("");
  lines.push(`  ${color(`[${icon}] ${f.severity.toUpperCase()}`)} ${chalk.bold(f.title)}`);
  lines.push(`  ${chalk.dim(`${f.id} | ${f.scanner}${f.target ? ` | ${f.target}` : ""}`)}`);
  lines.push(`  ${f.description}`);

  if (f.evidence) {
    if (f.evidence.payload) {
      lines.push(`  ${chalk.dim("Payload:")} ${f.evidence.payload}`);
    }
    if (f.evidence.response) {
      lines.push(`  ${chalk.dim("Response:")} ${f.evidence.response.slice(0, 200)}`);
    }
  }

  if (f.remediation) {
    lines.push(`  ${chalk.green("Fix:")} ${f.remediation}`);
  }

  if (f.cwe) {
    lines.push(`  ${chalk.dim(`CWE: ${f.cwe}`)}`);
  }

  return lines.join("\n");
}
