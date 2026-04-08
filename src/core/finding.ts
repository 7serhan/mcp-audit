/**
 * Security finding types and severity levels.
 */

export enum Severity {
  Critical = "critical",
  High = "high",
  Medium = "medium",
  Low = "low",
  Info = "info",
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  [Severity.Critical]: 4,
  [Severity.High]: 3,
  [Severity.Medium]: 2,
  [Severity.Low]: 1,
  [Severity.Info]: 0,
};

export interface Finding {
  /** Unique finding ID, e.g. "SSRF-001" */
  id: string;
  /** Scanner that produced this finding */
  scanner: string;
  /** Short title */
  title: string;
  /** Detailed description */
  description: string;
  severity: Severity;
  /** Affected MCP tool or resource name */
  target?: string;
  /** Evidence: request/response snippets, payloads used */
  evidence?: Evidence;
  /** Remediation guidance */
  remediation?: string;
  /** CWE ID if applicable */
  cwe?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

export interface Evidence {
  /** What was sent */
  request?: string;
  /** What came back */
  response?: string;
  /** The payload that triggered the finding */
  payload?: string;
  /** Relevant code or config snippet */
  snippet?: string;
}

export interface ScanResult {
  /** Target that was scanned */
  target: string;
  /** Timestamp of scan start */
  startedAt: Date;
  /** Timestamp of scan completion */
  completedAt: Date;
  /** Duration in ms */
  duration: number;
  /** All findings */
  findings: Finding[];
  /** Scanners that were run */
  scannersRun: string[];
  /** Scanners that errored */
  scannerErrors: ScannerError[];
  /** Summary counts by severity */
  summary: SeveritySummary;
}

export interface ScannerError {
  scanner: string;
  error: string;
}

export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export function createSeveritySummary(findings: Finding[]): SeveritySummary {
  const summary: SeveritySummary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: findings.length,
  };

  for (const f of findings) {
    summary[f.severity]++;
  }

  return summary;
}

export function severityMeetsThreshold(
  severity: Severity,
  threshold: Severity,
): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold];
}
