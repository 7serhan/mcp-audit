/**
 * SARIF output — Static Analysis Results Interchange Format.
 * Compatible with GitHub Code Scanning.
 */

import type { ScanResult, Finding } from "../../core/finding.js";
import { Severity } from "../../core/finding.js";

const SEVERITY_TO_LEVEL: Record<Severity, string> = {
  [Severity.Critical]: "error",
  [Severity.High]: "error",
  [Severity.Medium]: "warning",
  [Severity.Low]: "note",
  [Severity.Info]: "none",
};

interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  help?: { text: string };
  properties?: {
    tags?: string[];
    "security-severity"?: string;
  };
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations?: Array<{
    physicalLocation?: {
      artifactLocation: { uri: string };
    };
  }>;
  properties?: Record<string, unknown>;
}

export function renderSarif(result: ScanResult): string {
  const rules: SarifRule[] = [];
  const results: SarifResult[] = [];
  const ruleIdSet = new Set<string>();

  for (const finding of result.findings) {
    // Add rule if not already added
    if (!ruleIdSet.has(finding.id)) {
      ruleIdSet.add(finding.id);
      rules.push(findingToRule(finding));
    }

    results.push(findingToResult(finding, result.target));
  }

  const sarif: SarifLog = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-audit",
            version: "0.1.0",
            informationUri: "https://github.com/mcp-audit/mcp-audit",
            rules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

function findingToRule(f: Finding): SarifRule {
  const securitySeverity: Record<Severity, string> = {
    [Severity.Critical]: "9.0",
    [Severity.High]: "7.0",
    [Severity.Medium]: "4.0",
    [Severity.Low]: "2.0",
    [Severity.Info]: "0.0",
  };

  return {
    id: f.id,
    name: f.title,
    shortDescription: { text: f.title },
    fullDescription: f.description ? { text: f.description } : undefined,
    help: f.remediation ? { text: f.remediation } : undefined,
    properties: {
      tags: ["security", f.scanner, ...(f.cwe ? [f.cwe] : [])],
      "security-severity": securitySeverity[f.severity],
    },
  };
}

function findingToResult(f: Finding, target: string): SarifResult {
  return {
    ruleId: f.id,
    level: SEVERITY_TO_LEVEL[f.severity],
    message: {
      text: `${f.description}${f.remediation ? `\n\nRemediation: ${f.remediation}` : ""}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.target ?? target },
        },
      },
    ],
    properties: {
      severity: f.severity,
      scanner: f.scanner,
      ...(f.cwe ? { cwe: f.cwe } : {}),
      ...(f.evidence ? { evidence: f.evidence } : {}),
    },
  };
}
