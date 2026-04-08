import { describe, it, expect } from "vitest";
import {
  Severity,
  createSeveritySummary,
  severityMeetsThreshold,
  type Finding,
} from "../../../src/core/finding.js";

describe("createSeveritySummary", () => {
  it("counts findings by severity", () => {
    const findings: Finding[] = [
      makeFinding("F-1", Severity.Critical),
      makeFinding("F-2", Severity.High),
      makeFinding("F-3", Severity.High),
      makeFinding("F-4", Severity.Medium),
      makeFinding("F-5", Severity.Low),
      makeFinding("F-6", Severity.Info),
    ];

    const summary = createSeveritySummary(findings);

    expect(summary.critical).toBe(1);
    expect(summary.high).toBe(2);
    expect(summary.medium).toBe(1);
    expect(summary.low).toBe(1);
    expect(summary.info).toBe(1);
    expect(summary.total).toBe(6);
  });

  it("handles empty findings", () => {
    const summary = createSeveritySummary([]);
    expect(summary.total).toBe(0);
    expect(summary.critical).toBe(0);
  });
});

describe("severityMeetsThreshold", () => {
  it("critical meets all thresholds", () => {
    expect(severityMeetsThreshold(Severity.Critical, Severity.Critical)).toBe(true);
    expect(severityMeetsThreshold(Severity.Critical, Severity.Low)).toBe(true);
  });

  it("low does not meet high threshold", () => {
    expect(severityMeetsThreshold(Severity.Low, Severity.High)).toBe(false);
  });

  it("medium meets medium threshold", () => {
    expect(severityMeetsThreshold(Severity.Medium, Severity.Medium)).toBe(true);
  });
});

function makeFinding(id: string, severity: Severity): Finding {
  return {
    id,
    scanner: "test",
    title: `Test finding ${id}`,
    description: "Test",
    severity,
  };
}
