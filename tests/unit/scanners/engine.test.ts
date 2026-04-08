import { describe, it, expect } from "vitest";
import { ScanEngine } from "../../../src/core/engine.js";
import { Severity, type Finding } from "../../../src/core/finding.js";
import type { ScannerPlugin } from "../../../src/core/plugin.js";
import type { ScanContext } from "../../../src/core/context.js";
import { createDefaultConfig } from "../../../src/core/config.js";
import { TransportType } from "../../../src/core/target.js";
import { nullLogger } from "../../../src/utils/logger.js";

function makePlugin(name: string, findings: Finding[]): ScannerPlugin {
  return {
    name,
    description: `Test scanner ${name}`,
    version: "1.0.0",
    run: async () => findings,
  };
}

function makeContext(overrides?: Partial<ScanContext>): ScanContext {
  return {
    target: { type: TransportType.Stdio, command: "test", args: [], raw: "test" },
    config: createDefaultConfig(),
    logger: nullLogger,
    tools: [],
    resources: [],
    prompts: [],
    capabilities: {},
    callTool: async () => ({ content: [] }),
    readResource: async () => ({ contents: [] }),
    ...overrides,
  };
}

describe("ScanEngine", () => {
  it("registers and runs plugins", async () => {
    const engine = new ScanEngine();
    engine.register(
      makePlugin("test-scanner", [
        {
          id: "T-001",
          scanner: "test-scanner",
          title: "Test finding",
          description: "Found something",
          severity: Severity.Medium,
        },
      ]),
    );

    const result = await engine.scan(makeContext());
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].id).toBe("T-001");
    expect(result.scannersRun).toContain("test-scanner");
  });

  it("respects scanner selection", async () => {
    const engine = new ScanEngine();
    engine.register(makePlugin("a", [{ id: "A-1", scanner: "a", title: "A", description: "", severity: Severity.Low }]));
    engine.register(makePlugin("b", [{ id: "B-1", scanner: "b", title: "B", description: "", severity: Severity.Low }]));

    const result = await engine.scan(
      makeContext({ config: createDefaultConfig({ scanners: ["a"] }) }),
    );

    expect(result.scannersRun).toEqual(["a"]);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].scanner).toBe("a");
  });

  it("respects scanner exclusion", async () => {
    const engine = new ScanEngine();
    engine.register(makePlugin("a", [{ id: "A-1", scanner: "a", title: "A", description: "", severity: Severity.Low }]));
    engine.register(makePlugin("b", [{ id: "B-1", scanner: "b", title: "B", description: "", severity: Severity.Low }]));

    const result = await engine.scan(
      makeContext({ config: createDefaultConfig({ exclude: ["b"] }) }),
    );

    expect(result.scannersRun).toEqual(["a"]);
  });

  it("filters by minSeverity", async () => {
    const engine = new ScanEngine();
    engine.register(
      makePlugin("test", [
        { id: "T-1", scanner: "test", title: "Critical", description: "", severity: Severity.Critical },
        { id: "T-2", scanner: "test", title: "Low", description: "", severity: Severity.Low },
      ]),
    );

    const result = await engine.scan(
      makeContext({ config: createDefaultConfig({ minSeverity: Severity.High }) }),
    );

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe(Severity.Critical);
  });

  it("handles scanner errors gracefully", async () => {
    const engine = new ScanEngine();
    engine.register({
      name: "failing",
      description: "Always fails",
      version: "1.0.0",
      run: async () => {
        throw new Error("boom");
      },
    });

    const result = await engine.scan(makeContext());
    expect(result.findings).toHaveLength(0);
    expect(result.scannerErrors).toHaveLength(1);
    expect(result.scannerErrors[0].scanner).toBe("failing");
  });

  it("sorts findings by severity descending", async () => {
    const engine = new ScanEngine();
    engine.register(
      makePlugin("test", [
        { id: "T-1", scanner: "test", title: "Low", description: "", severity: Severity.Low },
        { id: "T-2", scanner: "test", title: "Critical", description: "", severity: Severity.Critical },
        { id: "T-3", scanner: "test", title: "Medium", description: "", severity: Severity.Medium },
      ]),
    );

    const result = await engine.scan(makeContext());
    expect(result.findings[0].severity).toBe(Severity.Critical);
    expect(result.findings[1].severity).toBe(Severity.Medium);
    expect(result.findings[2].severity).toBe(Severity.Low);
  });

  it("prevents duplicate plugin registration", () => {
    const engine = new ScanEngine();
    engine.register(makePlugin("dup", []));
    expect(() => engine.register(makePlugin("dup", []))).toThrow();
  });
});
