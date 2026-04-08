import { describe, it, expect } from "vitest";
import { createDefaultConfig, ScanConfigSchema } from "../../../src/core/config.js";
import { Severity } from "../../../src/core/finding.js";

describe("ScanConfig", () => {
  it("creates defaults", () => {
    const config = createDefaultConfig();
    expect(config.scanners).toEqual([]);
    expect(config.output).toBe("terminal");
    expect(config.timeout).toBe(30000);
    expect(config.concurrency).toBe(5);
    expect(config.verbose).toBe(false);
  });

  it("accepts overrides", () => {
    const config = createDefaultConfig({
      scanners: ["ssrf", "auth"],
      output: "json",
      failOn: Severity.High,
      verbose: true,
    });

    expect(config.scanners).toEqual(["ssrf", "auth"]);
    expect(config.output).toBe("json");
    expect(config.failOn).toBe(Severity.High);
    expect(config.verbose).toBe(true);
  });

  it("validates timeout range", () => {
    expect(() => ScanConfigSchema.parse({ timeout: 500 })).toThrow();
    expect(() => ScanConfigSchema.parse({ timeout: 60000 })).not.toThrow();
  });

  it("validates concurrency range", () => {
    expect(() => ScanConfigSchema.parse({ concurrency: 0 })).toThrow();
    expect(() => ScanConfigSchema.parse({ concurrency: 25 })).toThrow();
  });
});
