import { describe, it, expect } from "vitest";
import { resolveTarget, TransportType } from "../../../src/core/target.js";

describe("resolveTarget", () => {
  it("parses stdio targets", () => {
    const target = resolveTarget("stdio:npx -y @mcp/my-server --flag");
    expect(target.type).toBe(TransportType.Stdio);
    if (target.type === TransportType.Stdio) {
      expect(target.command).toBe("npx");
      expect(target.args).toEqual(["-y", "@mcp/my-server", "--flag"]);
    }
  });

  it("parses HTTP targets", () => {
    const target = resolveTarget("https://example.com/mcp");
    expect(target.type).toBe(TransportType.Http);
    if (target.type === TransportType.Http) {
      expect(target.url).toBe("https://example.com/mcp");
    }
  });

  it("parses HTTP (non-TLS) targets", () => {
    const target = resolveTarget("http://localhost:3000");
    expect(target.type).toBe(TransportType.Http);
  });

  it("defaults to config file for file paths", () => {
    const target = resolveTarget("./.mcp.json");
    expect(target.type).toBe(TransportType.ConfigFile);
    if (target.type === TransportType.ConfigFile) {
      expect(target.filePath).toBe("./.mcp.json");
    }
  });

  it("trims whitespace", () => {
    const target = resolveTarget("  https://example.com  ");
    expect(target.type).toBe(TransportType.Http);
  });
});
