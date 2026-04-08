# mcp-audit

Security auditing tool for [MCP (Model Context Protocol)](https://modelcontextprotocol.io) servers. CLI tool & MCP server.

Finds vulnerabilities that other tools miss: **active SSRF probing**, **command injection testing**, **prompt injection detection**, and more — all without external API dependencies.

## Features

- **10 Security Scanners** — SSRF, command injection, prompt injection, auth, data exfiltration, transport security, permissions, input validation, rate limiting, info disclosure
- **Active Probing** — Doesn't just analyze descriptions; actually tests tools with safe payloads
- **Zero External Dependencies** — No cloud APIs, everything runs locally
- **Multiple Output Formats** — Terminal (colored), JSON, SARIF (GitHub Code Scanning), Markdown
- **MCP Server Mode** — Use from Claude, Cursor, or any MCP client
- **Plugin System** — Write custom scanners with a simple interface
- **CI/CD Ready** — SARIF output + `--fail-on` flag for automated pipelines

## Install

```bash
npm install -g mcp-audit
```

## Quick Start

```bash
# Scan a config file (scans all servers in it)
mcp-audit scan ./.mcp.json

# Scan an HTTP MCP server
mcp-audit scan https://example.com/mcp

# Scan a stdio MCP server
mcp-audit scan "stdio:npx -y @modelcontextprotocol/server-filesystem /tmp"

# Only run specific scanners
mcp-audit scan ./.mcp.json -s ssrf,auth,command-injection

# JSON output for scripting
mcp-audit scan ./.mcp.json -o json

# SARIF for GitHub Code Scanning
mcp-audit scan ./.mcp.json -o sarif > results.sarif

# Fail CI if high+ severity findings
mcp-audit scan ./.mcp.json --fail-on high

# Just inspect (no scanning)
mcp-audit inspect ./.mcp.json
```

## Scanners

| Scanner | What it finds | Severity |
|---------|--------------|----------|
| `auth` | Missing authentication, unauthenticated tool access | Critical-High |
| `ssrf` | URL parameters that reach internal hosts / cloud metadata | Critical |
| `command-injection` | Shell metacharacter injection, argument injection | Critical |
| `prompt-injection` | LLM manipulation patterns in tool descriptions | Critical-Medium |
| `data-exfiltration` | Read+send tool chains, sensitive file access | Critical-High |
| `transport` | Unencrypted HTTP, CORS issues, env variable leaks | High-Medium |
| `permissions` | Excessive privileges, dangerous capability combos | Critical-Medium |
| `input-validation` | Missing schemas, prototype pollution, boundary issues | High-Low |
| `rate-limiting` | Missing throttling, DoS potential | Medium |
| `info-disclosure` | Version leaks, stack traces, internal paths | Medium-Low |

## MCP Server Mode

Add to your MCP config to use mcp-audit from any AI assistant:

```json
{
  "mcpServers": {
    "mcp-audit": {
      "command": "npx",
      "args": ["-y", "mcp-audit", "serve"]
    }
  }
}
```

### Available Tools

| Tool | Description |
|------|-------------|
| `scan_server` | Full security audit |
| `inspect_server` | List capabilities without scanning |
| `scan_config_file` | Scan all servers in a config |
| `list_scanners` | List available scanners |
| `explain_finding` | Detailed finding explanation |
| `generate_report` | Generate formatted report |

## Writing Custom Scanners

```typescript
import type { ScannerPlugin } from "mcp-audit";
import { Severity, type Finding } from "mcp-audit";

export const myScanner: ScannerPlugin = {
  name: "my-scanner",
  description: "My custom security check",
  version: "1.0.0",

  async run(context) {
    const findings: Finding[] = [];

    for (const tool of context.tools) {
      // Your security logic here
      if (someVulnerabilityDetected(tool)) {
        findings.push({
          id: "CUSTOM-001",
          scanner: "my-scanner",
          title: "Custom finding",
          description: "Details...",
          severity: Severity.High,
          target: tool.name,
          remediation: "How to fix...",
        });
      }
    }

    return findings;
  },
};
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: MCP Security Audit
  run: |
    npx mcp-audit scan ./.mcp.json -o sarif --fail-on high > mcp-audit.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp-audit.sarif
```

## How It Compares

| Feature | mcp-scan | Proximity | **mcp-audit** |
|---------|----------|-----------|---------------|
| Active SSRF probing | No | No | **Yes** |
| Command injection test | No | No | **Yes** |
| External API dependency | Yes | No | **No** |
| MCP server mode | No | No | **Yes** |
| SARIF output | No | No | **Yes** |
| Plugin system | No | No | **Yes** |
| Language | Python | TypeScript | **TypeScript** |

## License

MIT
