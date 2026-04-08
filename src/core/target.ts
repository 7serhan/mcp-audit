/**
 * ScanTarget — represents and resolves what we're scanning.
 */

export enum TransportType {
  Stdio = "stdio",
  Http = "http",
  ConfigFile = "config-file",
}

export interface StdioTarget {
  type: TransportType.Stdio;
  command: string;
  args: string[];
  env?: Record<string, string>;
  raw: string;
}

export interface HttpTarget {
  type: TransportType.Http;
  url: string;
  headers?: Record<string, string>;
  raw: string;
}

export interface ConfigFileTarget {
  type: TransportType.ConfigFile;
  filePath: string;
  raw: string;
}

export type ScanTarget = StdioTarget | HttpTarget | ConfigFileTarget;

/**
 * Parse a target string into a ScanTarget.
 *
 * Supported formats:
 *   - "stdio:command arg1 arg2"  → StdioTarget
 *   - "http://..." or "https://..." → HttpTarget
 *   - File path ending in .json  → ConfigFileTarget
 *   - Otherwise: try as file path
 */
export function resolveTarget(input: string): ScanTarget {
  const trimmed = input.trim();

  if (trimmed.startsWith("stdio:")) {
    const cmd = trimmed.slice("stdio:".length).trim();
    const parts = cmd.split(/\s+/);
    return {
      type: TransportType.Stdio,
      command: parts[0],
      args: parts.slice(1),
      raw: trimmed,
    };
  }

  if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
    return {
      type: TransportType.Http,
      url: trimmed,
      raw: trimmed,
    };
  }

  // Default: treat as config file
  return {
    type: TransportType.ConfigFile,
    filePath: trimmed,
    raw: trimmed,
  };
}
