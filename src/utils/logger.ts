/**
 * Simple structured logger for mcp-audit.
 */

export enum LogLevel {
  Debug = 0,
  Info = 1,
  Warn = 2,
  Error = 3,
  Silent = 4,
}

export interface Logger {
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
}

export function createLogger(level: LogLevel = LogLevel.Info): Logger {
  const log = (
    lvl: LogLevel,
    prefix: string,
    message: string,
    args: unknown[],
  ) => {
    if (lvl < level) return;
    const ts = new Date().toISOString();
    const formatted = args.length > 0 ? `${message} ${args.map(String).join(" ")}` : message;
    process.stderr.write(`${ts} [${prefix}] ${formatted}\n`);
  };

  return {
    debug: (msg, ...args) => log(LogLevel.Debug, "DBG", msg, args),
    info: (msg, ...args) => log(LogLevel.Info, "INF", msg, args),
    warn: (msg, ...args) => log(LogLevel.Warn, "WRN", msg, args),
    error: (msg, ...args) => log(LogLevel.Error, "ERR", msg, args),
  };
}

/** Silent logger for tests */
export const nullLogger: Logger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};
