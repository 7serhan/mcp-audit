/**
 * Scanner plugin interface — all scanners implement this.
 */

import type { Finding } from "./finding.js";
import type { ScanContext } from "./context.js";

export interface ScannerPlugin {
  /** Unique scanner name, e.g. "ssrf" */
  name: string;
  /** Human-readable description */
  description: string;
  /** Scanner version */
  version: string;
  /** Run the scan and return findings */
  run(context: ScanContext): Promise<Finding[]>;
}
