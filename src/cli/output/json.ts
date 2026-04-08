/**
 * JSON output — machine-readable scan results.
 */

import type { ScanResult } from "../../core/finding.js";

export function renderJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
