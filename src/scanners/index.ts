/**
 * Scanner registry — imports and exports all built-in scanners.
 */

import type { ScannerPlugin } from "../core/plugin.js";
import { authScanner } from "./auth.scanner.js";
import { transportScanner } from "./transport.scanner.js";
import { infoDisclosureScanner } from "./info-disclosure.scanner.js";
import { inputValidationScanner } from "./input-validation.scanner.js";
import { permissionsScanner } from "./permissions.scanner.js";
import { ssrfScanner } from "./ssrf.scanner.js";
import { commandInjectionScanner } from "./command-injection.scanner.js";
import { promptInjectionScanner } from "./prompt-injection.scanner.js";
import { rateLimitingScanner } from "./rate-limiting.scanner.js";
import { dataExfiltrationScanner } from "./data-exfiltration.scanner.js";

export {
  authScanner,
  transportScanner,
  infoDisclosureScanner,
  inputValidationScanner,
  permissionsScanner,
  ssrfScanner,
  commandInjectionScanner,
  promptInjectionScanner,
  rateLimitingScanner,
  dataExfiltrationScanner,
};

export function getAllScanners(): ScannerPlugin[] {
  return [
    authScanner,
    transportScanner,
    infoDisclosureScanner,
    inputValidationScanner,
    permissionsScanner,
    ssrfScanner,
    commandInjectionScanner,
    promptInjectionScanner,
    rateLimitingScanner,
    dataExfiltrationScanner,
  ];
}
