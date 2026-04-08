/**
 * Rate Limiting Scanner — checks for throttling/rate limit enforcement.
 *
 * Checks:
 * - Rapid sequential requests accepted without throttling
 * - No backoff or rate limit headers
 * - Resource exhaustion potential
 */

import { Severity, type Finding } from "../core/finding.js";
import type { ScannerPlugin } from "../core/plugin.js";
import type { ScanContext } from "../core/context.js";

const BURST_COUNT = 10;
const BURST_WINDOW_MS = 2000;

export const rateLimitingScanner: ScannerPlugin = {
  name: "rate-limiting",
  description: "Checks for rate limiting and throttling enforcement",
  version: "1.0.0",

  async run(context: ScanContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    if (context.tools.length === 0) return findings;

    // Pick the safest tool to burst-test
    const tool = findSafestTool(context);
    if (!tool) return findings;

    context.logger.debug(`Rate limit: burst-testing tool "${tool}" with ${BURST_COUNT} rapid calls`);

    // Fire rapid requests
    const start = Date.now();
    let successCount = 0;
    let errorCount = 0;

    const promises = Array.from({ length: BURST_COUNT }, () =>
      context.callTool(tool, {}).then(
        (r) => {
          if (r.isError) errorCount++;
          else successCount++;
        },
        () => {
          errorCount++;
        },
      ),
    );

    await Promise.all(promises);
    const elapsed = Date.now() - start;

    // Check 1: All requests succeeded within the window
    if (successCount === BURST_COUNT && elapsed < BURST_WINDOW_MS) {
      findings.push({
        id: "RATE-001",
        scanner: "rate-limiting",
        title: "No rate limiting detected",
        description:
          `Sent ${BURST_COUNT} concurrent requests to tool "${tool}" ` +
          `and all succeeded within ${elapsed}ms. No throttling or rate limiting was enforced. ` +
          "This makes the server vulnerable to denial-of-service and resource exhaustion attacks.",
        severity: Severity.Medium,
        target: tool,
        evidence: {
          request: `${BURST_COUNT} concurrent callTool("${tool}", {})`,
          response: `${successCount}/${BURST_COUNT} succeeded in ${elapsed}ms`,
        },
        remediation:
          "Implement rate limiting per client/session. Consider using a token bucket " +
          "or sliding window algorithm. Return 429 Too Many Requests when limits are exceeded.",
        cwe: "CWE-770",
      });
    }

    // Check 2: High success rate (but not 100%) still concerning
    if (successCount > BURST_COUNT * 0.8 && successCount < BURST_COUNT) {
      findings.push({
        id: "RATE-002",
        scanner: "rate-limiting",
        title: "Weak rate limiting detected",
        description:
          `${successCount}/${BURST_COUNT} burst requests to "${tool}" succeeded. ` +
          "Rate limiting exists but may be too permissive for production use.",
        severity: Severity.Low,
        target: tool,
        evidence: {
          response: `${successCount} success, ${errorCount} errors in ${elapsed}ms`,
        },
        remediation:
          "Review rate limiting thresholds. Consider stricter limits for sensitive operations.",
        cwe: "CWE-770",
      });
    }

    return findings;
  },
};

function findSafestTool(context: ScanContext): string | null {
  const safePatterns = [/list|get|read|fetch|search|find|show|describe|info|status|health|ping|version|echo/i];

  const safe = context.tools.find((t) =>
    safePatterns.some((p) => p.test(t.name) || p.test(t.description ?? "")),
  );

  return safe?.name ?? context.tools[0]?.name ?? null;
}
