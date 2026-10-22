import { buildDecisionPayload } from "./approval-scopes";
import type { GuardApprovalRequest, GuardApprovalResolutionInput } from "./guard-types";

export type BulkBlockOutcome = { blocked: number; failed: number };

/**
 * Refuse each request once, the same way "Keep blocked" does, one at a time.
 * `persist_policy: false` keeps a bulk refusal from saving any rule, so a
 * stale request cannot turn into a lasting deny.
 */
export async function blockRequestsOnce(
  requests: readonly GuardApprovalRequest[],
  resolve: (input: GuardApprovalResolutionInput) => Promise<unknown>,
): Promise<BulkBlockOutcome> {
  let blocked = 0;
  let failed = 0;
  for (const item of requests) {
    try {
      const payload = buildDecisionPayload({ item, action: "block", scope: "artifact", reason: "blocked in bulk review" });
      await resolve({ ...payload, persist_policy: false });
      blocked += 1;
    } catch {
      failed += 1;
    }
  }
  return { blocked, failed };
}

export function bulkBlockSummary(outcome: BulkBlockOutcome): string {
  const unit = outcome.blocked === 1 ? "request" : "requests";
  return `${outcome.blocked} ${unit} blocked.`;
}

export function bulkBlockFailureMessage(outcome: BulkBlockOutcome): string {
  if (outcome.blocked === 0) {
    return "Guard could not block the selected requests. Open them to block them one at a time.";
  }
  return `${outcome.blocked} blocked, ${outcome.failed} failed. Open the failed requests to block them one at a time.`;
}
