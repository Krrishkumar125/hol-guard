import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { blockRequestsOnce, bulkBlockFailureMessage, bulkBlockSummary } from "./bulk-block-requests";
import type { GuardApprovalRequest, GuardApprovalResolutionInput } from "./guard-types";
import { QueueBulkStickyBar } from "./queue-bulk-approve-flow";
import type { QueueGroup } from "./queue-state";
import {
  bulkBlockPrimaries,
  isBulkBlockableGroup,
  type QueueBulkStickyBarProps,
} from "./use-queue-bulk-approve";

const pending: GuardApprovalRequest = {
  request_id: "req-stale",
  harness: "omp",
  artifact_id: "omp:tool:bash",
  artifact_name: "bash",
  artifact_type: "tool_call",
  artifact_hash: "hash-stale",
  publisher: null,
  policy_action: "review",
  recommended_scope: "artifact",
  changed_fields: ["first_seen"],
  source_scope: "project",
  config_path: "/home/alice/.omp/agent/settings.json",
  transport: "stdio",
  review_command: "hol-guard approvals deny req-stale",
  approval_url: "http://127.0.0.1:5474/requests/req-stale",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-10-13T00:00:00Z",
  resolved_at: null,
};

function group(primary: GuardApprovalRequest, duplicateIds: string[] = []): QueueGroup {
  return { primary, duplicateCount: duplicateIds.length, duplicateIds };
}

// Any pending request can be refused; a resolved one cannot.
assert.equal(isBulkBlockableGroup(group(pending)), true);
assert.equal(isBulkBlockableGroup(group({ ...pending, status: "resolved" })), false);

// One request per selected group: the server settles a group's duplicates.
const second = { ...pending, request_id: "req-second" };
const groups = [group(pending, ["req-dup"]), group(second), group({ ...pending, request_id: "req-done", status: "resolved" })];
assert.deepEqual(
  bulkBlockPrimaries(groups, new Set(["req-stale", "req-done"])).map((item) => item.request_id),
  ["req-stale"],
);

// Each block is one-time, at artifact scope, and never saved as a rule.
const sent: GuardApprovalResolutionInput[] = [];
const outcome = await blockRequestsOnce([pending, second], async (input) => {
  sent.push(input);
  if (input.requestId === "req-second") throw new Error("gone");
});
assert.deepEqual(outcome, { blocked: 1, failed: 1 });
assert.deepEqual(
  sent.map((input) => [input.requestId, input.action, input.scope, input.persist_policy]),
  [["req-stale", "block", "artifact", false], ["req-second", "block", "artifact", false]],
);
assert.equal(bulkBlockSummary({ blocked: 2, failed: 0 }), "2 requests blocked.");
assert.equal(
  bulkBlockFailureMessage({ blocked: 1, failed: 1 }),
  "1 blocked, 1 failed. Open the failed requests to block them one at a time.",
);
assert.match(bulkBlockFailureMessage({ blocked: 0, failed: 3 }), /could not block the selected requests/);

const noop = () => undefined;
const bar: QueueBulkStickyBarProps = {
  visible: true,
  selectedGroupCount: 0,
  selectedActionCount: 0,
  selectedRequestCount: 3,
  canApprove: false,
  riskTier: "low",
  riskTone: "green",
  gateReady: false,
  blockAvailable: true,
  blockStep: "idle",
  blockError: null,
  onStartReview: noop,
  onRequestBlock: noop,
  onConfirmBlock: noop,
  onCancelBlock: noop,
  onClearSelection: noop,
};

// A selection of requests that can only be blocked offers no approval.
const blockOnly = renderToStaticMarkup(createElement(QueueBulkStickyBar, bar));
assert.match(blockOnly, />3<\/span> requests selected</);
assert.match(blockOnly, /Block selected/);
assert.doesNotMatch(blockOnly, /Review &amp; approve/);
assert.doesNotMatch(blockOnly, /Low risk/);

// Confirming names the count and says nothing is remembered.
const confirming = renderToStaticMarkup(createElement(QueueBulkStickyBar, { ...bar, blockStep: "confirming" }));
assert.match(confirming, /Block 3 requests\? Any agent still waiting is told no\. Nothing is remembered\./);
assert.match(confirming, />Block 3</);
assert.doesNotMatch(confirming, /Block selected/);

const blocking = renderToStaticMarkup(createElement(QueueBulkStickyBar, { ...bar, blockStep: "blocking" }));
assert.match(blocking, /Blocking…/);
assert.match(blocking, /disabled=""/);

// A mixed selection says how many of the selected requests can be approved.
const mixed = renderToStaticMarkup(createElement(QueueBulkStickyBar, {
  ...bar,
  canApprove: true,
  gateReady: true,
  selectedGroupCount: 1,
  selectedActionCount: 1,
}));
assert.match(mixed, /3<\/span> requests selected · 1 can be approved at once/);
assert.match(mixed, /Review &amp; approve/);
assert.match(mixed, /Block selected/);

const failed = renderToStaticMarkup(createElement(QueueBulkStickyBar, { ...bar, blockError: "1 blocked, 1 failed." }));
assert.match(failed, /role="alert"[^>]*>1 blocked, 1 failed\.</);

console.log("bulk-block-selected.test.tsx: all tests passed");
