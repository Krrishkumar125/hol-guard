import type { GuardPolicyDecision } from "./guard-types";
import { isCloudManagedPolicy } from "./policy-workspace-helpers";

export type PolicyActionFilter = "all" | "allow" | "block";

export interface PolicyRuleCounts {
  total: number;
  local: number;
  cloud: number;
  allow: number;
  block: number;
  other: number;
}

export function countPolicyRules(policies: readonly GuardPolicyDecision[]): PolicyRuleCounts {
  let local = 0;
  let cloud = 0;
  let allow = 0;
  let block = 0;
  let other = 0;
  for (const policy of policies) {
    if (isCloudManagedPolicy(policy.source)) {
      cloud += 1;
    } else {
      local += 1;
    }
    if (policy.action === "allow") {
      allow += 1;
    } else if (policy.action === "block") {
      block += 1;
    } else {
      other += 1;
    }
  }
  return { total: policies.length, local, cloud, allow, block, other };
}

export function filterPoliciesByAction(
  policies: readonly GuardPolicyDecision[],
  filter: PolicyActionFilter,
): GuardPolicyDecision[] {
  if (filter === "all") {
    return [...policies];
  }
  return policies.filter((policy) => policy.action === filter);
}

/** Stable identity for selection/bulk actions. Mirrors the row key used by the table. */
export function policySelectionKey(policy: GuardPolicyDecision): string {
  return `${policy.harness}-${policy.scope}-${policy.artifact_id ?? policy.publisher ?? "global"}-${policy.updated_at ?? ""}-${policy.source}`;
}

export function togglePolicySelection(selected: ReadonlySet<string>, key: string): Set<string> {
  const next = new Set(selected);
  if (next.has(key)) {
    next.delete(key);
  } else {
    next.add(key);
  }
  return next;
}

/** Keep only selections that still point at a visible, removable (local) rule. */
export function prunePolicySelection(
  selected: ReadonlySet<string>,
  removable: readonly GuardPolicyDecision[],
): Set<string> {
  const valid = new Set(removable.map(policySelectionKey));
  return new Set([...selected].filter((key) => valid.has(key)));
}

export function resolveRulesResultSummary(input: {
  visible: number;
  total: number;
  searchQuery: string;
  actionFilter: PolicyActionFilter;
  appFilter: string;
  familyFilter: string;
}): string | null {
  const filtered =
    input.searchQuery.trim() !== "" || input.actionFilter !== "all" || input.appFilter !== "" || input.familyFilter !== "";
  if (!filtered) {
    return null;
  }
  if (input.visible === 0) {
    return "No rules match. Clear the search or filters to see every remembered rule.";
  }
  return `Showing ${input.visible} of ${input.total} remembered rules.`;
}
