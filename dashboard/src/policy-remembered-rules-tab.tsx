import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent } from "react";
import { HiMiniAdjustmentsHorizontal, HiMiniArrowDownTray, HiMiniInbox, HiMiniMagnifyingGlass, HiMiniXMark } from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import { harnessDisplayName, policyActionLabel } from "./approval-center-utils";
import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";
import { PolicyActiveModeCard } from "./policy-active-mode-card";
import { downloadPolicies } from "./policy-export";
import { PolicyGuardCloudBundleCard } from "./policy-guard-cloud-bundle-card";
import {
  isCloudManagedPolicy,
  resolveCloudPolicyBundleCopy,
  resolveCloudExceptionsConnected,
  resolvePolicyDisplay,
  resolvePolicyMatcherFamily,
  resolveSecurityModeCopy,
  type PolicySortState,
} from "./policy-workspace-helpers";
import { resolvePolicyGoverningExtensionId, resolvePolicyRowSourceLabel } from "./policy-managed-authority";
import { groupPoliciesByFamily, resolveFamilyFilterLabel } from "./policy-workspace-views";
import { PolicyRememberedCloudRules } from "./policy-remembered-cloud-rules";
import { PolicyRememberedLocalRules } from "./policy-remembered-local-rules";
import { PolicyRememberedRulesRightRail } from "./policy-remembered-rules-right-rail";
import { PolicyRulesOverview } from "./policy-rules-overview";
import {
  countPolicyRules,
  filterPoliciesByAction,
  policySelectionKey,
  prunePolicySelection,
  resolveRulesResultSummary,
  togglePolicySelection,
  type PolicyActionFilter,
} from "./policy-rules-overview-model";
import { buildRulesExceptionsView } from "./managed-controls/rules-exceptions-model";

type PolicyRememberedRulesTabProps = {
  policies: GuardPolicyDecision[];
  snapshot: GuardRuntimeSnapshot;
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  onOpenCloudExceptions: () => void;
  onOpenInbox?: () => void;
  onNavigate?: (pathname: string) => void;
};

const ACTION_FILTERS: { value: PolicyActionFilter; label: string }[] = [
  { value: "all", label: "All actions" },
  { value: "allow", label: "Allow" },
  { value: "block", label: "Block" },
];

export function PolicyRememberedRulesTab({
  policies,
  snapshot,
  cloudControlsUrl,
  onClearPolicy,
  onOpenCloudExceptions,
  onOpenInbox,
  onNavigate,
}: PolicyRememberedRulesTabProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [appFilter, setAppFilter] = useState("");
  const [familyFilter, setFamilyFilter] = useState("");
  const [actionFilter, setActionFilter] = useState<PolicyActionFilter>("all");
  const [showFilters, setShowFilters] = useState(false);
  const [sort, setSort] = useState<PolicySortState>({ key: "updated", direction: "desc" });
  const [selectedKeys, setSelectedKeys] = useState<ReadonlySet<string>>(new Set());
  const searchInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const handleSearchChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(event.target.value);
  }, []);
  const handleClearSearch = useCallback(() => setSearchQuery(""), []);
  const handleToggleFilters = useCallback(() => setShowFilters((current) => !current), []);
  const handleClearFilters = useCallback(() => {
    setSearchQuery("");
    setAppFilter("");
    setFamilyFilter("");
    setActionFilter("all");
  }, []);

  const filteredPolicies = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    const byAction = filterPoliciesByAction(policies, actionFilter);
    return byAction.filter((policy) => {
      if (appFilter && policy.harness !== appFilter) return false;
      if (familyFilter) {
        const family = resolvePolicyMatcherFamily(policy) ?? "other";
        if (family !== familyFilter) return false;
      }
      if (!query) return true;
      const display = resolvePolicyDisplay(policy);
      const displayHaystack = [
        policy.harness, policy.artifact_id, policy.workspace, policy.publisher, policy.scope,
        policy.action, policy.reason, policy.remembered_command, policy.remembered_context,
        policy.workspace_label, policy.source_scope_path, policy.source_receipt_id,
        display.headline, display.kindLine, display.pathLine, display.projectLabel,
        display.rememberSentence, harnessDisplayName(policy.harness), policyActionLabel(policy.action),
      ].filter(Boolean).join(" ").toLowerCase();
      return displayHaystack.includes(query);
    });
  }, [policies, searchQuery, appFilter, familyFilter, actionFilter]);

  const rememberedRules = useMemo(
    () => filteredPolicies.filter((policy) => policy.action === "allow" || policy.action === "block"),
    [filteredPolicies],
  );
  const localRules = useMemo(
    () => rememberedRules.filter((policy) => !isCloudManagedPolicy(policy.source)),
    [rememberedRules],
  );
  const cloudRules = useMemo(
    () => rememberedRules.filter((policy) => isCloudManagedPolicy(policy.source)),
    [rememberedRules],
  );
  const allRemembered = useMemo(
    () => policies.filter((policy) => policy.action === "allow" || policy.action === "block"),
    [policies],
  );
  const counts = useMemo(() => countPolicyRules(allRemembered), [allRemembered]);
  const appOptions = useMemo(
    () => [...new Set(policies.map((policy) => policy.harness).filter(Boolean))].sort(),
    [policies],
  );
  const familyCounts = useMemo(() => groupPoliciesByFamily(rememberedRules), [rememberedRules]);
  const rulesView = useMemo(() => buildRulesExceptionsView(rememberedRules.map((policy, index) => {
    const resolvedAuthority = resolvePolicyRowSourceLabel(policy);
    const authority = resolvedAuthority === "Trusted local tool" ? "Remembered on this device" : resolvedAuthority;
    return {
      id: String(policy.decision_id ?? `${policy.source}-${index}`),
      title: resolvePolicyDisplay(policy).headline,
      authority,
      extensionId: resolvePolicyGoverningExtensionId(policy) ?? undefined,
    };
  })), [rememberedRules]);

  const resultSummary = resolveRulesResultSummary({
    visible: rememberedRules.length,
    total: allRemembered.length,
    searchQuery, actionFilter, appFilter, familyFilter,
  });
  const hasActiveFilters = searchQuery.trim() !== "" || actionFilter !== "all" || appFilter !== "" || familyFilter !== "";

  useEffect(() => {
    setSelectedKeys((current) => prunePolicySelection(current, localRules));
  }, [localRules]);

  const handleToggleSelect = useCallback((policy: GuardPolicyDecision) => {
    setSelectedKeys((current) => togglePolicySelection(current, policySelectionKey(policy)));
  }, []);
  const handleClearSelection = useCallback(() => setSelectedKeys(new Set()), []);
  const handleRemoveSelected = useCallback(() => {
    if (!onClearPolicy) return;
    for (const policy of localRules) {
      if (selectedKeys.has(policySelectionKey(policy))) onClearPolicy(policy);
    }
    setSelectedKeys(new Set());
  }, [localRules, onClearPolicy, selectedKeys]);

  const handleExportCsv = useCallback(() => downloadPolicies("csv", rememberedRules), [rememberedRules]);
  const handleExportJson = useCallback(() => downloadPolicies("json", rememberedRules), [rememberedRules]);

  const modeCopy = resolveSecurityModeCopy(snapshot.protection_posture ?? snapshot.security_level);
  const bundleCopy = resolveCloudPolicyBundleCopy(snapshot);
  const cloudConnected = resolveCloudExceptionsConnected(snapshot);

  const localEmptyAction = onOpenInbox ? (
    <ActionButton variant="primary" onClick={onOpenInbox}>
      <HiMiniInbox className="mr-1.5 h-4 w-4" aria-hidden="true" />
      Review pending requests
    </ActionButton>
  ) : undefined;

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-4 lg:grid-cols-[minmax(0,1fr)_280px] lg:items-start">
      <div className="min-w-0 space-y-4">
        <PolicyRulesOverview
          counts={counts}
          protectionLabel={modeCopy.label}
          cloudConnected={cloudConnected}
          bundleSynced={bundleCopy ? bundleCopy.tone === "green" : null}
        />

        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
            <div className="flex flex-1 items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-2 focus-within:border-brand-blue/40 focus-within:ring-2 focus-within:ring-brand-blue/20">
              <HiMiniMagnifyingGlass className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
              <input
                ref={searchInputRef}
                type="search"
                placeholder="Search remembered rules by app, action, or reason…"
                value={searchQuery}
                onChange={handleSearchChange}
                aria-label="Search remembered rules"
                className="w-full bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
              />
              {searchQuery ? (
                <button type="button" onClick={handleClearSearch} aria-label="Clear search" className="shrink-0 rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-brand-dark">
                  <HiMiniXMark className="h-4 w-4" aria-hidden="true" />
                </button>
              ) : (
                <kbd className="hidden shrink-0 rounded-md border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] font-medium text-slate-500 sm:inline">⌘K</kbd>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={handleToggleFilters}
                aria-expanded={showFilters}
                className={`inline-flex min-h-10 items-center gap-1.5 rounded-xl border px-3 py-2 text-sm font-medium transition-colors ${
                  showFilters || appFilter || familyFilter
                    ? "border-brand-blue/30 bg-brand-blue/[0.04] text-brand-dark"
                    : "border-slate-200 bg-white text-brand-dark hover:border-brand-blue/20"
                }`}
              >
                <HiMiniAdjustmentsHorizontal className="h-4 w-4 text-slate-500" aria-hidden="true" />
                Filters{(appFilter || familyFilter) ? " (active)" : ""}
              </button>
              <ActionButton variant="secondary" onClick={handleExportCsv}>
                <HiMiniArrowDownTray className="mr-1.5 h-4 w-4" aria-hidden="true" />
                Export CSV
              </ActionButton>
              <ActionButton variant="secondary" onClick={handleExportJson}>
                <HiMiniArrowDownTray className="mr-1.5 h-4 w-4" aria-hidden="true" />
                Export JSON
              </ActionButton>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filter by action">
            {ACTION_FILTERS.map((option) => {
              const selected = actionFilter === option.value;
              const count = option.value === "all" ? counts.total : option.value === "allow" ? counts.allow : counts.block;
              return (
                <button
                  key={option.value}
                  type="button"
                  aria-pressed={selected}
                  onClick={() => setActionFilter(option.value)}
                  className={`inline-flex min-h-9 items-center gap-1.5 rounded-full border px-3 py-1.5 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
                    selected
                      ? "border-brand-blue bg-brand-blue text-white"
                      : "border-slate-200 bg-white text-brand-dark hover:border-brand-blue/30"
                  }`}
                >
                  {option.label}
                  <span className={`tabular-nums text-xs ${selected ? "text-white/80" : "text-slate-500"}`}>{count}</span>
                </button>
              );
            })}
            {hasActiveFilters ? (
              <button type="button" onClick={handleClearFilters} className="min-h-9 px-2 text-sm font-medium text-brand-blue hover:underline">
                Clear search and filters
              </button>
            ) : null}
          </div>

          {showFilters ? (
            <div className="flex flex-wrap gap-2">
              <select value={appFilter} onChange={(event) => setAppFilter(event.target.value)} aria-label="Filter by app" className="min-h-10 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark">
                <option value="">All assets</option>
                {appOptions.map((app) => (
                  <option key={app} value={app}>{harnessDisplayName(app)}</option>
                ))}
              </select>
              <select value={familyFilter} onChange={(event) => setFamilyFilter(event.target.value)} aria-label="Filter by action type" className="min-h-10 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark">
                <option value="">All action types</option>
                {[...familyCounts.entries()].map(([family, count]) => (
                  <option key={family} value={family}>{resolveFamilyFilterLabel(family)} ({count})</option>
                ))}
              </select>
            </div>
          ) : null}

          {resultSummary ? (
            <p className="text-sm text-slate-600" role="status">{resultSummary}</p>
          ) : null}
        </div>

        <PolicyRememberedLocalRules
          policies={localRules}
          cloudControlsUrl={cloudControlsUrl}
          onClearPolicy={onClearPolicy}
          onNavigate={onNavigate}
          sort={sort}
          onSortChange={setSort}
          emptyAction={hasActiveFilters ? undefined : localEmptyAction}
          selectedKeys={selectedKeys}
          onToggleSelect={onClearPolicy ? handleToggleSelect : undefined}
          onClearSelection={handleClearSelection}
          onRemoveSelected={onClearPolicy ? handleRemoveSelected : undefined}
        />
        <PolicyRememberedCloudRules
          policies={cloudRules}
          cloudControlsUrl={cloudControlsUrl}
          sort={sort}
          onSortChange={setSort}
        />

        <details className="rounded-2xl border border-slate-200 bg-white shadow-sm">
          <summary className="cursor-pointer list-none px-4 py-3 text-sm font-medium text-brand-dark marker:hidden [&::-webkit-details-marker]:hidden">
            Sync and protection details
            <span className="mt-0.5 block text-xs font-normal text-slate-500">Guard Cloud bundle status and the protection mode active on this device.</span>
          </summary>
          <div className="grid gap-4 border-t border-slate-100 p-4 lg:grid-cols-[minmax(0,1.55fr)_minmax(10rem,1fr)] lg:items-start">
            <PolicyGuardCloudBundleCard snapshot={snapshot} />
            <PolicyActiveModeCard snapshot={snapshot} />
          </div>
        </details>
      </div>

      <PolicyRememberedRulesRightRail
        onOpenCloudExceptions={onOpenCloudExceptions}
        snapshot={snapshot}
        decisionOrder={rulesView.decisionOrder}
      />
    </div>
  );
}
