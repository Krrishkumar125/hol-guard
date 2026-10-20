import { useCallback, useEffect, useMemo, useState, Suspense } from "react";
import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";
import { WorkspacePageHeader } from "./workspace-page-header";
import { PolicyExceptionsToolbar, PolicyPageToolbar, PolicyUnderlineTabBar } from "./policy-page-chrome";
import type { PolicyPageView } from "./policy-workspace";
import { countPolicyRules } from "./policy-rules-overview-model";
import { resolveCloudPolicyControlsUrl, resolveCloudExceptionsConnected } from "./policy-workspace-helpers";
import { lazyWorkspace } from "./lazy-workspace";

const PolicyWorkspace = lazyWorkspace("policy-workspace", () =>
  import("./policy-workspace").then((module) => ({ default: module.PolicyWorkspace })),
);

function PolicyFallback() {
  return <div className="guard-skeleton h-40 w-full rounded-2xl" aria-busy="true" aria-live="polite" />;
}

export function resolveProtectionRulesPath(search: string): string {
  const params = new URLSearchParams({ section: "rules" });
  if (new URLSearchParams(search).get("demo") === "1") {
    params.set("demo", "1");
  }
  return `/settings?${params.toString()}`;
}

const POLICY_VIEW_HASH: Record<PolicyPageView, string> = {
  rules: "remembered-rules",
  exceptions: "cloud-exceptions",
  strict: "how-guard-decides",
};

export function resolvePolicyViewFromHash(hash: string): PolicyPageView {
  const value = hash.replace(/^#/, "");
  if (value === POLICY_VIEW_HASH.exceptions) return "exceptions";
  if (value === POLICY_VIEW_HASH.strict) return "strict";
  return "rules";
}

export function PolicyWorkspacePage(props: {
  snapshot: GuardRuntimeSnapshot;
  policies: GuardPolicyDecision[];
  onClearPolicy: (policy: GuardPolicyDecision) => void;
  onOpenSettings: (pathname?: string) => void;
  onOpenInbox: () => void;
  onRefreshPolicies: () => void;
  onNavigate?: (pathname: string) => void;
}) {
  const [activeView, setActiveView] = useState<PolicyPageView>(() =>
    typeof window === "undefined" ? "rules" : resolvePolicyViewFromHash(window.location.hash),
  );
  const [reloading, setReloading] = useState(false);
  const [exceptionRequestOpen, setExceptionRequestOpen] = useState(false);
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(props.snapshot);
  const cloudConnected = resolveCloudExceptionsConnected(props.snapshot);
  const ruleCounts = useMemo(
    () => countPolicyRules(props.policies.filter((p) => p.action === "allow" || p.action === "block")),
    [props.policies],
  );

  useEffect(() => {
    const handleHashChange = () => setActiveView(resolvePolicyViewFromHash(window.location.hash));
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  const handleOpenSettings = useCallback(() => {
    const settingsPath = resolveProtectionRulesPath(window.location.search);
    if (props.onNavigate) {
      props.onNavigate(settingsPath);
      return;
    }
    props.onOpenSettings(settingsPath);
  }, [props]);
  const handleOpenInbox = useCallback(() => props.onOpenInbox(), [props]);
  const handleViewChange = useCallback((view: PolicyPageView) => {
    setActiveView(view);
    const hash = `#${POLICY_VIEW_HASH[view]}`;
    if (window.location.hash !== hash) {
      window.history.replaceState(null, "", hash);
    }
  }, []);

  const handleReloadPolicy = useCallback(() => {
    setReloading(true);
    try {
      props.onRefreshPolicies();
    } finally {
      window.setTimeout(() => setReloading(false), 600);
    }
  }, [props]);

  return (
    <div className="space-y-6">
      <WorkspacePageHeader
        eyebrow="Rules & exceptions"
        title="What Guard remembers, allows, and blocks"
        description="Every decision Guard will repeat without asking — where it came from, what it covers, and how to undo it. Configure tools and capability posture in Extensions."
        actions={
          activeView === "exceptions" ? (
            <PolicyExceptionsToolbar
              cloudConnected={cloudConnected}
              cloudControlsUrl={cloudControlsUrl}
              onRequestException={() => setExceptionRequestOpen(true)}
            />
          ) : (
            <PolicyPageToolbar
              snapshot={props.snapshot}
              onReloadPolicy={handleReloadPolicy}
              reloading={reloading}
            />
          )
        }
      />
      <PolicyUnderlineTabBar activeView={activeView} onViewChange={handleViewChange} counts={{ rules: ruleCounts.total }} />
      <Suspense fallback={<PolicyFallback />}>
        <PolicyWorkspace
          activeView={activeView}
          policies={props.policies}
          snapshot={props.snapshot}
          onClearPolicy={props.onClearPolicy}
          onOpenSettings={handleOpenSettings}
          onOpenInbox={handleOpenInbox}
          onOpenCloudExceptions={() => handleViewChange("exceptions")}
          exceptionRequestOpen={exceptionRequestOpen}
          onExceptionRequestOpenChange={setExceptionRequestOpen}
          onReloadPolicy={handleReloadPolicy}
          reloadingPolicy={reloading}
          onNavigate={props.onNavigate}
        />
      </Suspense>
    </div>
  );
}
