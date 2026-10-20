import { HiMiniCheckCircle, HiMiniCloud, HiMiniComputerDesktop, HiMiniNoSymbol } from "react-icons/hi2";
import type { PolicyRuleCounts } from "./policy-rules-overview-model";

type PolicyRulesOverviewProps = {
  counts: PolicyRuleCounts;
  protectionLabel: string;
  cloudConnected: boolean;
  bundleSynced: boolean | null;
};

function StatItem({
  icon,
  label,
  value,
  detail,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  detail: string;
}) {
  return (
    <div className="flex min-w-0 items-start gap-3 px-4 py-3.5">
      <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-500" aria-hidden="true">
        {icon}
      </span>
      <div className="min-w-0">
        <p className="text-xl font-semibold leading-none tabular-nums text-brand-dark">{value}</p>
        <p className="mt-1.5 text-xs font-medium text-brand-dark">{label}</p>
        <p className="mt-0.5 text-xs leading-relaxed text-slate-500">{detail}</p>
      </div>
    </div>
  );
}

export function PolicyRulesOverview({ counts, protectionLabel, cloudConnected, bundleSynced }: PolicyRulesOverviewProps) {
  const cloudDetail = !cloudConnected
    ? "Guard Cloud is not connected"
    : bundleSynced === null
      ? "Connected — first bundle sync pending"
      : bundleSynced
        ? "Synced to this device"
        : "Sync needs attention — see below";
  return (
    <section aria-label="Rules at a glance" className="rounded-2xl border border-slate-200 bg-white shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 border-b border-slate-100 px-4 py-3">
        <h2 className="text-sm font-semibold text-brand-dark">At a glance</h2>
        <p className="text-xs text-slate-500">
          Protection: <span className="font-medium text-brand-dark">{protectionLabel}</span>
          <span aria-hidden="true"> · </span>
          {counts.total === 1 ? "1 remembered rule" : `${counts.total} remembered rules`}
        </p>
      </div>
      <div className="grid grid-cols-2 divide-slate-100 max-lg:[&>*:nth-child(odd)]:border-l-0 lg:grid-cols-4 lg:divide-x">
        <StatItem
          icon={<HiMiniComputerDesktop className="h-4 w-4" />}
          label="On this device"
          value={counts.local}
          detail="Decisions you remembered here"
        />
        <StatItem
          icon={<HiMiniCloud className="h-4 w-4" />}
          label="From Guard Cloud"
          value={counts.cloud}
          detail={cloudDetail}
        />
        <StatItem
          icon={<HiMiniCheckCircle className="h-4 w-4" />}
          label="Allow"
          value={counts.allow}
          detail="Actions Guard lets through"
        />
        <StatItem
          icon={<HiMiniNoSymbol className="h-4 w-4" />}
          label="Block"
          value={counts.block}
          detail="Actions Guard stops"
        />
      </div>
    </section>
  );
}
