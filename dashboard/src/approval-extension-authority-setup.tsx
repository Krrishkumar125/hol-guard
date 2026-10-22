import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { HiMiniCheck, HiMiniClipboard, HiMiniClipboardDocumentCheck } from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import { approvalGateProofReady } from "./approval-proof-inline";
import type { GuardApprovalExtensionRecommendation } from "./approval-extension-recommendation-types";
import { fetchEffectiveExtensionControls, type EffectiveExtensionControls } from "./extension-controls-api";
import { fetchRequest, fetchSettings } from "./guard-api";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

const DEFAULT_ENROLL_COMMAND = "hol-guard command controls enroll";
/** How often an open card looks for an enrollment finished in the terminal. */
export const AUTHORITY_WATCH_INTERVAL_MS = 5000;

export type ExtensionAuthorityWatch = {
  effective: EffectiveExtensionControls | null;
  approvalGate: GuardApprovalGatePublicConfig | null;
  loadFailed: boolean;
  checking: boolean;
  checkResult: "unchanged" | null;
  checkAgain: () => void;
};

/**
 * Follow the device's protection authority while a recommendation is waiting
 * on it. Enrollment happens in a terminal, so the card polls the daemon and
 * swaps in the request's fresh recommendation once the authority is protected.
 */
export function useExtensionAuthorityWatch(input: {
  active: boolean;
  requestId: string;
  approvalGate: GuardApprovalGatePublicConfig | null;
  onAvailable: (recommendation: GuardApprovalExtensionRecommendation) => void;
}): ExtensionAuthorityWatch {
  const { active, requestId, onAvailable } = input;
  const [effective, setEffective] = useState<EffectiveExtensionControls | null>(null);
  const [liveGate, setLiveGate] = useState<GuardApprovalGatePublicConfig | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [checking, setChecking] = useState(false);
  const [checkResult, setCheckResult] = useState<"unchanged" | null>(null);
  // A manual check during a poll joins that poll instead of reporting a stale answer.
  const inFlight = useRef<Promise<boolean> | null>(null);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const load = useCallback(async (): Promise<boolean> => {
    try {
      const [nextEffective, settings] = await Promise.all([
        fetchEffectiveExtensionControls(),
        fetchSettings().catch(() => null),
      ]);
      if (!mounted.current) return false;
      setEffective(nextEffective);
      setLoadFailed(false);
      const gate = settings?.settings.approval_gate;
      if (gate !== undefined && gate !== null) setLiveGate(gate);
      if (nextEffective.health !== "protected") return false;
      const item = await fetchRequest(requestId);
      if (!mounted.current) return false;
      const recommendation = item.extension_recommendation;
      if (recommendation?.status !== "available") return false;
      onAvailable(recommendation);
      return true;
    } catch {
      if (mounted.current) setLoadFailed(true);
      return false;
    }
  }, [onAvailable, requestId]);

  const refresh = useCallback((): Promise<boolean> => {
    if (inFlight.current === null) {
      inFlight.current = load().finally(() => {
        inFlight.current = null;
      });
    }
    return inFlight.current;
  }, [load]);

  useEffect(() => {
    if (!active) return undefined;
    void refresh();
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void refresh();
    }, AUTHORITY_WATCH_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [active, refresh]);

  const checkAgain = useCallback(() => {
    if (checking) return;
    setChecking(true);
    setCheckResult(null);
    void refresh().then((available) => {
      if (!mounted.current) return;
      setChecking(false);
      if (!available) setCheckResult("unchanged");
    });
  }, [checking, refresh]);

  return { effective, approvalGate: liveGate ?? input.approvalGate, loadFailed, checking, checkResult, checkAgain };
}

function SetupStep(props: { index: number; done: boolean; title: string; children: ReactNode; current: boolean }) {
  return (
    <li className="flex gap-3">
      <span
        className={`mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full text-xs font-semibold ${
          props.done
            ? "bg-brand-green-text text-white"
            : props.current
              ? "bg-brand-blue text-white"
              : "border border-slate-300 bg-white text-slate-600"
        }`}
        aria-hidden="true"
      >
        {props.done ? <HiMiniCheck className="size-4" /> : props.index}
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-brand-dark">
          {props.title}
          {props.done && <span className="sr-only"> (done)</span>}
        </p>
        {props.children}
      </div>
    </li>
  );
}

function CopyCommand(props: { command: string; label: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(props.command);
      setState("copied");
    } catch {
      setState("failed");
    }
  };
  return (
    <div className="mt-2">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap rounded-lg border border-slate-200 bg-white px-3 py-2.5 font-mono text-xs text-brand-dark">
          {props.command}
        </code>
        <button
          type="button"
          onClick={() => void copy()}
          aria-label={state === "copied" ? "Command copied" : props.label}
          className="inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-4 text-sm font-semibold text-brand-blue hover:border-brand-blue/40 focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        >
          {state === "copied" ? (
            <HiMiniClipboardDocumentCheck className="size-4" aria-hidden="true" />
          ) : (
            <HiMiniClipboard className="size-4" aria-hidden="true" />
          )}
          {state === "copied" ? "Copied" : "Copy"}
        </button>
      </div>
      {state === "failed" && (
        <p className="mt-1 text-xs text-brand-dark/70" role="status">
          Copy is unavailable here. Select the command and copy it.
        </p>
      )}
    </div>
  );
}

function CheckAgain(props: { watch: ExtensionAuthorityWatch; note: string }) {
  const { watch } = props;
  return (
    <div className="mt-4 flex flex-wrap items-center gap-x-3 gap-y-2">
      <ActionButton variant="outline" onClick={watch.checkAgain} disabled={watch.checking} aria-busy={watch.checking}>
        {watch.checking ? "Checking…" : "Check again"}
      </ActionButton>
      <p className="min-w-0 flex-1 text-xs leading-5 text-slate-600" role="status" aria-live="polite">
        {watch.checking
          ? "Checking this device…"
          : watch.checkResult === "unchanged"
            ? "Not finished yet. Guard keeps checking while this page is open."
            : props.note}
      </p>
    </div>
  );
}

/**
 * The guided path for a recommendation Guard cannot save yet. A device that
 * never enrolled gets the two one-time steps in order; a damaged authority is
 * pointed at repair, since only a healthy one can take an Always allow.
 */
export function ExtensionAuthoritySetup(props: { watch: ExtensionAuthorityWatch; commandText: string }) {
  const { watch, commandText } = props;
  const health = watch.effective?.health ?? null;

  if (watch.effective === null) {
    return (
      <div className="mt-3">
        <p className="text-sm text-brand-dark/80" role="status">
          {watch.loadFailed
            ? "Guard could not read this device's protection settings."
            : "Checking whether this device can save extension settings…"}
        </p>
        {watch.loadFailed && <CheckAgain watch={watch} note="" />}
      </div>
    );
  }

  if (health === "unenrolled") {
    const gate = watch.approvalGate;
    const gateReady = approvalGateProofReady(gate);
    const terminal = watch.effective.terminal_commands;
    const terminalName = terminal?.shell === "powershell" ? "PowerShell" : "a terminal";
    return (
      <div className="mt-3 border-t border-brand-blue/15 pt-3">
        <p className="text-sm leading-relaxed text-brand-dark/80">
          This device hasn't saved its extension settings yet. Two one-time steps let you allow {commandText} from
          here.
        </p>
        <ol className="mt-3 space-y-4" aria-label="One-time setup">
          <SetupStep index={1} done={gateReady} current={!gateReady} title="Set up local approval">
            {gateReady ? (
              <p className="mt-0.5 text-sm text-brand-dark/70">Your approval password is ready.</p>
            ) : (
              <>
                <p className="mt-0.5 text-sm leading-relaxed text-brand-dark/70">
                  {gate?.configured
                    ? "Turn local approval back on. It keeps agents from changing protection on their own."
                    : "Choose an approval password. It stays on this device and keeps agents from changing protection on their own."}
                </p>
                <ActionButton href="/settings?section=approval" variant="primary" className="mt-2">
                  Open approval settings
                </ActionButton>
              </>
            )}
          </SetupStep>
          <SetupStep index={2} done={false} current={gateReady} title="Enroll this device">
            <p className="mt-0.5 text-sm leading-relaxed text-brand-dark/70">
              Run this once in {terminalName}. It asks for your approval password.
            </p>
            <CopyCommand command={terminal?.enroll ?? DEFAULT_ENROLL_COMMAND} label="Copy enroll command" />
          </SetupStep>
        </ol>
        <CheckAgain
          watch={watch}
          note={`When enrollment finishes, Approve & always allow ${commandText} appears here.`}
        />
      </div>
    );
  }

  if (health === "protected") {
    return (
      <div className="mt-3">
        <p className="text-sm text-brand-dark/80" role="status">
          Protection settings are ready. Loading the option to always allow {commandText}…
        </p>
        <CheckAgain watch={watch} note="" />
      </div>
    );
  }

  return (
    <div className="mt-3">
      <p className="text-sm leading-relaxed text-brand-dark/80">
        Guard is staying fail-safe because this device's protection settings need repair. Repair them, then you can
        allow {commandText} from here.
      </p>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <ActionButton href="/protection/repair" variant="primary">
          Repair protection
        </ActionButton>
      </div>
      <CheckAgain watch={watch} note="" />
    </div>
  );
}
