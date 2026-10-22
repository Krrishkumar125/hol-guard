import { useCallback, useEffect, useRef, useState } from "react";

import { ActionButton, EmptyState } from "../approval-center-primitives";
import { ReleaseArchiveList } from "./components/release-archive-list";
import { ReleaseDetailPanel } from "./components/release-detail-panel";
import { WhatsNewCard } from "./components/whats-new-card";
import { fetchReleaseDetail, fetchReleaseIndex } from "./releases-api";
import { dismissWhatsNew, failureCopy, installedRelease, isWhatsNewDismissed } from "./releases-model";
import type { ReleaseDetail, ReleaseFeedFailure, ReleaseIndex } from "./releases-types";

type IndexState =
  | { kind: "loading" }
  | { kind: "ready"; index: ReleaseIndex }
  | { kind: "failed"; failure: ReleaseFeedFailure };

type DetailState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; detail: ReleaseDetail }
  | { kind: "failed"; failure: ReleaseFeedFailure };

function FailureNotice(props: { failure: ReleaseFeedFailure; onRetry?: () => void }) {
  const copy = failureCopy(props.failure);
  return (
    <EmptyState
      title={copy.title}
      body={copy.body}
      action={
        props.onRetry ? (
          <ActionButton variant="outline" onClick={props.onRetry}>
            Try again
          </ActionButton>
        ) : undefined
      }
    />
  );
}

function LoadingNotice({ label }: { label: string }) {
  return (
    <p role="status" className="py-8 text-center text-sm text-brand-dark/60">
      {label}
    </p>
  );
}

/**
 * The release archive: every published Guard version, what each one changed,
 * and who is verified to have changed it. The daemon reads hol.org on this
 * screen's behalf; the browser never leaves the device's own origin.
 */
export function ReleasesWorkspace({ installedVersion }: { installedVersion?: string | null }) {
  const [page, setPage] = useState(1);
  const [indexState, setIndexState] = useState<IndexState>({ kind: "loading" });
  const [selectedSlug, setSelectedSlug] = useState<string | null>(null);
  const [detailState, setDetailState] = useState<DetailState>({ kind: "idle" });
  const [whatsNewDismissed, setWhatsNewDismissed] = useState(false);
  const [reloadToken, setReloadToken] = useState(0);
  const [detailToken, setDetailToken] = useState(0);
  const detailHeadingRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setIndexState({ kind: "loading" });
    fetchReleaseIndex({ page, signal: controller.signal })
      .then((result) => {
        if (controller.signal.aborted) return;
        if (result.status === "failed") {
          setIndexState({ kind: "failed", failure: result.failure });
          return;
        }
        setIndexState({ kind: "ready", index: result.index });
        // Open the release this device runs when the archive page holds it,
        // otherwise the newest one, so the screen is never blank on arrival.
        const installed = installedRelease(result.index.releases, installedVersion);
        const opening = installed?.slug ?? result.index.releases[0]?.slug ?? null;
        const onThisPage = (slug: string | null) =>
          slug !== null && result.index.releases.some((release) => release.slug === slug);
        setSelectedSlug((current) => (onThisPage(current) ? current : opening));
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setIndexState({ kind: "failed", failure: "unavailable" });
        }
      });
    return () => controller.abort();
  }, [page, reloadToken, installedVersion]);

  useEffect(() => {
    if (!selectedSlug) {
      setDetailState({ kind: "idle" });
      return;
    }
    const controller = new AbortController();
    setDetailState({ kind: "loading" });
    fetchReleaseDetail(selectedSlug, { signal: controller.signal })
      .then((result) => {
        if (controller.signal.aborted) return;
        setDetailState(
          result.status === "failed"
            ? { kind: "failed", failure: result.failure }
            : { kind: "ready", detail: result.detail },
        );
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setDetailState({ kind: "failed", failure: "unavailable" });
        }
      });
    return () => controller.abort();
  }, [selectedSlug, detailToken]);

  const installed =
    indexState.kind === "ready" ? installedRelease(indexState.index.releases, installedVersion) : null;

  useEffect(() => {
    if (!installed) return;
    setWhatsNewDismissed(isWhatsNewDismissed(installed.versionLabel));
  }, [installed?.versionLabel]);

  const handleSelect = useCallback((slug: string) => {
    setSelectedSlug(slug);
    detailHeadingRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  const handleReadWhatsNew = useCallback(() => {
    if (installed) handleSelect(installed.slug);
  }, [installed, handleSelect]);

  const handleDismissWhatsNew = useCallback(() => {
    if (!installed) return;
    dismissWhatsNew(installed.versionLabel);
    setWhatsNewDismissed(true);
  }, [installed]);

  return (
    <div className="space-y-6 pb-10">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight text-brand-dark">Releases</h1>
        <p className="text-sm text-brand-dark/65">
          Every published Guard version, what it changed, and who is verified to have changed it.
          {installedVersion ? ` This device is running ${installedVersion}.` : ""}
        </p>
      </header>

      {installed && !whatsNewDismissed ? (
        <WhatsNewCard release={installed} onRead={handleReadWhatsNew} onDismiss={handleDismissWhatsNew} />
      ) : null}

      {indexState.kind === "loading" ? <LoadingNotice label="Reading the release archive…" /> : null}

      {indexState.kind === "failed" ? (
        <FailureNotice
          failure={indexState.failure}
          onRetry={indexState.failure === "unsupported" ? undefined : () => setReloadToken((token) => token + 1)}
        />
      ) : null}

      {indexState.kind === "ready" && indexState.index.releases.length === 0 ? (
        <EmptyState
          title="No releases are published yet"
          body="Once a Guard release is published and verified, it appears here with its notes and contributors."
        />
      ) : null}

      {indexState.kind === "ready" && indexState.index.releases.length > 0 ? (
        <div className="grid gap-6 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
          <ReleaseArchiveList
            index={indexState.index}
            selectedSlug={selectedSlug}
            installedSlug={installed?.slug ?? null}
            onSelect={handleSelect}
            onPage={setPage}
          />
          <div ref={detailHeadingRef} className="min-w-0">
            {detailState.kind === "loading" ? <LoadingNotice label="Reading this release…" /> : null}
            {detailState.kind === "failed" ? (
              <FailureNotice
                failure={detailState.failure}
                onRetry={
                  detailState.failure === "unsupported" || detailState.failure === "not-found"
                    ? undefined
                    : () => setDetailToken((token) => token + 1)
                }
              />
            ) : null}
            {detailState.kind === "ready" ? <ReleaseDetailPanel detail={detailState.detail} /> : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}
