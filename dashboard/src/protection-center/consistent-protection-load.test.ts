import assert from "node:assert/strict";
import { REFRESH_DEADLINE_MS, refreshEffectiveExtensionControls } from "../extension-controls-api";
import {
  CONSISTENT_LOAD_RETRY_DELAYS_MS,
  PROTECTION_DATA_UNSETTLED_MESSAGE,
  PROTECTION_SAVE_UNSETTLED_MESSAGE,
  loadConsistentProtectionData,
} from "./consistent-protection-load";

const sequence = (...digests: string[]) => {
  let index = 0;
  return async () => ({ catalog_digest: digests[Math.min(index++, digests.length - 1)] as string });
};

// Every case supplies its own repair so no test reaches the daemon route.
const noRepair = async () => undefined;

// Matching digests load on the first attempt without waiting.
{
  const waits: number[] = [];
  const result = await loadConsistentProtectionData(sequence("a"), sequence("a"), {
    sleep: async (ms) => { waits.push(ms); },
    repair: noRepair,
  });
  assert.equal(result.catalog.catalog_digest, "a");
  assert.equal(result.consistent, true);
  assert.deepEqual(waits, []);
}

// A daemon still settling a new catalog converges after a retry instead of
// failing the page (the 3.50.0 -> 3.51.0 upgrade left them split until restart).
{
  const waits: number[] = [];
  const result = await loadConsistentProtectionData(sequence("old", "old", "new"), sequence("new"), {
    sleep: async (ms) => { waits.push(ms); },
    repair: noRepair,
  });
  assert.equal(result.catalog.catalog_digest, "new");
  assert.equal(result.effective.catalog_digest, "new");
  assert.deepEqual(waits, CONSISTENT_LOAD_RETRY_DELAYS_MS.slice(0, 2));
}

// A pair that never agrees still loads, marked unsettled. Refusing the read was
// the one outcome the user could not clear: the list, the policies and the
// editor all disappeared behind a "Try again" that ran the same read again.
// The daemon still refuses a mutation whose catalog digest is not its own, so
// nothing is applied against the wrong catalog.
{
  const waits: number[] = [];
  const result = await loadConsistentProtectionData(sequence("a"), sequence("b"), {
    sleep: async (ms) => { waits.push(ms); },
    repair: noRepair,
  });
  assert.equal(result.consistent, false);
  assert.equal(result.catalog.catalog_digest, "a");
  assert.equal(result.effective.catalog_digest, "b");
  assert.deepEqual(waits, [...CONSISTENT_LOAD_RETRY_DELAYS_MS]);
}

// The retry window spans at least one daemon control refresh (5 s).
assert.ok(CONSISTENT_LOAD_RETRY_DELAYS_MS.reduce((total, ms) => total + ms, 0) >= 5000);

// A split that waiting cannot settle asks the daemon to re-read before each
// retry. Without that request a daemon whose catalog binding and whose control
// snapshot settled on different catalogs never converges, and "Try again" runs
// the same unresolvable read forever.
{
  let repairs = 0;
  const effective = sequence("new");
  const catalog = async () => ({ catalog_digest: repairs === 0 ? "old" : "new" });
  const result = await loadConsistentProtectionData(catalog, effective, {
    sleep: async () => undefined,
    repair: async () => { repairs += 1; },
  });
  assert.equal(repairs, 1);
  assert.equal(result.consistent, true);
  assert.equal(result.catalog.catalog_digest, "new");
}

// A repair the daemon refuses still leaves the retry worth taking.
{
  let repairs = 0;
  const catalog = async () => ({ catalog_digest: repairs < 2 ? "old" : "new" });
  const result = await loadConsistentProtectionData(catalog, sequence("new"), {
    sleep: async () => undefined,
    repair: async () => { repairs += 1; throw new Error("refresh unavailable"); },
  });
  assert.equal(repairs, 2);
  assert.equal(result.catalog.catalog_digest, "new");
}

// The repair request is bounded. The daemon waits on its authority lease for
// far longer than a page should hold a load on, and an unbounded repair stalls
// the retry ladder on a single attempt instead of reading again.
assert.ok(REFRESH_DEADLINE_MS > 0 && REFRESH_DEADLINE_MS <= 5000);
{
  const storage = new Map<string, string>();
  const shim = {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => { storage.set(key, value); },
    removeItem: (key: string) => { storage.delete(key); },
  };
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      location: { origin: "http://127.0.0.1:4174", pathname: "/", search: "", hash: "" },
      sessionStorage: shim,
      localStorage: shim,
    },
  });
  const originalFetch = globalThis.fetch;
  let seenSignal: AbortSignal | undefined;
  globalThis.fetch = ((_input: RequestInfo | URL, init?: RequestInit) => {
    seenSignal = init?.signal ?? undefined;
    return new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => { reject(new Error("aborted")); });
    });
  }) as typeof fetch;
  try {
    await assert.rejects(refreshEffectiveExtensionControls(5));
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.ok(seenSignal?.aborted);
}

// A split pair always builds a mutation the daemon refuses, so neither notice
// may suggest that saving works while the page is unsettled.
assert.match(PROTECTION_DATA_UNSETTLED_MESSAGE, /cannot be saved yet/);
assert.ok(!/stays safe/.test(PROTECTION_DATA_UNSETTLED_MESSAGE));
assert.match(PROTECTION_SAVE_UNSETTLED_MESSAGE, /current protection is unchanged/);
assert.match(PROTECTION_SAVE_UNSETTLED_MESSAGE, /reload this page in a few seconds/);
