import assert from "node:assert/strict";
import {
  CONSISTENT_LOAD_RETRY_DELAYS_MS,
  loadConsistentProtectionData,
  PROTECTION_DATA_CHANGED_MESSAGE,
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

// A pair that never agrees is still refused after the retry window.
{
  const waits: number[] = [];
  await assert.rejects(
    loadConsistentProtectionData(sequence("a"), sequence("b"), {
      sleep: async (ms) => { waits.push(ms); },
      repair: noRepair,
    }),
    { message: PROTECTION_DATA_CHANGED_MESSAGE },
  );
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
