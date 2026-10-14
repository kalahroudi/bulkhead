// The five oracles are deterministic and boring.
import type { Response } from "./http.ts";
import type { StorageScan } from "./inspector.ts";

export interface Verdict {
  /** Never true for a skipped probe: a probe that did not run verified nothing. Consumers must check `skipped` before reading `passed` as a failure. */
  passed: boolean;
  evidence: string;
  /** Third outcome, "not applicable": the reason the target does not have the feature this probe exercises. Not a pass, not a finding. */
  skipped?: string;
  /**
   * Fourth outcome, "unverified": the target may well have the feature, but this run had no means to check it (no storage
   * directory, no route manifest). Never a pass and never a finding; a run that carries one is not green.
   */
  unverified?: string;
}

/** Canary: a marker planted in tenant A must not appear anywhere in tenant B's world. */
export function canaryOracle(marker: string, observations: { where: string; response: Response }[]): Verdict {
  const leaks = observations.filter((o) => o.response.body.includes(marker));
  return leaks.length
    ? { passed: false, evidence: `marker ${marker} found in: ${leaks.map((l) => `${l.where} (HTTP ${l.response.status})`).join(", ")}` }
    : { passed: true, evidence: "marker absent from all observed responses" };
}

/** Canary at rest: a marker the app was given must appear nowhere in the persisted storage, in any column or any raw byte. */
export function storageCanaryOracle(markers: readonly string[], scan: StorageScan): Verdict {
  const hits = scan.hits.filter((h) => markers.includes(h.marker));
  return hits.length
    ? { passed: false, evidence: `plaintext found in storage: ${hits.map((h) => `${h.layer} ${h.file} ${h.where}`).join(", ")}` }
    : { passed: true, evidence: `marker absent from ${scan.filesScanned} file(s), ${scan.tablesScanned} table(s), ${scan.rowsScanned} row(s) and all raw bytes` };
}

/** Spec: the rule says what must happen; the response either matches or not. */
export function specOracle(checks: { name: string; ok: boolean; detail: string }[]): Verdict {
  const failed = checks.filter((c) => !c.ok);
  return failed.length
    ? { passed: false, evidence: failed.map((c) => `${c.name}: ${c.detail}`).join("; ") }
    : { passed: true, evidence: "all spec expectations met" };
}

/** Differential: the same action by two actors differs only where policy says it may (here: not at all). */
export function differentialOracle(a: Response, b: Response, label: string): Verdict {
  const same = a.status === b.status && a.body === b.body;
  return same
    ? { passed: true, evidence: `${label}: responses identical` }
    : { passed: false, evidence: `${label}: HTTP ${a.status} ${a.body} vs HTTP ${b.status} ${b.body}` };
}

/** Metamorphic: adding tenant B must not change any response tenant A receives. */
export function metamorphicOracle(before: Response, after: Response, label: string): Verdict {
  const same = before.status === after.status && before.body === after.body;
  return same
    ? { passed: true, evidence: `${label}: unchanged after adding another tenant` }
    : { passed: false, evidence: `${label}: changed after adding another tenant (before ${before.body}; after ${after.body})` };
}

/**
 * Differential across actors (AUTH-3): every actor's outcome on every route must match what policy allows.
 * `expected` is the policy matrix (actor -> route -> allowed). A difference that policy does not explain is a finding.
 */
export function roleDifferentialOracle(observed: Record<string, Record<string, number>>, expected: Record<string, Record<string, boolean>>): Verdict {
  const bad: string[] = [];
  for (const [actor, routes] of Object.entries(expected))
    for (const [route, allowed] of Object.entries(routes)) {
      const status = observed[actor]?.[route];
      if (allowed ? status !== 200 : status !== 403) bad.push(`${actor} on ${route}: HTTP ${status ?? "none"}, policy says ${allowed ? "allowed (200)" : "denied (403)"}`);
    }
  return bad.length ? { passed: false, evidence: bad.join("; ") } : { passed: true, evidence: "every actor's outcomes match policy" };
}
