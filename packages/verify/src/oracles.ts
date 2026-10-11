// The five oracles are deterministic and boring. Phase 1 implements the three the probes need; metamorphic and state land with their packs.
import type { Response } from "./http.ts";

export interface Verdict {
  passed: boolean;
  evidence: string;
}

/** Canary: a marker planted in tenant A must not appear anywhere in tenant B's world. */
export function canaryOracle(marker: string, observations: { where: string; response: Response }[]): Verdict {
  const leaks = observations.filter((o) => o.response.body.includes(marker));
  return leaks.length
    ? { passed: false, evidence: `marker ${marker} found in: ${leaks.map((l) => `${l.where} (HTTP ${l.response.status})`).join(", ")}` }
    : { passed: true, evidence: "marker absent from all observed responses" };
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
