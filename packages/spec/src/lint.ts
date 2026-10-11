import { LIFECYCLE, ORACLES, TIERS, type LintIssue, type SpecDocument } from "./types.ts";

const ID = /^[A-Z]+-[1-9]\d*$/;
const SCENARIO = /^[a-z0-9-]+\/[a-z0-9-]+$/;
const SEMVER = /^\d+\.\d+\.\d+$/;

/** Returns every problem found; an empty array means the spec lints clean. */
export function lintSpec(doc: SpecDocument): LintIssue[] {
  const issues: LintIssue[] = [];
  const add = (ruleId: string, code: string, message: string) => issues.push({ ruleId, code, message });

  if (!SEMVER.test(doc.version)) add("-", "bad-version", `spec version "${doc.version}" is not semver`);
  if (doc.rules.length === 0) add("-", "empty", "spec has no rules");

  const ids = new Set<string>();
  const scenarios = new Map<string, string>();
  for (const r of doc.rules) {
    if (!ID.test(r.id)) add(r.id, "bad-id", "ID must look like AREA-N");
    if (ids.has(r.id)) add(r.id, "duplicate-id", "rule ID is used more than once");
    ids.add(r.id);

    for (const k of ["statement", "reason", "enforcement"] as const)
      if (!r[k]?.trim()) add(r.id, `missing-${k}`, `${k} is required`);
    if (!TIERS.includes(r.tier)) add(r.id, "bad-tier", `tier must be one of ${TIERS.join(", ")}`);
    if (!LIFECYCLE.includes(r.state)) add(r.id, "bad-state", `state must be one of ${LIFECYCLE.join(", ")}`);
    if (!ORACLES.includes(r.oracle)) add(r.id, "bad-oracle", `oracle must be one of ${ORACLES.join(", ")}`);
    if (!Number.isInteger(r.principle) || r.principle < 1 || r.principle > 9) add(r.id, "bad-principle", "principle must be 1-9");

    if (!r.scenario || !SCENARIO.test(r.scenario)) add(r.id, "bad-scenario", "scenario stub must look like pack/scenario-name");
    else {
      const other = scenarios.get(r.scenario);
      if (other) add(r.id, "duplicate-scenario", `scenario stub already used by ${other}`);
      scenarios.set(r.scenario, r.id);
    }
  }
  return issues;
}
