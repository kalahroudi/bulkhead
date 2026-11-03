import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { validateFinding, type Finding } from "@kalahroudi/bulkhead-spec";
import { seededBugs } from "./bugs.ts";
import { EventLog } from "./eventlog.ts";
import { makeRequester } from "./http.ts";
import { DEFAULT_COOKIE_NAME, DEFAULT_HOST_SUFFIX, DEFAULT_WEBHOOK_SECRET, inRunScope, missingRoutes, parseManifest, probes, type Context, type Probe, type TargetEnv } from "./probes.ts";

export const VERIFY_VERSION = "0.0.0";
export const WEBHOOK_SECRET = DEFAULT_WEBHOOK_SECRET;
/** The fixture's own bootstrap secret. Real targets supply theirs via BULKHEAD_VERIFY_BOOTSTRAP_TOKEN. */
export const FIXTURE_BOOTSTRAP_TOKEN = "bootstrap_fixture_0123456789abcdef0123";
export const LIMITS = "A green result means no known leak paths, not proof that none exist. Coverage measures only what has been written down.";

export interface ProbeResult {
  probe: Probe;
  passed: boolean;
  evidence: string;
  reproduction: string;
  /** Set when the probe does not apply to this target (a missing feature): neither a pass nor a finding. */
  skipped?: string;
  /** Set when the run had no means to check this probe (no storage directory, no manifest): neither a pass nor a finding, and the run is not green. */
  unverified?: string;
}

export async function runProbes(target: URL, only: readonly Probe[] = probes, bootstrapToken: string | undefined = FIXTURE_BOOTSTRAP_TOKEN, env: TargetEnv = {}): Promise<ProbeResult[]> {
  const { cookieName = DEFAULT_COOKIE_NAME, hostSuffix = DEFAULT_HOST_SUFFIX, webhookSecret = DEFAULT_WEBHOOK_SECRET, ...rest } = env;
  const ctx: Context = { req: makeRequester(target), host: (t) => `${t}.${hostSuffix}`, webhookSecret, cookieName, bootstrapToken, ...rest };
  const out: ProbeResult[] = [];
  for (const probe of only) {
    // DR-0016 decision 2: a probe whose routes the target's manifest does not list has nothing to attack. It is UNVERIFIED before it sends a request, so it cannot reach an assertion.
    const missing = missingRoutes(ctx.routes, probe.needs);
    if (missing.length) {
      const reason = `the route manifest lacks ${missing.join(", ")}; ${probe.id} needs ${missing.length === 1 ? "it" : "them"} to run its attack, so ${probe.ruleId} is unverified on this target`;
      out.push({ probe, passed: false, evidence: reason, reproduction: "n/a (not run: missing route)", unverified: reason });
      continue;
    }
    try {
      const v = await inRunScope(cookieName, () => probe.run(ctx));
      out.push({ probe, passed: v.passed, evidence: v.evidence, reproduction: v.reproduction, ...(v.skipped !== undefined ? { skipped: v.skipped } : {}), ...(v.unverified !== undefined ? { unverified: v.unverified } : {}) });
    } catch (e) {
      // An unreachable or crashing target is not a pass.
      out.push({ probe, passed: false, evidence: `probe error: ${(e as Error).message}`, reproduction: "n/a" });
    }
  }
  return out;
}

export interface Fixture {
  url: URL;
  /** Where the fixture persists tenant SQLite files, and its route manifest: what a gate launcher would hand to a real target. */
  env: TargetEnv;
  /** The fixture process, so a test can kill exactly this one. */
  pid: number;
  stop(): Promise<void>;
}

const FIXTURE_MANIFEST = fileURLToPath(new URL("../fixture/route-manifest.json", import.meta.url));

export function startFixture(bugs: string[]): Promise<Fixture> {
  const server = fileURLToPath(new URL("../fixture/server.ts", import.meta.url));
  const persistDir = mkdtempSync(join(tmpdir(), "bulkhead-fixture-state-"));
  const env: TargetEnv = { persistDir, routes: parseManifest(readFileSync(FIXTURE_MANIFEST, "utf8")) };
  const child = spawn(process.execPath, ["--no-warnings", server], {
    env: { ...process.env, FIXTURE_BUGS: bugs.length ? bugs.join(",") : "none", FIXTURE_WEBHOOK_SECRET: WEBHOOK_SECRET, FIXTURE_BOOTSTRAP_TOKEN, FIXTURE_PERSIST_DIR: persistDir, PORT: "0" },
    stdio: ["ignore", "pipe", "inherit"],
  });
  return new Promise((resolve, reject) => {
    let buf = "";
    const cleanup = () => rmSync(persistDir, { recursive: true, force: true });
    child.once("error", (e) => { cleanup(); reject(e); });
    child.once("exit", cleanup); // the temp dir goes whenever the fixture dies, early, mid-run or on stop
    const early = (c: number | null) => reject(new Error(`fixture exited early (${c})`));
    child.once("exit", early);
    child.stdout.on("data", (d: Buffer) => {
      buf += d.toString();
      const m = /LISTENING (\d+)/.exec(buf);
      if (m) {
        child.removeListener("exit", early);
        resolve({ url: new URL(`http://127.0.0.1:${m[1]}`), env, pid: child.pid!, stop: () => new Promise((r) => { if (child.exitCode !== null || child.signalCode !== null) { cleanup(); r(); return; } child.once("exit", () => r()); child.kill(); }) });
      }
    });
  });
}

export interface SelfCheckCase {
  name: string;
  bugs: string[];
  expectedFailures: string[];
  actualFailures: string[];
  ok: boolean;
  /** Set when the case could not run at all (the fixture did not start, a probe run threw): the message names this case. */
  error?: string;
}

/** One line for a self-check case that is not ok: its name, what was expected, what happened. Shared by the CLI's selfcheck and run commands. */
export function describeCase(c: SelfCheckCase): string {
  return `self-check case "${c.name}" (bugs: ${c.bugs.length ? c.bugs.join(",") : "none"}): ${c.error !== undefined ? `could not run: ${c.error}` : `expected failures [${c.expectedFailures}] but got [${c.actualFailures}]`}`;
}

export interface SelfCheck {
  /** VERIFY-3: the run is invalid unless every seeded bug is caught, attributed to its probe, with no false positives. */
  valid: boolean;
  cases: SelfCheckCase[];
  seededBugsFound: number;
  seededBugsTotal: number;
}

/** Failing probe ids of a self-check run. An unverified probe surfaces as `UNVERIFIED:<id>`: the oracle could not be exercised, which must be a mismatch, never dropped. */
export function selfCheckFailureIds(results: readonly ProbeResult[]): string[] {
  return results.filter((r) => (!r.passed && r.skipped === undefined) || r.unverified !== undefined).map((r) => (r.unverified !== undefined ? `UNVERIFIED:${r.probe.id}` : r.probe.id)).sort();
}

async function failuresAgainst(bugs: string[]): Promise<string[]> {
  const fx = await startFixture(bugs);
  try {
    return selfCheckFailureIds(await runProbes(fx.url, probes, FIXTURE_BOOTSTRAP_TOKEN, fx.env));
  } finally {
    await fx.stop();
  }
}

/** With every bug at once, a probe that one bug leaves unable to run reports UNVERIFIED and no longer reaches its own failure: the unverified outcome masks it. */
export function expectedWithAll(ids: readonly string[]): string[] {
  const all = new Set(ids);
  for (const id of ids) if (id.startsWith("UNVERIFIED:")) all.delete(id.slice("UNVERIFIED:".length));
  return [...all].sort();
}

/** `adjustExpected` exists so a test can force a mismatch and see it reported; the real check never passes it. */
export async function selfCheck(adjustExpected: (caseName: string, expected: string[]) => string[] = (_n, e) => e): Promise<SelfCheck> {
  const plan: { name: string; bugs: string[]; expected: string[] }[] = [
    { name: "fixed fixture: no false positives", bugs: [], expected: [] },
    ...seededBugs.map((b) => ({ name: `only ${b.id}`, bugs: [b.id], expected: [...b.probeIds].sort() })),
    { name: "all bugs", bugs: seededBugs.map((b) => b.id), expected: expectedWithAll(seededBugs.flatMap((b) => b.probeIds)) },
  ];
  const cases: SelfCheckCase[] = [];
  for (const p of plan) {
    const expected = adjustExpected(p.name, p.expected);
    try {
      const actual = await failuresAgainst(p.bugs);
      cases.push({ name: p.name, bugs: p.bugs, expectedFailures: expected, actualFailures: actual, ok: JSON.stringify(actual) === JSON.stringify(expected) });
    } catch (e) {
      // Name the case: a bare "fixture exited early" or "request timed out" says nothing about which bug set was running.
      cases.push({ name: p.name, bugs: p.bugs, expectedFailures: expected, actualFailures: [], ok: false, error: (e as Error).message });
    }
  }
  const found = seededBugs.filter((b) => cases.find((c) => c.bugs.length === 1 && c.bugs[0] === b.id)?.ok).length;
  return { valid: cases.every((c) => c.ok), cases, seededBugsFound: found, seededBugsTotal: seededBugs.length };
}

export interface RunReport {
  valid: boolean;
  /** Selected probes that could not be checked on this target (no storage dir or manifest). A report with any is not green. */
  unverified: ProbeResult[];
  /** Probes not run because of the rule filter. Reported, never silently dropped. */
  skipped: Probe[];
  results: ProbeResult[];
  findings: Finding[];
  selfCheck: SelfCheck;
}

/**
 * Rule filter for a targeted run. Unknown IDs and an empty selection are refused outright: a typo
 * must not silently narrow the run to nothing and hand back a green report.
 */
export function selectProbes(rules?: readonly string[]): Probe[] {
  if (rules === undefined) return probes;
  const known = new Set(probes.map((p) => p.ruleId));
  const unknown = [...new Set(rules)].filter((r) => !known.has(r));
  if (unknown.length) throw new Error(`unknown rule id(s): ${unknown.join(", ")}`);
  const selected = probes.filter((p) => rules.includes(p.ruleId));
  if (!selected.length) throw new Error("no probes selected");
  return selected;
}

/** Self-check first (the run is invalid if it fails), then the probes against the target. Events go to the log. */
export async function verifyTarget(target: URL, log: EventLog, rules?: readonly string[], bootstrapToken?: string, env: TargetEnv = {}): Promise<RunReport> {
  const selected = selectProbes(rules);
  const skipped = probes.filter((p) => !selected.includes(p));
  log.append("verify.run", { phase: "started", target: target.host, verifyVersion: VERIFY_VERSION });
  const sc = await selfCheck();
  log.append("verify.run", { phase: "selfcheck", valid: sc.valid, seededBugsFound: sc.seededBugsFound, seededBugsTotal: sc.seededBugsTotal });
  if (!sc.valid) {
    log.append("verify.run", { phase: "finished", valid: false, reason: "oracle self-check failed; run is invalid" });
    return { valid: false, unverified: [], skipped, results: [], findings: [], selfCheck: sc };
  }
  const results = await runProbes(target, selected, bootstrapToken, env);
  const findings: Finding[] = [];
  const notApplicable = results.filter((x) => x.skipped !== undefined);
  const unverified = results.filter((x) => x.unverified !== undefined);
  const ran = results.length - notApplicable.length - unverified.length;
  for (const r of results.filter((x) => !x.passed && x.skipped === undefined && x.unverified === undefined)) {
    const n = findings.length + 1;
    const f: Finding = {
      id: `F-${String(n).padStart(3, "0")}`,
      title: `${r.probe.scenario}: ${r.probe.id} failed`,
      verdict: "confirmed",
      severity: "high",
      ruleId: r.probe.ruleId,
      oracle: r.probe.oracle,
      reproduction: r.reproduction,
      regressionId: `RS-${String(n).padStart(4, "0")}`,
      source: "black-box",
    };
    const v = validateFinding(f);
    if (!v.ok) throw new Error(`internal: invalid finding ${v.errors.join("; ")}`);
    findings.push(f);
    log.append("finding.recorded", { finding: f, evidence: r.evidence });
  }
  log.append("verify.run", { phase: "finished", valid: true, passed: ran > 0 && findings.length === 0 && unverified.length === 0, probes: ran, unverifiedCount: unverified.length, unverified: unverified.map((r) => ({ probe: r.probe.id, rule: r.probe.ruleId, reason: r.unverified })), skipped: skipped.map((p) => p.id), notApplicableCount: notApplicable.length, notApplicable: notApplicable.map((r) => ({ probe: r.probe.id, rule: r.probe.ruleId, reason: r.skipped })), findings: findings.length });
  return { valid: true, unverified, skipped, results, findings, selfCheck: sc };
}
