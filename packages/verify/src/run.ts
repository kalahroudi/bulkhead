import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { validateFinding, type Finding } from "@kalahroudi/bulkhead-spec";
import { seededBugs } from "./bugs.ts";
import { EventLog } from "./eventlog.ts";
import { makeRequester } from "./http.ts";
import { parseManifest, probes, type Context, type Probe, type TargetEnv } from "./probes.ts";

export const VERIFY_VERSION = "0.0.0";
export const WEBHOOK_SECRET = "whsec_fixture";
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
  const ctx: Context = { req: makeRequester(target), host: (t) => `${t}.demo.localhost`, webhookSecret: WEBHOOK_SECRET, bootstrapToken, ...env };
  const out: ProbeResult[] = [];
  for (const probe of only) {
    try {
      const v = await probe.run(ctx);
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
    child.once("error", (e) => { rmSync(persistDir, { recursive: true, force: true }); reject(e); });
    child.once("exit", (c) => { rmSync(persistDir, { recursive: true, force: true }); reject(new Error(`fixture exited early (${c})`)); });
    child.stdout.on("data", (d: Buffer) => {
      buf += d.toString();
      const m = /LISTENING (\d+)/.exec(buf);
      if (m) {
        child.removeAllListeners("exit");
        resolve({ url: new URL(`http://127.0.0.1:${m[1]}`), env, stop: () => new Promise((r) => { child.once("exit", () => { rmSync(persistDir, { recursive: true, force: true }); r(); }); child.kill(); }) });
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
}

export interface SelfCheck {
  /** VERIFY-3: the run is invalid unless every seeded bug is caught, attributed to its probe, with no false positives. */
  valid: boolean;
  cases: SelfCheckCase[];
  seededBugsFound: number;
  seededBugsTotal: number;
}

async function failuresAgainst(bugs: string[]): Promise<string[]> {
  const fx = await startFixture(bugs);
  try {
    // An unverified probe in the self-check means the oracle could not be exercised here: it must surface as a mismatch, never be dropped.
    return (await runProbes(fx.url, probes, FIXTURE_BOOTSTRAP_TOKEN, fx.env)).filter((r) => (!r.passed && r.skipped === undefined) || r.unverified !== undefined).map((r) => (r.unverified !== undefined ? `UNVERIFIED:${r.probe.id}` : r.probe.id)).sort();
  } finally {
    await fx.stop();
  }
}

export async function selfCheck(): Promise<SelfCheck> {
  const plan: { name: string; bugs: string[]; expected: string[] }[] = [
    { name: "fixed fixture: no false positives", bugs: [], expected: [] },
    ...seededBugs.map((b) => ({ name: `only ${b.id}`, bugs: [b.id], expected: [...b.probeIds].sort() })),
    { name: "all bugs", bugs: seededBugs.map((b) => b.id), expected: [...new Set(seededBugs.flatMap((b) => b.probeIds))].sort() },
  ];
  const cases: SelfCheckCase[] = [];
  for (const p of plan) {
    const actual = await failuresAgainst(p.bugs);
    cases.push({ name: p.name, bugs: p.bugs, expectedFailures: p.expected, actualFailures: actual, ok: JSON.stringify(actual) === JSON.stringify(p.expected) });
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
