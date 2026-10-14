#!/usr/bin/env node
import { readFileSync, statSync } from "node:fs";
import { parseArgs } from "node:util";
import { spec } from "@kalahroudi/bulkhead-spec";
import { EventLog } from "./eventlog.ts";
import { LIMITS, selectProbes, selfCheck, verifyTarget } from "./run.ts";
import { parseManifest, probes, type TargetEnv } from "./probes.ts";
import { checkTarget } from "./targets.ts";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: { target: { type: "string" }, rules: { type: "string" }, "log-dir": { type: "string", default: ".bulkhead" }, "persist-dir": { type: "string" }, "route-manifest": { type: "string" } },
});
const dir = values["log-dir"] as string;
const cmd = positionals[0];

function coverage(ran: string[]) {
  const covered = new Set(probes.map((p) => p.ruleId));
  console.log(`Spec coverage: ${new Set(ran).size} rule(s) exercised this run (${[...new Set(ran)].sort().join(", ")}); ${covered.size} of ${spec.rules.length} rules have any scenario. The rest are stubs.`);
}

if (cmd === "selfcheck") {
  const log = new EventLog(dir, "verify");
  const sc = await selfCheck();
  log.append("verify.run", { phase: "selfcheck", valid: sc.valid, seededBugsFound: sc.seededBugsFound, seededBugsTotal: sc.seededBugsTotal });
  for (const c of sc.cases) console.log(`${c.ok ? "ok  " : "FAIL"} ${c.name}${c.ok ? "" : `: expected [${c.expectedFailures}] got [${c.actualFailures}]`}`);
  console.log(`Seeded bugs caught: ${sc.seededBugsFound}/${sc.seededBugsTotal}. Oracle ${sc.valid ? "healthy" : "INVALID"}.`);
  process.exit(sc.valid ? 0 : 1);
} else if (cmd === "run") {
  if (!values.target) { console.error("usage: bulkhead-verify run --target <url> [--rules TENANT-1,TENANT-5]"); process.exit(2); }
  const target = new URL(values.target);
  const allowed = checkTarget(target, dir);
  if (!allowed.ok) { console.error(`refused: ${allowed.reason}`); process.exit(2); }
  const rules = values.rules?.split(",");
  try { selectProbes(rules); } catch (e) { console.error(`refused: ${(e as Error).message}`); process.exit(2); }
  const env: TargetEnv = {};
  try {
    if (values["persist-dir"]) { if (!statSync(values["persist-dir"]).isDirectory()) throw new Error(`--persist-dir ${values["persist-dir"]} is not a directory`); env.persistDir = values["persist-dir"]; }
    if (values["route-manifest"]) env.routes = parseManifest(readFileSync(values["route-manifest"], "utf8"));
  } catch (e) { console.error(`refused: ${(e as Error).message}`); process.exit(2); }
  const report = await verifyTarget(target, new EventLog(dir, "verify"), rules, process.env.BULKHEAD_VERIFY_BOOTSTRAP_TOKEN, env);
  if (!report.valid) { console.error("run INVALID: oracle self-check failed"); process.exit(1); }
  for (const r of report.results) {
    if (r.unverified !== undefined) console.log(`UNVERIFIED ${r.probe.ruleId} ${r.probe.id}: ${r.unverified}`);
    else if (r.skipped !== undefined) console.log(`skip  ${r.probe.ruleId} ${r.probe.id}: ${r.skipped}`);
    else console.log(`${r.passed ? "pass" : "FAIL"} ${r.probe.ruleId} ${r.probe.id}${r.passed ? "" : `: ${r.evidence}`}`);
  }
  const applied = report.results.filter((r) => r.skipped === undefined && r.unverified === undefined);
  if (report.skipped.length) console.log(`Skipped by rule filter: ${report.skipped.map((p) => `${p.ruleId} ${p.id}`).join(", ")}`);
  coverage(applied.map((r) => r.probe.ruleId));
  const na = report.results.length - applied.length - report.unverified.length;
  console.log(`${report.findings.length} confirmed finding(s).${na ? ` ${na} probe(s) not applicable.` : ""} ${LIMITS}`);
  if (report.unverified.length) { console.error(`NOT GREEN: ${report.unverified.length} selected probe(s) could not be verified on this target: ${report.unverified.map((r) => `${r.probe.ruleId} ${r.probe.id}`).join(", ")}`); process.exit(report.findings.length ? 1 : 3); }
  if (applied.length === 0) { console.error("no selected probe applied to this target; nothing was verified"); process.exit(2); }
  process.exit(report.findings.length ? 1 : 0);
} else {
  console.error("usage: bulkhead-verify selfcheck | run --target <url>");
  process.exit(2);
}
