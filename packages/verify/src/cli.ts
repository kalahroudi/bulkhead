#!/usr/bin/env node
import { parseArgs } from "node:util";
import { spec } from "@kalahroudi/bulkhead-spec";
import { EventLog } from "./eventlog.ts";
import { LIMITS, selfCheck, verifyTarget } from "./run.ts";
import { probes } from "./probes.ts";
import { checkTarget } from "./targets.ts";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: { target: { type: "string" }, rules: { type: "string" }, "log-dir": { type: "string", default: ".bulkhead" } },
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
  const report = await verifyTarget(target, new EventLog(dir, "verify"), values.rules?.split(","));
  if (!report.valid) { console.error("run INVALID: oracle self-check failed"); process.exit(1); }
  for (const r of report.results) console.log(`${r.passed ? "pass" : "FAIL"} ${r.probe.ruleId} ${r.probe.id}${r.passed ? "" : `: ${r.evidence}`}`);
  if (report.skipped.length) console.log(`Skipped by rule filter: ${report.skipped.map((p) => `${p.ruleId} ${p.id}`).join(", ")}`);
  coverage(report.results.map((r) => r.probe.ruleId));
  console.log(`${report.findings.length} confirmed finding(s). ${LIMITS}`);
  process.exit(report.findings.length ? 1 : 0);
} else {
  console.error("usage: bulkhead-verify selfcheck | run --target <url>");
  process.exit(2);
}
