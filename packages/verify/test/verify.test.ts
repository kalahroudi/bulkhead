import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { seededBugs } from "../src/bugs.ts";
import { EventLog } from "../src/eventlog.ts";
import { runProbes, selectProbes, selfCheck, startFixture, verifyTarget } from "../src/run.ts";
import { checkTarget } from "../src/targets.ts";
import { probes } from "../src/probes.ts";
import { spec } from "@kalahroudi/bulkhead-spec";

test("self-check catches 100% of seeded bugs with no false positives (Phase 1 gate)", async () => {
  const sc = await selfCheck();
  assert.deepEqual(sc.cases.filter((c) => !c.ok), []);
  assert.equal(sc.seededBugsFound, sc.seededBugsTotal);
  assert.equal(sc.seededBugsTotal, seededBugs.length);
  assert.equal(sc.valid, true);
});

test("every probe maps to a real spec rule and its scenario stub", () => {
  for (const p of probes) {
    const rule = spec.rules.find((r) => r.id === p.ruleId);
    assert.ok(rule, `${p.id}: unknown rule ${p.ruleId}`);
    assert.equal(rule.scenario, p.scenario);
    assert.equal(rule.oracle, p.oracle);
  }
});

test("with every bug present, exactly the cataloged probes fail", async () => {
  const fx = await startFixture(seededBugs.map((b) => b.id));
  try {
    const failed = (await runProbes(fx.url)).filter((r) => !r.passed).map((r) => r.probe.id).sort();
    assert.deepEqual(failed, [...new Set(seededBugs.flatMap((b) => b.probeIds))].sort());
  } finally {
    await fx.stop();
  }
});

test("the rule filter refuses unknown ids and refuses to run nothing", () => {
  assert.throws(() => selectProbes(["TENANT-9"]), /unknown rule id/);
  assert.throws(() => selectProbes([]), /no probes selected/);
  assert.deepEqual(selectProbes(["TENANT-1"]).map((p) => p.id), ["identity-header-differential"]);
  assert.equal(selectProbes().length, probes.length);
});

test("verifyTarget records confirmed findings and events against a vulnerable target", async () => {
  const dir = mkdtempSync(join(tmpdir(), "bulkhead-verify-"));
  const fx = await startFixture(["shared-cache-key"]);
  try {
    const report = await verifyTarget(fx.url, new EventLog(dir, "verify"));
    assert.equal(report.valid, true);
    assert.equal(report.findings.length, 1);
    assert.equal(report.findings[0]?.ruleId, "TENANT-5");
    assert.equal(report.findings[0]?.verdict, "confirmed");
  } finally {
    await fx.stop();
  }
});

test("targets: loopback allowed, others refused unless registered", () => {
  const dir = mkdtempSync(join(tmpdir(), "bulkhead-targets-"));
  assert.equal(checkTarget(new URL("http://127.0.0.1:8787"), dir).ok, true);
  assert.equal(checkTarget(new URL("https://app.example.com"), dir).ok, false);
  assert.equal(checkTarget(new URL("ftp://127.0.0.1"), dir).ok, false);
});
