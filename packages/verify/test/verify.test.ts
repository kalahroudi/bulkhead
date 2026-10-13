import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
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
    const failed = (await runProbes(fx.url)).filter((r) => !r.passed && r.skipped === undefined).map((r) => r.probe.id).sort();
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

/** A target that answers 404 to everything: an app with none of the routes a probe exercises. */
async function startEmptyTarget() {
  const server = createServer((_req, res) => { res.writeHead(404, { "content-type": "application/json" }); res.end('{"error":"not found"}'); });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  return { url: new URL(`http://127.0.0.1:${port}`), port, stop: () => new Promise<void>((r) => { server.close(() => r()); server.closeAllConnections(); }) };
}

test("a probe that does not apply to the target is skipped, not a finding", async () => {
  const bill = probes.filter((p) => p.ruleId === "BILL-2");
  assert.equal(bill.length, 1);
  // (a) an app without billing routes: skipped, zero findings, and never read as a pass
  const empty = await startEmptyTarget();
  const dir = mkdtempSync(join(tmpdir(), "bulkhead-verify-"));
  try {
    const [r] = await runProbes(empty.url, bill);
    assert.equal(r?.skipped, "target has no billing routes (GET /plan is 404)");
    assert.equal(r?.passed, false);
    const report = await verifyTarget(empty.url, new EventLog(dir, "verify"), ["BILL-2"]);
    assert.equal(report.valid, true);
    assert.equal(report.findings.length, 0);
    assert.equal(report.results.length, 1);
    assert.ok(report.results[0]?.skipped);
    const logged = readdirSync(dir, { recursive: true, withFileTypes: true }).filter((e) => e.isFile()).map((e) => readFileSync(join(e.parentPath, e.name), "utf8")).join("\n");
    assert.match(logged, /"notApplicable":\[\{"probe":"forged-signature"/);
  } finally {
    await empty.stop();
  }
  // (c) with billing present the probe runs: the bug is a FAIL, the fixed fixture a pass
  const buggy = await startFixture(["skipped-signature-check"]);
  try {
    const [r] = await runProbes(buggy.url, bill);
    assert.equal(r?.skipped, undefined);
    assert.equal(r?.passed, false);
    assert.match(r?.evidence ?? "", /forged webhook rejected/);
  } finally {
    await buggy.stop();
  }
  const fixed = await startFixture([]);
  try {
    const [r] = await runProbes(fixed.url, bill);
    assert.equal(r?.skipped, undefined);
    assert.equal(r?.passed, true);
  } finally {
    await fixed.stop();
  }
});

test("a run that verified nothing exits non-zero", async () => {
  const empty = await startEmptyTarget();
  const dir = mkdtempSync(join(tmpdir(), "bulkhead-verify-"));
  try {
    const cli = new URL("../src/cli.ts", import.meta.url).pathname;
    const r = await new Promise<{ status: number | null; stdout: string; stderr: string }>((resolve) => {
      const c = spawn(process.execPath, [cli, "run", "--target", empty.url.origin, "--rules", "BILL-2", "--log-dir", dir]);
      let stdout = "", stderr = "";
      c.stdout.on("data", (d: Buffer) => (stdout += d));
      c.stderr.on("data", (d: Buffer) => (stderr += d));
      c.on("close", (status) => resolve({ status, stdout, stderr }));
    });
    assert.equal(r.status, 2, r.stdout + r.stderr);
    assert.match(r.stderr, /no selected probe applied to this target; nothing was verified/);
    assert.match(r.stdout, /^skip  BILL-2 forged-signature: target has no billing routes/m);
    assert.doesNotMatch(r.stdout, /^(pass|FAIL) /m);
    assert.match(r.stdout, /0 rule\(s\) exercised/);
  } finally {
    await empty.stop();
  }
});
