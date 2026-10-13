import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { seededBugs } from "../src/bugs.ts";
import { EventLog } from "../src/eventlog.ts";
import { FIXTURE_BOOTSTRAP_TOKEN, runProbes, selectProbes, selfCheck, startFixture, verifyTarget } from "../src/run.ts";
import { checkTarget } from "../src/targets.ts";
import { probes } from "../src/probes.ts";
import { makeRequester } from "../src/http.ts";
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
    assert.equal(r?.skipped, "target has no billing routes (GET /plan and POST /webhooks/billing are both 404)");
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

test("a target that serves the webhook but not GET /plan is not skipped", async () => {
  const server = createServer((req, res) => {
    const ok = req.method === "POST" && req.url === "/webhooks/billing";
    res.writeHead(ok ? 200 : 404, { "content-type": "application/json" });
    res.end(ok ? '{"ok":true}' : '{"error":"not found"}');
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  try {
    const url = new URL(`http://127.0.0.1:${(server.address() as { port: number }).port}`);
    const [r] = await runProbes(url, probes.filter((p) => p.ruleId === "BILL-2"));
    assert.equal(r?.skipped, undefined);
    assert.equal(r?.passed, false); // accepts a forged webhook (200) and has no readable plan: a real FAIL
    assert.match(r?.evidence ?? "", /forged webhook rejected/);
  } finally {
    await new Promise<void>((r) => { server.close(() => r()); server.closeAllConnections(); });
  }
});

test("the run log and CLI summary agree with what was actually verified", async () => {
  const readLog = (dir: string) => readdirSync(dir, { recursive: true, withFileTypes: true }).filter((e) => e.isFile()).map((e) => readFileSync(join(e.parentPath, e.name), "utf8")).join("\n");
  const finished = (text: string) => text.split("\n").filter((l) => l.includes('"phase":"finished"')).map((l) => JSON.parse(l) as { data: Record<string, unknown> }).pop()!.data;
  // nothing ran: the log must not say passed
  const empty = await startEmptyTarget();
  const d1 = mkdtempSync(join(tmpdir(), "bulkhead-verify-"));
  try {
    await verifyTarget(empty.url, new EventLog(d1, "verify"), ["BILL-2"]);
    const f = finished(readLog(d1));
    assert.equal(f.passed, false);
    assert.equal(f.probes, 0);
    assert.equal(f.notApplicableCount, 1);
  } finally {
    await empty.stop();
  }
  // a partial skip: the other rule's probe ran against a 404 target and failed; counts exclude the skipped one and the summary line says so
  const d2 = mkdtempSync(join(tmpdir(), "bulkhead-verify-"));
  const fx = await startFixture([]);
  try {
    const cli = new URL("../src/cli.ts", import.meta.url).pathname;
    // fixture has billing, so nothing is skipped there; use the empty target with two rules to get one applied failure and one skip
    const e2 = await startEmptyTarget();
    try {
      const out = await new Promise<{ status: number | null; stdout: string }>((resolve) => {
        const c = spawn(process.execPath, [cli, "run", "--target", e2.url.origin, "--rules", "BILL-2,TENANT-1", "--log-dir", d2]);
        let stdout = "";
        c.stdout.on("data", (d: Buffer) => (stdout += d));
        c.on("close", (status) => resolve({ status, stdout }));
      });
      assert.equal(out.status, 1, out.stdout);
      assert.match(out.stdout.trim().split("\n").pop()!, /1 probe\(s\) not applicable\./);
      const f = finished(readLog(d2));
      assert.equal(f.probes, 1);
      assert.equal(f.notApplicableCount, 1);
      assert.equal(f.passed, false);
    } finally {
      await e2.stop();
    }
  } finally {
    await fx.stop();
  }
});

test("the listing secret-shape checks catch leaks the old needle list cannot see", async () => {
  const OLD_NEEDLES = ["pbkdf2", "password_hash", "secret_hash", "password"];
  for (const bug of ["listing-leaks-digest", "listing-leaks-token"]) {
    const fx = await startFixture([bug]);
    try {
      const req = makeRequester(fx.url);
      const h = "shape.demo.localhost";
      await req(h, "POST", "/auth/bootstrap", { body: JSON.stringify({ token: FIXTURE_BOOTSTRAP_TOKEN, email: "o@x.test", password: "verify-probe-password-1" }) });
      const login = await req(h, "POST", "/auth/login", { body: JSON.stringify({ email: "o@x.test", password: "verify-probe-password-1" }) });
      const cookie = String([login.headers["set-cookie"]].flat()[0]).split(";")[0]!;
      await req(h, "POST", "/api-keys", { headers: { cookie, origin: `http://${h}` }, body: JSON.stringify({ name: "k", role: "member", permissions: ["private:read"] }) });
      const bodies = (await Promise.all(["/users", "/api-keys"].map((p) => req(h, "GET", p, { headers: { cookie } })))).map((r) => r.body.toLowerCase());
      for (const b of bodies) for (const n of OLD_NEEDLES) assert.ok(!b.includes(n), `${bug}: old needle ${n} would already see it`);
      const [r] = await runProbes(fx.url, probes.filter((p) => p.id === "listings-hide-secrets"));
      assert.equal(r?.passed, false, bug);
      assert.match(r?.evidence ?? "", bug === "listing-leaks-digest" ? /64-hex/ : /43-character/);
    } finally {
      await fx.stop();
    }
  }
});
