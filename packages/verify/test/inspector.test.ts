import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { openReadOnly, scanStorage } from "../src/inspector.ts";
import { FIXTURE_BOOTSTRAP_TOKEN, runProbes, selfCheckFailureIds, startFixture, verifyTarget } from "../src/run.ts";
import { EventLog } from "../src/eventlog.ts";
import { probes } from "../src/probes.ts";

const CANARY = "CANARY-0123456789ab";
const tmp = () => mkdtempSync(join(tmpdir(), "bulkhead-inspect-"));
const digest = (dir: string) => readdirSync(dir, { recursive: true, withFileTypes: true }).filter((e) => e.isFile()).map((e) => `${e.parentPath}/${e.name}:${createHash("sha256").update(readFileSync(join(e.parentPath, e.name))).digest("hex")}`).sort().join("\n");

test("inspector finds a canary in a table column, through SQL and in the bytes", () => {
  const dir = tmp();
  const db = new DatabaseSync(join(dir, "t1.sqlite"));
  db.exec(`create table notes (id integer primary key, text text); insert into notes (text) values ('${CANARY}')`);
  db.close();
  const scan = scanStorage(dir, [CANARY]);
  assert.ok(scan.hits.some((h) => h.layer === "column" && h.where === "notes.text"), JSON.stringify(scan.hits));
  assert.ok(scan.hits.some((h) => h.layer === "raw"));
  assert.equal(scan.sqliteOpened, 1);
  assert.deepEqual(scan.incomplete, []);
});

test("inspector finds a canary in a BLOB column", () => {
  const dir = tmp();
  const db = new DatabaseSync(join(dir, "t.sqlite"));
  db.exec("create table b (v blob)");
  db.prepare("insert into b values (?)").run(Buffer.from(`xx${CANARY}yy`));
  db.close();
  assert.ok(scanStorage(dir, [CANARY]).hits.some((h) => h.layer === "column" && h.where === "b.v"));
});

test("inspector finds a canary only the raw layer can see: a deleted row's bytes and a non-SQLite side file", () => {
  const dir = tmp();
  const db = new DatabaseSync(join(dir, "t2.sqlite"));
  db.exec(`pragma journal_mode = wal; create table s (v text); insert into s values ('${CANARY}'); delete from s`);
  writeFileSync(join(dir, "side.bin"), Buffer.from(`junk${CANARY}junk`));
  const scan = scanStorage(dir, [CANARY]); // db still open: the plaintext lives in the WAL
  db.close();
  assert.equal(scan.hits.filter((h) => h.layer === "column").length, 0, "no cell holds it, so SQL alone would call this clean");
  const files = new Set(scan.hits.filter((h) => h.layer === "raw").map((h) => h.file));
  assert.ok(files.has("side.bin"));
  assert.ok([...files].some((f) => f.includes("t2.sqlite")), `expected a hit in the database or WAL, got ${[...files]}`);
});

test("inspector reports a clean store as clean, and counts what it looked at", () => {
  const dir = tmp();
  mkdirSync(join(dir, "nested"));
  const db = new DatabaseSync(join(dir, "nested", "t3.sqlite"));
  db.exec("create table notes (text text); insert into notes values ('bk1:1:abc:def')");
  db.close();
  const scan = scanStorage(dir, [CANARY]);
  assert.deepEqual(scan.hits, []);
  assert.equal(scan.rowsScanned, 1);
  assert.equal(scan.filesScanned, 1);
});

test("inspector never writes: the handle is read-only and a scan leaves every byte of the directory as it was", () => {
  const dir = tmp();
  const path = join(dir, "t4.sqlite");
  const db = new DatabaseSync(path);
  db.exec("create table notes (text text); insert into notes values ('a')");
  db.close();
  const before = digest(dir);
  const ro = openReadOnly(path);
  assert.throws(() => ro.exec("insert into notes values ('b')"), /readonly/i);
  assert.throws(() => ro.exec("drop table notes"), /readonly/i);
  ro.close();
  scanStorage(dir, [CANARY]);
  assert.equal(digest(dir), before);
  assert.deepEqual(readdirSync(dir), ["t4.sqlite"]);
});

test("inspector refuses a path that is not a directory instead of reporting 'nothing found'", () => {
  const dir = tmp();
  writeFileSync(join(dir, "f"), "x");
  assert.throws(() => scanStorage(join(dir, "f"), [CANARY]), /not a directory/);
  assert.throws(() => scanStorage(join(dir, "missing"), [CANARY]), /ENOENT/);
});

test("inspector says so when a database cannot be read, rather than skipping it", () => {
  const dir = tmp();
  writeFileSync(join(dir, "broken.sqlite"), Buffer.concat([Buffer.from("SQLite format 3\0"), Buffer.alloc(200, 7)]));
  const scan = scanStorage(dir, [CANARY]);
  assert.ok(scan.incomplete.length > 0);
});

const storage = probes.find((p) => p.id === "storage-canary-at-rest")!;
const secrets = probes.find((p) => p.id === "secret-write-only-readback")!;

test("without a storage directory the CRYPTO-1 probe is UNVERIFIED, never a pass, and the run is not green", async () => {
  const fx = await startFixture([]);
  const dir = tmp();
  try {
    const [r] = await runProbes(fx.url, [storage], FIXTURE_BOOTSTRAP_TOKEN, { routes: fx.env.routes });
    assert.ok(r?.unverified, "must carry an unverified reason");
    assert.equal(r?.passed, false);
    assert.equal(r?.skipped, undefined);
    const report = await verifyTarget(fx.url, new EventLog(dir, "verify"), ["CRYPTO-1"], FIXTURE_BOOTSTRAP_TOKEN, {});
    assert.equal(report.valid, true);
    assert.equal(report.findings.length, 0);
    assert.equal(report.unverified.length, 1);
    const logged = readdirSync(dir, { recursive: true, withFileTypes: true }).filter((e) => e.isFile()).map((e) => readFileSync(join(e.parentPath, e.name), "utf8")).join("\n");
    const fin = JSON.parse(logged.split("\n").filter((l) => l.includes('"phase":"finished"')).pop()!) as { data: Record<string, unknown> };
    assert.equal(fin.data.passed, false);
    assert.equal(fin.data.unverifiedCount, 1);
  } finally {
    await fx.stop();
  }
});

test("an empty storage directory after a successful write is unverified, not a pass", async () => {
  const fx = await startFixture([]);
  try {
    const [r] = await runProbes(fx.url, [storage], FIXTURE_BOOTSTRAP_TOKEN, { persistDir: tmp() }); // wrong directory
    assert.match(r?.unverified ?? "", /no SQLite database/);
    assert.equal(r?.passed, false);
  } finally {
    await fx.stop();
  }
});

test("a missing manifest, or one without a secret store route, leaves CRYPTO-5 unverified", async () => {
  const fx = await startFixture([]);
  try {
    const [a] = await runProbes(fx.url, [secrets], FIXTURE_BOOTSTRAP_TOKEN, {});
    assert.match(a?.unverified ?? "", /no route manifest/);
    const [b] = await runProbes(fx.url, [secrets], FIXTURE_BOOTSTRAP_TOKEN, { routes: [{ method: "GET", path: "/notes" }] });
    assert.match(b?.unverified ?? "", /no POST \/secrets/);
  } finally {
    await fx.stop();
  }
});

test("CRYPTO-5 never passes if a read-back route errors: a 500 hides what it would return", async () => {
  const { createServer } = await import("node:http");
  const stub = createServer((req, res) => {
    req.resume();
    const ok = (status: number, extra: Record<string, string> = {}) => { res.writeHead(status, { "content-type": "application/json", ...extra }); res.end("{}"); };
    if (req.url === "/auth/bootstrap") return ok(201);
    if (req.url === "/auth/login") return ok(200, { "set-cookie": "__Host-bk_session=bks_x; Path=/; Secure; HttpOnly" });
    if (req.url === "/secrets" && req.method === "POST") return ok(201);
    if (req.url === "/boom") return ok(500);
    return ok(404);
  });
  await new Promise<void>((r) => stub.listen(0, "127.0.0.1", () => r()));
  const url = new URL(`http://127.0.0.1:${(stub.address() as { port: number }).port}`);
  try {
    const routes = [{ method: "POST", path: "/secrets" }, { method: "GET", path: "/clean" }];
    const [clean] = await runProbes(url, [secrets], FIXTURE_BOOTSTRAP_TOKEN, { routes });
    assert.equal(clean?.passed, true, "control: without a 5xx route the same stub passes");
    const [r] = await runProbes(url, [secrets], FIXTURE_BOOTSTRAP_TOKEN, { routes: [...routes, { method: "GET", path: "/boom" }] });
    assert.equal(r?.passed, false);
    assert.match(r?.unverified ?? "", /HTTP 500/);
  } finally {
    await new Promise<void>((r) => { stub.close(() => r()); stub.closeAllConnections(); });
  }
});

test("each new probe passes the fixed fixture and fails only on its own seeded bugs", async () => {
  const cases: [string, string[]][] = [
    ["notes-plaintext-at-rest", ["storage-canary-at-rest"]],
    ["secret-plaintext-at-rest", ["storage-canary-at-rest"]],
    ["plaintext-in-freed-page", ["storage-canary-at-rest"]],
    ["secret-readable-via-list", ["secret-write-only-readback"]],
    ["secret-readable-via-param-route", ["secret-write-only-readback"]],
    ["secret-echoed-on-store", ["secret-write-only-readback"]],
  ];
  for (const [bug, expected] of [["", []] as [string, string[]], ...cases]) {
    const fx = await startFixture(bug ? [bug] : []);
    try {
      const rs = await runProbes(fx.url, [storage, secrets], FIXTURE_BOOTSTRAP_TOKEN, fx.env);
      assert.deepEqual(rs.filter((r) => r.unverified !== undefined).map((r) => r.unverified), [], `${bug}: nothing may be unverified in the self-check`);
      assert.deepEqual(rs.filter((r) => !r.passed).map((r) => r.probe.id).sort(), expected, bug || "fixed fixture");
    } finally {
      await fx.stop();
    }
  }
});

test("the freed-page leak is invisible to the column scan and visible to the raw scan", async () => {
  const fx = await startFixture(["plaintext-in-freed-page"]);
  try {
    const [r] = await runProbes(fx.url, [storage], FIXTURE_BOOTSTRAP_TOKEN, fx.env);
    assert.equal(r?.passed, false);
    assert.match(r?.evidence ?? "", /raw /);
    assert.doesNotMatch(r?.evidence ?? "", /column /);
  } finally {
    await fx.stop();
  }
});

test("CLI: an unverified selected rule exits 3 with UNVERIFIED on stdout; a bad --persist-dir is refused", async () => {
  const fx = await startFixture([]);
  const cli = new URL("../src/cli.ts", import.meta.url).pathname;
  const run = (args: string[]) => new Promise<{ status: number | null; stdout: string; stderr: string }>((resolve) => {
    const c = spawn(process.execPath, ["--no-warnings", cli, "run", "--target", fx.url.origin, "--log-dir", tmp(), ...args], { env: { ...process.env, BULKHEAD_VERIFY_BOOTSTRAP_TOKEN: FIXTURE_BOOTSTRAP_TOKEN } });
    let stdout = "", stderr = "";
    c.stdout.on("data", (d: Buffer) => (stdout += d));
    c.stderr.on("data", (d: Buffer) => (stderr += d));
    c.on("close", (status) => resolve({ status, stdout, stderr }));
  });
  try {
    const noDir = await run(["--rules", "CRYPTO-1"]);
    assert.equal(noDir.status, 3, noDir.stdout + noDir.stderr);
    assert.match(noDir.stdout, /^UNVERIFIED CRYPTO-1 storage-canary-at-rest:/m);
    assert.doesNotMatch(noDir.stdout, /^pass /m);
    const mixed = await run(["--rules", "CRYPTO-1,TENANT-1"]);
    assert.equal(mixed.status, 3, "a passing TENANT-1 must not hide the unverified CRYPTO-1");
    assert.match(mixed.stdout, /^pass TENANT-1/m);
    const bad = await run(["--rules", "CRYPTO-1", "--persist-dir", join(fx.env.persistDir!, "nope")]);
    assert.equal(bad.status, 2, bad.stdout + bad.stderr);
    const ok = await run(["--rules", "CRYPTO-1,CRYPTO-5", "--persist-dir", fx.env.persistDir!, "--route-manifest", new URL("../fixture/route-manifest.json", import.meta.url).pathname]);
    assert.equal(ok.status, 0, ok.stdout + ok.stderr);
    assert.match(ok.stdout, /^pass CRYPTO-1 storage-canary-at-rest/m);
    assert.match(ok.stdout, /^pass CRYPTO-5 secret-write-only-readback/m);
  } finally {
    await fx.stop();
  }
});

test("VERIFY-1: nothing under verify imports core, auth, the demo or any workspace package other than spec", () => {
  const root = new URL("../", import.meta.url).pathname;
  const bad: string[] = [];
  for (const dir of ["src", "test", "fixture"])
    for (const f of readdirSync(join(root, dir)).filter((x) => x.endsWith(".ts"))) {
      const text = readFileSync(join(root, dir, f), "utf8");
      for (const m of text.matchAll(/(?:from|import)\s*\(?\s*["']([^"']+)["']/g)) {
        const spec = m[1]!;
        if (spec.startsWith("@kalahroudi/") && spec !== "@kalahroudi/bulkhead-spec") bad.push(`${dir}/${f}: ${spec}`);
        if (/(^|\/)(packages\/(core|auth)|examples)(\/|$)/.test(spec) || (spec.startsWith("../") && /\.\.\/(\.\.\/)+(packages|examples)/.test(spec))) bad.push(`${dir}/${f}: ${spec}`);
      }
    }
  assert.deepEqual(bad, []);
  assert.ok(existsSync(join(root, "src/inspector.ts")));
});

test("the self-check counts an unverified probe as a mismatch, never as nothing", () => {
  const mk = (extra: object) => ({ probe: storage, passed: false, evidence: "", reproduction: "", ...extra });
  assert.deepEqual(selfCheckFailureIds([mk({ unverified: "no dir" })]), ["UNVERIFIED:storage-canary-at-rest"]);
  assert.deepEqual(selfCheckFailureIds([mk({ skipped: "n/a" })]), []);
  assert.deepEqual(selfCheckFailureIds([mk({})]), ["storage-canary-at-rest"]);
  assert.deepEqual(selfCheckFailureIds([mk({ passed: true })]), []);
});
