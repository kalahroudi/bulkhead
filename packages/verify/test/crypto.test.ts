import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { seededBugs } from "../src/bugs.ts";
import { sealedCells } from "../src/inspector.ts";
import { probes } from "../src/probes.ts";
import { overwriteCell } from "../src/tamper.ts";
import { expectedWithAll, FIXTURE_BOOTSTRAP_TOKEN, runProbes, selfCheckFailureIds, startFixture } from "../src/run.ts";

const byId = (...ids: string[]) => ids.map((id) => probes.find((p) => p.id === id)!);
const crypto = byId("aad-transplant-fails", "shredding-makes-data-unreadable", "nonce-uniqueness-and-rotation");
const tmp = () => mkdtempSync(join(tmpdir(), "bulkhead-crypto-"));
const digest = (dir: string) => readdirSync(dir, { recursive: true, withFileTypes: true }).filter((e) => e.isFile()).map((e) => `${e.name}:${createHash("sha256").update(readFileSync(join(e.parentPath, e.name))).digest("hex")}`).sort().join("\n");

test("CRYPTO-2/3/4 pass the fixed fixture, and each fails exactly on its own seeded bugs", async () => {
  const mine = seededBugs.filter((b) => b.probeIds.some((p) => crypto.some((c) => c.id === p) && !p.startsWith("UNVERIFIED:")) && b.probeIds.length === 1);
  assert.ok(mine.length >= 10, "every new probe has seeded bugs");
  for (const [bug, expected] of [["", []] as [string, string[]], ...mine.map((b) => [b.id, b.probeIds] as [string, string[]])]) {
    const fx = await startFixture(bug ? [bug] : []);
    try {
      const rs = await runProbes(fx.url, crypto, FIXTURE_BOOTSTRAP_TOKEN, fx.env);
      assert.deepEqual(selfCheckFailureIds(rs), [...expected].sort(), bug || "fixed fixture");
    } finally {
      await fx.stop();
    }
  }
});

test("CRYPTO-2/3/4 are UNVERIFIED without a storage directory, never a pass and never a finding", async () => {
  const fx = await startFixture([]);
  try {
    const rs = await runProbes(fx.url, crypto, FIXTURE_BOOTSTRAP_TOKEN, { routes: fx.env.routes });
    for (const r of rs) { assert.equal(r.passed, false, r.probe.id); assert.match(r.unverified ?? "", /persist/, r.probe.id); }
  } finally {
    await fx.stop();
  }
});

test("CRYPTO-2 needs the secret route; CRYPTO-3 and CRYPTO-4 need their lifecycle routes in the manifest, else UNVERIFIED", async () => {
  const fx = await startFixture([]);
  try {
    const routes = fx.env.routes!;
    const without = (path: string) => routes.filter((r) => r.path !== path);
    const cases: [string, string, string][] = [["aad-transplant-fails", "/secrets", "POST /secrets"], ["shredding-makes-data-unreadable", "/admin/shred", "shred"], ["nonce-uniqueness-and-rotation", "/admin/rotate-key", "rotate"]];
    for (const [id, path, word] of cases) {
      const [r] = await runProbes(fx.url, byId(id), FIXTURE_BOOTSTRAP_TOKEN, { persistDir: fx.env.persistDir, routes: without(path).filter((x) => !(path === "/secrets" && x.path.startsWith("/secrets"))) });
      assert.match(r?.unverified ?? "", new RegExp(word), id);
    }
    // No manifest at all: CRYPTO-2 cannot tell whether the secret route exists.
    const [noManifest] = await runProbes(fx.url, byId("aad-transplant-fails"), FIXTURE_BOOTSTRAP_TOKEN, { persistDir: fx.env.persistDir });
    assert.match(noManifest?.unverified ?? "", /manifest/);
  } finally {
    await fx.stop();
  }
});

test("a plaintext column leaves the envelope probes UNVERIFIED (the write produced no envelope), not failed and not passed", async () => {
  const fx = await startFixture(["notes-plaintext-at-rest"]);
  try {
    const rs = await runProbes(fx.url, byId("aad-transplant-fails", "nonce-uniqueness-and-rotation"), FIXTURE_BOOTSTRAP_TOKEN, fx.env);
    for (const r of rs) { assert.equal(r.passed, false); assert.ok(r.unverified !== undefined, `${r.probe.id}: ${r.evidence}`); }
  } finally {
    await fx.stop();
  }
});

test("sealedCells reads envelopes read-only, addresses them by rowid, and tolerates a WITHOUT ROWID table", () => {
  const dir = tmp();
  try {
    mkdirSync(join(dir, "sub"));
    const db = new DatabaseSync(join(dir, "sub", "t.sqlite"));
    db.exec("create table notes (id integer primary key, text text); create table plain (v text); create table norowid (k text primary key, v text) without rowid;");
    db.prepare("insert into notes (id, text) values (7, ?)").run("bk1:1:AAAAAAAAAAAAAAAB:abcd");
    db.prepare("insert into plain (v) values ('bk1x'), (NULL)").run();
    db.prepare("insert into norowid (k, v) values ('a', ?)").run("bk1:1:AAAAAAAAAAAAAAAC:efgh");
    db.close();
    const before = digest(dir);
    const { cells, incomplete } = sealedCells(dir);
    assert.deepEqual(incomplete, []);
    assert.deepEqual(cells.map((c) => [c.file, c.table, c.column, c.rowid, c.value]).sort(), [["sub/t.sqlite", "norowid", "v", -1, "bk1:1:AAAAAAAAAAAAAAAC:efgh"], ["sub/t.sqlite", "notes", "text", 7, "bk1:1:AAAAAAAAAAAAAAAB:abcd"]]);
    assert.equal(digest(dir), before, "reading changed bytes on disk");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("overwriteCell changes exactly the one named cell, and says so when it cannot", () => {
  const dir = tmp();
  try {
    const db = new DatabaseSync(join(dir, "t.sqlite"));
    db.exec("create table notes (id integer primary key, text text)");
    db.prepare("insert into notes (id, text) values (1, 'one'), (2, 'two')").run();
    db.close();
    assert.deepEqual(overwriteCell(dir, { file: "t.sqlite", table: "notes", column: "text", rowid: 2 }, "X"), { ok: true, detail: "written" });
    const check = new DatabaseSync(join(dir, "t.sqlite"), { readOnly: true });
    assert.deepEqual(check.prepare("select text from notes order by id").all().map((r) => r.text), ["one", "X"]);
    check.close();
    assert.equal(overwriteCell(dir, { file: "t.sqlite", table: "notes", column: "text", rowid: 99 }, "X").ok, false, "no such row");
    assert.equal(overwriteCell(dir, { file: "missing.sqlite", table: "notes", column: "text", rowid: 1 }, "X").ok, false, "no such file");
    assert.equal(overwriteCell(dir, { file: "t.sqlite", table: "nope", column: "text", rowid: 1 }, "X").ok, false, "no such table");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("self-check expectation: an UNVERIFIED outcome masks the failure it prevents, only in the all-bugs case", () => {
  assert.deepEqual(expectedWithAll(["a", "b", "UNVERIFIED:b", "c", "c"]), ["UNVERIFIED:b", "a", "c"].sort());
  assert.deepEqual(expectedWithAll(["x"]), ["x"]);
});

test("CRYPTO-2 is UNVERIFIED when a tamper write demonstrably does not reach the running app, never a vacuous pass", async () => {
  const fx = await startFixture(["reads-ignore-disk"]);
  try {
    const [r] = await runProbes(fx.url, byId("aad-transplant-fails"), FIXTURE_BOOTSTRAP_TOKEN, fx.env);
    assert.equal(r?.passed, false);
    assert.match(r?.unverified ?? "", /did not demonstrably reach the app/, r?.evidence);
  } finally {
    await fx.stop();
  }
});
