import assert from "node:assert/strict";
import { test } from "node:test";
import { DatabaseSync } from "node:sqlite";
import { createApp } from "../src/api/index.ts";
import { createKeyRing, enforceClassification, KeyDestroyedError, loadMasterKeys, parseClassification, sealedCheck, KeyUnavailableError } from "../src/crypto/index.ts";
import { TenantStore } from "../src/tenant/store.ts";
import { fakeD1, makeEnv } from "./fakes.ts";

const key = (n: number) => Buffer.alloc(32, n).toString("base64");
const KEYS = { BULKHEAD_MASTER_KEY_CURRENT: "1", BULKHEAD_MASTER_KEY_V1: key(1) };
const CLASSIFICATION = parseClassification({
  version: 1,
  fields: [
    { table: "notes", field: "id", class: "public" },
    { table: "notes", field: "text", class: "sensitive" },
    { table: "notes", field: "label", class: "internal" },
    { table: "vault", field: "name", class: "internal" },
    { table: "vault", field: "value", class: "secret", writeOnly: true },
  ],
});
const SCHEMA = [
  `create table notes (id integer primary key autoincrement, text text not null ${sealedCheck("text")}, label text)`,
  `create table vault (name text not null, value text not null ${sealedCheck("value")})`,
];

function build() {
  const env = makeEnv(KEYS);
  const app = createApp({ schema: SCHEMA, classification: CLASSIFICATION });
  const open = { public: { reason: "test" } } as const;
  const owner = { role: "owner" } as const;
  app.route("POST", "/seal", open, async (c) => {
    const b = (await c.req.json()) as { table: string; field: string; text: string };
    return c.json({ sealed: await c.db.seal(b.table, b.field, b.text) });
  });
  app.route("POST", "/open", open, async (c) => {
    const b = (await c.req.json()) as { table: string; field: string; sealed: string };
    return c.json({ text: await c.db.open(b.table, b.field, b.sealed) });
  });
  app.route("POST", "/raw", open, async (c) => {
    const b = (await c.req.json()) as { sql: string };
    return c.json(await c.db.run(b.sql));
  });
  app.route("POST", "/rotate", open, async (c) => c.json({ version: await c.keys.rotate() }));
  app.route("POST", "/shred", open, async (c) => (await c.keys.shred(), c.json({ ok: true })));
  void owner;
  const call = async (tenant: string, path: string, body: unknown) => {
    const r = await app.fetch(new Request(`http://${tenant}.demo.localhost${path}`, { method: "POST", body: JSON.stringify(body) }), env);
    return { status: r.status, json: (await r.json()) as Record<string, string | number> };
  };
  return { env, call };
}

test("BOOT-1: missing, malformed or wrong-sized master keys refuse to load", () => {
  assert.equal(loadMasterKeys(KEYS).current, 1);
  assert.throws(() => loadMasterKeys({}), /CURRENT/);
  assert.throws(() => loadMasterKeys({ BULKHEAD_MASTER_KEY_CURRENT: "2", BULKHEAD_MASTER_KEY_V1: key(1) }), /V2 is missing/);
  assert.throws(() => loadMasterKeys({ ...KEYS, BULKHEAD_MASTER_KEY_V1: Buffer.alloc(16).toString("base64") }), /32 bytes/);
  assert.throws(() => loadMasterKeys({ ...KEYS, BULKHEAD_MASTER_KEY_V3: "!!!" }), /not base64/);
});

test("BOOT-1: an app with classified data serves nothing when keys are missing (no plaintext fallback)", async () => {
  const app = createApp({ schema: SCHEMA, classification: CLASSIFICATION });
  app.route("POST", "/seal", { public: { reason: "test" } }, (c) => c.json({ ok: true }));
  const r = await app.fetch(new Request("http://a.demo.localhost/seal", { method: "POST" }), makeEnv());
  assert.equal(r.status, 500);
});

function store() {
  const db = new DatabaseSync(":memory:");
  const exec = (sql: string, params: unknown[]) => {
    const s = db.prepare(sql);
    return /^\s*select/i.test(sql) ? { rows: s.all(...(params as never[])) as never, changes: 0 } : { rows: [], changes: Number(s.run(...(params as never[])).changes) };
  };
  return { db, store: new TenantStore(exec) };
}

test("CRYPTO-1: an unclassified column, a missing CHECK or a stale classification stops the tenant initialising", () => {
  const unclassified = store();
  assert.throws(() => unclassified.store.run("t", [...SCHEMA, "create table extra (a text)"], "select 1", [], CLASSIFICATION), /unclassified column extra\.a/);
  const noCheck = store();
  assert.throws(() => noCheck.store.run("t", ["create table notes (id integer primary key, text text, label text)", SCHEMA[1] as string], "select 1", [], CLASSIFICATION), /no sealed-value CHECK/);
  const stale = store();
  assert.throws(() => stale.store.run("t", SCHEMA, "select 1", [], parseClassification({ version: 1, fields: [...CLASSIFICATION.fields, { table: "notes", field: "gone", class: "public" }] })), /does not exist/);
  // A refused tenant is refused again, not half-initialised.
  assert.throws(() => unclassified.store.run("t", [], "select 1", [], CLASSIFICATION));
});

test("CRYPTO-1: the database itself rejects plaintext, a look-alike prefix and wrong-case envelopes in sealed columns", () => {
  const s = store();
  s.store.run("t", SCHEMA, "select 1", [], CLASSIFICATION);
  for (const bad of ["hello", "bk1:hello", "BK1:1:AAAAAAAAAAAAAAAA:x", "bk1:1:short:x", "bk1:1:AAAAAAAAAAAAAAAA:x y"])
    assert.throws(() => s.store.run("t", SCHEMA, "insert into notes (text) values (?)", [bad], CLASSIFICATION), /CHECK/i, bad);
  s.store.run("t", SCHEMA, "insert into notes (text) values (?)", ["bk1:1:AAAAAAAAAAAAAAAA:abc_-"], CLASSIFICATION);
});

test("CRYPTO-4: nonce reservations are unique and counted per key version", async () => {
  const s = store();
  const seen = new Set<number>();
  await Promise.all(Array.from({ length: 500 }, async () => seen.add(s.store.nonce("t", SCHEMA, 1, CLASSIFICATION))));
  assert.equal(seen.size, 500);
  assert.equal(s.store.nonce("t", SCHEMA, 2, CLASSIFICATION), 1);
  assert.equal(s.store.nonce("t", SCHEMA, 1, CLASSIFICATION), 501);
  assert.throws(() => s.store.nonce("other", SCHEMA, 1, CLASSIFICATION), /tenant mismatch/);
  assert.throws(() => s.store.run("t", [], "select * from _bulkhead_meta", []), /reserved/);
});

test("CRYPTO-1/4: sealing never repeats a nonce or a ciphertext for the same plaintext, and the envelope hides the plaintext", async () => {
  const { call } = build();
  const a = (await call("a", "/seal", { table: "notes", field: "text", text: "canary-123" })).json.sealed as string;
  const b = (await call("a", "/seal", { table: "notes", field: "text", text: "canary-123" })).json.sealed as string;
  assert.notEqual(a, b);
  assert.notEqual(a.split(":")[2], b.split(":")[2]);
  assert.ok(!a.includes("canary-123") && a.startsWith("bk1:1:"));
});

test("CRYPTO-2: a sealed value opens in its own tenant, table and field, and nowhere else", async () => {
  const { call } = build();
  const sealed = (await call("a", "/seal", { table: "notes", field: "text", text: "secret-note" })).json.sealed as string;
  assert.equal((await call("a", "/open", { table: "notes", field: "text", sealed })).json.text, "secret-note");
  await call("b", "/seal", { table: "notes", field: "text", text: "x" }); // tenant b gets its own key
  assert.notEqual((await call("b", "/open", { table: "notes", field: "text", sealed })).status, 200);
  assert.notEqual((await call("a", "/open", { table: "vault", field: "name", sealed })).status, 200);
  // Same tenant, another sealed column.
  const other = await call("a", "/open", { table: "vault", field: "value", sealed });
  assert.notEqual(other.status, 200);
});

test("CRYPTO-5: a write-only field can be sealed but the handle never opens it; unsealed fields cannot be sealed", async () => {
  const { call } = build();
  const sealed = (await call("a", "/seal", { table: "vault", field: "value", text: "hunter2" })).json.sealed as string;
  assert.equal((await call("a", "/open", { table: "vault", field: "value", sealed })).status, 500);
  assert.equal((await call("a", "/seal", { table: "notes", field: "label", text: "x" })).status, 500);
  assert.equal((await call("a", "/seal", { table: "nope", field: "x", text: "x" })).status, 500);
});

test("CRYPTO-4: rotation adds a version, old values still open, new values use the new key", async () => {
  const { call } = build();
  const old = (await call("a", "/seal", { table: "notes", field: "text", text: "before" })).json.sealed as string;
  assert.equal((await call("a", "/rotate", {})).json.version, 2);
  const fresh = (await call("a", "/seal", { table: "notes", field: "text", text: "after" })).json.sealed as string;
  assert.ok(old.startsWith("bk1:1:") && fresh.startsWith("bk1:2:"));
  assert.equal((await call("a", "/open", { table: "notes", field: "text", sealed: old })).json.text, "before");
  assert.equal((await call("a", "/open", { table: "notes", field: "text", sealed: fresh })).json.text, "after");
});

test("CRYPTO-3: shredding makes the tenant's data unreadable, and a shredded tenant is never re-keyed", async () => {
  const { call, env } = build();
  const sealed = (await call("a", "/seal", { table: "notes", field: "text", text: "gone soon" })).json.sealed as string;
  assert.equal((await call("a", "/shred", {})).status, 200);
  assert.equal((await call("a", "/open", { table: "notes", field: "text", sealed })).status, 410);
  assert.equal((await call("a", "/seal", { table: "notes", field: "text", text: "again" })).status, 410);
  assert.equal((await call("a", "/rotate", {})).status, 410);
  const rows = (env.BULKHEAD_DB as ReturnType<typeof fakeD1>).raw.prepare("select version, wrapped from tenant_keys").all() as { wrapped: unknown }[];
  assert.ok(rows.length > 0 && rows.every((r) => r.wrapped === null));
});

test("CRYPTO-3: the data key cache lasts 60 seconds, so a shred in another isolate bites within a minute", async () => {
  const db = fakeD1();
  let t = 1_000;
  const master = loadMasterKeys(KEYS);
  const a = createKeyRing(db, master, () => t);
  const b = createKeyRing(db, master, () => t); // another isolate
  await a.ensureTenantKey("x");
  await b.current("x");
  await a.shred("x");
  await b.current("x"); // still cached
  t += 61_000;
  await assert.rejects(() => b.current("x"), KeyUnavailableError);
});

test("CRYPTO-3: a wrapped data key does not unwrap for another tenant or under another master key", async () => {
  const db = fakeD1();
  const ring = createKeyRing(db, loadMasterKeys(KEYS));
  await ring.ensureTenantKey("a");
  db.raw.prepare("insert into tenant_keys select 'b', version, master_version, wrapped, created_at, null from tenant_keys where tenant_id = 'a'").run();
  await assert.rejects(() => createKeyRing(db, loadMasterKeys(KEYS)).get("b", 1), KeyUnavailableError);
  const other = createKeyRing(db, loadMasterKeys({ BULKHEAD_MASTER_KEY_CURRENT: "1", BULKHEAD_MASTER_KEY_V1: key(9) }));
  await assert.rejects(() => other.get("a", 1), KeyUnavailableError);
});

test("enforceClassification can be called on its own", () => {
  const s = store();
  s.db.exec(SCHEMA.join(";"));
  enforceClassification((q, p) => { const st = s.db.prepare(q); return { rows: st.all(...(p as never[])) as never, changes: 0 }; }, CLASSIFICATION);
});

test("CRYPTO-2: the tenant is part of the AAD at the sealer level, even when two tenants share one key", async () => {
  const { createSealer } = await import("../src/crypto/index.ts");
  const db = fakeD1();
  const ring = createKeyRing(db, loadMasterKeys(KEYS));
  await ring.ensureTenantKey("a");
  const shared = { current: (_: string) => ring.current("a"), get: (_: string, v: number) => ring.get("a", v) } as unknown as Parameters<typeof createSealer>[1];
  let n = 0;
  const reserve = async () => ++n;
  const a = createSealer("a", shared, CLASSIFICATION, reserve);
  const b = createSealer("b", shared, CLASSIFICATION, reserve);
  const sealed = await a.seal("notes", "text", "for a only");
  assert.equal(await a.open("notes", "text", sealed), "for a only");
  await assert.rejects(() => b.open("notes", "text", sealed), /cannot open/);
});

test("CRYPTO-3: shredding a tenant that was never keyed still leaves marker rows, so it is never keyed afterwards", async () => {
  const db = fakeD1();
  const ring = createKeyRing(db, loadMasterKeys(KEYS));
  await ring.shred("fresh");
  await assert.rejects(() => ring.current("fresh"), KeyUnavailableError);
  await assert.rejects(() => createKeyRing(db, loadMasterKeys(KEYS)).current("fresh"), KeyUnavailableError); // another isolate
  const rows = db.raw.prepare("select wrapped from tenant_keys where tenant_id = 'fresh'").all() as { wrapped: unknown }[];
  assert.ok(rows.length > 0 && rows.every((r) => r.wrapped === null));
});

test("CRYPTO-1: with classified data a route can run only single data statements: no pragma, no DDL, no second statement", () => {
  const s = store();
  s.store.run("t", SCHEMA, "select 1", [], CLASSIFICATION);
  for (const bad of ["pragma ignore_check_constraints = 1", "create table leak (x text)", "alter table notes add column plain text", "drop table notes", "insert into notes (text) values ('bk1:1:AAAAAAAAAAAAAAAA:x'); create table leak2 (x text)", "attach database ':memory:' as x"])
    assert.throws(() => s.store.run("t", SCHEMA, bad, [], CLASSIFICATION), /only single data statements/, bad);
  assert.throws(() => s.store.run("t", SCHEMA, "insert into notes (text) values ('PLAIN')", [], CLASSIFICATION), /CHECK/i); // the CHECK is still live
  s.store.run("t", SCHEMA, "/* note */ select count(*) as n from notes; ", [], CLASSIFICATION);
});

test("CRYPTO-1: the sealed-value CHECK must be real SQL: a comment or a default value that spells it does not count", () => {
  const check = sealedCheck("text");
  const fake = [
    `create table notes (id integer primary key autoincrement, text text not null /* ${check} */, label text)`,
    `create table notes (id integer primary key autoincrement, text text not null, label text default '${check.replaceAll("'", "''")}')`,
    `create table notes (id integer primary key autoincrement, text text not null, label text) -- ${check}`,
  ];
  for (const ddl of fake) {
    const s = store();
    assert.throws(() => s.store.run("t", [ddl, SCHEMA[1] as string], "select 1", [], CLASSIFICATION), /no sealed-value CHECK/, ddl);
  }
});

test("CRYPTO-1: the CHECK refuses an empty ciphertext part", () => {
  const s = store();
  s.store.run("t", SCHEMA, "select 1", [], CLASSIFICATION);
  assert.throws(() => s.store.run("t", SCHEMA, "insert into notes (text) values (?)", ["bk1:1:AAAAAAAAAAAAAAAA:"], CLASSIFICATION), /CHECK/i);
});

test("CRYPTO-1: runtime-table exemptions are exact names, so an app table cannot hide behind a prefix", () => {
  for (const name of ["__miniflare_x", "_cf_x", "_bulkhead_x"]) {
    const s = store();
    assert.throws(() => s.store.run("t", [...SCHEMA, `create table ${name} (secret text)`], "select 1", [], CLASSIFICATION), /unclassified column/, name);
  }
});

test("CRYPTO-3: a rotation that races a shred cannot leave a live key behind", async () => {
  const db = fakeD1();
  const master = loadMasterKeys(KEYS);
  const ring = createKeyRing(db, master);
  await ring.ensureTenantKey("r");
  let armed = false;
  const racing = {
    ...db,
    prepare: (sql: string) => {
      const st = db.prepare(sql) as ReturnType<typeof db.prepare>;
      if (!/^select version, master_version, wrapped/.test(sql)) return st;
      return { ...st, bind: (...v: unknown[]) => { const b = st.bind(...v); return { ...b, all: async () => { const r = await b.all(); if (armed) db.raw.prepare("update tenant_keys set wrapped = null").run(); return r; } }; } } as never;
    },
  } as typeof db;
  const racer = createKeyRing(racing, master);
  armed = true;
  await racer.rotate("r").catch(() => undefined); // the shred lands between rotate's read and its insert
  armed = false;
  const live = db.raw.prepare("select count(*) as n from tenant_keys where wrapped is not null").get() as { n: number };
  assert.equal(live.n, 0);
  await assert.rejects(() => createKeyRing(db, master).current("r"), KeyDestroyedError);
});

test("only a destroyed tenant key answers 410; a forged key version or a missing master key is an ordinary 500", async () => {
  const { call } = build();
  await call("a", "/seal", { table: "notes", field: "text", text: "x" });
  const forged = await call("a", "/open", { table: "notes", field: "text", sealed: "bk1:99:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" });
  assert.equal(forged.status, 500);
  await call("a", "/shred", {});
  assert.equal((await call("a", "/seal", { table: "notes", field: "text", text: "x" })).status, 410);
});

test("CRYPTO-3: a live newer key version beside a destroyed one is still refused (the tenant is shredded, whatever rows exist)", async () => {
  const db = fakeD1();
  const master = loadMasterKeys(KEYS);
  const ring = createKeyRing(db, master);
  await ring.ensureTenantKey("s");
  await ring.rotate("s"); // v1 and v2, both live
  db.raw.prepare("update tenant_keys set wrapped = null where tenant_id = 's' and version = 1").run(); // v1 destroyed, v2 live
  await assert.rejects(() => createKeyRing(db, master).current("s"), KeyDestroyedError);
});
