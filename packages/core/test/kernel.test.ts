import { test } from "node:test";
import assert from "node:assert/strict";
import { createApp, PolicyError, type RouteContext } from "../src/api/index.ts";
import { ConfigError, loadConfig, slugFromHostname, TenantStore } from "../src/tenant/index.ts";
import { DatabaseSync } from "node:sqlite";
import { makeEnv } from "./fakes.ts";

const call = (app: ReturnType<typeof createApp>, env: unknown, host: string, path = "/", init: RequestInit = {}) =>
  app.fetch(new Request(`http://${host}${path}`, init), env);

test("ROUTE-1: a route without a valid policy does not register", () => {
  const app = createApp();
  const h = () => new Response("x");
  for (const bad of [undefined, null, {}, { role: "root" }, { role: "member", public: { reason: "r" } }, { public: {} }, { public: { reason: " " } }, { public: { reason: "ok" }, feature: "f" }])
    assert.throws(() => app.route("GET", "/x", bad as never, h), PolicyError, JSON.stringify(bad));
  assert.deepEqual(app.manifest(), []);
});

test("ROUTE-2: manifest lists every registered route with its policy, and duplicates are refused", () => {
  const app = createApp();
  const h = () => new Response("x");
  app.route("POST", "/exports", { role: "admin", feature: "export" }, h);
  app.route("GET", "/health", { public: { reason: "liveness probe" } }, h);
  assert.deepEqual(app.manifest(), [
    { method: "POST", path: "/exports", access: { kind: "role", role: "admin", feature: "export" } },
    { method: "GET", path: "/health", access: { kind: "public", reason: "liveness probe" } },
  ]);
  assert.throws(() => app.route("GET", "/health", { public: { reason: "again" } }, h), PolicyError);
});

test("ROUTE-4/AUTH-1: gate runs before the handler; no user means no access", async () => {
  let ran = 0;
  const app = createApp();
  app.route("GET", "/secret", { role: "member" }, () => (ran++, new Response("secret")));
  const r = await call(app, makeEnv(), "a.demo.localhost", "/secret");
  assert.equal(r.status, 401);
  assert.equal(ran, 0);
});

test("role ordering and feature entitlements fail closed", async () => {
  let ran = 0;
  const app = createApp({ authenticate: async (req) => ({ id: "u", role: (req.headers.get("x-test-role") ?? "member") as "member" }), });
  app.route("GET", "/admin", { role: "admin" }, () => (ran++, new Response("ok")));
  app.route("GET", "/export", { role: "member", feature: "export" }, () => (ran++, new Response("ok")));
  const env = makeEnv();
  assert.equal((await call(app, env, "a.demo.localhost", "/admin", { headers: { "x-test-role": "member" } })).status, 403);
  assert.equal((await call(app, env, "a.demo.localhost", "/admin", { headers: { "x-test-role": "owner" } })).status, 200);
  assert.equal((await call(app, env, "a.demo.localhost", "/export")).status, 403); // no entitlement provider: denied
  assert.equal(ran, 1);
});

test("TENANT-1: tenant comes from the hostname only; headers, query and body are ignored", async () => {
  const app = createApp();
  app.route("POST", "/whoami", { public: { reason: "test" } }, (c) => c.json({ slug: c.tenant.slug }));
  const env = makeEnv();
  const r = await call(app, env, "b.demo.localhost", "/whoami?tenant=a", { method: "POST", headers: { "x-tenant": "a", "x-forwarded-host": "a.demo.localhost" }, body: JSON.stringify({ tenant: "a" }) });
  assert.deepEqual(await r.json(), { slug: "b" });
});

test("TENANT-2/3/5: each tenant has its own database and handlers only see their own rows", async () => {
  const env = makeEnv();
  const app = createApp({ schema: ["create table notes (id integer primary key, text text not null)"] });
  app.route("POST", "/notes", { public: { reason: "test" } }, async (c) => (await c.db.run("insert into notes (text) values (?)", String((await c.req.json() as { text: string }).text)), c.json({ ok: true }, 201)));
  app.route("GET", "/notes", { public: { reason: "test" } }, async (c) => c.json(await c.db.query("select text from notes")));
  await call(app, env, "a.demo.localhost", "/notes", { method: "POST", body: JSON.stringify({ text: "CANARY-A" }) });
  const b = await (await call(app, env, "b.demo.localhost", "/notes")).text();
  assert.ok(!b.includes("CANARY-A"));
  await call(app, env, "b.demo.localhost", "/notes", { method: "POST", body: JSON.stringify({ text: "B1" }) });
  assert.ok(!(await (await call(app, env, "a.demo.localhost", "/notes")).text()).includes("B1"));
  // Physically separate databases: each holds exactly its own row.
  const dbs = [...env.BULKHEAD_TENANT.databases.values()];
  assert.equal(dbs.length, 2);
  assert.deepEqual(dbs.map((d) => JSON.stringify(d.prepare("select text from notes").all())).sort(), ['[{"text":"B1"}]', '[{"text":"CANARY-A"}]']);
});

test("handlers get no raw bindings", async () => {
  let seen: RouteContext | undefined;
  const app = createApp();
  app.route("GET", "/x", { public: { reason: "test" } }, (c) => ((seen = c), new Response("ok")));
  await call(app, makeEnv(), "a.demo.localhost", "/x");
  assert.ok(seen);
  assert.ok(!("env" in seen));
  assert.ok(!JSON.stringify(Object.keys(seen)).includes("BULKHEAD"));
  assert.ok(Object.isFrozen(seen.db));
});

test("an unknown host and an unknown route are indistinguishable", async () => {
  const app = createApp();
  app.route("GET", "/x", { public: { reason: "test" } }, () => new Response("ok"));
  const env = makeEnv({ BULKHEAD_AUTO_PROVISION: "false" });
  const noHost = await call(app, env, "evil.example.com", "/x");
  const noTenant = await call(app, env, "ghost.demo.localhost", "/x");
  const noRoute = await call(app, makeEnv(), "a.demo.localhost", "/nope");
  for (const r of [noHost, noTenant, noRoute]) assert.equal(r.status, 404);
  const bodies = await Promise.all([noHost, noTenant, noRoute].map((r) => r.text()));
  assert.equal(new Set(bodies).size, 1);
});

test("BOOT-1: missing or contradictory config serves nothing", async () => {
  const ok = makeEnv();
  assert.doesNotThrow(() => loadConfig(ok));
  for (const bad of [{ BULKHEAD_ENV: undefined }, { BULKHEAD_ENV: "prod" }, { BULKHEAD_BASE_DOMAIN: "" }, { BULKHEAD_DB: undefined }, { BULKHEAD_TENANT: undefined }, { BULKHEAD_ENV: "production" }])
    assert.throws(() => loadConfig({ ...ok, ...bad }), ConfigError, JSON.stringify(Object.keys(bad)));
  let ran = 0;
  const app = createApp();
  app.route("GET", "/x", { public: { reason: "test" } }, () => (ran++, new Response("ok")));
  const r = await call(app, { ...ok, BULKHEAD_DB: undefined }, "a.demo.localhost", "/x");
  assert.equal(r.status, 500);
  assert.equal(ran, 0);
});

test("slugFromHostname accepts only single-label subdomains of the base domain", () => {
  assert.equal(slugFromHostname("a.demo.localhost", "demo.localhost"), "a");
  assert.equal(slugFromHostname("A.Demo.Localhost.", "demo.localhost"), "a");
  for (const h of ["demo.localhost", "a.b.demo.localhost", "evil.com", "a.demo.localhost.evil.com", "-a.demo.localhost", "a_b.demo.localhost"])
    assert.equal(slugFromHostname(h, "demo.localhost"), null, h);
});

test("tenant store refuses another tenant and reserved tables", () => {
  const db = new DatabaseSync(":memory:");
  const store = new TenantStore((sql, params) => {
    const s = db.prepare(sql);
    const p = params as never[];
    return /^\s*select/i.test(sql) ? { rows: s.all(...p) as never, changes: 0 } : { rows: [], changes: Number(s.run(...p).changes) };
  });
  store.run("t1", ["create table t (v text)"], "insert into t values ('x')", []);
  assert.throws(() => store.run("t2", [], "select * from t", []), /tenant mismatch/);
  assert.throws(() => store.run("t1", [], "select * from _bulkhead_meta", []), /reserved/);
  assert.equal(JSON.stringify(store.run("t1", [], "select v from t", []).rows), '[{"v":"x"}]');
});
