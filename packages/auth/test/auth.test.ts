import { test } from "node:test";
import assert from "node:assert/strict";
import { createApp } from "@kalahroudi/bulkhead-core/api";
import { createAuth, SESSION_COOKIE } from "../src/index.ts";
import { SESSION_IDLE_MS, SESSION_TTL_MS } from "../src/authenticate.ts";
import { hashPassword, verifyPassword } from "../src/secrets.ts";
import { makeEnv } from "./fakes.ts";

const TOKEN = "bootstrap-token-for-tests-0123456789";
const PW = "correct horse battery";

function setup() {
  const clock = { t: 1_700_000_000_000, now() { return this.t; } };
  const auth = createAuth({ bootstrapToken: () => TOKEN, clock });
  const app = createApp({ schema: auth.schema, authenticate: auth.authenticate });
  auth.registerRoutes(app);
  app.route("GET", "/m", { role: "member", permission: "m:read" }, (c) => c.json({ who: c.user!.id }));
  app.route("GET", "/a", { role: "admin", permission: "a:read" }, (c) => c.json({ ok: true }));
  app.route("GET", "/o", { role: "owner" }, (c) => c.json({ ok: true }));
  app.route("POST", "/w", { role: "member" }, (c) => c.json({ ok: true }));
  const env = makeEnv();
  const call = async (host: string, method: string, path: string, opts: { body?: unknown; cookie?: string; bearer?: string; headers?: Record<string, string> } = {}) => {
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    if (opts.cookie) {
      headers.cookie = `${SESSION_COOKIE}=${opts.cookie}`;
      // A browser always sends Origin or Sec-Fetch-Site on a write; default to a same-origin Origin unless the test sets one.
      if (!headers.origin && !headers["sec-fetch-site"]) headers.origin = `http://${host}.demo.localhost`;
    }
    if (opts.bearer) headers.authorization = `Bearer ${opts.bearer}`;
    const res = await app.fetch(new Request(`http://${host}.demo.localhost${path}`, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) }), env);
    const text = await res.text();
    const setCookie = res.headers.get("set-cookie");
    return { status: res.status, json: text ? JSON.parse(text) : null, text, setCookie, token: setCookie ? new RegExp(`${SESSION_COOKIE}=([^;]*)`).exec(setCookie)?.[1] ?? null : null };
  };
  const owner = async (host: string) => {
    assert.equal((await call(host, "POST", "/auth/bootstrap", { body: { token: TOKEN, email: "o@x.io", password: PW } })).status, 201);
    return (await call(host, "POST", "/auth/login", { body: { email: "o@x.io", password: PW } })).token!;
  };
  const mkUser = async (host: string, ownerTok: string, email: string, role: string) =>
    (await call(host, "POST", "/users", { cookie: ownerTok, body: { email, password: PW, role } })).json.id as string;
  return { app, env, call, clock, owner, mkUser };
}

test("AUTH-1: no credential, garbage credential and wrong-shape credential are all denied; nothing defaults to a role", async () => {
  const { call } = setup();
  for (const opts of [{}, { cookie: "bks_garbage" }, { cookie: "x" }, { bearer: "nope" }, { bearer: "bkk_0000000000000000_" + "A".repeat(43) }]) {
    const r = await call("t1", "GET", "/m", opts);
    assert.equal(r.status, 401, JSON.stringify(opts));
  }
});

test("bootstrap: needs the secret, works once, and is disabled when no secret is configured", async () => {
  const { call, app, env } = setup();
  assert.equal((await call("t1", "POST", "/auth/bootstrap", { body: { token: "wrong", email: "o@x.io", password: PW } })).status, 403);
  assert.equal((await call("t1", "POST", "/auth/bootstrap", { body: { token: TOKEN, email: "o@x.io", password: "short" } })).status, 400);
  assert.equal((await call("t1", "POST", "/auth/bootstrap", { body: { token: TOKEN, email: "o@x.io", password: PW } })).status, 201);
  assert.equal((await call("t1", "POST", "/auth/bootstrap", { body: { token: TOKEN, email: "evil@x.io", password: PW } })).status, 409);
  // tenant two is independent
  assert.equal((await call("t2", "POST", "/auth/bootstrap", { body: { token: TOKEN, email: "o@x.io", password: PW } })).status, 201);
  const off = createAuth({ bootstrapToken: () => undefined });
  const a2 = createApp({ schema: off.schema, authenticate: off.authenticate });
  off.registerRoutes(a2);
  const r = await a2.fetch(new Request("http://t9.demo.localhost/auth/bootstrap", { method: "POST", body: JSON.stringify({ token: "", email: "o@x.io", password: PW }) }), env);
  assert.equal(r.status, 403);
  // A secret shorter than the 32-character floor is treated as unset, even when it is presented correctly.
  const short = createAuth({ bootstrapToken: () => "short-secret" });
  const a3 = createApp({ schema: short.schema, authenticate: short.authenticate });
  short.registerRoutes(a3);
  const rs = await a3.fetch(new Request("http://t9.demo.localhost/auth/bootstrap", { method: "POST", body: JSON.stringify({ token: "short-secret", email: "o@x.io", password: PW }) }), env);
  assert.equal(rs.status, 403);
  void app;
});

test("AUTH-2: login sets a host-only, Secure, HttpOnly cookie and rotates; the client cannot choose the token", async () => {
  const { call, owner } = setup();
  const first = await owner("t1");
  const r = await call("t1", "POST", "/auth/login", { cookie: first, body: { email: "o@x.io", password: PW } });
  assert.equal(r.status, 200);
  assert.notEqual(r.token, first);
  assert.match(r.setCookie!, /^__Host-bk_session=bks_[A-Za-z0-9_-]{43}; /);
  for (const flag of ["Secure", "HttpOnly", "Path=/", "SameSite=Lax"]) assert.ok(r.setCookie!.includes(flag), flag);
  assert.ok(!/domain=/i.test(r.setCookie!));
  assert.equal((await call("t1", "GET", "/m", { cookie: first })).status, 401); // the presented session died
  assert.equal((await call("t1", "GET", "/m", { cookie: r.token! })).status, 200);
});

test("AUTH-2: logout, role change and disable revoke sessions and keys immediately", async () => {
  const { call, owner, mkUser } = setup();
  const o = await owner("t1");
  const uid = await mkUser("t1", o, "m@x.io", "member");
  const m = (await call("t1", "POST", "/auth/login", { body: { email: "m@x.io", password: PW } })).token!;
  assert.equal((await call("t1", "GET", "/m", { cookie: m })).status, 200);
  assert.equal((await call("t1", "POST", "/auth/logout", { cookie: m })).status, 200);
  assert.equal((await call("t1", "GET", "/m", { cookie: m })).status, 401);

  const m2 = (await call("t1", "POST", "/auth/login", { body: { email: "m@x.io", password: PW } })).token!;
  assert.equal((await call("t1", "PATCH", `/users/${uid}/role`, { cookie: o, body: { role: "admin" } })).status, 200);
  assert.equal((await call("t1", "GET", "/m", { cookie: m2 })).status, 401);

  const m3 = (await call("t1", "POST", "/auth/login", { body: { email: "m@x.io", password: PW } })).token!;
  assert.equal((await call("t1", "GET", "/a", { cookie: m3 })).status, 200); // new role applies from the next login
  assert.equal((await call("t1", "DELETE", `/users/${uid}`, { cookie: o })).status, 200);
  assert.equal((await call("t1", "GET", "/m", { cookie: m3 })).status, 401);
  assert.equal((await call("t1", "POST", "/auth/login", { body: { email: "m@x.io", password: PW } })).status, 401);
});

test("sessions expire (absolute and idle) and unsafe cross-origin writes with a cookie are refused", async () => {
  const { call, owner, clock, app, env } = setup();
  const o = await owner("t1");
  assert.equal((await call("t1", "POST", "/w", { cookie: o, headers: { origin: "http://evil.example" } })).status, 401);
  assert.equal((await call("t1", "POST", "/w", { cookie: o, headers: { origin: "http://t1.demo.localhost" } })).status, 200);
  assert.equal((await call("t1", "POST", "/w", { cookie: o, headers: { "sec-fetch-site": "cross-site" } })).status, 401);
  assert.equal((await call("t1", "POST", "/w", { cookie: o, headers: { "sec-fetch-site": "same-origin" } })).status, 200);
  // A cookie write with neither Origin nor Sec-Fetch-Site is refused (a non-browser client must present a key).
  const bare = await app.fetch(new Request("http://t1.demo.localhost/w", { method: "POST", headers: { cookie: `${SESSION_COOKIE}=${o}` } }), env);
  assert.equal(bare.status, 401);
  clock.t += SESSION_IDLE_MS + 1;
  assert.equal((await call("t1", "GET", "/m", { cookie: o })).status, 401);
  clock.t += SESSION_TTL_MS;
  const o2 = (await call("t1", "POST", "/auth/login", { body: { email: "o@x.io", password: PW } })).token!;
  for (let i = 0; i < 6; i++) { clock.t += SESSION_IDLE_MS / 2; assert.equal((await call("t1", "GET", "/m", { cookie: o2 })).status, 200, `activity keeps the session alive (step ${i})`); }
  clock.t += SESSION_TTL_MS;
  assert.equal((await call("t1", "GET", "/m", { cookie: o2 })).status, 401);
});

test("a session from one tenant is useless on another tenant's hostname", async () => {
  const { call, owner } = setup();
  const a = await owner("t1");
  await owner("t2");
  assert.equal((await call("t1", "GET", "/m", { cookie: a })).status, 200);
  assert.equal((await call("t2", "GET", "/m", { cookie: a })).status, 401);
});

test("login: one answer for unknown user and wrong password, and failures lock the email out", async () => {
  const { call, owner, clock } = setup();
  await owner("t1");
  const unknown = await call("t1", "POST", "/auth/login", { body: { email: "ghost@x.io", password: PW } });
  const wrong = await call("t1", "POST", "/auth/login", { body: { email: "o@x.io", password: "wrong wrong wrong" } });
  assert.deepEqual([unknown.status, unknown.text], [wrong.status, wrong.text]);
  for (let i = 0; i < 4; i++) await call("t1", "POST", "/auth/login", { body: { email: "o@x.io", password: "wrong wrong wrong" } });
  assert.equal((await call("t1", "POST", "/auth/login", { body: { email: "o@x.io", password: PW } })).status, 429); // even the right password
  clock.t += 16 * 60_000;
  assert.equal((await call("t1", "POST", "/auth/login", { body: { email: "o@x.io", password: PW } })).status, 200);
});

test("AUTH-3: roles reach exactly the routes policy allows", async () => {
  const { call, owner, mkUser } = setup();
  const o = await owner("t1");
  await mkUser("t1", o, "a@x.io", "admin");
  await mkUser("t1", o, "m@x.io", "member");
  const a = (await call("t1", "POST", "/auth/login", { body: { email: "a@x.io", password: PW } })).token!;
  const m = (await call("t1", "POST", "/auth/login", { body: { email: "m@x.io", password: PW } })).token!;
  const matrix = async (tok: string) => [(await call("t1", "GET", "/m", { cookie: tok })).status, (await call("t1", "GET", "/a", { cookie: tok })).status, (await call("t1", "GET", "/o", { cookie: tok })).status];
  assert.deepEqual(await matrix(m), [200, 403, 403]);
  assert.deepEqual(await matrix(a), [200, 200, 403]);
  assert.deepEqual(await matrix(o), [200, 200, 200]);
});

test("user management cannot escalate: no granting above your own role, no touching higher users, last owner is protected", async () => {
  const { call, owner, mkUser } = setup();
  const o = await owner("t1");
  const adminId = await mkUser("t1", o, "a@x.io", "admin");
  const a = (await call("t1", "POST", "/auth/login", { body: { email: "a@x.io", password: PW } })).token!;
  assert.equal((await call("t1", "POST", "/users", { cookie: a, body: { email: "x@x.io", password: PW, role: "owner" } })).status, 403);
  assert.equal((await call("t1", "PATCH", `/users/${adminId}/role`, { cookie: a, body: { role: "owner" } })).status, 403);
  const ownerId = ((await call("t1", "GET", "/users", { cookie: o })).json.users as { id: string; role: string }[]).find((u) => u.role === "owner")!.id;
  assert.equal((await call("t1", "DELETE", `/users/${ownerId}`, { cookie: a })).status, 403);
  assert.equal((await call("t1", "PATCH", `/users/${ownerId}/role`, { cookie: o, body: { role: "member" } })).status, 409);
  assert.equal((await call("t1", "DELETE", `/users/${ownerId}`, { cookie: o })).status, 409);
});

test("AUTH-4: keys are tenant-bound, permission-scoped, role-capped, revocable, expiring and never readable back", async () => {
  const { call, app, env, owner, mkUser, clock } = setup();
  const o = await owner("t1");
  await owner("t2");
  assert.equal((await call("t1", "POST", "/api-keys", { cookie: o, body: { name: "k", permissions: ["typo:read"] } })).status, 400);
  assert.equal((await call("t1", "POST", "/api-keys", { cookie: o, body: { name: "k", permissions: [] } })).status, 400);
  const made = await call("t1", "POST", "/api-keys", { cookie: o, body: { name: "ci", permissions: ["m:read"], role: "member", expiresInDays: 1 } });
  assert.equal(made.status, 201);
  const key = made.json.key as string;
  assert.equal((await call("t1", "GET", "/m", { bearer: key })).json.who, `key:${made.json.id}`);
  assert.equal((await call("t1", "GET", "/a", { bearer: key })).status, 403); // role
  assert.equal((await call("t1", "GET", "/o", { bearer: key })).status, 403);
  assert.equal((await call("t1", "POST", "/w", { bearer: key })).status, 403); // route declares no permission: unreachable by keys
  assert.equal((await call("t1", "GET", "/users", { bearer: key })).status, 403);
  assert.equal((await call("t2", "GET", "/m", { bearer: key })).status, 401); // other tenant
  assert.equal((await call("t1", "GET", "/m", { bearer: key, cookie: o })).status, 200); // bearer wins, cookie ignored
  assert.equal((await call("t1", "GET", "/m", { bearer: key.slice(0, -1) + (key.endsWith("A") ? "B" : "A") })).status, 401);

  const listed = await call("t1", "GET", "/api-keys", { cookie: o });
  assert.ok(!listed.text.includes(key) && !listed.text.includes(key.slice(21)));
  // At rest: only a hash.
  const stored = JSON.stringify([...env.BULKHEAD_TENANT.databases.values()].flatMap((d) => d.prepare("select * from api_keys").all()));
  assert.ok(!stored.includes(key.slice(21)));
  assert.match(stored, /"secret_hash":"[0-9a-f]{64}"/);

  const admin = await call("t1", "POST", "/api-keys", { cookie: o, body: { name: "adm", permissions: ["a:read"], role: "admin" } });
  assert.equal((await call("t1", "GET", "/a", { bearer: admin.json.key })).status, 200);
  assert.equal((await call("t1", "DELETE", `/api-keys/${admin.json.id}`, { cookie: o })).status, 200);
  assert.equal((await call("t1", "GET", "/a", { bearer: admin.json.key })).status, 401);

  const uid = await mkUser("t1", o, "a@x.io", "admin");
  const a = (await call("t1", "POST", "/auth/login", { body: { email: "a@x.io", password: PW } })).token!;
  assert.equal((await call("t1", "POST", "/api-keys", { cookie: a, body: { name: "up", permissions: ["m:read"], role: "owner" } })).status, 403);
  const k2 = (await call("t1", "POST", "/api-keys", { cookie: a, body: { name: "adm2", permissions: ["a:read"], role: "admin" } })).json.key as string;
  assert.equal((await call("t1", "GET", "/a", { bearer: k2 })).status, 200);
  await call("t1", "PATCH", `/users/${uid}/role`, { cookie: o, body: { role: "member" } }); // demotion revokes the keys they minted
  assert.equal((await call("t1", "GET", "/a", { bearer: k2 })).status, 401);

  clock.t += 2 * 86_400_000;
  assert.equal((await call("t1", "GET", "/m", { bearer: key })).status, 401); // expired
  void app;
});

test("passwords: salted PBKDF2, round-trips, rejects wrong and malformed hashes", async () => {
  const h1 = await hashPassword(PW);
  const h2 = await hashPassword(PW);
  assert.notEqual(h1, h2);
  assert.ok(!h1.includes(PW));
  assert.equal(await verifyPassword(PW, h1), true);
  assert.equal(await verifyPassword("other password!!", h1), false);
  assert.equal(await verifyPassword(PW, null), false);
  assert.equal(await verifyPassword(PW, "pbkdf2-sha256$999999999$AA$AA"), false);
  assert.equal(await verifyPassword(PW, "garbage"), false);
});

test("at rest: neither passwords nor session tokens are stored in plaintext", async () => {
  const { call, owner, env } = setup();
  const tok = await owner("t1");
  void call;
  const dump = JSON.stringify([...env.BULKHEAD_TENANT.databases.values()].flatMap((d) => [d.prepare("select * from users").all(), d.prepare("select * from sessions").all()]));
  assert.ok(!dump.includes(PW));
  assert.ok(!dump.includes(tok));
});

test("defence in depth: a disabled user's existing session and keys fail even if revocation was missed", async () => {
  const { call, owner, mkUser, env } = setup();
  const o = await owner("t1");
  await mkUser("t1", o, "m@x.io", "member");
  const m = (await call("t1", "POST", "/auth/login", { body: { email: "m@x.io", password: PW } })).token!;
  const key = (await call("t1", "POST", "/api-keys", { cookie: o, body: { name: "k", permissions: ["m:read"] } })).json.key as string;
  assert.equal((await call("t1", "GET", "/m", { cookie: m })).status, 200);
  assert.equal((await call("t1", "GET", "/m", { bearer: key })).status, 200);
  for (const d of env.BULKHEAD_TENANT.databases.values()) d.prepare("update users set disabled = 1").run();
  assert.equal((await call("t1", "GET", "/m", { cookie: m })).status, 401);
  assert.equal((await call("t1", "GET", "/m", { bearer: key })).status, 401);
});
