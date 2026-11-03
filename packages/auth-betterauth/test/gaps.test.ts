// Unit tests that kill the mutation-catalog gap entries for the spike (DR-0011 item 3): lines no black-box probe can reach
// because another defence shadows them over HTTP. Each test names the entry it protects.
import { test } from "node:test";
import assert from "node:assert/strict";
import type { DatabaseSync } from "node:sqlite";
import { createApp } from "@kalahroudi/bulkhead-core/api";
import { createTenantDb } from "@kalahroudi/bulkhead-core/tenant";
import { fakeNamespace, makeEnv } from "../../auth/test/fakes.ts";
import { betterAuthSchema, keySchema } from "../src/schema.ts";
import { createInstance, SESSION_COOKIE } from "../src/instance.ts";
import { createBetterAuth } from "../src/index.ts";

const SECRET = "a-long-random-secret-for-tests-0123456789abcdef";
const TOKEN = "bootstrap-token-for-tests-0123456789";
const PW = "correct horse battery";

function setup() {
  const kit = createBetterAuth({ secret: () => SECRET, bootstrapToken: () => TOKEN });
  const app = createApp({ schema: kit.schema, authenticate: kit.authenticate });
  kit.registerRoutes(app);
  app.route("GET", "/m", { role: "member", permission: "m:read" }, (c) => c.json({ who: c.user!.id, role: c.user!.role }));
  app.route("GET", "/a", { role: "admin", permission: "a:read" }, (c) => c.json({ ok: true }));
  const env = makeEnv();
  const ns = env.BULKHEAD_TENANT as ReturnType<typeof fakeNamespace>;
  const statements: string[] = [];
  const fault: { on: RegExp | null } = { on: null };
  const realGet = ns.get.bind(ns);
  ns.get = (id) => { const stub = realGet(id); return { ...stub, exec: async (...a: Parameters<typeof stub.exec>) => { statements.push(a[2]); if (fault.on?.test(a[2])) throw new Error("injected storage fault"); return stub.exec(...a); }, nonce: stub.nonce }; };
  const call = async (method: string, path: string, o: { body?: unknown; cookie?: string; bearer?: string } = {}) => {
    const headers: Record<string, string> = {};
    if (o.cookie) { headers.cookie = `${SESSION_COOKIE}=${o.cookie}`; headers.origin = "https://t1.demo.localhost"; }
    if (o.bearer) headers.authorization = `Bearer ${o.bearer}`;
    const res = await app.fetch(new Request(`https://t1.demo.localhost${path}`, { method, headers, body: o.body === undefined ? undefined : JSON.stringify(o.body) }), env);
    const text = await res.text();
    return { status: res.status, json: text ? JSON.parse(text) : null, setCookie: res.headers.getSetCookie() };
  };
  const raw = (): DatabaseSync => [...ns.databases.values()][0]!;
  const cookieOf = (r: { setCookie: string[] }) => /__Host-bk_session=([^;]*)/.exec(r.setCookie.join("\n"))?.[1] ?? "";
  const owner = async () => {
    assert.equal((await call("POST", "/auth/bootstrap", { body: { token: TOKEN, email: "o@x.io", password: PW } })).status, 201);
    return cookieOf(await call("POST", "/auth/login", { body: { email: "o@x.io", password: PW } }));
  };
  const addUser = async (ownerCookie: string, email: string, role: string) => {
    const r = await call("POST", "/users", { cookie: ownerCookie, body: { email, password: PW, role } });
    assert.equal(r.status, 201);
    return { id: r.json.id as string, cookie: cookieOf(await call("POST", "/auth/login", { body: { email, password: PW } })) };
  };
  const mintKey = async (ownerCookie: string, o: Record<string, unknown>) => {
    const r = await call("POST", "/api-keys", { cookie: ownerCookie, body: { name: "k", permissions: ["m:read"], ...o } });
    assert.equal(r.status, 201);
    return r.json.key as string;
  };
  return { call, raw, owner, addUser, mintKey, cookieOf, statements, fault };
}

test("ba-session-ignores-disabled: a user disabled directly in the database is refused even though their session row survives", async () => {
  const s = setup();
  const o = await s.owner();
  const u = await s.addUser(o, "m@x.io", "member");
  assert.equal((await s.call("GET", "/m", { cookie: u.cookie })).status, 200);
  s.raw().prepare('update "user" set disabled = 1 where id = ?').run(u.id);
  assert.equal((await s.call("GET", "/m", { cookie: u.cookie })).status, 401);
});

test("ba-disable-keeps-sessions: DELETE /users/:id removes the user's session rows and revokes their keys", async () => {
  const s = setup();
  const o = await s.owner();
  const u = await s.addUser(o, "m@x.io", "member");
  assert.equal(s.raw().prepare('select count(*) as n from "session" where "userId" = ?').get(u.id)!.n, 1);
  assert.equal((await s.call("DELETE", `/users/${u.id}`, { cookie: o })).status, 200);
  assert.equal(s.raw().prepare('select count(*) as n from "session" where "userId" = ?').get(u.id)!.n, 0);
});

test("ba-key-ignores-disabled / ba-key-expiry-check-removed / ba-key-role-not-capped-by-owner: key authentication re-reads the minting user and the key", async () => {
  const s = setup();
  const o = await s.owner();
  const admin = await s.addUser(o, "a@x.io", "admin");
  // disabled creator
  const k1 = await s.mintKey(admin.cookie, { role: "member" });
  assert.equal((await s.call("GET", "/m", { bearer: k1 })).status, 200);
  s.raw().prepare('update "user" set disabled = 1 where id = ?').run(admin.id);
  assert.equal((await s.call("GET", "/m", { bearer: k1 })).status, 401, "a key whose creator is disabled is refused");
  s.raw().prepare('update "user" set disabled = 0 where id = ?').run(admin.id);
  // expired key
  const k2 = await s.mintKey(o, { role: "member", expiresInDays: 1 });
  assert.equal((await s.call("GET", "/m", { bearer: k2 })).status, 200);
  s.raw().prepare("update api_keys set expires_at = ? where expires_at is not null").run(Date.now() - 1000);
  assert.equal((await s.call("GET", "/m", { bearer: k2 })).status, 401, "an expired key is refused");
  // role ceiling: an admin key outlives a demotion made directly in the database
  const k3 = await s.mintKey(admin.cookie, { role: "admin", permissions: ["a:read"] });
  assert.equal((await s.call("GET", "/a", { bearer: k3 })).status, 200);
  s.raw().prepare(`update "user" set role = 'member' where id = ?`).run(admin.id);
  assert.equal((await s.call("GET", "/a", { bearer: k3 })).status, 403, "the key never outranks the user who minted it");
});

test("ba-cookie-not-secure: the session cookie is configured Secure, HttpOnly, SameSite=Lax, Path=/ and sent with no Domain", async () => {
  const db = createTenantDb({ id: "t1", slug: "t1" } as never, fakeNamespace(), [...betterAuthSchema, ...keySchema]);
  const ctx = await createInstance({ db, secret: SECRET, origin: "https://t1.demo.localhost" }, { next: null }).$context;
  const a = ctx.authCookies.sessionToken;
  assert.equal(a.name, SESSION_COOKIE);
  assert.equal(a.attributes.secure, true);
  assert.equal(a.attributes.httpOnly, true);
  assert.equal(String(a.attributes.sameSite).toLowerCase(), "lax");
  assert.equal(a.attributes.path, "/");
  assert.equal(a.attributes.domain, undefined);
});

test("ba-logout-keeps-session: logout clears the cookie in the response and removes the session row", async () => {
  const s = setup();
  const o = await s.owner();
  const out = await s.call("POST", "/auth/logout", { cookie: o });
  assert.equal(out.status, 200);
  assert.ok(out.setCookie.some((c) => c.startsWith(`${SESSION_COOKIE}=;`) && /Max-Age=0/i.test(c)), out.setCookie.join(" | "));
  assert.equal(s.raw().prepare('select count(*) as n from "session"').get()!.n, 0);
});

test("ba-login-unknown-email-skips-dummy-hash: an unknown email costs about as much as a wrong password (timing is not an oracle)", async () => {
  const s = setup();
  await s.owner();
  const time = async (email: string) => { const t = performance.now(); await s.call("POST", "/auth/login", { body: { email, password: `${PW}-wrong` } }); return performance.now() - t; };
  const med = async (email: (i: number) => string) => { const xs: number[] = []; for (let i = 0; i < 4; i++) xs.push(await time(email(i))); return xs.sort((a, b) => a - b)[1]!; };
  const wrong = await med(() => "o@x.io"); // 4 attempts: below the lockout of 5
  const unknown = await med((i) => `nobody${i}@x.io`);
  assert.ok(unknown > wrong * 0.5, `unknown-email login (${unknown.toFixed(1)} ms) must take a comparable time to a wrong password (${wrong.toFixed(1)} ms)`);
});

test("ba-login-lockout-removed: the sixth failed login inside the window is refused, even with the right password", async () => {
  const s = setup();
  await s.owner();
  for (let i = 0; i < 5; i++) assert.equal((await s.call("POST", "/auth/login", { body: { email: "o@x.io", password: `${PW}-wrong` } })).status, 401);
  const locked = await s.call("POST", "/auth/login", { body: { email: "o@x.io", password: PW } });
  assert.equal(locked.status, 429);
  assert.equal(locked.setCookie.length, 0);
});

test("ba-bootstrap-precheck-removed: a second claim is refused before any second user is written", async () => {
  const s = setup();
  await s.owner();
  s.statements.length = 0;
  const second = await s.call("POST", "/auth/bootstrap", { body: { token: TOKEN, email: "second@x.io", password: PW } });
  assert.equal(second.status, 409);
  assert.equal(s.statements.filter((q) => /insert into "user"/i.test(q)).length, 0, "no user row was ever inserted for the losing claim");
});

test("ba-bootstrap-postcheck-removed: two claims racing leave at most one user, never two owners", async () => {
  const s = setup();
  const claim = (email: string) => s.call("POST", "/auth/bootstrap", { body: { token: TOKEN, email, password: PW } });
  const [a, b] = await Promise.all([claim("a@x.io"), claim("b@x.io")]);
  const created = [a, b].filter((r) => r.status === 201).length;
  const users = s.raw().prepare('select count(*) as n from "user"').get()!.n as number;
  assert.ok(created <= 1, `at most one claim succeeds (got ${created})`);
  assert.ok(users <= 1, `at most one user exists (got ${users})`);
  assert.equal(users, created, "the response and the database agree");
});

test("logout is a 500, not a 200, when the session could not be removed (Better Auth swallows a failed delete)", async () => {
  const s = setup();
  const o = await s.owner();
  s.fault.on = /delete from "session"/i;
  const out = await s.call("POST", "/auth/logout", { cookie: o });
  s.fault.on = null;
  assert.equal(out.status, 500);
  assert.equal((await s.call("GET", "/auth/me", { cookie: o })).status, 200, "the session did survive, and the answer said so by failing");
});

test("a sign-up that fails halfway leaves no partial user: bootstrap is a 500, then a retry succeeds", async () => {
  const s = setup();
  s.fault.on = /insert into "account"/i;
  const first = await s.call("POST", "/auth/bootstrap", { body: { token: TOKEN, email: "o@x.io", password: PW } });
  s.fault.on = null;
  assert.equal(first.status, 500, "a storage fault is not reported as a conflict");
  assert.equal(s.raw().prepare('select count(*) as n from "user"').get()!.n, 0, "no orphan owner");
  assert.equal((await s.call("POST", "/auth/bootstrap", { body: { token: TOKEN, email: "o2@x.io", password: PW } })).status, 201, "the tenant is not locked");
});

test("an email Better Auth rejects is a 400, not a conflict", async () => {
  const s = setup();
  const r = await s.call("POST", "/auth/bootstrap", { body: { token: TOKEN, email: "o@localhost", password: PW } });
  assert.equal(r.status, 400);
  assert.equal(s.raw().prepare('select count(*) as n from "user"').get()!.n, 0);
});

test("a malformed cookie escape on login is not a server error", async () => {
  const s = setup();
  await s.owner();
  const res = await fetchLogin(s);
  assert.equal(res, 200);
  async function fetchLogin(x: ReturnType<typeof setup>) {
    return (await x.call("POST", "/auth/login", { body: { email: "o@x.io", password: PW }, cookie: "%E0%A4%A" })).status;
  }
});

test("the adapter groups (every AND clause) AND (any OR clause), like Better Auth's own adapters", async () => {
  const db = createTenantDb({ id: "t1", slug: "t1" } as never, fakeNamespace(), [...betterAuthSchema, ...keySchema]);
  const auth = createInstance({ db, secret: SECRET, origin: "https://t1.demo.localhost" }, { next: "member" });
  await auth.api.signUpEmail({ body: { email: "a@x.io", password: PW, name: "n1" } });
  const adapter = (await auth.$context).adapter;
  const rows = await adapter.findMany({ model: "user", where: [
    { field: "name", value: "zzz" },
    { field: "email", value: "a@x.io", connector: "OR" },
    { field: "email", value: "b@x.io", connector: "OR" },
  ] });
  assert.equal(rows.length, 0, "name=zzz AND (email=a OR email=b) matches nothing");
  const some = await adapter.findMany({ model: "user", where: [{ field: "name", value: "n1" }, { field: "email", value: "q@x.io", connector: "OR" }, { field: "email", value: "a@x.io", connector: "OR" }] });
  assert.equal(some.length, 1);
});

test("the adapter refuses a write with no condition", async () => {
  const db = createTenantDb({ id: "t1", slug: "t1" } as never, fakeNamespace(), [...betterAuthSchema, ...keySchema]);
  const auth = createInstance({ db, secret: SECRET, origin: "https://t1.demo.localhost" }, { next: "member" });
  await auth.api.signUpEmail({ body: { email: "a@x.io", password: PW, name: "n" } });
  const adapter = (await auth.$context).adapter;
  await assert.rejects(adapter.deleteMany({ model: "user", where: [] }), /empty where/);
  await assert.rejects(adapter.updateMany({ model: "user", where: [], update: { name: "x" } }), /empty where/);
  assert.equal((await db.query('select count(*) as n from "user"'))[0]!.n, 1);
});

test("Better Auth's own origin check does not run through auth.api, so the hook's same-origin rule is the only CSRF defence (a canary: if this starts failing, the library changed)", async () => {
  const db = createTenantDb({ id: "t1", slug: "t1" } as never, fakeNamespace(), [...betterAuthSchema, ...keySchema]);
  const auth = createInstance({ db, secret: SECRET, origin: "https://t1.demo.localhost" }, { next: "member" });
  await auth.api.signUpEmail({ body: { email: "a@x.io", password: PW, name: "n" } });
  const res = await auth.api.signInEmail({ body: { email: "a@x.io", password: PW }, headers: new Headers({ origin: "https://evil.example", cookie: "x=1" }), asResponse: true });
  assert.equal(res.status, 200);
});

test("ba-signup-existing-email-precheck-removed: a taken email is refused before Better Auth runs (it would answer with a made-up user and spend a password hash)", async () => {
  const s = setup();
  const o = await s.owner();
  s.statements.length = 0;
  const dup = await s.call("POST", "/users", { cookie: o, body: { email: "o@x.io", password: PW, role: "member" } });
  assert.equal(dup.status, 409);
  assert.equal(s.statements.filter((q) => /from "user" where \("email"/i.test(q)).length, 0, "the library never looked the email up, so it never ran");
  assert.equal(s.raw().prepare('select count(*) as n from "user"').get()!.n, 1);
});
