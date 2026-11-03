import { test } from "node:test";
import assert from "node:assert/strict";
import { createApp } from "@kalahroudi/bulkhead-core/api";
import { createTenantDb } from "@kalahroudi/bulkhead-core/tenant";
import { fakeNamespace, makeEnv } from "../../auth/test/fakes.ts";
import { betterAuthSchema, keySchema } from "../src/schema.ts";
import { createInstance, SESSION_COOKIE } from "../src/instance.ts";
import { createBetterAuth } from "../src/index.ts";

const SECRET = "a-long-random-secret-for-tests-0123456789abcdef";
const TOKEN = "bootstrap-token-for-tests-0123456789";
const PW = "correct horse battery";
const ORIGIN = "https://t1.demo.localhost";

function dbFor(tenant: string, ns = fakeNamespace()) {
  return createTenantDb({ id: tenant, slug: tenant } as never, ns, [...betterAuthSchema, ...keySchema]);
}

test("the adapter reaches storage only through the TenantDb it was built with (TENANT-1): two tenants, one namespace, no shared rows", async () => {
  const ns = fakeNamespace();
  const a = dbFor("a", ns), b = dbFor("b", ns);
  await createInstance({ db: a, secret: SECRET, origin: ORIGIN }, { next: "owner" }).api.signUpEmail({ body: { email: "x@y.co", password: PW, name: "x" } });
  assert.equal((await a.query('select count(*) as n from "user"'))[0]!.n, 1);
  assert.equal((await b.query('select count(*) as n from "user"'))[0]!.n, 0);
  // The same email can be created in the other tenant: uniqueness is per tenant, because the tables are.
  await createInstance({ db: b, secret: SECRET, origin: ORIGIN }, { next: "member" }).api.signUpEmail({ body: { email: "x@y.co", password: PW, name: "x" } });
  assert.equal((await b.query('select count(*) as n from "user"'))[0]!.n, 1);
});

test("AUTH-1: a user cannot be created without an explicit role, and the schema refuses a bad one", async () => {
  const db = dbFor("t1");
  const slot: { next: "owner" | "admin" | "member" | null } = { next: null };
  const auth = createInstance({ db, secret: SECRET, origin: ORIGIN }, slot);
  await assert.rejects(auth.api.signUpEmail({ body: { email: "n@y.co", password: PW, name: "n" } }));
  assert.equal((await db.query('select count(*) as n from "user"'))[0]!.n, 0, "nothing was written");
  // The role slot is consumed by one creation: the next sign-up without a fresh role also fails.
  slot.next = "member";
  await auth.api.signUpEmail({ body: { email: "m@y.co", password: PW, name: "m" } });
  await assert.rejects(auth.api.signUpEmail({ body: { email: "m2@y.co", password: PW, name: "m2" } }));
  await assert.rejects(db.run(`insert into "user" (id, name, email, "createdAt", "updatedAt", role) values ('z','z','z@y.co',1,1,'root')`), /CHECK|constraint/i);
});

test("the adapter builds parameterised SQL and refuses identifiers that are not plain words", async () => {
  const db = dbFor("t1");
  const auth = createInstance({ db, secret: SECRET, origin: ORIGIN }, { next: "member" });
  await auth.api.signUpEmail({ body: { email: "ab@y.co", password: PW, name: "pct" } });
  const adapter = (await auth.$context).adapter;
  // A LIKE wildcard in the value is a literal character, not a wildcard.
  assert.equal((await adapter.findMany({ model: "user", where: [{ field: "email", operator: "contains", value: "%" }] })).length, 0);
  assert.equal((await adapter.findMany({ model: "user", where: [{ field: "email", operator: "contains", value: "_" }] })).length, 0);
  assert.equal((await adapter.findMany({ model: "user", where: [{ field: "email", operator: "starts_with", value: "a_" }] })).length, 0);
  assert.equal((await adapter.findMany({ model: "user", where: [{ field: "email", operator: "contains", value: "b@y" }] })).length, 1);
  // A hostile value is a bound parameter.
  assert.equal((await adapter.findMany({ model: "user", where: [{ field: "email", value: "x' or '1'='1" }] })).length, 0);
  // Empty IN matches nothing; empty NOT IN matches everything.
  assert.equal((await adapter.findMany({ model: "user", where: [{ field: "id", operator: "in", value: [] }] })).length, 0);
  assert.equal((await adapter.findMany({ model: "user", where: [{ field: "id", operator: "not_in", value: [] }] })).length, 1);
  // A field name that is not a plain word never reaches SQL.
  await assert.rejects(adapter.findMany({ model: "user", where: [{ field: 'email" or 1=1 --', value: "x" }] }));
});

test("the kit: session cookie is verified by Better Auth; a forged, unsigned or foreign-tenant cookie is not a session", async () => {
  const kit = createBetterAuth({ secret: () => SECRET, bootstrapToken: () => TOKEN });
  const app = createApp({ schema: kit.schema, authenticate: kit.authenticate });
  kit.registerRoutes(app);
  app.route("GET", "/m", { role: "member", permission: "m:read" }, (c) => c.json({ who: c.user!.id }));
  const env = makeEnv();
  const call = async (host: string, method: string, path: string, o: { body?: unknown; cookie?: string } = {}) => {
    const headers: Record<string, string> = {};
    if (o.cookie) { headers.cookie = `${SESSION_COOKIE}=${o.cookie}`; headers.origin = `https://${host}.demo.localhost`; }
    const res = await app.fetch(new Request(`https://${host}.demo.localhost${path}`, { method, headers, body: o.body === undefined ? undefined : JSON.stringify(o.body) }), env);
    const text = await res.text();
    return { status: res.status, setCookie: res.headers.getSetCookie(), json: text ? JSON.parse(text) : null };
  };
  assert.equal((await call("t1", "POST", "/auth/bootstrap", { body: { token: TOKEN, email: "o@x.io", password: PW } })).status, 201);
  const login = await call("t1", "POST", "/auth/login", { body: { email: "o@x.io", password: PW } });
  assert.equal(login.status, 200);
  const cookie = /__Host-bk_session=([^;]*)/.exec(login.setCookie.join("\n"))![1]!;
  assert.equal((await call("t1", "GET", "/m", { cookie })).status, 200);
  const [token] = decodeURIComponent(cookie).split(".");
  assert.equal((await call("t1", "GET", "/m", { cookie: token! })).status, 401, "the raw token without its signature is not a session");
  assert.equal((await call("t1", "GET", "/m", { cookie: encodeURIComponent(`${token}.${"A".repeat(44)}`) })).status, 401, "a wrong signature is not a session");
  assert.equal((await call("t2", "GET", "/m", { cookie })).status, 401, "another tenant does not know this session");
});

test("without the signing secret nothing authenticates and login does not mint a session (fails closed)", async () => {
  let secret: string | undefined = SECRET;
  const kit = createBetterAuth({ secret: () => secret, bootstrapToken: () => TOKEN });
  const app = createApp({ schema: kit.schema, authenticate: kit.authenticate });
  kit.registerRoutes(app);
  app.route("GET", "/m", { role: "member" }, (c) => c.json({ ok: true }));
  const env = makeEnv();
  const send = (path: string, init: RequestInit = {}) => app.fetch(new Request(`https://t1.demo.localhost${path}`, init), env);
  await send("/auth/bootstrap", { method: "POST", body: JSON.stringify({ token: TOKEN, email: "o@x.io", password: PW }) });
  const login = await send("/auth/login", { method: "POST", body: JSON.stringify({ email: "o@x.io", password: PW }) });
  const cookie = /__Host-bk_session=([^;]*)/.exec(login.headers.getSetCookie().join("\n"))![1]!;
  secret = undefined;
  assert.equal((await send("/m", { headers: { cookie: `${SESSION_COOKIE}=${cookie}` } })).status, 401);
  const again = await send("/auth/login", { method: "POST", body: JSON.stringify({ email: "o@x.io", password: PW }) });
  assert.notEqual(again.status, 200);
  assert.equal(again.headers.getSetCookie().length, 0);
});
