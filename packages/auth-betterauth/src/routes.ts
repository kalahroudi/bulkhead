// DR-0011 spike: the shipped auth HTTP contract (same paths, statuses and bodies, so the AUTH probes run unmodified),
// with Better Auth doing sign-up, sign-in, session lookup and sign-out. Every route is registered individually with a policy (ROUTE-1/2).
import type { createApp, RouteContext, Role } from "@kalahroudi/bulkhead-core/api";
import { verifyPassword } from "@kalahroudi/bulkhead-auth";
import { createInstance, SESSION_COOKIE, type RoleSlot } from "./instance.ts";
import { newKey, safeEqual, sha256 } from "./keys.ts";
import { originOf, ROLE_VALUES, type KitOptions } from "./authenticate.ts";

type App = ReturnType<typeof createApp>;

const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MS = 15 * 60_000;
const MIN_PASSWORD = 12;
const MIN_BOOTSTRAP_SECRET = 32;
const rank = (r: Role) => ROLE_VALUES.indexOf(r);
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}$/;
const normalizeEmail = (v: unknown) => (typeof v === "string" && EMAIL.test(v.trim()) && v.length <= 320 ? v.trim().toLowerCase() : null);
const validPassword = (v: unknown): v is string => typeof v === "string" && v.length >= MIN_PASSWORD && v.length <= 256;
const isRole = (v: unknown): v is Role => ROLE_VALUES.includes(v as Role);

async function body(c: RouteContext): Promise<Record<string, unknown> | null> {
  const v = await c.req.json().catch(() => null);
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

const cookieValue = (header: string | null) => {
  for (const part of (header ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === SESSION_COOKIE) return part.slice(i + 1).trim();
  }
  return null;
};
/** Better Auth's cookie value is `<token>.<signature>` (URL-encoded); the token is the part before the first dot. */
const tokenOf = (cookie: string | null) => {
  if (!cookie) return null;
  try { return decodeURIComponent(cookie).split(".")[0] || null; } catch { return null; } // a malformed escape is no session, not a 500
};

const exists = async (c: RouteContext, userId: string) => (await c.db.query('select 1 from "user" where id = ?', userId)).length === 1;
const revokeSessionsOf = (c: RouteContext, userId: string) => c.db.run('delete from "session" where "userId" = ?', userId);
const revokeKeysOf = (c: RouteContext, userId: string) => c.db.run("update api_keys set revoked_at = ? where created_by = ? and revoked_at is null", Date.now(), userId);

export function registerBetterAuthRoutes(app: App, options: KitOptions) {
  const instance = (c: RouteContext, slot: RoleSlot = { next: null }) => {
    const secret = options.secret();
    if (!secret) throw new Error("Better Auth secret is not configured");
    return createInstance({ db: c.db, secret, origin: originOf(c.req) }, slot);
  };

  type Created = { id: string } | { error: "exists" | "invalid" };
  /** Removes a user and what hangs off it. There is no transaction through TenantDb, so a failed sign-up must clean up after itself. */
  const discardUser = async (c: RouteContext, id: string) => {
    await c.db.run('delete from "session" where "userId" = ?', id);
    await c.db.run('delete from "account" where "userId" = ?', id);
    await c.db.run('delete from "user" where id = ?', id);
  };

  /**
   * Creates a user through Better Auth with an explicit role. "exists" means the email is taken; "invalid" that Better Auth rejected the input.
   * Anything else (a storage fault, a missing secret) is rethrown and becomes a 500: it is never reported as a conflict.
   */
  async function createUser(c: RouteContext, email: string, password: string, role: Role, pending = false): Promise<Created> {
    // Better Auth answers a duplicate email with a made-up user instead of an error, so the email is checked first and the row confirmed after.
    if ((await c.db.query('select 1 from "user" where email = ?', email)).length > 0) return { error: "exists" };
    try {
      const out = await instance(c, { next: role, disabled: pending ? 1 : 0 }).api.signUpEmail({ body: { email, password, name: email } });
      return (await exists(c, out.user.id)) ? { id: out.user.id } : { error: "exists" };
    } catch (e) {
      // The email was free a moment ago, so any partial user under it is ours.
      const [partial] = await c.db.query<{ id: string }>('select id from "user" where email = ?', email);
      if (partial) await discardUser(c, partial.id);
      if ((e as { status?: unknown; statusCode?: unknown }).statusCode === 400) return { error: "invalid" };
      throw e;
    }
  }

  app.route("POST", "/auth/bootstrap", { public: { reason: "first-owner claim of an empty tenant; requires the bootstrap secret and succeeds only while the tenant has no users" } }, async (c) => {
    const b = await body(c);
    const secret = options.bootstrapToken();
    if (!secret || secret.length < MIN_BOOTSTRAP_SECRET || typeof b?.token !== "string" || !safeEqual(b.token, secret)) return c.json({ error: "forbidden" }, 403);
    const email = normalizeEmail(b.email);
    if (!email || !validPassword(b.password)) return c.json({ error: `email and a password of at least ${MIN_PASSWORD} characters are required` }, 400);
    // Better Auth creates the user in several statements, so "only while empty" cannot be one statement as in the shipped code.
    // The user is created disabled (it cannot sign in); the claim is then a single guarded update that succeeds only while this is the only user,
    // and a loser is removed again before it was ever usable.
    if (((await c.db.query<{ n: number }>('select count(*) as n from "user"'))[0]?.n ?? 0) > 0) return c.json({ error: "tenant already has users" }, 409);
    const made = await createUser(c, email, b.password, "owner", true);
    if ("error" in made) return made.error === "invalid" ? c.json({ error: "email is not acceptable" }, 400) : c.json({ error: "tenant already has users" }, 409);
    const id = made.id;
    await c.db.run('update "user" set disabled = 0 where id = ? and (select count(*) from "user") = 1', id);
    if ((await c.db.query<{ disabled: number }>('select disabled from "user" where id = ?', id))[0]?.disabled !== 0) {
      await discardUser(c, id);
      return c.json({ error: "tenant already has users" }, 409);
    }
    return c.json({ id, email, role: "owner" }, 201);
  });

  app.route("POST", "/auth/login", { public: { reason: "exchanges credentials for a session; throttled per email" } }, async (c) => {
    const b = await body(c);
    const email = normalizeEmail(b?.email);
    const bad = () => c.json({ error: "invalid credentials" }, 401);
    if (!email || typeof b?.password !== "string" || b.password.length > 256) return bad();
    const now = Date.now();
    await c.db.run("delete from login_attempts where at < ?", now - LOCKOUT_MS);
    const [{ n } = { n: 0 }] = await c.db.query<{ n: number }>("select count(*) as n from login_attempts where email = ? and at >= ?", email, now - LOCKOUT_MS);
    if (n >= MAX_FAILED_LOGINS) return c.json({ error: "too many attempts" }, 429);

    const [user] = await c.db.query<{ id: string; disabled: number }>('select id, disabled from "user" where email = ?', email);
    if (!user || user.disabled !== 0) {
      await verifyPassword(b.password, null); // the same work as a real check, so timing does not separate the cases
      await c.db.run("insert into login_attempts (email, at) values (?, ?)", email, now);
      return bad();
    }
    // Rotation (AUTH-2): a presented session is destroyed; Better Auth issues the fresh token.
    const presented = tokenOf(cookieValue(c.req.headers.get("cookie")));
    const res = await instance(c).api.signInEmail({ body: { email, password: b.password }, headers: c.req.headers, asResponse: true }).catch(() => null);
    if (!res || res.status !== 200) {
      await c.db.run("insert into login_attempts (email, at) values (?, ?)", email, now);
      return bad();
    }
    if (presented) await c.db.run('delete from "session" where token = ?', presented);
    await c.db.run("delete from login_attempts where email = ?", email);
    await c.db.run('delete from "session" where "userId" = ? and "expiresAt" <= ?', user.id, new Date(now).toISOString()); // Better Auth stores dates as ISO text, which sorts chronologically
    const out = c.json({ ok: true }, 200);
    for (const sc of res.headers.getSetCookie()) out.headers.append("set-cookie", sc);
    out.headers.set("cache-control", "no-store");
    return out;
  });

  app.route("POST", "/auth/logout", { role: "member" }, async (c) => {
    const presented = tokenOf(cookieValue(c.req.headers.get("cookie")));
    const res = await instance(c).api.signOut({ headers: c.req.headers, asResponse: true });
    // Better Auth logs a failed session delete and still answers success, so revocation is confirmed here: a logout that did not revoke is a 500, never a 200.
    if (presented) {
      await c.db.run('delete from "session" where token = ?', presented);
      if (((await c.db.query<{ n: number }>('select count(*) as n from "session" where token = ?', presented))[0]?.n ?? 1) !== 0) throw new Error("session survived logout");
    }
    const out = c.json({ ok: true });
    for (const sc of res.headers.getSetCookie()) out.headers.append("set-cookie", sc);
    return out;
  });

  app.route("GET", "/auth/me", { role: "member", permission: "self:read" }, (c) => c.json({ id: c.user!.id, role: c.user!.role }));

  app.route("GET", "/users", { role: "admin" }, async (c) =>
    c.json({ users: await c.db.query('select id, email, role, disabled, "createdAt" as created_at from "user" order by "createdAt", id') }));

  app.route("POST", "/users", { role: "admin" }, async (c) => {
    const b = await body(c);
    const email = normalizeEmail(b?.email);
    if (!email || !validPassword(b?.password)) return c.json({ error: `email and a password of at least ${MIN_PASSWORD} characters are required` }, 400);
    if (!isRole(b?.role)) return c.json({ error: "role must be member, admin or owner" }, 400);
    if (rank(b.role) > rank(c.user!.role)) return c.json({ error: "cannot grant a role above your own" }, 403);
    const made = await createUser(c, email, b.password as string, b.role);
    if ("error" in made) return made.error === "invalid" ? c.json({ error: "email is not acceptable" }, 400) : c.json({ error: "email already in use" }, 409);
    return c.json({ id: made.id, email, role: b.role }, 201);
  });

  async function guardTarget(c: RouteContext, id: string, leavesOwner: boolean) {
    const [target] = await c.db.query<{ role: Role; disabled: number }>('select role, disabled from "user" where id = ?', id);
    if (!target) return c.json({ error: "not found" }, 404);
    if (rank(target.role) > rank(c.user!.role)) return c.json({ error: "cannot modify a user above your own role" }, 403);
    if (target.role === "owner" && target.disabled === 0 && leavesOwner) {
      const [{ n } = { n: 0 }] = await c.db.query<{ n: number }>("select count(*) as n from \"user\" where role = 'owner' and disabled = 0");
      if (n <= 1) return c.json({ error: "cannot remove the last owner" }, 409);
    }
    return null;
  }

  app.route("PATCH", "/users/:id/role", { role: "admin" }, async (c) => {
    const id = c.params.id as string;
    const b = await body(c);
    if (!isRole(b?.role)) return c.json({ error: "role must be member, admin or owner" }, 400);
    if (rank(b.role) > rank(c.user!.role)) return c.json({ error: "cannot grant a role above your own" }, 403);
    const refused = await guardTarget(c, id, b.role !== "owner");
    if (refused) return refused;
    await c.db.run('update "user" set role = ?, "updatedAt" = ? where id = ?', b.role, new Date().toISOString(), id);
    await revokeSessionsOf(c, id);
    await revokeKeysOf(c, id);
    return c.json({ id, role: b.role });
  });

  app.route("DELETE", "/users/:id", { role: "admin" }, async (c) => {
    const id = c.params.id as string;
    const refused = await guardTarget(c, id, true);
    if (refused) return refused;
    await c.db.run('update "user" set disabled = 1, "updatedAt" = ? where id = ?', new Date().toISOString(), id);
    await revokeSessionsOf(c, id);
    await revokeKeysOf(c, id);
    return c.json({ id, disabled: true });
  });

  app.route("GET", "/api-keys", { role: "admin" }, async (c) =>
    c.json({ keys: (await c.db.query<{ permissions: string }>("select id, name, role, permissions, created_by, created_at, expires_at, revoked_at from api_keys order by created_at, id")).map((k) => ({ ...k, permissions: JSON.parse(k.permissions) })) }));

  app.route("POST", "/api-keys", { role: "admin" }, async (c) => {
    const b = await body(c);
    const name = typeof b?.name === "string" && b.name.trim() && b.name.length <= 100 ? b.name.trim() : null;
    const role = b?.role === undefined ? "member" : b.role;
    const perms = b?.permissions;
    if (!name) return c.json({ error: "name is required" }, 400);
    if (!isRole(role)) return c.json({ error: "role must be member, admin or owner" }, 400);
    if (rank(role) > rank(c.user!.role)) return c.json({ error: "cannot mint a key above your own role" }, 403);
    const declared = new Set(app.manifest().flatMap((m) => (m.access.kind === "role" && m.access.permission ? [m.access.permission] : [])));
    if (!Array.isArray(perms) || perms.length === 0 || !perms.every((p) => typeof p === "string" && declared.has(p)))
      return c.json({ error: `permissions must be a non-empty list drawn from: ${[...declared].sort().join(", ")}` }, 400);
    const days = b?.expiresInDays;
    if (days !== undefined && (!Number.isInteger(days) || (days as number) < 1 || (days as number) > 365)) return c.json({ error: "expiresInDays must be 1..365" }, 400);
    const now = Date.now();
    const key = newKey();
    await c.db.run(
      "insert into api_keys (id, secret_hash, name, role, permissions, created_by, created_at, expires_at) values (?, ?, ?, ?, ?, ?, ?, ?)",
      key.id, await sha256(key.secret), name, role, JSON.stringify([...new Set(perms as string[])].sort()), c.user!.id, now, days === undefined ? null : now + (days as number) * 86_400_000,
    );
    const res = c.json({ id: key.id, key: key.token, permissions: [...new Set(perms as string[])].sort(), role }, 201);
    res.headers.set("cache-control", "no-store");
    return res;
  });

  app.route("DELETE", "/api-keys/:id", { role: "admin" }, async (c) => {
    const { changes } = await c.db.run("update api_keys set revoked_at = ? where id = ? and revoked_at is null", Date.now(), c.params.id as string);
    return changes > 0 ? c.json({ id: c.params.id, revoked: true }) : c.json({ error: "not found" }, 404);
  });
}
