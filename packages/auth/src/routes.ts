import type { createApp, RouteContext, Role } from "@kalahroudi/bulkhead-core/api";
import {
  clearedSessionCookie, createSession, newApiKey, revokeKeysOf, revokeSessionToken, revokeSessionsOf, ROLE_VALUES,
  SESSION_TTL_MS, sessionCookie, sessionTokenOf, type Clock,
} from "./authenticate.ts";
import { hashPassword, safeEqual, sha256, verifyPassword } from "./secrets.ts";

type App = ReturnType<typeof createApp>;

export interface AuthRoutesOptions {
  /**
   * The shared secret that lets the first owner claim an empty tenant. Return undefined to disable bootstrap
   * (fail closed). Phase 6 provisioning will create owners directly; until then this is the only way in.
   */
  bootstrapToken: () => string | undefined;
  clock?: Clock;
}

const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MS = 15 * 60_000;
const MIN_PASSWORD = 12;
const rank = (r: Role) => ROLE_VALUES.indexOf(r);
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}$/;

const normalizeEmail = (v: unknown) => (typeof v === "string" && EMAIL.test(v.trim()) && v.length <= 320 ? v.trim().toLowerCase() : null);
const validPassword = (v: unknown): v is string => typeof v === "string" && v.length >= MIN_PASSWORD && v.length <= 256;
const isRole = (v: unknown): v is Role => ROLE_VALUES.includes(v as Role);

async function body(c: RouteContext): Promise<Record<string, unknown> | null> {
  const v = await c.req.json().catch(() => null);
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

// `changes` is the Durable Object's rowsWritten, which counts index writes: one inserted user reads as 3, not 1.
// So an insert's outcome is confirmed by reading the row back, and updates only ever test `changes > 0`.
const exists = async (c: RouteContext, userId: string) => (await c.db.query("select 1 from users where id = ?", userId)).length === 1;

/** Registers the auth routes. Every one declares a policy like any other route, so they appear in the manifest (ROUTE-2). */
export function registerAuthRoutes(app: App, options: AuthRoutesOptions) {
  const clock = options.clock ?? { now: Date.now };
  const withSession = (c: RouteContext, token: string, status: number, payload: unknown) => {
    const res = c.json(payload, status);
    res.headers.append("set-cookie", sessionCookie(token, SESSION_TTL_MS / 1000));
    res.headers.set("cache-control", "no-store");
    return res;
  };

  app.route("POST", "/auth/bootstrap", { public: { reason: "first-owner claim of an empty tenant; requires the bootstrap secret and succeeds only while the tenant has no users" } }, async (c) => {
    const b = await body(c);
    const secret = options.bootstrapToken();
    if (!secret || typeof b?.token !== "string" || !safeEqual(b.token, secret)) return c.json({ error: "forbidden" }, 403);
    const email = normalizeEmail(b.email);
    if (!email || !validPassword(b.password)) return c.json({ error: `email and a password of at least ${MIN_PASSWORD} characters are required` }, 400);
    const id = crypto.randomUUID();
    // One statement: the emptiness check and the insert cannot interleave with a second claim.
    await c.db.run(
      "insert into users (id, email, password_hash, role, created_at) select ?, ?, ?, 'owner', ? where not exists (select 1 from users)",
      id, email, await hashPassword(b.password), clock.now(),
    );
    if (!(await exists(c, id))) return c.json({ error: "tenant already has users" }, 409);
    return c.json({ id, email, role: "owner" }, 201);
  });

  app.route("POST", "/auth/login", { public: { reason: "exchanges credentials for a session; throttled per email" } }, async (c) => {
    const b = await body(c);
    const email = normalizeEmail(b?.email);
    const bad = () => c.json({ error: "invalid credentials" }, 401); // one answer for unknown email, wrong password and disabled user
    if (!email || typeof b?.password !== "string" || b.password.length > 256) return bad();
    const now = clock.now();
    await c.db.run("delete from login_attempts where at < ?", now - LOCKOUT_MS);
    const [{ n } = { n: 0 }] = await c.db.query<{ n: number }>("select count(*) as n from login_attempts where email = ? and at >= ?", email, now - LOCKOUT_MS);
    if (n >= MAX_FAILED_LOGINS) return c.json({ error: "too many attempts" }, 429);

    const [user] = await c.db.query<{ id: string; password_hash: string; disabled: number }>("select id, password_hash, disabled from users where email = ?", email);
    const ok = await verifyPassword(b.password, user?.password_hash ?? null);
    if (!user || !ok || user.disabled !== 0) {
      await c.db.run("insert into login_attempts (email, at) values (?, ?)", email, now);
      return bad();
    }
    await c.db.run("delete from login_attempts where email = ?", email);
    // Rotation (AUTH-2): a presented session is destroyed and a fresh token issued; the client never chooses the token.
    await revokeSessionToken(c.db, sessionTokenOf(c.req));
    await c.db.run("delete from sessions where user_id = ? and expires_at <= ?", user.id, now);
    return withSession(c, await createSession(c.db, user.id, now), 200, { ok: true });
  });

  app.route("POST", "/auth/logout", { role: "member" }, async (c) => {
    await revokeSessionToken(c.db, sessionTokenOf(c.req));
    const res = c.json({ ok: true });
    res.headers.append("set-cookie", clearedSessionCookie());
    return res;
  });

  app.route("GET", "/auth/me", { role: "member", permission: "self:read" }, (c) => c.json({ id: c.user!.id, role: c.user!.role }));

  app.route("GET", "/users", { role: "admin" }, async (c) =>
    c.json({ users: await c.db.query("select id, email, role, disabled, created_at from users order by created_at, id") }));

  app.route("POST", "/users", { role: "admin" }, async (c) => {
    const b = await body(c);
    const email = normalizeEmail(b?.email);
    if (!email || !validPassword(b?.password)) return c.json({ error: `email and a password of at least ${MIN_PASSWORD} characters are required` }, 400);
    if (!isRole(b?.role)) return c.json({ error: "role must be member, admin or owner" }, 400);
    if (rank(b.role) > rank(c.user!.role)) return c.json({ error: "cannot grant a role above your own" }, 403);
    const id = crypto.randomUUID();
    await c.db.run("insert or ignore into users (id, email, password_hash, role, created_at) values (?, ?, ?, ?, ?)", id, email, await hashPassword(b.password as string), b.role, clock.now());
    return (await exists(c, id)) ? c.json({ id, email, role: b.role }, 201) : c.json({ error: "email already in use" }, 409);
  });

  /** Shared by role change and disable: refuses to touch someone above you, or to leave the tenant without an owner. */
  async function guardTarget(c: RouteContext, id: string, leavesOwner: boolean) {
    const [target] = await c.db.query<{ role: Role; disabled: number }>("select role, disabled from users where id = ?", id);
    if (!target) return c.json({ error: "not found" }, 404);
    if (rank(target.role) > rank(c.user!.role)) return c.json({ error: "cannot modify a user above your own role" }, 403);
    if (target.role === "owner" && target.disabled === 0 && leavesOwner) {
      const [{ n } = { n: 0 }] = await c.db.query<{ n: number }>("select count(*) as n from users where role = 'owner' and disabled = 0");
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
    await c.db.run("update users set role = ? where id = ?", b.role, id);
    // Stale authority must not survive a role change (AUTH-2): drop every session and key the user holds.
    await revokeSessionsOf(c.db, id);
    await revokeKeysOf(c.db, id, clock.now());
    return c.json({ id, role: b.role });
  });

  app.route("DELETE", "/users/:id", { role: "admin" }, async (c) => {
    const id = c.params.id as string;
    const refused = await guardTarget(c, id, true);
    if (refused) return refused;
    await c.db.run("update users set disabled = 1 where id = ?", id);
    await revokeSessionsOf(c.db, id);
    await revokeKeysOf(c.db, id, clock.now());
    return c.json({ id, disabled: true });
  });

  app.route("GET", "/api-keys", { role: "admin" }, async (c) =>
    // Metadata only. The secret is shown once at creation and cannot be read back.
    c.json({ keys: (await c.db.query<{ permissions: string }>("select id, name, role, permissions, created_by, created_at, expires_at, revoked_at from api_keys order by created_at, id")).map((k) => ({ ...k, permissions: JSON.parse(k.permissions) })) }));

  app.route("POST", "/api-keys", { role: "admin" }, async (c) => {
    const b = await body(c);
    const name = typeof b?.name === "string" && b.name.trim() && b.name.length <= 100 ? b.name.trim() : null;
    const role = b?.role === undefined ? "member" : b.role;
    const perms = b?.permissions;
    if (!name) return c.json({ error: "name is required" }, 400);
    if (!isRole(role)) return c.json({ error: "role must be member, admin or owner" }, 400);
    if (rank(role) > rank(c.user!.role)) return c.json({ error: "cannot mint a key above your own role" }, 403);
    // A key's permissions must name permissions that routes actually declare, so a typo cannot create a dead or misleading scope.
    const declared = new Set(app.manifest().flatMap((m) => (m.access.kind === "role" && m.access.permission ? [m.access.permission] : [])));
    if (!Array.isArray(perms) || perms.length === 0 || !perms.every((p) => typeof p === "string" && declared.has(p)))
      return c.json({ error: `permissions must be a non-empty list drawn from: ${[...declared].sort().join(", ")}` }, 400);
    const days = b?.expiresInDays;
    if (days !== undefined && (!Number.isInteger(days) || (days as number) < 1 || (days as number) > 365)) return c.json({ error: "expiresInDays must be 1..365" }, 400);
    const now = clock.now();
    const key = newApiKey();
    await c.db.run(
      "insert into api_keys (id, secret_hash, name, role, permissions, created_by, created_at, expires_at) values (?, ?, ?, ?, ?, ?, ?, ?)",
      key.id, await sha256(key.secret), name, role, JSON.stringify([...new Set(perms as string[])].sort()), c.user!.id, now, days === undefined ? null : now + (days as number) * 86_400_000,
    );
    const res = c.json({ id: key.id, key: key.token, permissions: [...new Set(perms as string[])].sort(), role }, 201);
    res.headers.set("cache-control", "no-store");
    return res;
  });

  app.route("DELETE", "/api-keys/:id", { role: "admin" }, async (c) => {
    const { changes } = await c.db.run("update api_keys set revoked_at = ? where id = ? and revoked_at is null", clock.now(), c.params.id as string);
    return changes > 0 ? c.json({ id: c.params.id, revoked: true }) : c.json({ error: "not found" }, 404);
  });
}
