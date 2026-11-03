// DR-0011 spike: the `authenticate` hook, with Better Auth resolving the session cookie.
import type { Role, User } from "@kalahroudi/bulkhead-core/api";
import type { Tenant, TenantDb } from "@kalahroudi/bulkhead-core/tenant";
import { createInstance, SESSION_COOKIE, type RoleSlot } from "./instance.ts";
import { sha256, safeEqual, newKey } from "./keys.ts";

export const ROLE_VALUES: readonly Role[] = ["member", "admin", "owner"];
const isRole = (v: unknown): v is Role => ROLE_VALUES.includes(v as Role);

export const hasSessionCookie = (req: Request) => (req.headers.get("cookie") ?? "").split(";").some((p) => p.trim().startsWith(`${SESSION_COOKIE}=`));

/** Cookie-authenticated writes must come from this host; same rule as the shipped hook (a non-browser client should present a key). */
export function sameOrigin(req: Request): boolean {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return true;
  const origin = req.headers.get("origin");
  if (origin !== null) {
    try { return new URL(origin).host === new URL(req.url).host; } catch { return false; }
  }
  const site = req.headers.get("sec-fetch-site");
  return site === "same-origin" || site === "none";
}

export const originOf = (req: Request) => new URL(req.url).origin;
export const noRole = (): RoleSlot => ({ next: null });

export interface KitOptions { secret: () => string | undefined; bootstrapToken: () => string | undefined }

export function createAuthenticate(options: KitOptions) {
  return async function authenticate(req: Request, _tenant: Tenant, db: TenantDb): Promise<User | null> {
    const authz = req.headers.get("authorization");
    if (authz !== null) return authenticateKey(authz, db, Date.now());
    if (!hasSessionCookie(req) || !sameOrigin(req)) return null;
    const secret = options.secret();
    if (!secret) return null;
    const auth = createInstance({ db, secret, origin: originOf(req) }, noRole());
    // disableCookieCache: the session and the user are read from the database on every request, so a role change or disable lands at once (DR-0011 2d).
    const found = await auth.api.getSession({ headers: req.headers, query: { disableCookieCache: true } }).catch(() => null);
    if (!found) return null;
    const u = found.user as unknown as { id: string; role: unknown; disabled: unknown };
    if (u.disabled !== 0 || !isRole(u.role)) return null;
    return { id: u.id, role: u.role };
  };
}

interface KeyRow { secret_hash: string; role: string; permissions: string; created_by: string; user_role: string | null; user_disabled: number | null }

async function authenticateKey(header: string, db: TenantDb, now: number): Promise<User | null> {
  const m = /^Bearer (bkk_([0-9a-f]{16})_([A-Za-z0-9_-]{43}))$/.exec(header);
  if (!m) return null;
  const [, , id, secret] = m;
  const [row] = await db.query<KeyRow>(
    `select k.secret_hash, k.role, k.permissions, k.created_by, u.role as user_role, u.disabled as user_disabled
       from api_keys k left join "user" u on u.id = k.created_by
      where k.id = ? and k.revoked_at is null and (k.expires_at is null or k.expires_at > ?)`,
    id, now,
  );
  const ok = safeEqual(await sha256(secret as string), row?.secret_hash ?? "0".repeat(64));
  if (!row || !ok || row.user_disabled !== 0 || !isRole(row.role) || !isRole(row.user_role)) return null;
  const role = ROLE_VALUES.indexOf(row.role) <= ROLE_VALUES.indexOf(row.user_role) ? row.role : row.user_role;
  let permissions: unknown;
  try { permissions = JSON.parse(row.permissions); } catch { return null; }
  if (!Array.isArray(permissions) || !permissions.every((p) => typeof p === "string")) return null;
  return { id: `key:${id}`, role, permissions };
}

export { newKey };
