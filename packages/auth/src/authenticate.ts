import type { Role, User } from "@kalahroudi/bulkhead-core/api";
import type { Tenant, TenantDb } from "@kalahroudi/bulkhead-core/tenant";
import { randomToken, safeEqual, sha256 } from "./secrets.ts";

export const SESSION_COOKIE = "__Host-bk_session"; // the __Host- prefix makes browsers enforce: Secure, Path=/, no Domain (host-only, AUTH-2)
export const SESSION_TTL_MS = 7 * 24 * 3600_000;
export const SESSION_IDLE_MS = 24 * 3600_000;
const TOUCH_AFTER_MS = 5 * 60_000;
const SESSION_PREFIX = "bks_";
const KEY_PREFIX = "bkk_";
export const ROLE_VALUES: readonly Role[] = ["member", "admin", "owner"];
const isRole = (v: unknown): v is Role => ROLE_VALUES.includes(v as Role);

export interface Clock {
  now(): number;
}

export const parseCookie = (header: string | null, name: string): string | null => {
  for (const part of (header ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
};

export function sessionCookie(token: string, maxAgeSeconds: number): string {
  return `${SESSION_COOKIE}=${token}; Max-Age=${maxAgeSeconds}; Path=/; Secure; HttpOnly; SameSite=Lax`;
}
export const clearedSessionCookie = () => sessionCookie("", 0);

export async function createSession(db: TenantDb, userId: string, now: number): Promise<string> {
  const token = SESSION_PREFIX + randomToken();
  await db.run("insert into sessions (token_hash, user_id, created_at, last_seen, expires_at) values (?, ?, ?, ?, ?)", await sha256(token), userId, now, now, now + SESSION_TTL_MS);
  return token;
}

export const revokeSessionsOf = (db: TenantDb, userId: string) => db.run("delete from sessions where user_id = ?", userId);
export const revokeKeysOf = (db: TenantDb, userId: string, now: number) => db.run("update api_keys set revoked_at = ? where created_by = ? and revoked_at is null", now, userId);

export async function revokeSessionToken(db: TenantDb, token: string | null) {
  if (token) await db.run("delete from sessions where token_hash = ?", await sha256(token));
}

export const sessionTokenOf = (req: Request) => parseCookie(req.headers.get("cookie"), SESSION_COOKIE);

/** Cookie-authenticated writes must come from this host. SameSite=Lax is the first line; this is the second (CSRF). */
function sameOrigin(req: Request): boolean {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return true;
  const origin = req.headers.get("origin");
  if (origin) {
    try {
      return new URL(origin).host === new URL(req.url).host;
    } catch {
      return false;
    }
  }
  const site = req.headers.get("sec-fetch-site");
  return site === null || site === "same-origin" || site === "none";
}

interface SessionRow { user_id: string; role: string; last_seen: number; token_hash: string }
interface KeyRow { secret_hash: string; role: string; permissions: string; created_by: string; user_role: string | null; user_disabled: number | null }

/**
 * The `authenticate` hook for core's gate. Role comes from the database on every request, so a role change or
 * disable takes effect immediately. Anything unrecognised returns null, which the gate turns into 401 (AUTH-1).
 */
export function createAuthenticator(clock: Clock = { now: Date.now }) {
  return async function authenticate(req: Request, _tenant: Tenant, db: TenantDb): Promise<User | null> {
    const authz = req.headers.get("authorization");
    if (authz !== null) return authenticateKey(authz, db, clock.now()); // a presented bearer credential is the only one considered

    const token = sessionTokenOf(req);
    if (!token || !token.startsWith(SESSION_PREFIX) || !sameOrigin(req)) return null;
    const now = clock.now();
    const hash = await sha256(token);
    const [row] = await db.query<SessionRow>(
      `select s.token_hash, s.user_id, s.last_seen, u.role from sessions s join users u on u.id = s.user_id
       where s.token_hash = ? and s.expires_at > ? and s.last_seen > ? and u.disabled = 0`,
      hash, now, now - SESSION_IDLE_MS,
    );
    if (!row || !isRole(row.role)) return null;
    if (now - row.last_seen > TOUCH_AFTER_MS) await db.run("update sessions set last_seen = ? where token_hash = ?", now, row.token_hash);
    return { id: row.user_id, role: row.role };
  };
}

async function authenticateKey(header: string, db: TenantDb, now: number): Promise<User | null> {
  const m = /^Bearer (bkk_([0-9a-f]{16})_([A-Za-z0-9_-]{43}))$/.exec(header);
  if (!m) return null;
  const [, , id, secret] = m;
  const [row] = await db.query<KeyRow>(
    `select k.secret_hash, k.role, k.permissions, k.created_by, u.role as user_role, u.disabled as user_disabled
       from api_keys k left join users u on u.id = k.created_by
      where k.id = ? and k.revoked_at is null and (k.expires_at is null or k.expires_at > ?)`,
    id, now,
  );
  // Compare against a hash even when the key is unknown so lookups take the same path.
  const ok = safeEqual(await sha256(secret as string), row?.secret_hash ?? "0".repeat(64));
  if (!row || !ok || row.user_disabled !== 0 || !isRole(row.role) || !isRole(row.user_role)) return null;
  // A key never outranks the user who minted it, even if that user was demoted after minting.
  const role = ROLE_VALUES.indexOf(row.role) <= ROLE_VALUES.indexOf(row.user_role) ? row.role : row.user_role;
  let permissions: unknown;
  try { permissions = JSON.parse(row.permissions); } catch { return null; }
  if (!Array.isArray(permissions) || !permissions.every((p) => typeof p === "string")) return null;
  return { id: `key:${id}`, role, permissions };
}

export function newApiKey(): { id: string; token: string; secret: string } {
  const id = [...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, "0")).join("");
  const secret = randomToken(32);
  return { id, secret, token: `${KEY_PREFIX}${id}_${secret}` };
}
