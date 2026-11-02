// Deliberately vulnerable fixture app. Never deploy. Bugs are toggled by FIXTURE_BUGS (comma list, or "all"/"none").
import { createServer } from "node:http";
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

const ALL = [
  "missing-tenant-filter", "shared-cache-key", "skipped-signature-check", "tenant-from-header",
  "default-role", "session-fixation", "weak-cookie", "logout-keeps-session", "role-change-keeps-session", "admin-open-to-member", "api-key-cross-tenant", "api-key-unscoped",
  "session-cross-tenant", "csrf-ignored", "member-can-list-users", "escalation-allowed", "key-revocation-ignored", "disabled-user-can-login",
  "key-secret-unchecked", "bootstrap-token-unchecked", "bootstrap-second-owner", "role-patch-escalation", "admin-modifies-owner", "key-above-minter-role", "listing-leaks-hash", "tenant-from-forwarded-host", "unknown-email-login-errors", "key-secret-length-ignored", "admin-user-create-refused", "listing-leaks-digest", "listing-leaks-token",
  "notes-plaintext-at-rest", "secret-plaintext-at-rest", "plaintext-in-freed-page", "secret-readable-via-list", "secret-readable-via-param-route", "secret-echoed-on-store", "notes-plaintext-on-second", "secret-plaintext-on-second",
  "aad-ignores-table-field", "shared-data-key", "shred-noop", "shred-rekeys-on-write", "shred-keeps-summary-cache", "shred-destroys-all-tenants", "nonce-reused", "nonce-race", "rotation-ignored", "rotation-orphans-old",
];
const raw = process.env.FIXTURE_BUGS ?? "all";
const bugs = new Set(raw === "all" ? ALL : raw === "none" ? [] : raw.split(",").filter(Boolean));
const SECRET = process.env.FIXTURE_WEBHOOK_SECRET ?? "whsec_fixture";
const BOOTSTRAP = process.env.FIXTURE_BOOTSTRAP_TOKEN ?? "bootstrap_fixture_0123456789abcdef0123";

// --- auth (in-memory, per tenant). Mirrors the documented API surface only; shares no code with the real implementation. ---
type Role = "member" | "admin" | "owner";
const RANK: Record<Role, number> = { member: 0, admin: 1, owner: 2 };
const POLICY: Record<string, { role: Role; permission?: string }> = {
  "/private/member": { role: "member", permission: "private:read" },
  "/private/admin": { role: "admin", permission: "private:admin" },
  "/private/owner": { role: "owner" },
};
const users = new Map<string, { id: string; email: string; password: string; role: Role; disabled: boolean }>(); // key: tenant|email
const sessions = new Map<string, { tenant: string; userId: string; role: Role }>();
const keys = new Map<string, { tenant: string; secret: string; role: Role; permissions: string[]; createdBy: string; revoked: boolean }>();
const tenantUsers = (tenant: string) => [...users.values()].filter((u) => users.get(`${tenant}|${u.email}`) === u);
const COOKIE = "__Host-bk_session";
const token = (n: number) => randomBytes(n).toString("base64url");

// --- at-rest storage (only when FIXTURE_PERSIST_DIR is set): one SQLite file per tenant, WAL mode, classified columns sealed. ---
// The fixture's own implementation of the documented envelope `bk1:<keyVersion>:<16-char b64url nonce>:<b64url ct+tag>` (AES-256-GCM,
// AAD `bulkhead/v1|tenant|table|field|keyVersion`, nonce = 4 zero bytes + 64-bit big-endian per-(tenant,keyVersion) counter kept in the
// tenant's own database). It shares nothing with the real implementation. Data keys live in memory here, not in the tenant file.
const PERSIST = process.env.FIXTURE_PERSIST_DIR;
const dbs = new Map<string, DatabaseSync>();
class Gone extends Error {}
class CannotOpen extends Error {}
interface Ring { versions: Map<number, Buffer>; current: number; shredded: boolean }
const rings = new Map<string, Ring>();
const GLOBAL_KEYS = new Map<number, Buffer>(); // only used by the shared-data-key bug
const newRing = (): Ring => ({ versions: new Map([[1, randomBytes(32)]]), current: 1, shredded: false });
function ringOf(tenant: string): Ring {
  let r = rings.get(tenant);
  if (!r) rings.set(tenant, (r = newRing()));
  if (r.shredded) throw new Gone("tenant data is unavailable");
  return r;
}
function keyFor(tenant: string, ring: Ring, version: number): Buffer {
  if (bugs.has("shared-data-key")) {
    let k = GLOBAL_KEYS.get(version);
    if (!k) GLOBAL_KEYS.set(version, (k = randomBytes(32)));
    return k;
  }
  const k = ring.versions.get(version);
  if (!k) throw new CannotOpen("no such key version");
  return k;
}
const aad = (tenant: string, table: string, field: string, version: number) =>
  Buffer.from(bugs.has("aad-ignores-table-field") ? `bulkhead/v1|${tenant}|${version}` : bugs.has("shared-data-key") ? `bulkhead/v1|${table}|${field}|${version}` : `bulkhead/v1|${tenant}|${table}|${field}|${version}`);
function tenantDb(tenant: string): DatabaseSync | null {
  if (!PERSIST) return null;
  let db = dbs.get(tenant);
  if (!db) {
    mkdirSync(PERSIST, { recursive: true });
    db = new DatabaseSync(join(PERSIST, `${tenant}.sqlite`), { timeout: 5000 });
    db.exec("pragma journal_mode = wal; create table if not exists _bulkhead_meta (key text primary key, value text not null); create table if not exists notes (id integer primary key autoincrement, text text not null); create table if not exists tenant_secrets (id text primary key, name text not null, value text not null, created_at integer not null); create table if not exists scratch (v text)");
    db.prepare("insert or ignore into _bulkhead_meta (key, value) values ('tenant_id', ?)").run(tenant);
    dbs.set(tenant, db);
  }
  return db;
}
/** Reserves the next nonce counter for (tenant, keyVersion): one number, never handed out twice. */
async function reserveNonce(tenant: string, db: DatabaseSync, version: number): Promise<number> {
  if (bugs.has("nonce-reused")) return 1;
  const key = `nonce:${version}`;
  if (bugs.has("nonce-race")) {
    // Read, yield, then write: two concurrent writes read the same number. The real code does the bump in one statement with no await.
    const cur = Number((db.prepare("select value from _bulkhead_meta where key = ?").get(key) as { value?: string } | undefined)?.value ?? 0);
    await new Promise((r) => setImmediate(r));
    db.prepare("insert or replace into _bulkhead_meta (key, value) values (?, ?)").run(key, String(cur + 1));
    return cur + 1;
  }
  db.prepare("insert into _bulkhead_meta (key, value) values (?, '1') on conflict (key) do update set value = cast(cast(value as integer) + 1 as text)").run(key);
  return Number((db.prepare("select value from _bulkhead_meta where key = ?").get(key) as { value: string }).value);
}
async function seal(tenant: string, db: DatabaseSync, table: string, field: string, plain: string): Promise<string> {
  const ring = ringOf(tenant);
  const version = bugs.has("rotation-ignored") ? 1 : ring.current;
  const counter = await reserveNonce(tenant, db, version);
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64BE(BigInt(counter), 4);
  const c = createCipheriv("aes-256-gcm", keyFor(tenant, ring, version), nonce);
  c.setAAD(aad(tenant, table, field, version));
  const ct = Buffer.concat([c.update(plain, "utf8"), c.final(), c.getAuthTag()]);
  return `bk1:${version}:${nonce.toString("base64url")}:${ct.toString("base64url")}`;
}
function open(tenant: string, table: string, field: string, sealed: string): string {
  const m = /^bk1:([1-9][0-9]*):([A-Za-z0-9_-]{16}):([A-Za-z0-9_-]+)$/.exec(sealed);
  if (!m) throw new CannotOpen("not a sealed value");
  const version = Number(m[1]);
  const ring = ringOf(tenant);
  const raw = Buffer.from(m[3] as string, "base64url");
  try {
    const d = createDecipheriv("aes-256-gcm", keyFor(tenant, ring, version), Buffer.from(m[2] as string, "base64url"));
    d.setAAD(aad(tenant, table, field, version));
    d.setAuthTag(raw.subarray(raw.length - 16));
    return Buffer.concat([d.update(raw.subarray(0, raw.length - 16)), d.final()]).toString("utf8");
  } catch {
    throw new CannotOpen("cannot open");
  }
}
// Not in the seeded-bug catalog on purpose: these produce UNVERIFIED (the write never lands), which the catalog's fail-lists cannot express. Unit tests use them.
async function persistNote(tenant: string, text: string) {
  const db = tenantDb(tenant);
  if (!db) return;
  if (bugs.has("notes-dropped")) return; // creates the tenant database on first use, then stores nothing
  const plain = bugs.has("notes-plaintext-at-rest") || (bugs.has("notes-plaintext-on-second") && notes.filter((n) => n.tenant === tenant).length >= 1);
  db.prepare("insert into notes (text) values (?)").run(plain ? text : await seal(tenant, db, "notes", "text", text));
  if (bugs.has("plaintext-in-freed-page")) {
    db.prepare("insert into scratch (v) values (?)").run(text);
    db.exec("delete from scratch");
  }
}
async function persistSecret(tenant: string, name: string, value: string) {
  if (bugs.has("secrets-dropped")) { tenantDb(tenant); return; }
  const db = tenantDb(tenant);
  if (!db) return;
  const plain = bugs.has("secret-plaintext-at-rest") || (bugs.has("secret-plaintext-on-second") && [...secrets.keys()].filter((k) => k.startsWith(`${tenant}|`)).length >= 2);
  db.prepare("insert into tenant_secrets (id, name, value, created_at) values (?, ?, ?, ?)").run(randomBytes(8).toString("hex"), name, plain ? value : await seal(tenant, db, "tenant_secrets", "value", value), Date.now());
}
/** Notes as the app reads them: opened from storage when the fixture persists, else from memory. The missing-tenant-filter bug reads every tenant (that can be read). */
function readNotes(tenant: string, everyone = false): string[] {
  if (!PERSIST) return everyone ? notes.map((n) => n.text) : notes.filter((n) => n.tenant === tenant).map((n) => n.text);
  const out: string[] = [];
  for (const t of everyone ? [...dbs.keys()] : [tenant]) {
    try {
      ringOf(t); // a shredded tenant answers Gone before any row is touched
      for (const r of tenantDb(t)!.prepare("select text from notes order by id").all() as { text: string }[]) out.push(r.text.startsWith("bk1:") ? open(t, "notes", "text", r.text) : r.text);
    } catch (e) {
      if (!everyone || t === tenant) throw e; // the leaky read skips other tenants it cannot open
    }
  }
  return out;
}
function rotate(tenant: string): number {
  const ring = ringOf(tenant);
  ring.current += 1;
  ring.versions.set(ring.current, randomBytes(32));
  if (bugs.has("rotation-orphans-old")) for (const v of [...ring.versions.keys()]) if (v !== ring.current) ring.versions.delete(v);
  return ring.current;
}
function shred(tenant: string) {
  if (bugs.has("shred-noop")) return;
  if (bugs.has("shred-destroys-all-tenants")) for (const r of rings.values()) { r.versions.clear(); r.shredded = true; }
  if (bugs.has("shred-rekeys-on-write")) { rings.delete(tenant); return; } // the key is gone, and so is the record that it was destroyed: the next write mints a fresh one
  const r = rings.get(tenant) ?? newRing();
  r.versions.clear();
  r.shredded = true;
  rings.set(tenant, r);
  if (!bugs.has("shred-keeps-summary-cache")) for (const k of [...cache.keys()]) if (k.startsWith(`${tenant}:`) || k === "summary") cache.delete(k);
}
const secrets = new Map<string, string>(); // key: tenant|name

const notes: { tenant: string; text: string }[] = [];
const plans = new Map<string, string>();
const cache = new Map<string, string>();

function tenantOf(host: string | undefined, header: string | undefined, forwardedHost?: string): string | null {
  const m = /^([a-z0-9-]+)\.demo\.localhost(:\d+)?$/.exec((bugs.has("tenant-from-forwarded-host") && forwardedHost ? forwardedHost : host) ?? "");
  if (bugs.has("tenant-from-header") && header) return header;
  return m ? (m[1] as string) : null; // unknown host: fail closed
}

interface AuthReply { status: number; body: unknown; cookie?: string }
const reply = (status: number, body: unknown, cookie?: string): AuthReply => ({ status, body, ...(cookie ? { cookie } : {}) });
const cookieOf = (h: string | undefined) => new RegExp(`${COOKIE}=([^;\\s]+)`).exec(h ?? "")?.[1];

/** Cookie-authenticated writes need a same-origin Origin or Sec-Fetch-Site, mirroring the real gate (CSRF). */
function csrfOk(headers: Record<string, string | string[] | undefined>): boolean {
  if (bugs.has("csrf-ignored")) return true;
  const origin = headers.origin === undefined ? undefined : String(headers.origin);
  if (origin !== undefined) {
    try {
      return new URL(origin).host === String(headers.host ?? "");
    } catch {
      return false;
    }
  }
  const site = headers["sec-fetch-site"];
  return site === "same-origin" || site === "none";
}

function principal(tenant: string, headers: Record<string, string | string[] | undefined>): { role: Role; perms?: string[]; id: string } | null {
  const authz = String(headers.authorization ?? "");
  if (authz) {
    const m = /^Bearer bkk_([0-9a-f]{16})_(\S+)$/.exec(authz);
    const k = m && keys.get(m[1] as string);
    if (!k || (k.secret !== m[2] && !bugs.has("key-secret-unchecked") && !(bugs.has("key-secret-length-ignored") && (m[2] as string).startsWith(k.secret)))) return null;
    if (k.revoked && !bugs.has("key-revocation-ignored")) return null;
    if (k.tenant !== tenant && !bugs.has("api-key-cross-tenant")) return null;
    return { role: k.role, perms: k.permissions, id: `key:${m[1]}` };
  }
  const sess = sessions.get(cookieOf(String(headers.cookie ?? "")) ?? "");
  if (sess && (bugs.has("session-cross-tenant") || sess.tenant === tenant)) return { role: sess.role, id: sess.userId };
  return bugs.has("default-role") ? { role: "member", id: "anonymous" } : null;
}

async function authRoute(method: string, path: string, tenant: string, headers: Record<string, string | string[] | undefined>, raw: string): Promise<AuthReply | null> {
  const json = (): Record<string, unknown> => { try { return JSON.parse(raw || "{}"); } catch { return {}; } };
  const isPublic = path === "/auth/login" || path === "/auth/bootstrap";
  const cookieWrite = headers.cookie !== undefined && !String(headers.authorization ?? "") && method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
  if (!isPublic && cookieWrite && !csrfOk(headers)) return reply(401, { error: "authentication required" });
  const policy = POLICY[path];
  if (policy && method === "GET") {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    const need = bugs.has("admin-open-to-member") && path === "/private/admin" ? "member" : policy.role;
    if (RANK[p.role] < RANK[need]) return reply(403, { error: "forbidden" });
    if (p.perms && !bugs.has("api-key-unscoped") && !(policy.permission && p.perms.includes(policy.permission))) return reply(403, { error: "forbidden" });
    return reply(200, { area: path.split("/")[2], who: p.id });
  }
  if (method === "POST" && path === "/auth/bootstrap") {
    const b = json();
    if (typeof b.token !== "string" || (b.token !== BOOTSTRAP && !bugs.has("bootstrap-token-unchecked"))) return reply(403, { error: "forbidden" });
    if (tenantUsers(tenant).length && !bugs.has("bootstrap-second-owner")) return reply(409, { error: "tenant already has users" });
    const u = { id: token(8), email: String(b.email), password: String(b.password), role: "owner" as Role, disabled: false };
    users.set(`${tenant}|${u.email}`, u);
    return reply(201, { id: u.id, role: "owner" });
  }
  if (method === "POST" && path === "/auth/login") {
    const b = json();
    const u = users.get(`${tenant}|${b.email}`);
    if (!u && bugs.has("unknown-email-login-errors")) return reply(500, { error: "internal error" });
    if (!u || u.password !== b.password || (u.disabled && !bugs.has("disabled-user-can-login"))) return reply(401, { error: "invalid credentials" });
    const presented = cookieOf(String(headers.cookie ?? ""));
    if (presented && !bugs.has("session-fixation")) sessions.delete(presented);
    const t = bugs.has("session-fixation") && presented ? presented : `bks_${token(32)}`;
    sessions.set(t, { tenant, userId: u.id, role: u.role });
    const flags = bugs.has("weak-cookie") ? "Path=/; Secure; Domain=demo.localhost; SameSite=Lax" : "Path=/; Secure; HttpOnly; SameSite=Lax";
    return reply(200, { ok: true }, `${COOKIE}=${t}; Max-Age=604800; ${flags}`);
  }
  if (method === "POST" && path === "/auth/logout") {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (!bugs.has("logout-keeps-session")) sessions.delete(cookieOf(String(headers.cookie ?? "")) ?? "");
    return reply(200, { ok: true });
  }
  if (method === "GET" && path === "/users") {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < (bugs.has("member-can-list-users") ? RANK.member : RANK.admin)) return reply(403, { error: "forbidden" });
    return reply(200, { users: tenantUsers(tenant).map((u) => ({ id: u.id, email: u.email, role: u.role, disabled: u.disabled ? 1 : 0, ...(bugs.has("listing-leaks-digest") ? { digest: randomBytes(32).toString("hex") } : {}), ...(bugs.has("listing-leaks-hash") ? { password_hash: `pbkdf2$100000$${token(8)}$${token(32)}` } : {}) })) });
  }
  if (method === "POST" && path === "/users") {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < RANK.admin || (bugs.has("admin-user-create-refused") && p.role === "admin")) return reply(403, { error: "forbidden" });
    const b = json();
    const wanted = b.role as Role;
    if (!bugs.has("escalation-allowed") && RANK[wanted] > RANK[p.role]) return reply(403, { error: "cannot grant a role above your own" });
    const u = { id: token(8), email: String(b.email), password: String(b.password), role: wanted, disabled: false };
    users.set(`${tenant}|${u.email}`, u);
    return reply(201, { id: u.id, role: u.role });
  }
  const rolePath = /^\/users\/([^/]+)\/role$/.exec(path);
  if (method === "PATCH" && rolePath) {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < RANK.admin) return reply(403, { error: "forbidden" });
    const wanted = String(json().role) as Role;
    if (!(wanted in RANK)) return reply(400, { error: "role must be member, admin or owner" });
    if (!bugs.has("role-patch-escalation") && RANK[wanted] > RANK[p.role]) return reply(403, { error: "cannot grant a role above your own" });
    const u = tenantUsers(tenant).find((x) => x.id === rolePath[1]);
    if (!u) return reply(404, { error: "not found" });
    if (!bugs.has("admin-modifies-owner") && RANK[u.role] > RANK[p.role]) return reply(403, { error: "cannot modify a user above your own role" });
    if (u.role === "owner" && wanted !== "owner" && !u.disabled && tenantUsers(tenant).filter((x) => x.role === "owner" && !x.disabled).length <= 1) return reply(409, { error: "cannot remove the last owner" });
    u.role = wanted;
    if (!bugs.has("role-change-keeps-session")) for (const [k, s] of sessions) if (s.userId === u.id) sessions.delete(k);
    if (!bugs.has("key-revocation-ignored")) for (const [, k] of keys) if (k.createdBy === u.id) k.revoked = true;
    return reply(200, { id: u.id, role: u.role });
  }
  const userPath = /^\/users\/([^/]+)$/.exec(path);
  if (method === "DELETE" && userPath) {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < RANK.admin) return reply(403, { error: "forbidden" });
    const u = tenantUsers(tenant).find((x) => x.id === userPath[1]);
    if (!u) return reply(404, { error: "not found" });
    if (!bugs.has("admin-modifies-owner") && RANK[u.role] > RANK[p.role]) return reply(403, { error: "cannot modify a user above your own role" });
    if (u.role === "owner" && !u.disabled && tenantUsers(tenant).filter((x) => x.role === "owner" && !x.disabled).length <= 1) return reply(409, { error: "cannot remove the last owner" });
    u.disabled = true;
    for (const [k, s] of sessions) if (s.userId === u.id) sessions.delete(k);
    for (const [, k] of keys) if (k.createdBy === u.id) k.revoked = true;
    return reply(200, { id: u.id, disabled: true });
  }
  if (method === "POST" && path === "/api-keys") {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < RANK.admin) return reply(403, { error: "forbidden" });
    const b = json();
    const role = (b.role as Role | undefined) ?? "member";
    if (!(role in RANK)) return reply(400, { error: "role must be member, admin or owner" });
    if (!bugs.has("key-above-minter-role") && RANK[role] > RANK[p.role]) return reply(403, { error: "cannot mint a key above your own role" });
    const id = randomBytes(8).toString("hex");
    const secret = token(32);
    keys.set(id, { tenant, secret, role, permissions: (b.permissions as string[]) ?? [], createdBy: p.id, revoked: false });
    return reply(201, { id, key: `bkk_${id}_${secret}` });
  }
  const keyPath = /^\/api-keys\/([^/]+)$/.exec(path);
  if (method === "DELETE" && keyPath) {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < RANK.admin) return reply(403, { error: "forbidden" });
    const k = keys.get(keyPath[1] as string);
    if (!k || k.tenant !== tenant) return reply(404, { error: "not found" });
    k.revoked = true;
    return reply(200, { id: keyPath[1], revoked: true });
  }
  if (method === "GET" && path === "/api-keys") {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < (bugs.has("member-can-list-users") ? RANK.member : RANK.admin)) return reply(403, { error: "forbidden" });
    return reply(200, { keys: [...keys].filter(([, k]) => k.tenant === tenant).map(([id, k]) => ({ id, role: k.role, permissions: k.permissions, ...(bugs.has("listing-leaks-token") ? { x: token(32) } : {}), ...(bugs.has("listing-leaks-hash") ? { secret_hash: createHash("sha256").update(k.secret).digest("hex") } : {}) })) });
  }
  // Key lifecycle (CRYPTO-3/4): owner only.
  if (method === "POST" && (path === "/admin/rotate-key" || path === "/admin/shred")) {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < RANK.owner) return reply(403, { error: "forbidden" });
    try {
      if (path === "/admin/shred") { shred(tenant); return reply(200, { shredded: true }); }
      return reply(200, { keyVersion: rotate(tenant) });
    } catch (e) {
      if (e instanceof Gone) return reply(410, { error: "tenant data is unavailable" });
      throw e;
    }
  }
  // Tenant secrets (CRYPTO-5): a store route, a listing of names, a per-name metadata route. None may ever return the value.
  if (method === "POST" && path === "/secrets") {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < RANK.admin) return reply(403, { error: "forbidden" });
    const b = json();
    if (typeof b.name !== "string" || typeof b.value !== "string") return reply(400, { error: "name and value required" });
    secrets.set(`${tenant}|${b.name}`, b.value);
    try { await persistSecret(tenant, b.name, b.value); } catch (e) { if (e instanceof Gone) return reply(410, { error: "tenant data is unavailable" }); throw e; }
    return reply(201, { id: b.name, name: b.name, ...(bugs.has("secret-echoed-on-store") ? { value: b.value } : {}) });
  }
  if (method === "GET" && path === "/secrets") {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < RANK.admin) return reply(403, { error: "forbidden" });
    return reply(200, { secrets: [...secrets].filter(([k]) => k.startsWith(`${tenant}|`)).map(([k, v]) => ({ name: k.slice(tenant.length + 1), ...(bugs.has("secret-readable-via-list") ? { value: v } : {}) })) });
  }
  const secretPath = /^\/secrets\/([^/]+)$/.exec(path);
  if (method === "GET" && secretPath) {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < RANK.admin) return reply(403, { error: "forbidden" });
    const name = decodeURIComponent(secretPath[1] as string);
    const v = secrets.get(`${tenant}|${name}`);
    if (v === undefined) return reply(404, { error: "not found" });
    return reply(200, { name, stored: true, ...(bugs.has("secret-readable-via-param-route") ? { value: v } : {}) });
  }
  return null;
}

const server = createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => chunks.push(c));
  req.on("end", async () => {
    const body = Buffer.concat(chunks);
    const send = (status: number, obj: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    const failure = (e: unknown) => (e instanceof Gone ? send(410, { error: "tenant data is unavailable" }) : send(500, { error: "internal error" }));
    const tenant = tenantOf(req.headers.host, req.headers["x-tenant"] as string | undefined, req.headers["x-forwarded-host"] as string | undefined);
    if (!tenant) return send(404, { error: "unknown host" });
    const url = new URL(req.url ?? "/", "http://x");

    const auth = await authRoute(req.method ?? "GET", url.pathname, tenant, req.headers, body.toString());
    if (auth) {
      res.writeHead(auth.status, { "content-type": "application/json", ...(auth.cookie ? { "set-cookie": auth.cookie } : {}) });
      return res.end(JSON.stringify(auth.body));
    }

    if (req.method === "GET" && url.pathname === "/whoami") return send(200, { tenant });
    if (req.method === "POST" && url.pathname === "/notes") {
      const text = String(JSON.parse(body.toString() || "{}").text ?? "");
      try { await persistNote(tenant, text); } catch (e) { if (e instanceof Gone) return send(410, { error: "tenant data is unavailable" }); throw e; }
      notes.push({ tenant, text });
      cache.clear();
      return send(201, { ok: true });
    }
    if (req.method === "GET" && url.pathname === "/notes") {
      try { return send(200, { notes: readNotes(tenant, bugs.has("missing-tenant-filter")) }); } catch (e) { return failure(e); }
    }
    if (req.method === "GET" && url.pathname === "/summary") {
      const key = bugs.has("shared-cache-key") ? "summary" : `${tenant}:summary`;
      let v = cache.get(key);
      try { if (v === undefined) cache.set(key, (v = readNotes(tenant).join(" | "))); } catch (e) { return failure(e); }
      return send(200, { summary: v });
    }
    if (req.method === "POST" && url.pathname === "/webhooks/billing") {
      const given = String(req.headers["x-signature"] ?? "");
      const want = createHmac("sha256", SECRET).update(body).digest("hex");
      const ok = given.length === want.length && timingSafeEqual(Buffer.from(given), Buffer.from(want));
      if (!ok && !bugs.has("skipped-signature-check")) return send(400, { error: "bad signature" });
      plans.set(tenant, String(JSON.parse(body.toString() || "{}").plan ?? "free"));
      return send(200, { ok: true });
    }
    if (req.method === "GET" && url.pathname === "/plan") return send(200, { plan: plans.get(tenant) ?? "free" });
    return send(404, { error: "not found" });
  });
});

server.listen(Number(process.env.PORT ?? 0), "127.0.0.1", () => {
  const addr = server.address();
  console.log(`LISTENING ${typeof addr === "object" && addr ? addr.port : ""}`);
});
