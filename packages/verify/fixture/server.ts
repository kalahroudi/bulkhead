// Deliberately vulnerable fixture app. Never deploy. Bugs are toggled by FIXTURE_BUGS (comma list, or "all"/"none").
import { createServer } from "node:http";
import { createCipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

const ALL = [
  "missing-tenant-filter", "shared-cache-key", "skipped-signature-check", "tenant-from-header",
  "default-role", "session-fixation", "weak-cookie", "logout-keeps-session", "role-change-keeps-session", "admin-open-to-member", "api-key-cross-tenant", "api-key-unscoped",
  "session-cross-tenant", "csrf-ignored", "member-can-list-users", "escalation-allowed", "key-revocation-ignored", "disabled-user-can-login",
  "key-secret-unchecked", "bootstrap-token-unchecked", "bootstrap-second-owner", "role-patch-escalation", "admin-modifies-owner", "key-above-minter-role", "listing-leaks-hash", "tenant-from-forwarded-host", "unknown-email-login-errors", "key-secret-length-ignored", "admin-user-create-refused", "listing-leaks-digest", "listing-leaks-token",
  "notes-plaintext-at-rest", "secret-plaintext-at-rest", "plaintext-in-freed-page", "secret-readable-via-list", "secret-readable-via-param-route", "secret-echoed-on-store",
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
// The fixture's own AES-256-GCM envelope `bk1:1:<nonce>:<ct>`; it shares nothing with the real implementation.
const PERSIST = process.env.FIXTURE_PERSIST_DIR;
const DATA_KEY = randomBytes(32);
const dbs = new Map<string, DatabaseSync>();
function seal(tenant: string, table: string, field: string, plain: string): string {
  const nonce = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", DATA_KEY, nonce);
  c.setAAD(Buffer.from(`${tenant}|${table}|${field}`));
  const ct = Buffer.concat([c.update(plain, "utf8"), c.final(), c.getAuthTag()]);
  return `bk1:1:${nonce.toString("base64url")}:${ct.toString("base64url")}`;
}
function tenantDb(tenant: string): DatabaseSync | null {
  if (!PERSIST) return null;
  let db = dbs.get(tenant);
  if (!db) {
    mkdirSync(PERSIST, { recursive: true });
    db = new DatabaseSync(join(PERSIST, `${tenant}.sqlite`));
    db.exec("pragma journal_mode = wal; create table if not exists notes (id integer primary key autoincrement, text text not null); create table if not exists tenant_secrets (name text primary key, value text not null); create table if not exists scratch (v text)");
    dbs.set(tenant, db);
  }
  return db;
}
function persistNote(tenant: string, text: string) {
  const db = tenantDb(tenant);
  if (!db) return;
  db.prepare("insert into notes (text) values (?)").run(bugs.has("notes-plaintext-at-rest") ? text : seal(tenant, "notes", "text", text));
  if (bugs.has("plaintext-in-freed-page")) {
    db.prepare("insert into scratch (v) values (?)").run(text);
    db.exec("delete from scratch");
  }
}
function persistSecret(tenant: string, name: string, value: string) {
  tenantDb(tenant)?.prepare("insert or replace into tenant_secrets (name, value) values (?, ?)").run(name, bugs.has("secret-plaintext-at-rest") ? value : seal(tenant, "tenant_secrets", "value", value));
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

function authRoute(method: string, path: string, tenant: string, headers: Record<string, string | string[] | undefined>, raw: string): AuthReply | null {
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
  // Tenant secrets (CRYPTO-5): a store route, a listing of names, a per-name metadata route. None may ever return the value.
  if (method === "POST" && path === "/secrets") {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < RANK.admin) return reply(403, { error: "forbidden" });
    const b = json();
    if (typeof b.name !== "string" || typeof b.value !== "string") return reply(400, { error: "name and value required" });
    secrets.set(`${tenant}|${b.name}`, b.value);
    persistSecret(tenant, b.name, b.value);
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
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    const send = (status: number, obj: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    const tenant = tenantOf(req.headers.host, req.headers["x-tenant"] as string | undefined, req.headers["x-forwarded-host"] as string | undefined);
    if (!tenant) return send(404, { error: "unknown host" });
    const url = new URL(req.url ?? "/", "http://x");
    const mine = () => notes.filter((n) => n.tenant === tenant).map((n) => n.text);

    const auth = authRoute(req.method ?? "GET", url.pathname, tenant, req.headers, body.toString());
    if (auth) {
      res.writeHead(auth.status, { "content-type": "application/json", ...(auth.cookie ? { "set-cookie": auth.cookie } : {}) });
      return res.end(JSON.stringify(auth.body));
    }

    if (req.method === "GET" && url.pathname === "/whoami") return send(200, { tenant });
    if (req.method === "POST" && url.pathname === "/notes") {
      const text = String(JSON.parse(body.toString() || "{}").text ?? "");
      notes.push({ tenant, text });
      persistNote(tenant, text);
      cache.clear();
      return send(201, { ok: true });
    }
    if (req.method === "GET" && url.pathname === "/notes") {
      const list = bugs.has("missing-tenant-filter") ? notes.map((n) => n.text) : mine();
      return send(200, { notes: list });
    }
    if (req.method === "GET" && url.pathname === "/summary") {
      const key = bugs.has("shared-cache-key") ? "summary" : `${tenant}:summary`;
      let v = cache.get(key);
      if (v === undefined) cache.set(key, (v = mine().join(" | ")));
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
