// Deliberately vulnerable fixture app. Never deploy. Bugs are toggled by FIXTURE_BUGS (comma list, or "all"/"none").
import { createServer } from "node:http";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const ALL = [
  "missing-tenant-filter", "shared-cache-key", "skipped-signature-check", "tenant-from-header",
  "default-role", "session-fixation", "weak-cookie", "logout-keeps-session", "role-change-keeps-session", "admin-open-to-member", "api-key-cross-tenant", "api-key-unscoped",
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
const users = new Map<string, { id: string; email: string; password: string; role: Role }>(); // key: tenant|email
const sessions = new Map<string, { tenant: string; userId: string; role: Role }>();
const keys = new Map<string, { tenant: string; secret: string; role: Role; permissions: string[] }>();
const tenantUsers = (tenant: string) => [...users.values()].filter((u) => users.get(`${tenant}|${u.email}`) === u);
const COOKIE = "__Host-bk_session";
const token = (n: number) => randomBytes(n).toString("base64url");

const notes: { tenant: string; text: string }[] = [];
const plans = new Map<string, string>();
const cache = new Map<string, string>();

function tenantOf(host: string | undefined, header: string | undefined): string | null {
  const m = /^([a-z0-9-]+)\.demo\.localhost(:\d+)?$/.exec(host ?? "");
  if (bugs.has("tenant-from-header") && header) return header;
  return m ? (m[1] as string) : null; // unknown host: fail closed
}

interface AuthReply { status: number; body: unknown; cookie?: string }
const reply = (status: number, body: unknown, cookie?: string): AuthReply => ({ status, body, ...(cookie ? { cookie } : {}) });
const cookieOf = (h: string | undefined) => new RegExp(`${COOKIE}=([^;\\s]+)`).exec(h ?? "")?.[1];

function principal(tenant: string, headers: Record<string, string | string[] | undefined>): { role: Role; perms?: string[]; id: string } | null {
  const authz = String(headers.authorization ?? "");
  if (authz) {
    const m = /^Bearer bkk_([0-9a-f]{16})_(\S+)$/.exec(authz);
    const k = m && keys.get(m[1] as string);
    if (!k || k.secret !== m[2]) return null;
    if (k.tenant !== tenant && !bugs.has("api-key-cross-tenant")) return null;
    return { role: k.role, perms: k.permissions, id: `key:${m[1]}` };
  }
  const sess = sessions.get(cookieOf(String(headers.cookie ?? "")) ?? "");
  if (sess && sess.tenant === tenant) return { role: sess.role, id: sess.userId };
  return bugs.has("default-role") ? { role: "member", id: "anonymous" } : null;
}

function authRoute(method: string, path: string, tenant: string, headers: Record<string, string | string[] | undefined>, raw: string): AuthReply | null {
  const json = (): Record<string, unknown> => { try { return JSON.parse(raw || "{}"); } catch { return {}; } };
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
    if (b.token !== BOOTSTRAP) return reply(403, { error: "forbidden" });
    if (tenantUsers(tenant).length) return reply(409, { error: "tenant already has users" });
    const u = { id: token(8), email: String(b.email), password: String(b.password), role: "owner" as Role };
    users.set(`${tenant}|${u.email}`, u);
    return reply(201, { id: u.id, role: "owner" });
  }
  if (method === "POST" && path === "/auth/login") {
    const b = json();
    const u = users.get(`${tenant}|${b.email}`);
    if (!u || u.password !== b.password) return reply(401, { error: "invalid credentials" });
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
  if (method === "POST" && path === "/users") {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < RANK.admin) return reply(403, { error: "forbidden" });
    const b = json();
    const u = { id: token(8), email: String(b.email), password: String(b.password), role: b.role as Role };
    users.set(`${tenant}|${u.email}`, u);
    return reply(201, { id: u.id, role: u.role });
  }
  const rolePath = /^\/users\/([^/]+)\/role$/.exec(path);
  if (method === "PATCH" && rolePath) {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < RANK.admin) return reply(403, { error: "forbidden" });
    const u = tenantUsers(tenant).find((x) => x.id === rolePath[1]);
    if (!u) return reply(404, { error: "not found" });
    u.role = String(json().role) as Role;
    if (!bugs.has("role-change-keeps-session")) for (const [k, s] of sessions) if (s.userId === u.id) sessions.delete(k);
    return reply(200, { id: u.id, role: u.role });
  }
  if (method === "POST" && path === "/api-keys") {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < RANK.admin) return reply(403, { error: "forbidden" });
    const b = json();
    const id = randomBytes(8).toString("hex");
    const secret = token(32);
    keys.set(id, { tenant, secret, role: (b.role as Role) ?? "member", permissions: (b.permissions as string[]) ?? [] });
    return reply(201, { id, key: `bkk_${id}_${secret}` });
  }
  if (method === "GET" && path === "/api-keys") {
    const p = principal(tenant, headers);
    if (!p) return reply(401, { error: "authentication required" });
    if (RANK[p.role] < RANK.admin) return reply(403, { error: "forbidden" });
    return reply(200, { keys: [...keys].filter(([, k]) => k.tenant === tenant).map(([id, k]) => ({ id, role: k.role, permissions: k.permissions })) });
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
    const tenant = tenantOf(req.headers.host, req.headers["x-tenant"] as string | undefined);
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
      notes.push({ tenant, text: String(JSON.parse(body.toString() || "{}").text ?? "") });
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
