import { createHmac, randomBytes } from "node:crypto";
import type { Oracle } from "@kalahroudi/bulkhead-spec";
import type { Requester, Response } from "./http.ts";
import { fingerprintStorage, scanStorage, sealedCells, storageChanged, type SealedCell } from "./inspector.ts";
import { overwriteCell } from "./tamper.ts";
import { canaryOracle, differentialOracle, metamorphicOracle, roleDifferentialOracle, specOracle, storageCanaryOracle, type Verdict } from "./oracles.ts";

/** One entry of the committed route manifest (ROUTE-2). Verify reads the JSON file; it never imports the app that wrote it. */
export interface ManifestRoute {
  method: string;
  path: string;
}

/** What a run was given besides the HTTP address. Anything absent makes the probes that need it report "unverified". */
export interface TargetEnv {
  /** Local persisted-storage directory (workerd --persist-to) of the target. Only a local target has one (DR-0010 choice 7). */
  persistDir?: string;
  /** The committed route manifest of the target. */
  routes?: ManifestRoute[];
}

export function parseManifest(text: string): ManifestRoute[] {
  const data: unknown = JSON.parse(text);
  if (!Array.isArray(data) || !data.every((r) => r && typeof r.method === "string" && typeof r.path === "string")) throw new Error("route manifest must be a JSON array of {method, path, ...}");
  return data.map((r) => ({ method: String(r.method).toUpperCase(), path: String(r.path) }));
}

export interface Context extends TargetEnv {
  req: Requester;
  /** Throwaway tenant hostnames. Tenant identity comes from the hostname only. */
  host: (tenant: string) => string;
  /** Webhook secret for the registered test environment. */
  webhookSecret: string;
  /** First-owner bootstrap secret of the registered test environment. Undefined makes the auth probes fail loudly, never pass. */
  bootstrapToken: string | undefined;
}

export interface Probe {
  /** Unique probe ID, used by the seeded-bug catalog. */
  id: string;
  /** Spec rule this probe checks, and the scenario stub name from the spec. */
  ruleId: string;
  scenario: string;
  oracle: Oracle;
  run(ctx: Context): Promise<Verdict & { reproduction: string }>;
}

const marker = () => `CANARY-${randomBytes(6).toString("hex")}`;
const json = (o: unknown) => JSON.stringify(o);

/**
 * A probe's setup requests must succeed. "We could not plant the marker" is not "the marker did
 * not leak": without this, a failed setup (a 404, a missing route) would read as a pass.
 */
function requireSetup(res: Response, what: string, reproduction: string): (Verdict & { reproduction: string }) | null {
  if (res.status >= 200 && res.status < 300) return null;
  return { passed: false, evidence: `${what} did not succeed: HTTP ${res.status} ${res.body}`, reproduction };
}

const PASSWORD = "verify-probe-password-1";
const SESSION_COOKIE = "__Host-bk_session";
const setCookies = (r: Response): string[] => [r.headers["set-cookie"] ?? []].flat();
const sessionOf = (r: Response) => setCookies(r).map((c) => new RegExp(`^${SESSION_COOKIE}=([^;]+)`).exec(c)?.[1]).find(Boolean);
const withCookie = (token: string) => ({ headers: { cookie: `${SESSION_COOKIE}=${token}` } });
/** A cookie-authenticated write, with the same-origin Origin a browser always sends (the gate refuses cookie writes with neither Origin nor Sec-Fetch-Site). */
const cookieWrite = (host: string, token: string) => ({ headers: { cookie: `${SESSION_COOKIE}=${token}`, origin: `http://${host}` } });
/** Third outcome: the target does not have the feature this probe exercises. Not a pass and never a finding. */
const skip = (reason: string, reproduction: string) => ({ passed: false, evidence: reason, skipped: reason, reproduction });
const fail = (evidence: string, reproduction: string) => ({ passed: false, evidence, reproduction });
/** Fourth outcome: the run had no means to check this (no storage dir, no manifest). Not a pass, not a finding, and the run is not green. */
const unverified = (reason: string, reproduction: string) => ({ passed: false, evidence: reason, unverified: reason, reproduction });

/** Path parameter forms a manifest may use. */
const PARAM_ALL = /:[A-Za-z_]\w*|\{[^}/]+\}|\[[^\]/]+\]|\*/g;
const PARAM = new RegExp(PARAM_ALL.source);
/**
 * The tenant-secret store route the CRYPTO-5 probe plants through: POST /secrets {name, value}. This is a verify-side
 * convention that DR-0010 step (g) has not fixed yet (see the report); a target whose manifest lacks it is "unverified".
 */
const SECRET_STORE = { method: "POST", path: "/secrets" } as const;
const hasStoreRoute = (routes: ManifestRoute[] | undefined) => !!routes?.some((r) => r.method === SECRET_STORE.method && r.path === SECRET_STORE.path);


/** Key lifecycle routes of a target (DR-0010 step e/f): POST /admin/shred and POST /admin/rotate-key, both owner-only. */
const SHRED_ROUTE = "/admin/shred";
const ROTATE_ROUTE = "/admin/rotate-key";
const hasRoute = (routes: ManifestRoute[] | undefined, method: string, path: string) => !routes || routes.some((r) => r.method === method && r.path === path);
const ENVELOPE = /^bk1:([1-9][0-9]*):([A-Za-z0-9_-]{16}):([A-Za-z0-9_-]+)$/;
const cellKey = (c: SealedCell) => `${c.file}|${c.table}|${c.column}|${c.rowid}`;
const countOf = (haystack: string, needle: string) => haystack.split(needle).length - 1;

/** A throwaway tenant with an owner who is signed in. Every step must succeed or the probe fails (setup is not a pass). */
async function ownerTenant({ req, host, bootstrapToken }: Context, name: string, reproduction: string) {
  if (!bootstrapToken) return { error: fail("no bootstrap token configured for this target (set BULKHEAD_VERIFY_BOOTSTRAP_TOKEN); auth probes cannot run", reproduction) };
  const h = host(`${name}-${randomBytes(3).toString("hex")}`);
  const boot = await req(h, "POST", "/auth/bootstrap", { body: json({ token: bootstrapToken, email: "owner@probe.test", password: PASSWORD }) });
  const brokenBoot = requireSetup(boot, `bootstrapping an owner on ${h}`, reproduction);
  if (brokenBoot) return { error: brokenBoot };
  const login = await req(h, "POST", "/auth/login", { body: json({ email: "owner@probe.test", password: PASSWORD }) });
  const brokenLogin = requireSetup(login, "owner login", reproduction);
  const token = sessionOf(login);
  if (brokenLogin || !token) return { error: brokenLogin ?? fail("owner login set no session cookie", reproduction) };
  const addUser = async (email: string, role: string) => {
    const r = await req(h, "POST", "/users", { ...cookieWrite(h, token), body: json({ email, password: PASSWORD, role }) });
    const broken = requireSetup(r, `creating ${role} ${email}`, reproduction);
    return broken ? { error: broken } : { id: (JSON.parse(r.body) as { id: string }).id };
  };
  const loginAs = async (email: string) => {
    const r = await req(h, "POST", "/auth/login", { body: json({ email, password: PASSWORD }) });
    const t = sessionOf(r);
    return r.status === 200 && t ? { token: t, res: r } : { error: fail(`login as ${email} did not succeed: HTTP ${r.status} ${r.body}`, reproduction) };
  };
  return { h, token, addUser, loginAs, ctx: { req } };
}

export const probes: Probe[] = [
  {
    id: "notes-list-canary",
    ruleId: "TENANT-5",
    scenario: "tenant-isolation/canary-does-not-cross",
    oracle: "canary",
    async run({ req, host }) {
      const m = marker();
      const reproduction = `Plant ${m} in tenant A via POST /notes (Host: ${host("canary-a")}). Then GET /notes with Host: ${host("canary-b")} and scan the body for the marker.`;
      const planted = await req(host("canary-a"), "POST", "/notes", { body: json({ text: m }) });
      const broken = requireSetup(planted, "planting the marker as tenant A", reproduction);
      if (broken) return broken;
      const r = await req(host("canary-b"), "GET", "/notes");
      const brokenRead = requireSetup(r, "reading tenant B's notes (a 4xx or 5xx would read as 'marker absent')", reproduction);
      if (brokenRead) return brokenRead;
      return { ...canaryOracle(m, [{ where: "GET /notes as tenant B", response: r }]), reproduction };
    },
  },
  {
    id: "cache-canary",
    ruleId: "TENANT-5",
    scenario: "tenant-isolation/canary-does-not-cross",
    oracle: "canary",
    async run({ req, host }) {
      const m = marker();
      const reproduction = `Plant ${m} in tenant A, GET /summary as A, then GET /summary with Host: ${host("cache-b")} and scan for the marker.`;
      const planted = await req(host("cache-a"), "POST", "/notes", { body: json({ text: m }) });
      const brokenPlant = requireSetup(planted, "planting the marker as tenant A", reproduction);
      if (brokenPlant) return brokenPlant;
      const warmed = await req(host("cache-a"), "GET", "/summary"); // warm any cache with tenant A's view
      const brokenWarm = requireSetup(warmed, "warming the cache as tenant A", reproduction);
      if (brokenWarm) return brokenWarm;
      const r = await req(host("cache-b"), "GET", "/summary");
      const brokenRead = requireSetup(r, "reading tenant B's summary (a 4xx or 5xx would read as 'marker absent')", reproduction);
      if (brokenRead) return brokenRead;
      return { ...canaryOracle(m, [{ where: "GET /summary as tenant B after tenant A warmed it", response: r }]), reproduction };
    },
  },
  {
    id: "add-tenant-metamorphic",
    ruleId: "TENANT-4",
    scenario: "tenant-isolation/adding-tenant-is-invisible",
    oracle: "metamorphic",
    async run({ req, host }) {
      const run = randomBytes(4).toString("hex");
      const a = host(`meta-a-${run}`);
      const b = host(`meta-b-${run}`);
      const reproduction = `As ${a}: POST a note, GET /notes. Then create tenant ${b} by POSTing a note there. GET /notes as ${a} again; the two responses must be identical.`;
      const plantedA = await req(a, "POST", "/notes", { body: json({ text: `a-note-${run}` }) });
      const brokenA = requireSetup(plantedA, `creating tenant ${a}`, reproduction);
      if (brokenA) return brokenA;
      const before = await req(a, "GET", "/notes");
      const brokenBefore = requireSetup(before, `reading ${a}'s notes`, reproduction);
      if (brokenBefore) return brokenBefore;
      const createdB = await req(b, "POST", "/notes", { body: json({ text: `b-note-${run}` }) }); // tenant B appears and writes
      const brokenB = requireSetup(createdB, `creating tenant ${b}`, reproduction);
      if (brokenB) return brokenB;
      const after = await req(a, "GET", "/notes");
      const brokenAfter = requireSetup(after, `re-reading ${a}'s notes`, reproduction);
      if (brokenAfter) return brokenAfter;
      return { ...metamorphicOracle(before, after, "tenant A's GET /notes"), reproduction };
    },
  },
  {
    id: "identity-header-differential",
    ruleId: "TENANT-1",
    scenario: "tenant-isolation/identity-from-host-or-session-only",
    oracle: "differential",
    async run({ req, host }) {
      const reproduction = `GET /whoami with Host: ${host("ident-b")}, then repeat it once per extra input naming tenant ident-a: headers x-tenant, x-tenant-id, x-forwarded-host, x-original-host, x-host, forwarded: host=${host("ident-a")}, and a ?tenant=ident-a query. Every response must be identical to the plain one.`;
      const plain = await req(host("ident-b"), "GET", "/whoami");
      const brokenPlain = requireSetup(plain, "GET /whoami as tenant B", reproduction);
      if (brokenPlain) return brokenPlain;
      const a = host("ident-a");
      const variants: { name: string; path: string; headers: Record<string, string> }[] = [
        { name: "x-tenant", path: "/whoami", headers: { "x-tenant": "ident-a" } },
        { name: "x-tenant-id", path: "/whoami", headers: { "x-tenant-id": "ident-a" } },
        { name: "x-forwarded-host", path: "/whoami", headers: { "x-forwarded-host": a } },
        { name: "x-original-host", path: "/whoami", headers: { "x-original-host": a } },
        { name: "x-host", path: "/whoami", headers: { "x-host": a } },
        { name: "forwarded", path: "/whoami", headers: { forwarded: `host=${a}` } },
        { name: "?tenant= query", path: "/whoami?tenant=ident-a", headers: {} },
      ];
      const checks: { name: string; ok: boolean; detail: string }[] = [];
      for (const v of variants) {
        const r = await req(host("ident-b"), "GET", v.path, { headers: v.headers });
        const brokenRead = requireSetup(r, `GET /whoami with ${v.name}`, reproduction);
        if (brokenRead) return brokenRead;
        const d = differentialOracle(plain, r, `GET /whoami with and without ${v.name}`);
        checks.push({ name: `${v.name} changes nothing`, ok: d.passed, detail: d.evidence });
      }
      return { ...specOracle(checks), reproduction };
    },
  },
  {
    id: "forged-signature",
    ruleId: "BILL-2",
    scenario: "messaging/forged-and-replayed-webhooks",
    oracle: "state", // verdict hinges on tenant state (plan) staying unchanged, plus a spec status check
    async run({ req, host, webhookSecret }) {
      const t = host("hook-a");
      const body = json({ plan: "pro" });
      const planBefore = await req(t, "GET", "/plan");
      const forged = await req(t, "POST", "/webhooks/billing", { body, headers: { "x-signature": createHmac("sha256", "not-the-secret").update(body).digest("hex") } });
      // Not applicable only when BOTH the plan route and the webhook route are absent; one 404 alone (an unprovisioned tenant host, a plan served elsewhere) proves nothing.
      if (planBefore.status === 404 && forged.status === 404) return skip("target has no billing routes (GET /plan and POST /webhooks/billing are both 404)", `GET /plan and a forged POST /webhooks/billing on Host: ${t} both answered 404, so the billing routes are absent and BILL-2 does not apply.`);
      const plan = await req(t, "GET", "/plan");
      const genuine = await req(t, "POST", "/webhooks/billing", { body: json({ plan: "free" }), headers: { "x-signature": createHmac("sha256", webhookSecret).update(json({ plan: "free" })).digest("hex") } });
      return {
        ...specOracle([
          { name: "forged webhook rejected", ok: forged.status >= 400 && forged.status < 500, detail: `HTTP ${forged.status}` },
          { name: "plan unchanged after forged webhook", ok: plan.body.includes('"free"'), detail: plan.body },
          { name: "genuine webhook still accepted", ok: genuine.status === 200, detail: `HTTP ${genuine.status}` },
        ]),
        reproduction: `POST /webhooks/billing {"plan":"pro"} to Host: ${t} signed with a wrong key. Expect a 4xx and GET /plan to remain "free". Replay and out-of-order delivery are not yet probed.`,
      };
    },
  },
  {
    id: "no-default-role",
    ruleId: "AUTH-1",
    scenario: "auth/no-default-role",
    oracle: "differential",
    async run({ req, host }) {
      const h = host("authz-none");
      const reproduction = `GET /private/member on ${h} with no credential, then with a forged session cookie, then with a forged bearer key. All three must be 401 and identical.`;
      const none = await req(h, "GET", "/private/member");
      const cookie = await req(h, "GET", "/private/member", withCookie(`bks_${"A".repeat(43)}`));
      const bearer = await req(h, "GET", "/private/member", { headers: { authorization: `Bearer bkk_${"0".repeat(16)}_${"A".repeat(43)}` } });
      for (const [what, r] of [["no credential", none], ["a forged cookie", cookie], ["a forged bearer key", bearer]] as const)
        if (r.status !== 401) return fail(`${what} was not denied: HTTP ${r.status} ${r.body}`, reproduction);
      const a = differentialOracle(none, cookie, "no credential vs forged cookie");
      return a.passed ? { ...differentialOracle(none, bearer, "no credential vs forged bearer"), reproduction } : { ...a, reproduction };
    },
  },
  {
    id: "session-rotation",
    ruleId: "AUTH-2",
    scenario: "session/rotation-revocation-and-cookie-flags",
    oracle: "state",
    async run(ctx) {
      const { req } = ctx;
      const reproduction = "Log in presenting an attacker-chosen session cookie; the issued session must differ from it. Log in again presenting the first session; it must stop working.";
      const t = await ownerTenant(ctx, "rot", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h, token } = t as Extract<typeof t, { h: string }>;
      const chosen = `bks_${"B".repeat(43)}`;
      const fixated = await req(h, "POST", "/auth/login", { ...withCookie(chosen), body: json({ email: "owner@probe.test", password: PASSWORD }) });
      const issued = sessionOf(fixated);
      const second = await req(h, "POST", "/auth/login", { ...withCookie(token), body: json({ email: "owner@probe.test", password: PASSWORD }) });
      const rotated = sessionOf(second);
      const oldNow = await req(h, "GET", "/private/member", withCookie(token));
      const newNow = rotated ? await req(h, "GET", "/private/member", withCookie(rotated)) : undefined;
      return {
        ...specOracle([
          { name: "login ignores a client-chosen session token", ok: !!issued && issued !== chosen, detail: `issued ${issued ?? "none"}` },
          { name: "login while holding a session issues a different one", ok: !!rotated && rotated !== token, detail: `rotated ${rotated ?? "none"}` },
          { name: "the presented session no longer works after login", ok: oldNow.status === 401, detail: `HTTP ${oldNow.status}` },
          { name: "the new session works", ok: newNow?.status === 200, detail: `HTTP ${newNow?.status}` },
        ]),
        reproduction,
      };
    },
  },
  {
    id: "cookie-flags",
    ruleId: "AUTH-2",
    scenario: "session/rotation-revocation-and-cookie-flags",
    oracle: "state",
    async run(ctx) {
      const reproduction = "Log in and inspect Set-Cookie: it must be Secure, HttpOnly, Path=/ and carry no Domain attribute (host-only).";
      const t = await ownerTenant(ctx, "flags", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h, loginAs } = t as Extract<typeof t, { h: string }>;
      const login = await loginAs("owner@probe.test");
      if ("error" in login) return login.error!;
      const cookie = setCookies(login.res).find((c) => c.startsWith(`${SESSION_COOKIE}=`)) ?? "";
      const attrs = cookie.split(";").slice(1).map((a) => a.trim().toLowerCase());
      return {
        ...specOracle([
          { name: "Secure", ok: attrs.includes("secure"), detail: cookie },
          { name: "HttpOnly", ok: attrs.includes("httponly"), detail: cookie },
          { name: "Path=/", ok: attrs.includes("path=/"), detail: cookie },
          { name: "no Domain attribute (host-only)", ok: !attrs.some((a) => a.startsWith("domain=")), detail: cookie },
          { name: "SameSite set", ok: attrs.some((a) => /^samesite=(lax|strict)$/.test(a)), detail: cookie },
        ]),
        reproduction: `${reproduction} (tenant ${h})`,
      };
    },
  },
  {
    id: "logout-revokes",
    ruleId: "AUTH-2",
    scenario: "session/rotation-revocation-and-cookie-flags",
    oracle: "state",
    async run(ctx) {
      const { req } = ctx;
      const reproduction = "Log in, GET /private/member (200), POST /auth/logout, then GET /private/member with the same cookie: it must be 401.";
      const t = await ownerTenant(ctx, "logout", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h, token } = t as Extract<typeof t, { h: string }>;
      const before = await req(h, "GET", "/private/member", withCookie(token));
      const out = await req(h, "POST", "/auth/logout", cookieWrite(h, token));
      const after = await req(h, "GET", "/private/member", withCookie(token));
      return {
        ...specOracle([
          { name: "session worked before logout", ok: before.status === 200, detail: `HTTP ${before.status}` },
          { name: "logout succeeds", ok: out.status === 200, detail: `HTTP ${out.status}` },
          { name: "session is dead after logout", ok: after.status === 401, detail: `HTTP ${after.status} ${after.body}` },
        ]),
        reproduction,
      };
    },
  },
  {
    id: "role-change-revokes",
    ruleId: "AUTH-2",
    scenario: "session/rotation-revocation-and-cookie-flags",
    oracle: "state",
    async run(ctx) {
      const { req } = ctx;
      const reproduction = "Create a member, log them in, have the owner change their role to admin, then use the member's old cookie: it must be 401.";
      const t = await ownerTenant(ctx, "rolechg", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h, token, addUser, loginAs } = t as Extract<typeof t, { h: string }>;
      const added = await addUser("m@probe.test", "member");
      if ("error" in added) return added.error!;
      const m = await loginAs("m@probe.test");
      if ("error" in m) return m.error!;
      const before = await req(h, "GET", "/private/member", withCookie(m.token));
      const changed = await req(h, "PATCH", `/users/${added.id}/role`, { ...cookieWrite(h, token), body: json({ role: "admin" }) });
      const after = await req(h, "GET", "/private/member", withCookie(m.token));
      return {
        ...specOracle([
          { name: "member session worked", ok: before.status === 200, detail: `HTTP ${before.status}` },
          { name: "role change accepted", ok: changed.status === 200, detail: `HTTP ${changed.status} ${changed.body}` },
          { name: "old session is dead after role change", ok: after.status === 401, detail: `HTTP ${after.status}` },
        ]),
        reproduction,
      };
    },
  },
  {
    id: "role-matrix",
    ruleId: "AUTH-3",
    scenario: "auth/role-differential",
    oracle: "differential",
    async run(ctx) {
      const { req } = ctx;
      const reproduction = "Sign in as owner, admin and member on one tenant and GET /private/member, /private/admin, /private/owner. Outcomes must match the route policies (member: 200/403/403, admin: 200/200/403, owner: 200/200/200).";
      const t = await ownerTenant(ctx, "matrix", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h, token, addUser, loginAs } = t as Extract<typeof t, { h: string }>;
      const sessions: Record<string, string> = { owner: token };
      for (const role of ["admin", "member"]) {
        const added = await addUser(`${role}@probe.test`, role);
        if ("error" in added) return added.error!;
        const l = await loginAs(`${role}@probe.test`);
        if ("error" in l) return l.error!;
        sessions[role] = l.token;
      }
      const routes = ["/private/member", "/private/admin", "/private/owner"];
      const observed: Record<string, Record<string, number>> = {};
      for (const [actor, tok] of Object.entries(sessions)) {
        observed[actor] = {};
        for (const route of routes) observed[actor][route] = (await req(h, "GET", route, withCookie(tok))).status;
      }
      const allow = (...r: boolean[]) => Object.fromEntries(routes.map((route, i) => [route, r[i] as boolean]));
      return { ...roleDifferentialOracle(observed, { member: allow(true, false, false), admin: allow(true, true, false), owner: allow(true, true, true) }), reproduction };
    },
  },
  {
    id: "api-key-scope",
    ruleId: "AUTH-4",
    scenario: "auth/api-key-scope",
    oracle: "spec",
    async run(ctx) {
      const { req, host } = ctx;
      const reproduction = "As owner, mint an admin-role key with only the private:read permission. It must reach /private/member, be refused on /private/admin (lacks the permission) and /private/owner (role), be refused on another tenant, never appear in GET /api-keys.";
      const t = await ownerTenant(ctx, "keys", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h, token } = t as Extract<typeof t, { h: string }>;
      const made = await req(h, "POST", "/api-keys", { ...cookieWrite(h, token), body: json({ name: "probe", role: "admin", permissions: ["private:read"] }) });
      const broken = requireSetup(made, "minting a scoped key", reproduction);
      if (broken) return broken;
      const key = (JSON.parse(made.body) as { key: string }).key;
      const bearer = { headers: { authorization: `Bearer ${key}` } };
      const other = await ownerTenant(ctx, "keys-other", reproduction);
      if ("error" in other && other.error) return other.error;
      const otherHost = (other as Extract<typeof other, { h: string }>).h;
      const [member, admin, owner, elsewhere, listing] = await Promise.all([
        req(h, "GET", "/private/member", bearer),
        req(h, "GET", "/private/admin", bearer),
        req(h, "GET", "/private/owner", bearer),
        req(otherHost, "GET", "/private/member", bearer),
        req(h, "GET", "/api-keys", withCookie(token)),
      ]);
      const secret = key.slice("bkk_".length + 16 + 1); // base64url secrets may contain "_", so never split on it
      void host;
      return {
        ...specOracle([
          { name: "key reaches the route its permission names", ok: member.status === 200, detail: `HTTP ${member.status}` },
          { name: "key is refused where it lacks the permission, even though its role would allow it", ok: admin.status === 403, detail: `HTTP ${admin.status}` },
          { name: "key is refused above its role", ok: owner.status === 403, detail: `HTTP ${owner.status}` },
          { name: "key is refused on another tenant", ok: elsewhere.status === 401, detail: `HTTP ${elsewhere.status}` },
          { name: "key secret never appears in the key listing", ok: listing.status === 200 && !listing.body.includes(secret), detail: `HTTP ${listing.status}` },
        ]),
        reproduction,
      };
    },
  },
  {
    id: "cross-tenant-session",
    ruleId: "AUTH-2",
    scenario: "session/rotation-revocation-and-cookie-flags",
    oracle: "state",
    async run(ctx) {
      const { req } = ctx;
      const reproduction = "Sign in on tenant A, then present tenant A's session cookie on tenant B's hostname: it must be 401. The session must keep working on tenant A.";
      const a = await ownerTenant(ctx, "xten-a", reproduction);
      if ("error" in a && a.error) return a.error;
      const b = await ownerTenant(ctx, "xten-b", reproduction);
      if ("error" in b && b.error) return b.error;
      const { h: ha, token: ta } = a as Extract<typeof a, { h: string }>;
      const { h: hb } = b as Extract<typeof b, { h: string }>;
      const onA = await req(ha, "GET", "/private/member", withCookie(ta));
      const onB = await req(hb, "GET", "/private/member", withCookie(ta));
      return {
        ...specOracle([
          { name: "session works on the tenant that issued it", ok: onA.status === 200, detail: `HTTP ${onA.status}` },
          { name: "session is refused on another tenant", ok: onB.status === 401, detail: `HTTP ${onB.status} ${onB.body}` },
        ]),
        reproduction,
      };
    },
  },
  {
    id: "csrf-origin",
    ruleId: "AUTH-2",
    scenario: "session/rotation-revocation-and-cookie-flags",
    oracle: "state",
    async run(ctx) {
      const { req } = ctx;
      const reproduction = "POST /api-keys with a session cookie and a cross-origin Origin (or no Origin and no Sec-Fetch-Site): the write must be 401. The same write with the tenant's own Origin, or with Sec-Fetch-Site: same-origin, must succeed (201).";
      const t = await ownerTenant(ctx, "csrf", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h, token } = t as Extract<typeof t, { h: string }>;
      const key = (csrf: Record<string, string>) => ({ headers: { cookie: `${SESSION_COOKIE}=${token}`, ...csrf }, body: json({ name: "csrf-probe", permissions: ["self:read"] }) });
      const crossOrigin = await req(h, "POST", "/api-keys", key({ origin: "http://evil.example" }));
      const ownOrigin = await req(h, "POST", "/api-keys", key({ origin: `http://${h}` }));
      const noHeaders = await req(h, "POST", "/api-keys", key({}));
      const secFetch = await req(h, "POST", "/api-keys", key({ "sec-fetch-site": "same-origin" }));
      return {
        ...specOracle([
          { name: "cross-origin cookie write is refused", ok: crossOrigin.status === 401, detail: `HTTP ${crossOrigin.status}` },
          { name: "same-origin cookie write is allowed", ok: ownOrigin.status === 201, detail: `HTTP ${ownOrigin.status} ${ownOrigin.body}` },
          { name: "cookie write with neither Origin nor Sec-Fetch-Site is refused", ok: noHeaders.status === 401, detail: `HTTP ${noHeaders.status}` },
          { name: "Sec-Fetch-Site: same-origin is accepted without Origin", ok: secFetch.status === 201, detail: `HTTP ${secFetch.status} ${secFetch.body}` },
        ]),
        reproduction,
      };
    },
  },
  {
    id: "authority-matrix",
    ruleId: "AUTH-3",
    scenario: "auth/role-differential",
    oracle: "differential",
    async run(ctx) {
      const { req } = ctx;
      const reproduction = "On one tenant, sign in as member, admin and owner and compare GET /users, GET /api-keys and POST /users {role:owner}. Policy says: member is refused on all three; admin may list but not grant owner; owner may do all three.";
      const t = await ownerTenant(ctx, "authority", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h, token, addUser, loginAs } = t as Extract<typeof t, { h: string }>;
      const sessions: Record<string, string> = { owner: token };
      for (const role of ["admin", "member"]) {
        const added = await addUser(`${role}@probe.test`, role);
        if ("error" in added) return added.error!;
        const l = await loginAs(`${role}@probe.test`);
        if ("error" in l) return l.error!;
        sessions[role] = l.token;
      }
      const norm = (s: number) => (s >= 200 && s < 300 ? 200 : s); // roleDifferentialOracle reads allowed as 200; a create is 201
      const routes = ["GET /users", "GET /api-keys", "POST /users role=owner"];
      const observed: Record<string, Record<string, number>> = {};
      for (const [actor, tok] of Object.entries(sessions)) {
        const create = await req(h, "POST", "/users", { ...cookieWrite(h, tok), body: json({ email: `${actor}-grant@probe.test`, password: PASSWORD, role: "owner" }) });
        observed[actor] = {
          "GET /users": (await req(h, "GET", "/users", withCookie(tok))).status,
          "GET /api-keys": (await req(h, "GET", "/api-keys", withCookie(tok))).status,
          "POST /users role=owner": norm(create.status),
        };
      }
      const allow = (...r: boolean[]) => Object.fromEntries(routes.map((route, i) => [route, r[i] as boolean]));
      return { ...roleDifferentialOracle(observed, { member: allow(false, false, false), admin: allow(true, true, false), owner: allow(true, true, true) }), reproduction };
    },
  },
  {
    id: "key-revocation",
    ruleId: "AUTH-4",
    scenario: "auth/api-key-scope",
    oracle: "spec",
    async run(ctx) {
      const { req } = ctx;
      const reproduction = "As owner, create an admin and mint a key as that admin. DELETE /api-keys/:id must revoke it (401). Mint a second key as the admin, have the owner demote the admin, and that key must also stop working (401).";
      const t = await ownerTenant(ctx, "revoke", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h, token, addUser, loginAs } = t as Extract<typeof t, { h: string }>;
      const added = await addUser("revoker@probe.test", "admin");
      if ("error" in added) return added.error!;
      const admin = await loginAs("revoker@probe.test");
      if ("error" in admin) return admin.error!;
      const mint = async () => {
        const r = await req(h, "POST", "/api-keys", { ...cookieWrite(h, admin.token), body: json({ name: "probe", role: "admin", permissions: ["private:admin"] }) });
        const broken = requireSetup(r, "minting a key as the admin", reproduction);
        if (broken) return { error: broken } as const;
        return JSON.parse(r.body) as { id: string; key: string };
      };
      const bearer = (key: string) => ({ headers: { authorization: `Bearer ${key}` } });

      const first = await mint();
      if ("error" in first) return first.error;
      const firstWorks = await req(h, "GET", "/private/admin", bearer(first.key));
      const revoked = await req(h, "DELETE", `/api-keys/${first.id}`, cookieWrite(h, token));
      const firstDead = await req(h, "GET", "/private/admin", bearer(first.key));

      const second = await mint();
      if ("error" in second) return second.error;
      const secondWorks = await req(h, "GET", "/private/admin", bearer(second.key));
      const demoted = await req(h, "PATCH", `/users/${added.id}/role`, { ...cookieWrite(h, token), body: json({ role: "member" }) });
      const secondDead = await req(h, "GET", "/private/admin", bearer(second.key));

      return {
        ...specOracle([
          { name: "key works before it is revoked", ok: firstWorks.status === 200, detail: `HTTP ${firstWorks.status}` },
          { name: "DELETE /api-keys/:id revokes the key", ok: revoked.status === 200, detail: `HTTP ${revoked.status} ${revoked.body}` },
          { name: "revoked key is refused", ok: firstDead.status === 401, detail: `HTTP ${firstDead.status}` },
          { name: "second key works before the minter is demoted", ok: secondWorks.status === 200, detail: `HTTP ${secondWorks.status}` },
          { name: "demoting the minter is accepted", ok: demoted.status === 200, detail: `HTTP ${demoted.status} ${demoted.body}` },
          { name: "key of a demoted minter is refused", ok: secondDead.status === 401, detail: `HTTP ${secondDead.status}` },
        ]),
        reproduction,
      };
    },
  },
  {
    id: "disabled-user-denied",
    ruleId: "AUTH-2",
    scenario: "session/rotation-revocation-and-cookie-flags",
    oracle: "state",
    async run(ctx) {
      const { req } = ctx;
      const reproduction = "Create a member and log them in. Have the owner DELETE /users/:id. The member's old cookie must be 401, and a fresh POST /auth/login with the right password must be the same 401 as a wrong password.";
      const t = await ownerTenant(ctx, "disabled", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h, token, addUser, loginAs } = t as Extract<typeof t, { h: string }>;
      const added = await addUser("gone@probe.test", "member");
      if ("error" in added) return added.error!;
      const m = await loginAs("gone@probe.test");
      if ("error" in m) return m.error!;
      const before = await req(h, "GET", "/private/member", withCookie(m.token));
      const disabled = await req(h, "DELETE", `/users/${added.id}`, cookieWrite(h, token));
      const oldSession = await req(h, "GET", "/private/member", withCookie(m.token));
      const relogin = await req(h, "POST", "/auth/login", { body: json({ email: "gone@probe.test", password: PASSWORD }) });
      const wrong = await req(h, "POST", "/auth/login", { body: json({ email: "gone@probe.test", password: `${PASSWORD}-wrong` }) });
      return {
        ...specOracle([
          { name: "member session worked before disabling", ok: before.status === 200, detail: `HTTP ${before.status}` },
          { name: "disabling the member is accepted", ok: disabled.status === 200, detail: `HTTP ${disabled.status} ${disabled.body}` },
          { name: "old session is dead after disabling", ok: oldSession.status === 401, detail: `HTTP ${oldSession.status}` },
          { name: "wrong password is refused with 401 (baseline)", ok: wrong.status === 401, detail: `HTTP ${wrong.status} ${wrong.body}` },
          { name: "disabled user's correct password is refused with the same 401 and body as a wrong password", ok: relogin.status === 401 && relogin.status === wrong.status && relogin.body === wrong.body && !sessionOf(relogin), detail: `HTTP ${relogin.status} ${relogin.body} vs wrong password HTTP ${wrong.status} ${wrong.body}` },
        ]),
        reproduction,
      };
    },
  },
  {
    id: "key-wrong-secret-denied",
    ruleId: "AUTH-4",
    scenario: "auth/api-key-scope",
    oracle: "spec",
    async run(ctx) {
      const { req } = ctx;
      const reproduction = "As owner, mint a member key with private:read. The real key reaches /private/member. Then present 'Bearer bkk_<real id>_<43 wrong base64url chars>' with a random secret and near-misses (the real secret with its first, middle or last character changed, truncated by one or to half, one character appended, a long suffix appended): each must be 401, identical to a key with an unknown id.";
      const t = await ownerTenant(ctx, "keysecret", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h, token } = t as Extract<typeof t, { h: string }>;
      const made = await req(h, "POST", "/api-keys", { ...cookieWrite(h, token), body: json({ name: "probe", role: "member", permissions: ["private:read"] }) });
      const broken = requireSetup(made, "minting a key", reproduction);
      if (broken) return broken;
      const { id, key } = JSON.parse(made.body) as { id: string; key: string };
      const bearer = (k: string) => ({ headers: { authorization: `Bearer ${k}` } });
      const real = await req(h, "GET", "/private/member", bearer(key));
      const brokenReal = requireSetup(real, "presenting the real key", reproduction);
      if (brokenReal) return brokenReal;
      const secret = key.slice("bkk_".length + 16 + 1);
      const flipAt = (i: number) => `${secret.slice(0, i)}${secret[i] === "A" ? "B" : "A"}${secret.slice(i + 1)}`;
      const unknown = await req(h, "GET", "/private/member", bearer(`bkk_${randomBytes(8).toString("hex")}_${randomBytes(32).toString("base64url")}`));
      const variants: { name: string; secret: string }[] = [
        { name: "a random wrong secret", secret: randomBytes(32).toString("base64url") },
        { name: "the real secret's last character changed", secret: flipAt(secret.length - 1) },
        { name: "the real secret's first character changed", secret: flipAt(0) },
        { name: "the real secret's middle character changed", secret: flipAt(Math.floor(secret.length / 2)) },
        { name: "the real secret truncated by one character", secret: secret.slice(0, -1) },
        { name: "the real secret truncated to half its length", secret: secret.slice(0, Math.floor(secret.length / 2)) },
        { name: "the real secret with one extra character appended", secret: `${secret}A` },
        { name: "the real secret with a long suffix appended", secret: `${secret}${randomBytes(32).toString("base64url")}` },
      ];
      const answers = await Promise.all(variants.map(async (v) => ({ ...v, res: await req(h, "GET", "/private/member", bearer(`bkk_${id}_${v.secret}`)) })));
      return {
        ...specOracle([
          { name: "unknown key id is refused (baseline)", ok: unknown.status === 401, detail: `HTTP ${unknown.status} ${unknown.body}` },
          ...answers.flatMap((a) => [
            { name: `real id with ${a.name} is refused with 401`, ok: a.res.status === 401, detail: `HTTP ${a.res.status} ${a.res.body}` },
            { name: `real id with ${a.name} answers exactly like an unknown id`, ok: differentialOracle(unknown, a.res, a.name).passed, detail: differentialOracle(unknown, a.res, a.name).evidence },
          ]),
        ]),
        reproduction,
      };
    },
  },
  {
    id: "bootstrap-token-required",
    ruleId: "AUTH-1",
    scenario: "auth/no-default-role",
    oracle: "differential",
    async run({ req, host, bootstrapToken }) {
      const reproduction = "On a fresh empty tenant, POST /auth/bootstrap with a wrong token, a near-miss token (the real one with its last character changed) and no token: each must be 403 and create no user. Then the correct token (same email) must still return 201, proving the wrong attempts did not claim the tenant.";
      if (!bootstrapToken) return fail("no bootstrap token configured for this target (set BULKHEAD_VERIFY_BOOTSTRAP_TOKEN); auth probes cannot run", reproduction);
      const h = host(`boot-${randomBytes(3).toString("hex")}`);
      const squatter = { email: "squatter@probe.test", password: PASSWORD };
      const nearMiss = `${bootstrapToken.slice(0, -1)}${bootstrapToken.endsWith("0") ? "1" : "0"}`;
      const wrong = await req(h, "POST", "/auth/bootstrap", { body: json({ ...squatter, token: `wrong-${randomBytes(16).toString("hex")}` }) });
      const near = await req(h, "POST", "/auth/bootstrap", { body: json({ ...squatter, token: nearMiss }) });
      const none = await req(h, "POST", "/auth/bootstrap", { body: json(squatter) });
      // Same email as the refused attempts: if any of them had created the user, this would be a 409, not a 201.
      const real = await req(h, "POST", "/auth/bootstrap", { body: json({ ...squatter, token: bootstrapToken }) });
      return {
        ...specOracle([
          { name: "wrong token is refused with 403", ok: wrong.status === 403, detail: `HTTP ${wrong.status} ${wrong.body}` },
          { name: "near-miss token is refused with 403", ok: near.status === 403, detail: `HTTP ${near.status} ${near.body}` },
          { name: "missing token is refused with 403", ok: none.status === 403, detail: `HTTP ${none.status} ${none.body}` },
          { name: "the correct token still claims the tenant afterwards, so no refused attempt created a user", ok: real.status === 201, detail: `HTTP ${real.status} ${real.body}` },
        ]),
        reproduction,
      };
    },
  },
  {
    id: "bootstrap-claims-once",
    ruleId: "AUTH-1",
    scenario: "auth/no-default-role",
    oracle: "differential",
    async run(ctx) {
      const { req, bootstrapToken } = ctx;
      const reproduction = "Bootstrap an owner on a fresh tenant. POST /auth/bootstrap again with the CORRECT token and another email: it must be 409, the first owner's session must still be owner, and GET /users must list exactly one owner and one user.";
      const t = await ownerTenant(ctx, "claimonce", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h, token } = t as Extract<typeof t, { h: string }>;
      const second = await req(h, "POST", "/auth/bootstrap", { body: json({ token: bootstrapToken, email: "second-owner@probe.test", password: PASSWORD }) });
      const stillOwner = await req(h, "GET", "/private/owner", withCookie(token));
      const listing = await req(h, "GET", "/users", withCookie(token));
      const brokenList = requireSetup(listing, "listing users as the first owner", reproduction);
      if (brokenList) return brokenList;
      const users = (JSON.parse(listing.body) as { users: { role: string }[] }).users;
      return {
        ...specOracle([
          { name: "a second bootstrap with the correct token is refused with 409", ok: second.status === 409, detail: `HTTP ${second.status} ${second.body}` },
          { name: "the first owner's session still has the owner role", ok: stillOwner.status === 200, detail: `HTTP ${stillOwner.status}` },
          { name: "GET /users lists exactly one owner", ok: users.filter((u) => u.role === "owner").length === 1, detail: `${users.filter((u) => u.role === "owner").length} owner(s)` },
          { name: "GET /users lists exactly one user", ok: users.length === 1, detail: `${users.length} user(s)` },
        ]),
        reproduction,
      };
    },
  },
  {
    id: "role-change-authority",
    ruleId: "AUTH-3",
    scenario: "auth/role-differential",
    oracle: "differential",
    async run(ctx) {
      const { req } = ctx;
      const reproduction = "Create a second owner (so 'last owner' protection cannot mask anything) and an admin. As the admin, first POST /users {role:member} with the same cookie and headers (positive control, must be 201). Then PATCH /users/<admin id>/role {role:owner}, PATCH /users/<first owner id>/role {role:member} and DELETE /users/<first owner id> must each be 403. Afterwards the first owner is still an enabled owner and the admin is still an admin.";
      const t = await ownerTenant(ctx, "roleauth", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h, token, addUser, loginAs } = t as Extract<typeof t, { h: string }>;
      const owner2 = await addUser("owner2@probe.test", "owner");
      if ("error" in owner2) return owner2.error!;
      const added = await addUser("climber@probe.test", "admin");
      if ("error" in added) return added.error!;
      const admin = await loginAs("climber@probe.test");
      if ("error" in admin) return admin.error!;
      type Listed = { id: string; email: string; role: string; disabled?: number };
      const list = async () => {
        const r = await req(h, "GET", "/users", withCookie(token));
        const broken = requireSetup(r, "listing users as the owner", reproduction);
        return broken ? { error: broken } : { users: (JSON.parse(r.body) as { users: Listed[] }).users };
      };
      const before = await list();
      if ("error" in before) return before.error!;
      const owner = before.users.find((u) => u.email === "owner@probe.test");
      if (!owner || owner.role !== "owner") return fail("setup: the first owner is not listed with role owner", reproduction);

      // Positive control: the same admin cookie through the same cookieWrite helper must be able to do an allowed write,
      // so the 403s below cannot be the answer of some other gate (CSRF/origin, session) that would refuse everything.
      const control = await req(h, "POST", "/users", { ...cookieWrite(h, admin.token), body: json({ email: "control-member@probe.test", password: PASSWORD, role: "member" }) });
      const selfUp = await req(h, "PATCH", `/users/${added.id}/role`, { ...cookieWrite(h, admin.token), body: json({ role: "owner" }) });
      const demoteOwner = await req(h, "PATCH", `/users/${owner.id}/role`, { ...cookieWrite(h, admin.token), body: json({ role: "member" }) });
      const removeOwner = await req(h, "DELETE", `/users/${owner.id}`, cookieWrite(h, admin.token));

      const after = await list();
      if ("error" in after) return after.error!;
      const ownerAfter = after.users.find((u) => u.id === owner.id);
      const adminAfter = after.users.find((u) => u.id === added.id);
      const ownerRoute = await req(h, "GET", "/private/owner", withCookie(token));
      return {
        ...specOracle([
          { name: "positive control: the same admin cookie can POST /users to create a member (201), so the denials below come from the authority rule", ok: control.status === 201, detail: `HTTP ${control.status} ${control.body}` },
          { name: "admin cannot PATCH their own role to owner", ok: selfUp.status === 403, detail: `HTTP ${selfUp.status} ${selfUp.body}` },
          { name: "admin cannot PATCH the owner's role", ok: demoteOwner.status === 403, detail: `HTTP ${demoteOwner.status} ${demoteOwner.body}` },
          { name: "admin cannot DELETE the owner", ok: removeOwner.status === 403, detail: `HTTP ${removeOwner.status} ${removeOwner.body}` },
          { name: "the owner is still an enabled owner", ok: ownerAfter?.role === "owner" && !ownerAfter.disabled, detail: JSON.stringify(ownerAfter) },
          { name: "the owner's session still reaches the owner route", ok: ownerRoute.status === 200, detail: `HTTP ${ownerRoute.status}` },
          { name: "the admin is still an admin", ok: adminAfter?.role === "admin", detail: JSON.stringify(adminAfter) },
        ]),
        reproduction,
      };
    },
  },
  {
    id: "key-role-ceiling",
    ruleId: "AUTH-4",
    scenario: "auth/api-key-scope",
    oracle: "spec",
    async run(ctx) {
      const { req } = ctx;
      const reproduction = "As an admin, POST /api-keys {role:owner, permissions:[private:read]} must be 403 and no owner-role key may appear in GET /api-keys. An admin-role key minted by the same admin must be 201 and reach /private/admin.";
      const t = await ownerTenant(ctx, "keyceil", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h, token, addUser, loginAs } = t as Extract<typeof t, { h: string }>;
      const added = await addUser("minter@probe.test", "admin");
      if ("error" in added) return added.error!;
      const admin = await loginAs("minter@probe.test");
      if ("error" in admin) return admin.error!;
      const above = await req(h, "POST", "/api-keys", { ...cookieWrite(h, admin.token), body: json({ name: "probe-owner", role: "owner", permissions: ["private:read"] }) });
      const own = await req(h, "POST", "/api-keys", { ...cookieWrite(h, admin.token), body: json({ name: "probe-admin", role: "admin", permissions: ["private:admin"] }) });
      const brokenOwn = requireSetup(own, "the admin minting an admin-role key", reproduction);
      if (brokenOwn) return brokenOwn;
      const ownWorks = await req(h, "GET", "/private/admin", { headers: { authorization: `Bearer ${(JSON.parse(own.body) as { key: string }).key}` } });
      const listing = await req(h, "GET", "/api-keys", withCookie(token));
      const brokenList = requireSetup(listing, "listing API keys as the owner", reproduction);
      if (brokenList) return brokenList;
      const roles = (JSON.parse(listing.body) as { keys: { role: string }[] }).keys.map((k) => k.role);
      return {
        ...specOracle([
          { name: "an admin cannot mint an owner-role key (403)", ok: above.status === 403, detail: `HTTP ${above.status} ${above.body.replace(/bkk_\S+/g, "bkk_<redacted>")}` },
          { name: "no owner-role key exists afterwards", ok: !roles.includes("owner"), detail: `key roles: ${roles.join(", ")}` },
          { name: "an admin-role key minted by the admin works on /private/admin", ok: ownWorks.status === 200, detail: `HTTP ${ownWorks.status}` },
        ]),
        reproduction,
      };
    },
  },
  {
    id: "listings-hide-secrets",
    ruleId: "AUTH-4",
    scenario: "auth/api-key-scope",
    oracle: "spec",
    async run(ctx) {
      const { req } = ctx;
      const reproduction = "As owner, create an admin and mint two keys. GET /users and GET /api-keys must be 200 and contain none of: pbkdf2, password_hash, secret_hash, password, either minted key's secret, a 64-hex-digit string, 'pbkdf2-sha256$' or a 43-character base64url token.";
      const t = await ownerTenant(ctx, "listing", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h, token, addUser } = t as Extract<typeof t, { h: string }>;
      const added = await addUser("listed@probe.test", "admin");
      if ("error" in added) return added.error!;
      const secrets: string[] = [];
      for (const name of ["probe-1", "probe-2"]) {
        const made = await req(h, "POST", "/api-keys", { ...cookieWrite(h, token), body: json({ name, role: "member", permissions: ["private:read"] }) });
        const broken = requireSetup(made, `minting key ${name}`, reproduction);
        if (broken) return broken;
        secrets.push((JSON.parse(made.body) as { key: string }).key.slice("bkk_".length + 16 + 1));
      }
      const users = await req(h, "GET", "/users", withCookie(token));
      const brokenUsers = requireSetup(users, "GET /users as the owner (a 4xx would read as 'nothing leaked')", reproduction);
      if (brokenUsers) return brokenUsers;
      const keysList = await req(h, "GET", "/api-keys", withCookie(token));
      const brokenKeys = requireSetup(keysList, "GET /api-keys as the owner (a 4xx would read as 'nothing leaked')", reproduction);
      if (brokenKeys) return brokenKeys;
      const needles = ["pbkdf2", "password_hash", "secret_hash", "password"];
      // Shapes of secret material. Legitimate values in a listing never match: ids are UUIDs (36 chars with hyphens) or 16 hex digits,
      // timestamps are numbers, and emails/names contain '@', '.' or are short. A bare 43-char run of [A-Za-z0-9_-] is the shape of a
      // 32-byte base64url key secret or password hash; 64 hex digits is a SHA-256 digest; "$" in a hash breaks the runs, so the prefix is checked on its own.
      const shapes: { label: string; re: RegExp }[] = [
        { label: "a 64-hex-digit string (SHA-256 digest)", re: /[0-9a-f]{64}/i },
        { label: "'pbkdf2-sha256$' (password hash)", re: /pbkdf2-sha256\$/i },
        { label: "a 43-character base64url token (key secret or hash shape)", re: /(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/ },
      ];
      const checks = [{ where: "GET /users", res: users }, { where: "GET /api-keys", res: keysList }].flatMap(({ where, res }) => {
        const body = res.body.toLowerCase();
        return [
          ...needles.map((n) => ({ name: `${where} has no '${n}'`, ok: !body.includes(n), detail: "found in the response body" })),
          ...shapes.map((sh) => ({ name: `${where} has no ${sh.label}`, ok: !sh.re.test(res.body), detail: `matched ${sh.re} in the response body` })),
          ...secrets.map((s, i) => ({ name: `${where} does not contain minted key secret #${i + 1}`, ok: !res.body.includes(s), detail: "the secret reappears in a listing" })),
        ];
      });
      return { ...specOracle(checks), reproduction };
    },
  },
  {
    id: "unknown-email-login-same-answer",
    ruleId: "AUTH-2",
    scenario: "session/rotation-revocation-and-cookie-flags",
    oracle: "state",
    async run(ctx) {
      const { req } = ctx;
      const reproduction = "On a tenant with an owner, POST /auth/login for an unknown email and for the owner's email with a wrong password. Both must be 401 with byte-identical bodies and set no session cookie.";
      const t = await ownerTenant(ctx, "unknownlogin", reproduction);
      if ("error" in t && t.error) return t.error;
      const { h } = t as Extract<typeof t, { h: string }>;
      const wrong = await req(h, "POST", "/auth/login", { body: json({ email: "owner@probe.test", password: `${PASSWORD}-wrong` }) });
      const unknown = await req(h, "POST", "/auth/login", { body: json({ email: `nobody-${randomBytes(3).toString("hex")}@probe.test`, password: PASSWORD }) });
      return {
        ...specOracle([
          { name: "wrong password is refused with 401 (baseline)", ok: wrong.status === 401, detail: `HTTP ${wrong.status} ${wrong.body}` },
          { name: "unknown email is refused with 401 (a 5xx must not read as a pass)", ok: unknown.status === 401, detail: `HTTP ${unknown.status} ${unknown.body}` },
          { name: "unknown email's body is byte-identical to the wrong-password body", ok: unknown.body === wrong.body, detail: `${unknown.body} vs ${wrong.body}` },
          { name: "neither sets a session cookie", ok: !sessionOf(wrong) && !sessionOf(unknown), detail: "a session cookie was set" },
        ]),
        reproduction,
      };
    },
  },
  {
    id: "storage-canary-at-rest",
    ruleId: "CRYPTO-1",
    scenario: "crypto/no-plaintext-at-rest",
    oracle: "canary",
    async run(ctx) {
      const { req, host, persistDir } = ctx;
      const note = marker();
      const withSecret = hasStoreRoute(ctx.routes);
      const reproduction = `Plant ${note} via POST /notes (Host: ${host("atrest-n")}, a classified field) and a second marker via POST /secrets as an owner (needs POST /secrets in the route manifest, else unverified). Plant each twice on the same tenant and check that the persisted-storage directory changed after the second plant. Then open every SQLite file under it read-only and scan every table cell and every raw byte (pages, WAL) for the markers.`;
      if (!persistDir) return unverified("no persisted-storage directory supplied (--persist-dir); a storage read is impossible over HTTP, so CRYPTO-1 is unverified on this target", reproduction);
      const markers = [note];
      const stale: string[] = [];
      let setupError: (Verdict & { reproduction: string }) | undefined;
      const cannotRead = (e: unknown) => unverified(`persisted-storage directory could not be read while checking that the writes landed: ${(e as Error).message}`, reproduction);
      class Unreadable extends Error {}
      const fp = () => { try { return fingerprintStorage(persistDir); } catch (e) { throw new Unreadable((e as Error).message); } };
      /**
       * The first write to a tenant may create its database file, which changes the directory whether or not the value was stored.
       * So plant twice on the same tenant and require the SECOND plant to change the directory.
       */
      const plantTwice = async (label: string, firstMarker: string, plant: (marker: string) => Promise<Response>, what: string) => {
        const first = await plant(firstMarker);
        const broken = requireSetup(first, `planting the ${what} marker`, reproduction);
        if (broken) return { error: broken };
        const second = marker();
        markers.push(second);
        const before = fp();
        const res = await plant(second);
        const brokenSecond = requireSetup(res, `planting the second ${what} marker`, reproduction);
        if (brokenSecond) return { error: brokenSecond };
        if (!storageChanged(before, fp())) stale.push(label);
        return {};
      };
      try {
        const noteHost = host(`atrest-${randomBytes(3).toString("hex")}`);
        const r1 = await plantTwice("notes", note, (m) => req(noteHost, "POST", "/notes", { body: json({ text: m }) }), "classified notes field");
        if (r1.error) return r1.error;
        if (withSecret) {
          // A setup error here must not hide a notes leak: remember it, scan what was planted, report a leak first.
          const t = await ownerTenant(ctx, "atrest-s", reproduction);
          if ("error" in t && t.error) setupError = t.error;
          else {
            const owner = t as Extract<typeof t, { h: string }>;
            const secret = marker();
            markers.push(secret);
            let n = 0;
            const r2 = await plantTwice("secrets", secret, (m) => req(owner.h, "POST", SECRET_STORE.path, { ...cookieWrite(owner.h, owner.token), body: json({ name: `probe-secret-${n++}`, value: m }) }), "secret");
            if (r2.error) setupError = r2.error;
          }
        }
      } catch (e) {
        if (e instanceof Unreadable) return cannotRead(e); // the directory vanished or changed under us mid-run: unverified, never a thrown finding
        throw e;
      }
      let scan;
      try {
        scan = scanStorage(persistDir, markers);
      } catch (e) {
        return unverified(`persisted-storage directory could not be read: ${(e as Error).message}`, reproduction);
      }
      const verdict = storageCanaryOracle(markers, scan);
      if (!verdict.passed) return { ...verdict, reproduction }; // a leak is a finding whatever else is missing
      if (setupError) return setupError;
      if (scan.sqliteOpened === 0) return unverified(`no SQLite database under ${persistDir} after a successful write; wrong directory, or the target does not persist there, so the absence of the marker means nothing`, reproduction);
      if (stale.length) return unverified(`the persisted-storage directory did not change after the second ${stale.join(" and the second ")} plant on the same tenant, so the write did not demonstrably reach the inspected storage (wrong directory, writes dropped or buffered); absence of the marker means nothing`, reproduction);
      if (scan.rowsScanned === 0) return unverified("SQLite databases found but they hold no rows after a successful write; the write did not reach the inspected storage", reproduction);
      if (scan.incomplete.length) return unverified(`the scan was incomplete (${scan.incomplete.join("; ")}); a pass would overstate what was inspected`, reproduction);
      if (!withSecret) return unverified(`only the notes half was checked: the manifest has no ${SECRET_STORE.method} ${SECRET_STORE.path}, so no secret-class field could be planted and CRYPTO-1 is unverified for the secret class`, reproduction);
      return { ...verdict, evidence: `${verdict.evidence}. Classified fields planted: notes, secrets. Not covered: any other classified column, or data written by routes this probe does not call. Storage change is directory-wide, not per tenant.`, reproduction };
    },
  },
  {
    id: "secret-write-only-readback",
    ruleId: "CRYPTO-5",
    scenario: "crypto/tenant-secrets-write-only",
    oracle: "spec",
    async run(ctx) {
      const { req, routes } = ctx;
      const m = marker();
      const reproduction = `Store ${m} via POST /secrets {name, value} as an owner. Then, for every GET route in the committed route manifest (path parameters filled with the secret's name and with its id), request it as that owner and anonymously, and scan every response body and header for the marker. A route counts as read back only if the owner gets a 2xx (a parameter route: :x, {x}, [x] or *, for some fill value); at least one such route must be secret-related (path mentions secrets, or the body carries the stored name or id); otherwise unverified. Only GET/HEAD routes are read; write routes that might echo a secret are not exercised.`;
      if (!routes) return unverified("no route manifest supplied (--route-manifest); the routes to read back through are unknown, so CRYPTO-5 is unverified", reproduction);
      if (!hasStoreRoute(routes)) return unverified(`the manifest has no ${SECRET_STORE.method} ${SECRET_STORE.path}; no way to plant a secret, so CRYPTO-5 is unverified on this target`, reproduction);
      const t = await ownerTenant(ctx, "wo", reproduction);
      if ("error" in t && t.error) return t.error;
      const owner = t as Extract<typeof t, { h: string }>;
      const name = `probe-secret-${randomBytes(3).toString("hex")}`;
      const stored = await req(owner.h, "POST", SECRET_STORE.path, { ...cookieWrite(owner.h, owner.token), body: json({ name, value: m }) });
      const brokenStore = requireSetup(stored, "storing the secret", reproduction);
      if (brokenStore) return brokenStore;
      let id: string | undefined;
      try { const b = JSON.parse(stored.body) as { id?: unknown }; if (typeof b.id === "string") id = b.id; } catch { /* the store response need not be JSON */ }
      const candidates = [name, ...(id ? [id] : [])];
      const seen = (r: Response) => r.body.includes(m) || JSON.stringify(r.headers).includes(m);
      const checks: { name: string; ok: boolean; detail: string }[] = [{ name: `${SECRET_STORE.method} ${SECRET_STORE.path} response`, ok: !seen(stored), detail: "the store response echoes the secret" }];
      const unreadable: string[] = [];
      let exercised = 0;
      let trulyExercised = 0;
      let secretRelated = 0;
      const unreached: string[] = [];
      for (const route of routes.filter((r) => r.method === "GET" || r.method === "HEAD")) {
        const isParam = PARAM.test(route.path);
        const paths = isParam ? candidates.map((c) => route.path.replace(PARAM_ALL, () => encodeURIComponent(c))) : [route.path];
        // A route counts as exercised only on the OWNER's answer. A parameter route needs a 2xx (the lookup ran); a plain route
        // needs anything but 404/405 (the route is there). Anonymous requests are scanned for leaks but never prove coverage.
        let answered = false;
        let related = /secret/i.test(route.path);
        for (const path of paths) for (const [who, opts] of [["owner", withCookie(owner.token)], ["anonymous", {}]] as const) {
          const r = await req(owner.h, route.method, path, opts);
          exercised++;
          if (who === "owner" && r.status >= 200 && r.status < 300) {
            answered = true;
            if (r.body.includes(name) || (id !== undefined && id.length >= 8 && r.body.includes(id))) related = true; // the response carries the stored secret's name or id
          }
          if (r.status >= 500) unreadable.push(`${who} ${route.method} ${path}: HTTP ${r.status}`);
          checks.push({ name: `${who} ${route.method} ${path}`, ok: !seen(r), detail: `the stored secret was returned (HTTP ${r.status})` });
        }
        if (answered) { trulyExercised++; if (related) secretRelated++; }
        else if (isParam) unreached.push(`${route.method} ${route.path}`);
      }
      const verdict = specOracle(checks);
      if (verdict.passed && trulyExercised === 0) return unverified(`no GET/HEAD route in the manifest answered the owner (all 404/405 or absent), so nothing was really read back (${exercised} request(s) sent)`, reproduction);
      if (verdict.passed && unreadable.length) return unverified(`read-back could not be completed, a server error hides what the route would return: ${unreadable.join("; ")}`, reproduction);
      if (verdict.passed && unreached.length) return unverified(`parameter route(s) never gave the owner a 2xx for any fill value tried (the secret's name and id), so the lookup may not have run: ${unreached.join(", ")}`, reproduction);
      if (verdict.passed && secretRelated === 0) return unverified(`${trulyExercised} route(s) answered the owner with a 2xx, but none is secret-related (no path mentions secrets and no response carried the stored secret's name or id), so the places a secret could surface were not read`, reproduction);
      return { ...verdict, evidence: verdict.passed ? `secret absent from the store response and from ${exercised} read-back request(s). Limits: GET/HEAD routes in the manifest only; parameter routes filled with the secret's name and id only; write routes that might echo a secret were not exercised` : verdict.evidence, reproduction };
    },
  },
  {
    id: "aad-transplant-fails",
    ruleId: "CRYPTO-2",
    scenario: "crypto/aad-transplant-fails",
    oracle: "spec",
    async run(ctx) {
      const { req, host, persistDir } = ctx;
      const reproduction = `Tenant A (an owner): store secret S via POST /secrets, and notes N1 and N2 via POST /notes. Tenant B: store note B1. Read each stored envelope from the persisted tenant files (read-only), then, with the app still running, overwrite one cell at a time on disk: (control) A's N2 := A's N1 (same tenant, table and field), (1) A's N2 := A's secret envelope (other table), (2) B's B1 := A's N1 (other tenant), (3) B's B1 := A's secret envelope. After each, GET /notes as that tenant: the transplanted plaintext must not appear. Restore every cell afterwards.`;
      if (!persistDir) return unverified("no persisted-storage directory supplied (--persist-dir); a transplant needs the tenant files on disk, so CRYPTO-2 is unverified on this target", reproduction);
      if (!ctx.routes) return unverified("no route manifest supplied (--route-manifest); cannot tell whether the target has the secret store route the transplant uses, so CRYPTO-2 is unverified", reproduction);
      if (!hasStoreRoute(ctx.routes)) return unverified(`the manifest has no ${SECRET_STORE.method} ${SECRET_STORE.path}; without a second classified table the cross-table transplant cannot run, so CRYPTO-2 is unverified on this target`, reproduction);
      const cannot = (e: unknown) => unverified(`persisted-storage directory could not be read: ${(e as Error).message}`, reproduction);
      const snapshot = () => sealedCells(persistDir);
      /** Plants through `plant`, then returns the one sealed cell that appeared. Anything else (none, several, an unreadable directory) cannot be attributed. */
      const planted = async (what: string, plant: () => Promise<Response>): Promise<{ cell: SealedCell } | { error: Verdict & { reproduction: string } }> => {
        let before;
        try { before = snapshot(); } catch (e) { return { error: cannot(e) }; }
        const res = await plant();
        const broken = requireSetup(res, `planting the ${what}`, reproduction);
        if (broken) return { error: broken };
        let after;
        try { after = snapshot(); } catch (e) { return { error: cannot(e) }; }
        if (after.incomplete.length) return { error: unverified(`the storage scan was incomplete (${after.incomplete.join("; ")}); the sealed value of the ${what} cannot be located`, reproduction) };
        const known = new Set(before.cells.map(cellKey));
        const fresh = after.cells.filter((c) => !known.has(cellKey(c)));
        if (fresh.length !== 1) return { error: unverified(`planting the ${what} produced ${fresh.length} new sealed value(s) in the persisted storage, expected exactly 1; the stored envelope cannot be attributed (the write did not land, or the target does not store a bk1 envelope)`, reproduction) };
        return { cell: fresh[0] as SealedCell };
      };
      const a = await ownerTenant(ctx, "tx-a", reproduction);
      if ("error" in a && a.error) return a.error;
      const ownerA = a as Extract<typeof a, { h: string }>;
      const hostB = host(`tx-b-${randomBytes(3).toString("hex")}`);
      const S = marker(), N1 = marker(), N2 = marker(), B1 = marker(), B2 = marker();
      const secretP = await planted("secret", () => req(ownerA.h, "POST", SECRET_STORE.path, { ...cookieWrite(ownerA.h, ownerA.token), body: json({ name: `tx-${randomBytes(3).toString("hex")}`, value: S }) }));
      if ("error" in secretP) return secretP.error;
      const n1P = await planted("first note of tenant A", () => req(ownerA.h, "POST", "/notes", { body: json({ text: N1 }) }));
      if ("error" in n1P) return n1P.error;
      const n2P = await planted("second note of tenant A", () => req(ownerA.h, "POST", "/notes", { body: json({ text: N2 }) }));
      if ("error" in n2P) return n2P.error;
      const b1P = await planted("first note of tenant B", () => req(hostB, "POST", "/notes", { body: json({ text: B1 }) }));
      if ("error" in b1P) return b1P.error;
      const b2 = await req(hostB, "POST", "/notes", { body: json({ text: B2 }) });
      const brokenB2 = requireSetup(b2, "planting the second note of tenant B", reproduction);
      if (brokenB2) return brokenB2;
      const [secretCell, n1, n2, b1] = [secretP.cell, n1P.cell, n2P.cell, b1P.cell];
      if (new Set([secretCell.file, n1.file, n2.file]).size !== 1 || b1.file === n1.file) return unverified(`could not attribute the stored envelopes to two distinct tenant files (A: ${[secretCell.file, n1.file, n2.file].join(", ")}; B: ${b1.file})`, reproduction);
      if (secretCell.table === n1.table && secretCell.column === n1.column) return unverified("the secret and the note are stored in the same column; there is no second classified field to transplant between", reproduction);

      const writes: { cell: SealedCell; original: string }[] = [];
      const put = (cell: SealedCell, value: string) => {
        if (!writes.some((w) => w.cell === cell)) writes.push({ cell, original: cell.value });
        return overwriteCell(persistDir, cell, value);
      };
      const restore = () => { for (const w of writes) overwriteCell(persistDir, w.cell, w.original); writes.length = 0; };
      const checks: { name: string; ok: boolean; detail: string }[] = [];
      let rowBound = false;
      try {
        const base = await req(ownerA.h, "GET", "/notes");
        if (base.status < 200 || base.status >= 300 || !base.body.includes(N1) || !base.body.includes(N2)) return fail(`before any tampering, GET /notes as tenant A did not return both planted notes (HTTP ${base.status} ${base.body.slice(0, 200)}); the app is not working, so a transplant result would mean nothing`, reproduction);
        // Tenant isolation is another rule's business. If B already sees A's data before any tamper, a later leak could not be told apart from it.
        const baseB = await req(hostB, "GET", "/notes");
        if (baseB.status < 200 || baseB.status >= 300 || [N1, N2, S].some((x) => baseB.body.includes(x)) || ![B1, B2].every((x) => baseB.body.includes(x))) return unverified(`before any tampering, tenant B's GET /notes did not return exactly its own notes (HTTP ${baseB.status}); isolation or the read path is already broken, so a transplant leak could not be told apart from it`, reproduction);
        // Control: the same transplant within one tenant, table and field. If the running app does not see a cell written on disk, every later "failed to open" is meaningless.
        const w0 = put(n2, n1.value);
        if (!w0.ok) return unverified(`could not write into the tenant database on disk (${w0.detail}); no transplant can be tried`, reproduction);
        const same = await req(ownerA.h, "GET", "/notes");
        if (same.status >= 200 && same.status < 300 && countOf(same.body, N1) >= 2) { /* control: the app reads through what we wrote, and opens an envelope in its own context */ }
        else {
          rowBound = true; // the app also binds the row (stronger than the spec's three fields): the control cannot show the write reached the app
          restore();
          const healthy = await req(ownerA.h, "GET", "/notes");
          if (healthy.status < 200 || healthy.status >= 300 || !healthy.body.includes(N1) || !healthy.body.includes(N2)) return unverified(`the same-context control failed (HTTP ${same.status}) and the app did not recover after the cell was restored (HTTP ${healthy.status}); the tamper channel cannot be trusted`, reproduction);
        }
        restore();

        const attempts: { name: string; target: SealedCell; value: string; asTenant: string; forbidden: string; detail: string }[] = [
          { name: "other table, same tenant (A's secret envelope in A's notes column)", target: n2, value: secretCell.value, asTenant: ownerA.h, forbidden: S, detail: "the secret's plaintext was returned from the notes column" },
          { name: "other tenant (A's note envelope in B's notes column)", target: b1, value: n1.value, asTenant: hostB, forbidden: N1, detail: "tenant A's note plaintext was returned to tenant B" },
          { name: "other tenant and table (A's secret envelope in B's notes column)", target: b1, value: secretCell.value, asTenant: hostB, forbidden: S, detail: "tenant A's secret plaintext was returned to tenant B" },
        ];
        for (const t of attempts) {
          const w = put(t.target, t.value);
          if (!w.ok) return unverified(`could not write into the tenant database on disk for "${t.name}" (${w.detail})`, reproduction);
          const r = await req(t.asTenant, "GET", "/notes");
          checks.push({ name: t.name, ok: !r.body.includes(t.forbidden), detail: `${t.detail} (HTTP ${r.status})` });
          restore();
        }
        const afterA = await req(ownerA.h, "GET", "/notes");
        const afterB = await req(hostB, "GET", "/notes");
        for (const [who, r, need] of [["A", afterA, [N1, N2]], ["B", afterB, [B1, B2]]] as const)
          if (r.status < 200 || r.status >= 300 || !need.every((x) => r.body.includes(x))) return unverified(`after restoring every cell, tenant ${who} did not read back its own notes (HTTP ${r.status}); the restore failed or the tamper left the app broken`, reproduction);
      } finally {
        restore();
      }
      const verdict = specOracle(checks);
      if (!verdict.passed) return { ...verdict, reproduction };
      return { ...verdict, evidence: `${checks.length} transplant(s) failed to open or leaked nothing${rowBound ? "; the app also binds the row (the same-context row swap was refused)" : ""}. Limits: AAD binding of the tenant is not separable from the per-tenant data key over HTTP (a cross-tenant transplant fails on the key even if the tenant were missing from the AAD), this scenario does not vary the field or the key version (the demo has one classified column per table), and the spec's AAD does not bind the row${rowBound ? "" : " (the control shows a row swap within one column opens)"}`, reproduction };
    },
  },
  {
    id: "shredding-makes-data-unreadable",
    ruleId: "CRYPTO-3",
    scenario: "crypto/shredding-makes-data-unreadable",
    oracle: "state",
    async run(ctx) {
      const { req, host, persistDir, routes } = ctx;
      const reproduction = `Tenant A (owner): store notes C1, C2 and secret S; warm GET /summary. Tenant B stores note CB. Anonymous POST ${SHRED_ROUTE} must be refused. Then the owner shreds A via POST ${SHRED_ROUTE}. Afterwards, as anonymous and as owner, GET /notes must answer 410 and no GET route may return C1, C2, S; a new POST /notes and POST /secrets on A must not succeed (no new key may be minted) and POST ${ROTATE_ROUTE} must not succeed; tenant B must still read CB and write; a tenant that never stored anything, once shredded, must also refuse a first write. Finally scan the persisted storage for every canary.`;
      if (!persistDir) return unverified("no persisted-storage directory supplied (--persist-dir); CRYPTO-3 is verified on a local target only (DR-0010 choice 7), so it is unverified here", reproduction);
      if (!hasRoute(routes, "POST", SHRED_ROUTE)) return unverified(`the manifest has no POST ${SHRED_ROUTE}; the target has no way to shred a tenant, so CRYPTO-3 is unverified`, reproduction);
      const a = await ownerTenant(ctx, "shred-a", reproduction);
      if ("error" in a && a.error) return a.error;
      const ownerA = a as Extract<typeof a, { h: string }>;
      const c = await ownerTenant(ctx, "shred-c", reproduction);
      if ("error" in c && c.error) return c.error;
      const ownerC = c as Extract<typeof c, { h: string }>;
      const hostB = host(`shred-b-${randomBytes(3).toString("hex")}`);
      const C1 = marker(), C2 = marker(), S = marker(), CB = marker(), LATE = marker(), LATE_SECRET = marker(), LATE_C = marker(), LATE_B = marker();
      const opts = cookieWrite(ownerA.h, ownerA.token);
      for (const [what, res] of [
        ["note C1", await req(ownerA.h, "POST", "/notes", { body: json({ text: C1 }) })],
        ["note C2", await req(ownerA.h, "POST", "/notes", { body: json({ text: C2 }) })],
        ["secret S", await req(ownerA.h, "POST", SECRET_STORE.path, { ...opts, body: json({ name: "shred-probe-secret", value: S }) })],
        ["note CB", await req(hostB, "POST", "/notes", { body: json({ text: CB }) })],
      ] as const) {
        if (what === "secret S" && res.status === 404 && !hasStoreRoute(routes)) continue; // no secret store on this target: the notes half still runs
        const broken = requireSetup(res, `planting ${what}`, reproduction);
        if (broken) return broken;
      }
      const hasSecrets = hasStoreRoute(routes) || (await req(ownerA.h, "GET", "/secrets", withCookie(ownerA.token))).status === 200;
      const pre = await req(ownerA.h, "GET", "/notes");
      const preSummary = await req(ownerA.h, "GET", "/summary"); // warms any derived cache with the plaintext
      const preB = await req(hostB, "GET", "/notes");
      if (pre.status !== 200 || !pre.body.includes(C1) || !pre.body.includes(C2)) return fail(`before the shred, GET /notes as tenant A did not return its notes (HTTP ${pre.status} ${pre.body.slice(0, 200)}); nothing to shred`, reproduction);
      if (preB.status !== 200 || !preB.body.includes(CB)) return fail(`before the shred, GET /notes as tenant B did not return its note (HTTP ${preB.status})`, reproduction);
      const checks: { name: string; ok: boolean; detail: string }[] = [];
      const canaries = [C1, C2, S, LATE, LATE_SECRET];
      const leaks = (body: string) => canaries.filter((x) => body.includes(x));
      const refused = (r: Response) => r.status >= 400 && r.status < 500;

      const anon = await req(ownerA.h, "POST", SHRED_ROUTE);
      checks.push({ name: `anonymous POST ${SHRED_ROUTE}`, ok: refused(anon), detail: `an unauthenticated caller was not refused (HTTP ${anon.status})` });
      const still = await req(ownerA.h, "GET", "/notes");
      if (still.status !== 200 || !still.body.includes(C1)) checks.push({ name: "tenant after anonymous shred attempt", ok: false, detail: `the refused shred still changed the tenant (HTTP ${still.status})` });

      const shred = await req(ownerA.h, "POST", SHRED_ROUTE, opts);
      if (shred.status === 404 || shred.status === 405) return unverified(`POST ${SHRED_ROUTE} answered ${shred.status}; the target has no shred route, so CRYPTO-3 is unverified`, reproduction);
      const brokenShred = requireSetup(shred, "the owner's shred", reproduction);
      if (brokenShred) return brokenShred;

      const reads = async (label: string, who: "anonymous" | "owner") => {
        const o = who === "owner" ? withCookie(ownerA.token) : {};
        const notes = await req(ownerA.h, "GET", "/notes", o);
        checks.push({ name: `${label}: ${who} GET /notes`, ok: notes.status === 410 && leaks(notes.body).length === 0, detail: `expected 410 Gone and no plaintext, got HTTP ${notes.status}${leaks(notes.body).length ? ` carrying ${leaks(notes.body).join(", ")}` : ""}` });
        const seen: Response[] = [notes];
        // Every other GET route the target declares (parameters filled with the secret's name): none may return a canary, whatever its status.
        const extra = [...new Set(["/summary", "/secrets", ...(routes ?? []).filter((r) => r.method === "GET").map((r) => r.path)])].filter((p) => p !== "/notes");
        for (const p of extra) {
          const path = p.replace(PARAM_ALL, () => encodeURIComponent("shred-probe-secret"));
          const r = await req(ownerA.h, "GET", path, o);
          seen.push(r);
          checks.push({ name: `${label}: ${who} GET ${path}`, ok: leaks(r.body).length === 0 && !JSON.stringify(r.headers).includes(S), detail: `plaintext found (HTTP ${r.status}): ${leaks(r.body).join(", ")}` });
        }
        return seen;
      };
      await reads("after shred", "anonymous");
      await reads("after shred", "owner");

      const lateNote = await req(ownerA.h, "POST", "/notes", { body: json({ text: LATE }) });
      checks.push({ name: "write to the shredded tenant: POST /notes", ok: lateNote.status === 410, detail: `a shredded tenant accepted or mishandled a write (expected 410 Gone, got HTTP ${lateNote.status}): no new key may be minted` });
      if (hasSecrets) {
        const lateSecret = await req(ownerA.h, "POST", SECRET_STORE.path, { ...opts, body: json({ name: "late", value: LATE_SECRET }) });
        checks.push({ name: "write to the shredded tenant: POST /secrets", ok: lateSecret.status === 410, detail: `a shredded tenant accepted or mishandled a secret write (expected 410 Gone, got HTTP ${lateSecret.status})` });
      }
      if (hasRoute(routes, "POST", ROTATE_ROUTE)) {
        const rot = await req(ownerA.h, "POST", ROTATE_ROUTE, opts);
        checks.push({ name: `rotation on the shredded tenant: POST ${ROTATE_ROUTE}`, ok: rot.status >= 400 && rot.status !== 404 && rot.status !== 405, detail: `rotation of a shredded tenant must not succeed or mint a key (HTTP ${rot.status})` });
      }
      await reads("after a later write", "anonymous");

      // A tenant that never stored anything has no key row to destroy; shredding it must still leave it unwritable.
      const shredC = await req(ownerC.h, "POST", SHRED_ROUTE, cookieWrite(ownerC.h, ownerC.token));
      const brokenC = requireSetup(shredC, "shredding a tenant that never stored data", reproduction);
      if (brokenC) return brokenC;
      const lateC = await req(ownerC.h, "POST", "/notes", { body: json({ text: LATE_C }) });
      checks.push({ name: "write to a shredded tenant that never stored data", ok: lateC.status === 410, detail: `a never-keyed tenant, once shredded, accepted a write (expected 410, got HTTP ${lateC.status}): a fresh key was minted` });
      canaries.push(LATE_C);
      const readC = await req(ownerC.h, "GET", "/notes");
      checks.push({ name: "read of that tenant", ok: !readC.body.includes(LATE_C), detail: `the write refused above is readable (HTTP ${readC.status} ${readC.body.slice(0, 120)})` }); // an empty 200 is truthful here: the tenant holds no rows, so no key is needed to read it

      // Shredding is per tenant: B keeps its data and its ability to write, and never sees A's plaintext.
      const postB = await req(hostB, "GET", "/notes");
      checks.push({ name: "tenant B after A's shred: GET /notes", ok: postB.status === 200 && postB.body.includes(CB) && leaks(postB.body).length === 0, detail: `tenant B lost its data or saw tenant A's (HTTP ${postB.status} ${postB.body.slice(0, 160)})` });
      const writeB = await req(hostB, "POST", "/notes", { body: json({ text: LATE_B }) });
      checks.push({ name: "tenant B after A's shred: POST /notes", ok: writeB.status >= 200 && writeB.status < 300, detail: `shredding A broke writes for tenant B (HTTP ${writeB.status})` });

      let scan;
      try { scan = scanStorage(persistDir, [...canaries, CB, LATE_B]); } catch (e) { return unverified(`persisted-storage directory could not be read: ${(e as Error).message}`, reproduction); }
      const stored = scan.hits.filter((h) => canaries.includes(h.marker));
      checks.push({ name: "persisted storage after the shred", ok: stored.length === 0, detail: `plaintext found in storage: ${stored.map((h) => `${h.layer} ${h.file} ${h.where}`).join(", ")}` });
      const verdict = specOracle(checks);
      if (!verdict.passed) return { ...verdict, reproduction };
      if (scan.sqliteOpened === 0 || scan.rowsScanned === 0) return unverified(`no SQLite rows under ${persistDir}; the storage half of the scenario saw nothing, so the absence of plaintext means nothing`, reproduction);
      if (scan.incomplete.length) return unverified(`the storage scan was incomplete (${scan.incomplete.join("; ")}); a pass would overstate what was inspected`, reproduction);
      void preSummary;
      return { ...verdict, evidence: `${checks.length} checks: after the shred every read path refused tenant A (410) or returned no plaintext, writes and rotation were refused (no new key), tenant B was unaffected, and no plaintext is in ${scan.filesScanned} stored file(s). Not covered: the data-key cache window (up to 60 s in other isolates; this run shreds and reads in the same isolate, so a stale key in another isolate is not exercised), backups, and a re-read after the window has elapsed`, reproduction };
    },
  },
  {
    id: "nonce-uniqueness-and-rotation",
    ruleId: "CRYPTO-4",
    scenario: "crypto/nonce-uniqueness-and-rotation",
    oracle: "spec",
    async run(ctx) {
      const { req, persistDir, routes } = ctx;
      const reproduction = `On a fresh tenant (owner), store 24 notes and 4 secrets concurrently. Read every stored envelope from the persisted tenant file (read-only): no (keyVersion, nonce) pair may repeat. Then POST ${ROTATE_ROUTE} as the owner (an anonymous call must be refused), store 16 more notes and 2 secrets concurrently: the new envelopes must carry a higher key version, still never repeat a (keyVersion, nonce) pair of the whole tenant, and GET /notes must still return every earlier and later note.`;
      if (!persistDir) return unverified("no persisted-storage directory supplied (--persist-dir); envelopes cannot be read over HTTP, so CRYPTO-4 is unverified on this target", reproduction);
      if (!hasRoute(routes, "POST", ROTATE_ROUTE)) return unverified(`the manifest has no POST ${ROTATE_ROUTE}; the target has no way to rotate, so CRYPTO-4 is unverified`, reproduction);
      const hasSecrets = hasStoreRoute(routes);
      const t = await ownerTenant(ctx, "nonce", reproduction);
      if ("error" in t && t.error) return t.error;
      const owner = t as Extract<typeof t, { h: string }>;
      const opts = cookieWrite(owner.h, owner.token);
      const noteMarkers: string[] = [];
      const burst = async (notes: number, secretCount: number) => {
        const sent: Promise<Response>[] = [];
        for (let i = 0; i < notes; i++) { const m = marker(); noteMarkers.push(m); sent.push(req(owner.h, "POST", "/notes", { body: json({ text: m }) })); }
        if (hasSecrets) for (let i = 0; i < secretCount; i++) sent.push(req(owner.h, "POST", SECRET_STORE.path, { ...opts, body: json({ name: `n-${randomBytes(4).toString("hex")}`, value: marker() }) }));
        return Promise.all(sent);
      };
      const expectedCells = (notes: number, secretCount: number) => notes + (hasSecrets ? secretCount : 0);
      let before;
      try { before = sealedCells(persistDir); } catch (e) { return unverified(`persisted-storage directory could not be read: ${(e as Error).message}`, reproduction); }
      const known = new Set(before.cells.map(cellKey));

      const first = await burst(24, 4);
      const brokenFirst = first.map((r) => requireSetup(r, "a concurrent write", reproduction)).find(Boolean);
      if (brokenFirst) return brokenFirst;
      let mid;
      try { mid = sealedCells(persistDir); } catch (e) { return unverified(`persisted-storage directory could not be read: ${(e as Error).message}`, reproduction); }
      const fresh1 = mid.cells.filter((c) => !known.has(cellKey(c)));
      const files1 = [...new Set(fresh1.map((c) => c.file))];
      if (mid.incomplete.length) return unverified(`the storage scan was incomplete (${mid.incomplete.join("; ")})`, reproduction);
      if (files1.length !== 1 || fresh1.length !== expectedCells(24, 4)) return unverified(`${expectedCells(24, 4)} writes succeeded but the persisted storage gained ${fresh1.length} sealed value(s) in ${files1.length} file(s); the envelopes cannot be attributed to this tenant (writes did not land, or the target does not store bk1 envelopes)`, reproduction);
      const tenantFile = files1[0] as string;
      const parse = (cells: SealedCell[]) => cells.map((c) => ({ c, m: ENVELOPE.exec(c.value) }));
      const checks: { name: string; ok: boolean; detail: string }[] = [];
      const malformed = parse(mid.cells.filter((c) => c.file === tenantFile)).filter((p) => !p.m);
      checks.push({ name: "envelope shape", ok: malformed.length === 0, detail: `${malformed.length} stored value(s) are not bk1:<keyVersion>:<nonce>:<ciphertext> envelopes` });
      const pairs = (cells: SealedCell[]) => {
        const seen = new Map<string, number>();
        for (const p of parse(cells)) if (p.m) seen.set(`${p.m[1]}:${p.m[2]}`, (seen.get(`${p.m[1]}:${p.m[2]}`) ?? 0) + 1);
        return { seen, dups: [...seen].filter(([, n]) => n > 1).map(([k, n]) => `${k} x${n}`) };
      };
      const cells1 = mid.cells.filter((c) => c.file === tenantFile);
      const p1 = pairs(cells1);
      checks.push({ name: `nonce uniqueness over ${cells1.length} concurrent writes`, ok: p1.dups.length === 0, detail: `(keyVersion:nonce) pairs reused under one tenant key: ${p1.dups.slice(0, 5).join(", ")}` });
      const v0 = new Set(parse(cells1).map((p) => p.m && Number(p.m[1])));
      const oldVersion = Math.max(...[...v0].map((v) => v ?? 0));

      const anon = await req(owner.h, "POST", ROTATE_ROUTE);
      checks.push({ name: `anonymous POST ${ROTATE_ROUTE}`, ok: anon.status >= 400 && anon.status < 500, detail: `an unauthenticated caller was not refused (HTTP ${anon.status})` });
      const rot = await req(owner.h, "POST", ROTATE_ROUTE, opts);
      if (rot.status === 404 || rot.status === 405) return unverified(`POST ${ROTATE_ROUTE} answered ${rot.status}; the target has no rotation route`, reproduction);
      const brokenRot = requireSetup(rot, "the owner's key rotation", reproduction);
      if (brokenRot) return brokenRot;
      let announced: number | undefined;
      try { const v = (JSON.parse(rot.body) as { keyVersion?: unknown }).keyVersion; if (typeof v === "number") announced = v; } catch { /* the body need not be JSON */ }
      checks.push({ name: "rotation announces a newer version", ok: announced === undefined || announced > oldVersion, detail: `rotation answered key version ${announced}, not above the version in use (${oldVersion})` });

      const second = await burst(16, 2);
      const brokenSecond = second.map((r) => requireSetup(r, "a write after rotation", reproduction)).find(Boolean);
      if (brokenSecond) return brokenSecond;
      let end;
      try { end = sealedCells(persistDir); } catch (e) { return unverified(`persisted-storage directory could not be read: ${(e as Error).message}`, reproduction); }
      const all = end.cells.filter((c) => c.file === tenantFile);
      const known1 = new Set(cells1.map(cellKey));
      const fresh2 = all.filter((c) => !known1.has(cellKey(c)));
      if (fresh2.length !== expectedCells(16, 2)) return unverified(`${expectedCells(16, 2)} writes after rotation succeeded but the tenant's file gained ${fresh2.length} sealed value(s)`, reproduction);
      const newVersions = [...new Set(parse(fresh2).map((p) => (p.m ? Number(p.m[1]) : 0)))];
      checks.push({ name: "writes after rotation use the new key version", ok: newVersions.every((v) => v > oldVersion) && (announced === undefined || newVersions.every((v) => v === announced)), detail: `new envelopes carry key version(s) ${newVersions.join(", ")}; version ${oldVersion} was in use and rotation answered ${announced}` });
      const pAll = pairs(all);
      checks.push({ name: `nonce uniqueness over all ${all.length} envelopes across the rotation`, ok: pAll.dups.length === 0, detail: `(keyVersion:nonce) pairs reused: ${pAll.dups.slice(0, 5).join(", ")}` });
      const read = await req(owner.h, "GET", "/notes");
      const missing = noteMarkers.filter((m) => !read.body.includes(m));
      checks.push({ name: "every note, before and after rotation, still reads back", ok: read.status === 200 && missing.length === 0, detail: `GET /notes answered HTTP ${read.status}; ${missing.length} of ${noteMarkers.length} notes missing (data lost to rotation)` });
      const verdict = specOracle(checks);
      if (!verdict.passed) return { ...verdict, reproduction };
      if (end.incomplete.length) return unverified(`the storage scan was incomplete (${end.incomplete.join("; ")})`, reproduction);
      return { ...verdict, evidence: `${all.length} envelopes, key versions ${[...new Set([...v0, ...newVersions])].join(", ")}, no (keyVersion, nonce) pair repeated; all ${noteMarkers.length} notes read back after rotation. Limits: uniqueness is observed over this burst, not proven; counter semantics are not asserted; the key version is taken from the envelope header; one rotation only; concurrency is as deep as one burst`, reproduction };
    },
  },
];
