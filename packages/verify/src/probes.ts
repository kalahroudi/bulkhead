import { createHmac, randomBytes } from "node:crypto";
import type { Oracle } from "@kalahroudi/bulkhead-spec";
import type { Requester, Response } from "./http.ts";
import { canaryOracle, differentialOracle, metamorphicOracle, roleDifferentialOracle, specOracle, type Verdict } from "./oracles.ts";

export interface Context {
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
const fail = (evidence: string, reproduction: string) => ({ passed: false, evidence, reproduction });

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
      const forged = await req(t, "POST", "/webhooks/billing", { body, headers: { "x-signature": createHmac("sha256", "not-the-secret").update(body).digest("hex") } });
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
      const reproduction = "As owner, mint a member key with private:read. The real key reaches /private/member. Then present 'Bearer bkk_<real id>_<43 wrong base64url chars>' (a random secret, and the real secret with its last character changed): each must be 401, identical to a key with an unknown id.";
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
      const flipped = `${secret.slice(0, -1)}${secret.endsWith("A") ? "B" : "A"}`;
      const wrongRandom = await req(h, "GET", "/private/member", bearer(`bkk_${id}_${randomBytes(32).toString("base64url")}`));
      const wrongLast = await req(h, "GET", "/private/member", bearer(`bkk_${id}_${flipped}`));
      const unknown = await req(h, "GET", "/private/member", bearer(`bkk_${randomBytes(8).toString("hex")}_${randomBytes(32).toString("base64url")}`));
      const same = (r: Response, label: string) => differentialOracle(unknown, r, label);
      return {
        ...specOracle([
          { name: "unknown key id is refused (baseline)", ok: unknown.status === 401, detail: `HTTP ${unknown.status} ${unknown.body}` },
          { name: "real id with a random wrong secret is refused with 401", ok: wrongRandom.status === 401, detail: `HTTP ${wrongRandom.status} ${wrongRandom.body}` },
          { name: "real id with the real secret's last character changed is refused with 401", ok: wrongLast.status === 401, detail: `HTTP ${wrongLast.status} ${wrongLast.body}` },
          { name: "wrong secret answers exactly like an unknown id", ok: same(wrongRandom, "random wrong secret").passed && same(wrongLast, "near-miss secret").passed, detail: `${same(wrongRandom, "random wrong secret").evidence}; ${same(wrongLast, "near-miss secret").evidence}` },
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
      const reproduction = "Create a second owner (so 'last owner' protection cannot mask anything) and an admin. As the admin: PATCH /users/<admin id>/role {role:owner}, PATCH /users/<first owner id>/role {role:member} and DELETE /users/<first owner id> must each be 403. Afterwards the first owner is still an enabled owner and the admin is still an admin.";
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
      const reproduction = "As owner, create an admin and mint two keys. GET /users and GET /api-keys must be 200 and contain none of: pbkdf2, password_hash, secret_hash, password, or either minted key's secret.";
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
      const checks = [{ where: "GET /users", res: users }, { where: "GET /api-keys", res: keysList }].flatMap(({ where, res }) => {
        const body = res.body.toLowerCase();
        return [
          ...needles.map((n) => ({ name: `${where} has no '${n}'`, ok: !body.includes(n), detail: "found in the response body" })),
          ...secrets.map((s, i) => ({ name: `${where} does not contain minted key secret #${i + 1}`, ok: !res.body.includes(s), detail: "the secret reappears in a listing" })),
        ];
      });
      return { ...specOracle(checks), reproduction };
    },
  },
];
