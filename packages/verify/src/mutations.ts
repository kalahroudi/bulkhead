// Mutation catalog (DR-0007, VERIFY-4): each entry deliberately breaks one security-relevant line and names the
// probe ids that must then fail. `find` must occur exactly once in `file`, otherwise the runner errors instead of skipping.
// Every entry below was first proven by hand in Phases 2-3. New probes must arrive with at least one entry.
// Next to the seeded-bug catalog (DR-0007). Paths in `file` are relative to the repository root, because the runner
// (scripts/verify-mutations.ts) edits a scratch copy of the whole workspace; this module itself never touches a file.
export interface Edit {
  /** Repo-relative path, edited only in the scratch copy. */
  file: string;
  find: string;
  replace: string;
}

export interface Mutation {
  id: string;
  /** Rule the broken code upholds. */
  rule: string;
  /** The primary edit; `find` must match exactly once in `file`. */
  file: string;
  find: string;
  replace: string;
  /** Further edits applied together with the primary one, for mutations that must defeat two independent defences. */
  also?: Edit[];
  /** Probe ids that must fail, exactly. A missing one means a worthless scenario; an extra one means a mis-attributed scenario. */
  expect: string[];
  /**
   * Set only when no black-box probe can catch the mutation yet. `expect` must then be empty, and the unit tests of the
   * mutated package must fail instead, otherwise the line is unprotected and the gate fails. Naming the gap keeps it loud.
   */
  gap?: string;
}

/**
 * Probes that no catalog entry can break, each with the reason. A probe may only be listed here when its reason is
 * recorded; a new probe must otherwise arrive with a mutation entry (DR-0007 item 4, enforced in test/mutations.test.ts).
 */
export const UNMUTATABLE: Record<string, string> = {
  "forged-signature": "BILL-2: the demo Worker has no billing routes, so the kernel gate skips this probe; billing arrives in Phase 5",
};

const AUTH = "packages/auth/src/authenticate.ts";
const ROUTES = "packages/auth/src/routes.ts";

export const mutations: Mutation[] = [
  {
    id: "role-change-keeps-sessions", rule: "AUTH-2", file: ROUTES,
    find: "    await revokeSessionsOf(c.db, id);\n    await revokeKeysOf(c.db, id, clock.now());\n    return c.json({ id, role: b.role });",
    replace: "    await revokeKeysOf(c.db, id, clock.now());\n    return c.json({ id, role: b.role });",
    expect: ["role-change-revokes"],
  },
  {
    id: "role-change-keeps-keys", rule: "AUTH-4", file: ROUTES,
    find: "    await revokeSessionsOf(c.db, id);\n    await revokeKeysOf(c.db, id, clock.now());\n    return c.json({ id, role: b.role });",
    replace: "    await revokeSessionsOf(c.db, id);\n    return c.json({ id, role: b.role });",
    expect: ["key-revocation"],
  },
  {
    id: "key-permission-ignored", rule: "AUTH-4", file: "packages/core/src/api/app.ts",
    find: 'if (user.permissions && !(checked.permission && user.permissions.includes(checked.permission))) return reply(403, "forbidden");',
    replace: "",
    expect: ["api-key-scope"],
  },
  {
    id: "csrf-origin-ignored", rule: "AUTH-2", file: AUTH,
    find: "return new URL(origin).host === new URL(req.url).host;",
    replace: "return true;",
    expect: ["csrf-origin"],
  },
  {
    id: "csrf-no-header-allowed", rule: "AUTH-2", file: AUTH,
    find: 'return site === "same-origin" || site === "none";',
    replace: 'return site === null || site === "same-origin" || site === "none";',
    expect: ["csrf-origin"],
  },
  {
    id: "session-ignores-disabled", rule: "AUTH-2", file: AUTH,
    find: " and u.disabled = 0`",
    replace: "`",
    expect: [],
    gap: "no black-box probe disables a user and then retries; covered by auth unit tests only (DR-0006 known limits)",
  },
  {
    id: "key-ignores-disabled", rule: "AUTH-4", file: AUTH,
    find: "row.user_disabled !== 0 || ",
    replace: "",
    expect: [],
    gap: "no black-box probe disables a user and then retries; covered by auth unit tests only (DR-0006 known limits)",
  },
  {
    id: "login-ignores-disabled", rule: "AUTH-2", file: ROUTES,
    find: "if (!user || !ok || user.disabled !== 0) {",
    replace: "if (!user || !ok) {",
    expect: ["disabled-user-denied"],
  },
  {
    id: "login-no-rotation", rule: "AUTH-2", file: ROUTES,
    find: "    await revokeSessionToken(c.db, sessionTokenOf(c.req));\n    await c.db.run(\"delete from sessions where user_id = ? and expires_at <= ?\"",
    replace: "    await c.db.run(\"delete from sessions where user_id = ? and expires_at <= ?\"",
    expect: ["session-rotation"],
  },
  {
    id: "logout-keeps-session", rule: "AUTH-2", file: ROUTES,
    find: "  app.route(\"POST\", \"/auth/logout\", { role: \"member\" }, async (c) => {\n    await revokeSessionToken(c.db, sessionTokenOf(c.req));\n",
    replace: "  app.route(\"POST\", \"/auth/logout\", { role: \"member\" }, async (c) => {\n",
    expect: ["logout-revokes"],
  },
  {
    id: "cookie-not-httponly", rule: "AUTH-2", file: AUTH,
    find: "Path=/; Secure; HttpOnly; SameSite=Lax",
    replace: "Path=/; Secure; SameSite=Lax",
    expect: ["cookie-flags"],
  },
  {
    id: "grant-above-own-role", rule: "AUTH-3", file: ROUTES,
    find: '    if (rank(b.role) > rank(c.user!.role)) return c.json({ error: "cannot grant a role above your own" }, 403);\n    const id = crypto.randomUUID();',
    replace: "    const id = crypto.randomUUID();",
    expect: ["authority-matrix"],
  },
  {
    id: "key-delete-noop", rule: "AUTH-4", file: ROUTES,
    find: '"update api_keys set revoked_at = ? where id = ? and revoked_at is null"',
    replace: '"update api_keys set revoked_at = revoked_at where id = ? and ? is not null and revoked_at is null"',
    expect: ["key-revocation"],
  },

  {
    id: "tenant-from-header", rule: "TENANT-1", file: "packages/core/src/api/app.ts",
    find: "await resolveTenant(new URL(c.req.url).hostname, cfg);",
    replace: 'await resolveTenant(c.req.header("x-tenant") ? `${c.req.header("x-tenant")}.${cfg.baseDomain}` : new URL(c.req.url).hostname, cfg);',
    expect: ["identity-header-differential"],
  },
  {
    id: "tenants-share-one-object-and-binding-removed", rule: "TENANT-5", file: "packages/core/src/tenant/handle.ts",
    find: "const stub = ns.get(ns.idFromName(tenant.id));",
    replace: 'const stub = ns.get(ns.idFromName("shared"));',
    // Sharing one object alone is refused by the store's tenant binding (a second defence), which fails closed and
    // so hides the leak from the canary. Both must be broken for the canary to be able to see data cross.
    also: [
      { file: "packages/core/src/tenant/store.ts", find: 'else if (bound !== tenantId) throw new Error("tenant mismatch");', replace: "" },
      { file: "packages/core/src/tenant/store.ts", find: 'else if (this.exec("select value from _bulkhead_meta where key = \'tenant_id\'", []).rows[0]?.value !== tenantId) throw new Error("tenant mismatch");', replace: "" },
    ],
    expect: [
      "add-tenant-metamorphic", "api-key-scope", "authority-matrix", "cache-canary", "cookie-flags", "cross-tenant-session",
      "csrf-origin", "disabled-user-denied", "key-revocation", "logout-revokes", "notes-list-canary", "role-change-revokes", "role-matrix",
    ],
  },
  {
    id: "tenant-binding-check-removed", rule: "TENANT-3", file: "packages/core/src/tenant/store.ts",
    find: 'else if (this.exec("select value from _bulkhead_meta where key = \'tenant_id\'", []).rows[0]?.value !== tenantId) throw new Error("tenant mismatch");',
    replace: "",
    expect: [],
    gap: "the demo never hands a tenant another tenant's object, so the binding check is a second defence no HTTP probe reaches; covered by core unit tests",
  },
  {
    id: "summary-cached-across-tenants", rule: "TENANT-5", file: "examples/demo-app/src/routes.ts",
    find: 'c.json({ summary: (await c.db.query<{ text: string }>("select text from notes order by id")).map((r) => r.text).join(" | ") })',
    replace: 'c.json({ summary: ((globalThis as Record<string, string>).__summary ??= (await c.db.query<{ text: string }>("select text from notes order by id")).map((r) => r.text).join(" | ")) })',
    expect: ["cache-canary"],
  },
  {
    id: "role-gate-ignored", rule: "AUTH-3", file: "packages/core/src/api/app.ts",
    find: 'if (!roleAtLeast(user.role, checked.role!)) return reply(403, "forbidden");',
    replace: "",
    expect: ["authority-matrix", "role-matrix"],
  },
  {
    id: "unknown-session-gets-default-role", rule: "AUTH-1", file: AUTH,
    find: "if (!row || !isRole(row.role)) return null;",
    replace: 'if (!row || !isRole(row.role)) return { id: "anonymous", role: "member" };',
    expect: ["cross-tenant-session", "disabled-user-denied", "logout-revokes", "no-default-role", "role-change-revokes", "session-rotation"],
  },
  {
    id: "key-revoked-check-removed", rule: "AUTH-4", file: AUTH,
    find: "where k.id = ? and k.revoked_at is null and (k.expires_at is null or k.expires_at > ?)",
    replace: "where k.id = ? and (k.expires_at is null or k.expires_at > ?)",
    expect: ["key-revocation"],
  },
  // Lines found unprotected by the attacker pass (DR-0009): no black-box probe reaches them yet, so each is a named gap
  // that the auth unit tests must kill. The probes that would close them are listed as owed in DR-0009.
  {
    id: "key-secret-not-compared", rule: "AUTH-4", file: AUTH,
    find: "if (!row || !ok || row.user_disabled",
    replace: "if (!row || row.user_disabled",
    expect: [],
    gap: "no probe presents a real key id with a wrong secret (no-default-role uses an unknown id); covered by auth unit tests only",
  },
  {
    id: "bootstrap-token-unchecked", rule: "AUTH-1", file: ROUTES,
    find: "|| !safeEqual(b.token, secret)) return c.json({ error: \"forbidden\" }, 403);",
    replace: ") return c.json({ error: \"forbidden\" }, 403);",
    expect: [],
    gap: "no probe sends a wrong or missing bootstrap token; covered by auth unit tests only",
  },
  {
    id: "bootstrap-allows-second-owner", rule: "AUTH-1", file: ROUTES,
    find: ", ? where not exists (select 1 from users)\"",
    replace: ", ? \"",
    expect: [],
    gap: "probes bootstrap each tenant exactly once, never a second claim; covered by auth unit tests only",
  },
  {
    id: "role-patch-above-own-role", rule: "AUTH-3", file: ROUTES,
    find: "    if (rank(b.role) > rank(c.user!.role)) return c.json({ error: \"cannot grant a role above your own\" }, 403);\n    const refused = await guardTarget(c, id, b.role !== \"owner\");",
    replace: "    const refused = await guardTarget(c, id, b.role !== \"owner\");",
    expect: [],
    gap: "authority-matrix exercises POST /users but not PATCH /users/:id/role; covered by auth unit tests only",
  },
  {
    id: "guard-target-above-own-role", rule: "AUTH-3", file: ROUTES,
    find: "if (rank(target.role) > rank(c.user!.role)) return c.json({ error: \"cannot modify a user above your own role\" }, 403);",
    replace: "",
    expect: [],
    gap: "no probe has an admin modify or disable an owner; covered by auth unit tests only",
  },
  {
    id: "key-minted-above-own-role", rule: "AUTH-4", file: ROUTES,
    find: "if (rank(role) > rank(c.user!.role)) return c.json({ error: \"cannot mint a key above your own role\" }, 403);",
    replace: "",
    expect: [],
    gap: "api-key-scope mints as owner, so the role ceiling is never tested black-box; covered by auth unit tests only",
  },
  {
    id: "user-list-leaks-password-hash", rule: "AUTH-4", file: ROUTES,
    find: "select id, email, role, disabled, created_at from users order by created_at, id",
    replace: "select id, email, role, disabled, created_at, password_hash from users order by created_at, id",
    expect: [],
    gap: "no probe scans listings for hash material; covered by auth unit tests only",
  },
];
