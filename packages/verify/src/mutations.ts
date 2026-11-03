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
  /**
   * Repo-relative example Worker the entry is run against (passed to verify-kernel as `--app`). Default: the shipped demo.
   * The baseline of each app is run once and must be green before any of its entries counts.
   */
  app?: string;
}

// Exemption (DR-0016 decisions 2 and 3): the manifest route-need guard and the TargetEnv overrides (cookie name, host suffix, webhook
// secret) are verifier behaviour, not app code, so no catalog entry can break them (a mutation edits the app). They are covered by
// packages/verify/test/missing-route.test.ts and target-env.test.ts. Each was shown able to fail by breaking the code by hand
// (then restoring it), with these results:
//   run.ts `if (missing.length)` made `if (false)`   -> missing-route "each declared route removed ..." and "a manifest that is empty ..."
//   run.ts host built from a hard-coded demo.localhost -> target-env "a changed host suffix ...", "a changed cookie name ...", "a changed webhook secret ...", "two concurrent runs ..."
//   run.ts webhookSecret forced to the default         -> target-env "a changed webhook secret ..."
//   run.ts inRunScope given the default cookie name    -> target-env "a changed cookie name ..." and "two concurrent runs ..."
//   probes.ts forged-signature `if (listed.length)` made `if (false)` -> missing-route "forged-signature: not applicable only without a manifest ..."
//   probes.ts cookieName() no-scope throw disabled     -> target-env "a probe run outside a run scope throws ..."
//   probes.ts no-default-role control check disabled   -> target-env "no-default-role needs a control ..."
//   probes.ts no-default-role `needs` shortened        -> contract "each row of the doc's per-probe needs table equals ..."
//   docs path `/summary` renamed                       -> contract "every path literal in probes.ts appears ..."
/**
 * Probes that no catalog entry can break, each with the reason. A probe may only be listed here when its reason is
 * recorded; a new probe must otherwise arrive with a mutation entry (DR-0007 item 4, enforced in test/mutations.test.ts).
 */
export const UNMUTATABLE: Record<string, string> = {
  "forged-signature": "BILL-2: the demo Worker has no billing routes, so the kernel gate skips this probe; billing arrives in Phase 5",
};

const AUTH = "packages/auth/src/authenticate.ts";
const ROUTES = "packages/auth/src/routes.ts";
const KEYS = "packages/core/src/crypto/keys.ts";
const CLASSIFICATION = "packages/core/src/crypto/classification.ts";
const DEMO_ROUTES = "examples/demo-app/src/routes.ts";
// DR-0011 spike: Better Auth behind the authenticate hook, served by examples/demo-betterauth and run against that app.
const BA_APP = "examples/demo-betterauth";
const BA_ROUTES = "packages/auth-betterauth/src/routes.ts";
const BA_AUTH = "packages/auth-betterauth/src/authenticate.ts";
const BA_INSTANCE = "packages/auth-betterauth/src/instance.ts";
const BA_ADAPTER = "packages/auth-betterauth/src/adapter.ts";

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
    gap: "disable revokes sessions and keys first, so over HTTP this check is shadowed by revocation (defence in depth); covered by auth unit tests only",
  },
  {
    id: "key-ignores-disabled", rule: "AUTH-4", file: AUTH,
    find: "row.user_disabled !== 0 || ",
    replace: "",
    expect: [],
    gap: "disable revokes sessions and keys first, so over HTTP this check is shadowed by revocation (defence in depth); covered by auth unit tests only",
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
    id: "tenant-from-forwarded-host", rule: "TENANT-1", file: "packages/core/src/api/app.ts",
    find: "await resolveTenant(new URL(c.req.url).hostname, cfg);",
    replace: 'await resolveTenant(c.req.header("x-forwarded-host") ?? new URL(c.req.url).hostname, cfg);',
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
    // The probes that bootstrap or sign in on a throwaway tenant (ownerTenant, bootstrap-*) also fail: with one shared database
    // the "fresh" tenant is already claimed, so setup (a 409 on bootstrap) cannot succeed. Legitimate, like the older entries.
    expect: [
      "add-tenant-metamorphic", "api-key-scope", "authority-matrix", "bootstrap-claims-once", "bootstrap-token-required", "cache-canary",
      "cookie-flags", "cross-tenant-session", "csrf-origin", "disabled-user-denied", "key-revocation", "key-role-ceiling",
      "key-wrong-secret-denied", "listings-hide-secrets", "logout-revokes", "notes-list-canary", "role-change-authority",
      "role-change-revokes", "role-matrix", "unknown-email-login-same-answer",
      // no-default-role now signs in an owner as its control (DR-0016), so it claims the shared tenant first and session-rotation, which runs after it, finds it taken.
      "session-rotation",
      // The CRYPTO probes all bootstrap a fresh owner tenant (or plant into shared storage), so they fail on setup for the same reason.
      "aad-transplant-fails", "nonce-uniqueness-and-rotation", "secret-write-only-readback", "shredding-makes-data-unreadable", "storage-canary-at-rest",
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
    find: 'c.json({ summary: (await readNotes(c)).join(" | ") })',
    replace: 'c.json({ summary: ((globalThis as Record<string, string>).__summary ??= (await readNotes(c)).join(" | ")) })',
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
  {
    id: "unknown-user-dummy-at-module-scope", rule: "AUTH-2", file: "packages/auth/src/secrets.ts",
    // Stand-in for the module-scope DUMMY bug: the unknown-user path throws, so login answers 500 for unknown emails only.
    find: '(stored ?? DUMMY_HASH).split("$")',
    replace: '(stored ?? (() => { throw new Error("no dummy hash"); })()).split("$")',
    expect: ["unknown-email-login-same-answer"],
  },
  // Lines found unprotected by the attacker pass (DR-0009): no black-box probe reaches them yet, so each is a named gap
  // that the auth unit tests must kill. Those owed in DR-0009 have since been promoted to probes (the attacker session that built them).
  {
    id: "key-secret-not-compared", rule: "AUTH-4", file: AUTH,
    find: "if (!row || !ok || row.user_disabled",
    replace: "if (!row || row.user_disabled",
    expect: ["key-wrong-secret-denied"],
  },
  {
    id: "bootstrap-token-unchecked", rule: "AUTH-1", file: ROUTES,
    find: "|| !safeEqual(b.token, secret)) return c.json({ error: \"forbidden\" }, 403);",
    replace: ") return c.json({ error: \"forbidden\" }, 403);",
    expect: ["bootstrap-token-required"],
  },
  {
    id: "bootstrap-allows-second-owner", rule: "AUTH-1", file: ROUTES,
    find: ", ? where not exists (select 1 from users)\"",
    replace: ", ? \"",
    expect: ["bootstrap-claims-once"],
  },
  {
    id: "role-patch-above-own-role", rule: "AUTH-3", file: ROUTES,
    find: "    if (rank(b.role) > rank(c.user!.role)) return c.json({ error: \"cannot grant a role above your own\" }, 403);\n    const refused = await guardTarget(c, id, b.role !== \"owner\");",
    replace: "    const refused = await guardTarget(c, id, b.role !== \"owner\");",
    expect: ["role-change-authority"],
  },
  {
    id: "guard-target-above-own-role", rule: "AUTH-3", file: ROUTES,
    find: "if (rank(target.role) > rank(c.user!.role)) return c.json({ error: \"cannot modify a user above your own role\" }, 403);",
    replace: "",
    expect: ["role-change-authority"],
  },
  {
    id: "key-minted-above-own-role", rule: "AUTH-4", file: ROUTES,
    find: "if (rank(role) > rank(c.user!.role)) return c.json({ error: \"cannot mint a key above your own role\" }, 403);",
    replace: "",
    expect: ["key-role-ceiling"],
  },
  {
    id: "user-list-leaks-password-hash", rule: "AUTH-4", file: ROUTES,
    find: "select id, email, role, disabled, created_at from users order by created_at, id",
    replace: "select id, email, role, disabled, created_at, password_hash from users order by created_at, id",
    expect: ["listings-hide-secrets"],
  },

  // CRYPTO-1..5 (DR-0010 steps c-g). Mutations that keep the app running, so a probe, not a crash, is what kills each one.
  // A CHECK that no longer rejects plaintext is needed whenever a route is made to store plaintext; the CHECK is a second defence.
  {
    id: "notes-stored-plaintext", rule: "CRYPTO-1", file: DEMO_ROUTES,
    find: 'await c.db.run("insert into notes (text) values (?)", await c.db.seal("notes", "text", body.text));',
    replace: 'await c.db.run("insert into notes (text) values (?)", body.text);',
    // The read path would refuse a plaintext row and the CHECK would refuse the insert: both defences are removed so the app keeps running.
    also: [
      { file: DEMO_ROUTES, find: 'Promise.all((await c.db.query<{ text: string }>("select text from notes order by id")).map((r) => c.db.open("notes", "text", r.text)))', replace: 'Promise.all((await c.db.query<{ text: string }>("select text from notes order by id")).map((r) => r.text))' },
      { file: CLASSIFICATION, find: `glob 'bk1:[1-9]*:????????????????:?*' and`, replace: `glob '*' and` },
      { file: CLASSIFICATION, find: `"\${column}" not glob '*[^A-Za-z0-9_:-]*')\``, replace: `"\${column}" not glob '*[^A-Za-z0-9_:-]*' or 1)\`` },
    ],
    // Shredding cannot make plaintext unreadable, so the shred scenario fails too (plaintext still readable and in storage).
    expect: ["shredding-makes-data-unreadable", "storage-canary-at-rest"],
  },
  {
    id: "secret-stored-plaintext", rule: "CRYPTO-1", file: DEMO_ROUTES,
    find: 'await c.db.seal("tenant_secrets", "value", body.value)',
    replace: "body.value",
    also: [
      { file: CLASSIFICATION, find: `glob 'bk1:[1-9]*:????????????????:?*' and`, replace: `glob '*' and` },
      { file: CLASSIFICATION, find: `"\${column}" not glob '*[^A-Za-z0-9_:-]*')\``, replace: `"\${column}" not glob '*[^A-Za-z0-9_:-]*' or 1)\`` },
    ],
    expect: ["shredding-makes-data-unreadable", "storage-canary-at-rest"],
  },
  {
    id: "sealed-check-accepts-plaintext", rule: "CRYPTO-1", file: CLASSIFICATION,
    find: `glob 'bk1:[1-9]*:????????????????:?*' and`,
    replace: `glob '*' and`,
    expect: [],
    gap: "the demo only ever inserts sealed values, so a CHECK that accepts anything changes nothing over HTTP; the database refusing plaintext is a second defence that core unit tests prove (sealing.test.ts)",
  },
  {
    id: "unclassified-column-allowed", rule: "CRYPTO-1", file: CLASSIFICATION,
    find: "if (!f) throw new ClassificationError(`unclassified column ${key}: the tenant refuses to initialise`);",
    replace: "if (!f) continue;",
    expect: [],
    gap: "the demo classifies every column, so no HTTP request reaches the refusal; core unit tests prove an unclassified column stops the tenant initialising",
  },
  {
    id: "missing-check-allowed", rule: "CRYPTO-1", file: CLASSIFICATION,
    find: "if (isEncryptedClass(f.class) && !hasLiveCheck(sql, sealedCheck(col.name)))",
    replace: "if (false)",
    expect: [],
    gap: "the demo declares the CHECK on every sealed column, so no HTTP request reaches the refusal; core unit tests prove a missing CHECK stops the tenant initialising",
  },
  {
    id: "classification-not-enforced-at-init", rule: "CRYPTO-1", file: "packages/core/src/tenant/store.ts",
    find: "if (classification) enforceClassification(this.exec, classification);",
    replace: "",
    expect: [],
    gap: "the demo's schema is classified correctly, so skipping the init-time enforcement changes nothing over HTTP; core unit tests prove the tenant refuses to initialise",
  },
  {
    id: "stale-classification-allowed", rule: "CRYPTO-1", file: CLASSIFICATION,
    find: "for (const f of c.fields) if (!columns.has(`${f.table}.${f.field}`)) throw",
    replace: "for (const f of c.fields) if (false) throw",
    expect: [],
    gap: "the demo's classification names only real columns; core unit tests prove a stale entry stops the tenant initialising",
  },
  {
    id: "aad-binds-no-table-or-field", rule: "CRYPTO-2", file: KEYS,
    find: "const ctx: SealContext = { tenantId, table, field, keyVersion: version };",
    replace: 'const ctx: SealContext = { tenantId, table: "t", field: "f", keyVersion: version };',
    // Sealing and opening must agree, or every note would fail to open and a crash, not the probe, would kill the mutation.
    also: [{ file: KEYS, find: "{ tenantId, table, field, keyVersion: env.keyVersion }, sealed);", replace: '{ tenantId, table: "t", field: "f", keyVersion: env.keyVersion }, sealed);' }],
    expect: ["aad-transplant-fails"],
  },
  {
    id: "shred-of-keyless-tenant-leaves-no-marker", rule: "CRYPTO-3", file: KEYS,
    find: "      await ring.ensureTenantKey(tenantId); // a never-keyed tenant still gets marker rows, so a later request cannot mint a fresh key\n",
    replace: "",
    expect: [],
    gap: "every tenant is keyed when it is provisioned (directory.ts), so no demo tenant is keyless at shred time and the marker rows are a second defence no HTTP request reaches; core unit tests prove a never-keyed tenant stays unwritable after shred",
  },
  {
    id: "aad-binds-no-tenant", rule: "CRYPTO-2", file: KEYS,
    find: "const ctx: SealContext = { tenantId, table, field, keyVersion: version };",
    replace: 'const ctx: SealContext = { tenantId: "t", table, field, keyVersion: version };',
    also: [{ file: KEYS, find: "{ tenantId, table, field, keyVersion: env.keyVersion }, sealed);", replace: '{ tenantId: "t", table, field, keyVersion: env.keyVersion }, sealed);' }],
    expect: [],
    gap: "every tenant has its own data key, so a cross-tenant transplant still fails on the key even when the AAD omits the tenant; no HTTP scenario separates the two defences, core unit tests cover the AAD at the sealer level",
  },
  {
    id: "run-accepts-any-statement", rule: "CRYPTO-1", file: "packages/core/src/tenant/store.ts",
    find: "if (classification) assertDataStatement(sql);",
    replace: "",
    expect: [],
    gap: "the demo only sends single data statements, so no HTTP request reaches the refusal of DDL, pragmas and multi-statement text on a classified app; core unit tests prove it",
  },
  {
    id: "any-text-counts-as-a-live-check", rule: "CRYPTO-1", file: CLASSIFICATION,
    find: "function hasLiveCheck(tableSql: string, needle: string): boolean {",
    replace: "function hasLiveCheck(tableSql: string, needle: string): boolean {\n  if (tableSql !== null) return true;",
    expect: [],
    gap: "the demo declares a real CHECK on every sealed column, so no HTTP request reaches the refusal of a commented or quoted look-alike; core unit tests prove it",
  },
  {
    id: "key-insert-ignores-shredded-rows", rule: "CRYPTO-3", file: KEYS,
    find: 'select ?, ?, ?, ?, ? where not exists (select 1 from tenant_keys where tenant_id = ? and wrapped is null)").bind(tenantId, version, master.current, wrapped, now(), tenantId)',
    replace: 'values (?, ?, ?, ?, ?)").bind(tenantId, version, master.current, wrapped, now())',
    expect: [],
    gap: "the guard in insertVersion only matters when a rotation races a shred, which a sequential HTTP scenario cannot produce; core unit tests prove no live key is written for a shredded tenant",
  },
  {
    id: "current-key-ignores-shredded-rows", rule: "CRYPTO-3", file: KEYS,
    find: 'if (all.some((r) => r.wrapped === null)) throw new KeyDestroyedError("tenant key destroyed");',
    replace: "",
    expect: [],
    gap: "the shredded-row refusal in current() is shadowed over HTTP (a shredded tenant is never re-keyed and get() refuses the destroyed rows), so no request reaches it alone; core unit tests prove a live newer version beside a destroyed one is still refused",
  },
  {
    id: "nonce-counter-never-advances", rule: "CRYPTO-4", file: "packages/core/src/tenant/store.ts",
    find: "do update set value = cast(cast(value as integer) + 1 as text)",
    replace: "do update set value = value",
    expect: ["nonce-uniqueness-and-rotation"],
  },
  {
    id: "rotation-keeps-stale-current-key", rule: "CRYPTO-4", file: KEYS,
    find: "      await insertVersion(tenantId, next);\n      latest.delete(tenantId);\n      return next;",
    replace: "      await insertVersion(tenantId, next);\n      return next;",
    expect: ["nonce-uniqueness-and-rotation"],
  },
  {
    id: "rotation-destroys-old-versions", rule: "CRYPTO-4", file: KEYS,
    find: "      await insertVersion(tenantId, next);\n      latest.delete(tenantId);\n      return next;",
    replace: "      await insertVersion(tenantId, next);\n      latest.delete(tenantId);\n      await db.prepare(\"update tenant_keys set wrapped = null where tenant_id = ? and version < ?\").bind(tenantId, next).run();\n      cache.clear();\n      return next;",
    expect: ["nonce-uniqueness-and-rotation"],
  },
  {
    id: "rotate-route-announces-without-rotating", rule: "CRYPTO-4", file: DEMO_ROUTES,
    find: "c.json({ keyVersion: await c.keys.rotate() })",
    replace: "c.json({ keyVersion: 2 })",
    // The route also answers 200 for a shredded tenant (no rotation ran, so nothing refused it), which the shred scenario rightly rejects.
    expect: ["nonce-uniqueness-and-rotation", "shredding-makes-data-unreadable"],
  },
  {
    id: "shred-leaves-keys-wrapped", rule: "CRYPTO-3", file: KEYS,
    find: "update tenant_keys set wrapped = null, shredded_at = ? where tenant_id = ?",
    replace: "update tenant_keys set shredded_at = ? where tenant_id = ?",
    expect: ["shredding-makes-data-unreadable"],
  },
  {
    id: "shred-route-is-a-no-op", rule: "CRYPTO-3", file: DEMO_ROUTES,
    find: "(await c.keys.shred(), c.json({ shredded: true }))",
    replace: "c.json({ shredded: true })",
    expect: ["shredding-makes-data-unreadable"],
  },
  {
    id: "shred-open-to-anonymous", rule: "CRYPTO-3", file: DEMO_ROUTES,
    find: 'app.route("POST", "/admin/shred", { role: "owner" },',
    replace: 'app.route("POST", "/admin/shred", DEMO,',
    expect: ["shredding-makes-data-unreadable"],
  },
  {
    id: "shredded-tenant-is-rekeyed", rule: "CRYPTO-3", file: KEYS,
    find: "if ((await rows(tenantId)).length === 0) await insertVersion(tenantId, 1);",
    replace: "{ const have = await rows(tenantId); if (have.every((r) => r.wrapped === null)) await insertVersion(tenantId, have.length + 1); }",
    // The 60-second ensure memo would hide the re-mint inside the gate's window; the memo is a speed-up, not a defence.
    also: [
      { file: KEYS, find: "      ensured.set(tenantId, now() + ttlMs);\n", replace: "" },
      // Two more defences now refuse a re-key: insertVersion declines while any row is shredded, and current() refuses any tenant with a shredded row. Both go too.
      { file: KEYS, find: '        if (all.some((r) => r.wrapped === null)) throw new KeyDestroyedError("tenant key destroyed");\n', replace: "" },
      { file: KEYS, find: 'select ?, ?, ?, ?, ? where not exists (select 1 from tenant_keys where tenant_id = ? and wrapped is null)").bind(tenantId, version, master.current, wrapped, now(), tenantId)', replace: 'values (?, ?, ?, ?, ?)").bind(tenantId, version, master.current, wrapped, now())' },
    ],
    expect: ["shredding-makes-data-unreadable"],
  },
  {
    id: "rotation-of-shredded-tenant-allowed", rule: "CRYPTO-3", file: KEYS,
    find: "if (all.length === 0 || all.some((r) => r.wrapped === null)) throw new KeyDestroyedError(\"tenant key destroyed or absent\");",
    replace: "if (all.length === 0) throw new KeyDestroyedError(\"tenant key destroyed or absent\");",
    expect: ["shredding-makes-data-unreadable"],
  },
  {
    id: "destroyed-tenant-answers-500", rule: "CRYPTO-3", file: "packages/core/src/api/app.ts",
    find: 'if (err instanceof KeyDestroyedError) return reply(410, "tenant data is unavailable");',
    replace: "",
    expect: ["shredding-makes-data-unreadable"],
  },
  {
    id: "write-only-refusal-removed", rule: "CRYPTO-5", file: KEYS,
    find: "if (opening && f.writeOnly) throw new CryptoError(`${table}.${field} is write-only`);",
    replace: "",
    expect: [],
    gap: "no demo route opens a write-only field, so removing the handle's refusal changes nothing over HTTP on its own; core unit tests prove the handle refuses; the next entry shows the probe catches the end-to-end read-back",
  },
  {
    id: "secret-listing-returns-value", rule: "CRYPTO-5", file: DEMO_ROUTES,
    find: 'c.json({ secrets: await c.db.query("select id, name, created_at from tenant_secrets order by created_at") })',
    replace: 'c.json({ secrets: await Promise.all((await c.db.query<{ id: string; name: string; value: string; created_at: number }>("select id, name, value, created_at from tenant_secrets order by created_at")).map(async (r) => ({ ...r, value: await c.db.open("tenant_secrets", "value", r.value) }))) })',
    // Two defences are broken together: the route that returns the value, and the handle's write-only refusal.
    also: [{ file: KEYS, find: "if (opening && f.writeOnly) throw new CryptoError(`${table}.${field} is write-only`);", replace: "" }],
    expect: ["secret-write-only-readback"],
  },
  {
    id: "unsealed-field-can-be-sealed", rule: "CRYPTO-1", file: KEYS,
    find: "if (!f || !isEncryptedClass(f.class)) throw new CryptoError(`${table}.${field} is not a sealed field`);",
    replace: "if (!f) throw new CryptoError(`${table}.${field} is not a sealed field`);",
    expect: [],
    gap: "the demo seals only classified fields, so the sealer's own class check is never reached over HTTP; core unit tests prove unsealed fields cannot be sealed",
  },
  {
    id: "master-key-length-unchecked", rule: "BOOT-1", file: KEYS,
    find: "if (bytes.length !== 32) throw new MasterKeyError(`${name} must be exactly 32 bytes`);",
    replace: "",
    expect: [],
    gap: "BOOT-1 is a boot-time refusal that the HTTP verify cannot trigger (the gate always supplies good keys); core unit tests cover it, and the launcher-level boot check (scripts/verify-boot.ts) is the builder's, not claimed here",
  },
  {
    id: "master-keys-not-required-at-boot", rule: "BOOT-1", file: "packages/core/src/api/app.ts",
    find: "const cfg = (config ??= loadConfig(c.env as Record<string, unknown>, { requireMasterKeys: !!classification }));",
    replace: "const cfg = (config ??= loadConfig(c.env as Record<string, unknown>));",
    also: [{ file: "packages/core/src/api/app.ts", find: "config ??= loadConfig(env as Record<string, unknown>, { requireMasterKeys: !!classification });", replace: "config ??= loadConfig(env as Record<string, unknown>);" }],
    // Not a BOOT-1 check (the boot refusal is the launcher-level gate, scripts/verify-boot.ts, not claimed here): without the keys loaded the app has no
    // sealing at all, so every probe that stores or reads a sealed field fails. It shows these probes notice an app that lost its key hierarchy.
    expect: ["aad-transplant-fails", "add-tenant-metamorphic", "cache-canary", "nonce-uniqueness-and-rotation", "notes-list-canary", "secret-write-only-readback", "shredding-makes-data-unreadable", "storage-canary-at-rest"],
  },
  // DR-0011 spike (Better Auth). Each entry runs against examples/demo-betterauth. Entries on a single one of two overlapping
  // defences are named gaps: the other defence shadows them over HTTP, so only a unit test in packages/auth-betterauth can kill them.
  {
    id: "ba-role-change-keeps-sessions", rule: "AUTH-2", app: BA_APP, file: BA_ROUTES,
    find: "    await revokeSessionsOf(c, id);\n    await revokeKeysOf(c, id);\n    return c.json({ id, role: b.role });",
    replace: "    await revokeKeysOf(c, id);\n    return c.json({ id, role: b.role });",
    expect: ["role-change-revokes"],
  },
  {
    id: "ba-role-change-keeps-keys", rule: "AUTH-4", app: BA_APP, file: BA_ROUTES,
    find: "    await revokeSessionsOf(c, id);\n    await revokeKeysOf(c, id);\n    return c.json({ id, role: b.role });",
    replace: "    await revokeSessionsOf(c, id);\n    return c.json({ id, role: b.role });",
    expect: ["key-revocation"],
  },
  {
    id: "ba-disable-keeps-sessions-and-check-removed", rule: "AUTH-2", app: BA_APP, file: BA_ROUTES,
    find: "    await revokeSessionsOf(c, id);\n    await revokeKeysOf(c, id);\n    return c.json({ id, disabled: true });",
    replace: "    await revokeKeysOf(c, id);\n    return c.json({ id, disabled: true });",
    also: [{ file: BA_AUTH, find: "if (u.disabled !== 0 || !isRole(u.role)) return null;", replace: "if (!isRole(u.role)) return null;" }],
    expect: ["disabled-user-denied"],
  },
  {
    id: "ba-session-ignores-disabled", rule: "AUTH-2", app: BA_APP, file: BA_AUTH,
    find: "if (u.disabled !== 0 || !isRole(u.role)) return null;",
    replace: "if (!isRole(u.role)) return null;",
    expect: [],
    gap: "disable revokes sessions and keys first, so over HTTP this check is shadowed by revocation (defence in depth); only a unit test of authenticate can kill it",
  },
  {
    id: "ba-disable-keeps-sessions", rule: "AUTH-2", app: BA_APP, file: BA_ROUTES,
    find: "    await revokeSessionsOf(c, id);\n    await revokeKeysOf(c, id);\n    return c.json({ id, disabled: true });",
    replace: "    await revokeKeysOf(c, id);\n    return c.json({ id, disabled: true });",
    expect: [],
    gap: "authenticate re-reads the user's disabled flag on every request, so a surviving session is still refused; only a unit test of the route can kill it",
  },
  {
    id: "ba-login-ignores-disabled", rule: "AUTH-2", app: BA_APP, file: BA_ROUTES,
    find: "if (!user || user.disabled !== 0) {",
    replace: "if (!user) {",
    expect: ["disabled-user-denied"],
  },
  {
    id: "ba-cookie-cache-defers-revocation", rule: "AUTH-2", app: BA_APP, file: BA_INSTANCE,
    find: "cookieCache: { enabled: false }",
    replace: "cookieCache: { enabled: true, maxAge: 300 }",
    also: [{ file: BA_AUTH, find: "auth.api.getSession({ headers: req.headers, query: { disableCookieCache: true } })", replace: "auth.api.getSession({ headers: req.headers })" }],
    expect: ["role-change-revokes"],
  },
  {
    id: "ba-cookie-not-httponly", rule: "AUTH-2", app: BA_APP, file: BA_INSTANCE,
    find: "attributes: { httpOnly: true, secure: true,",
    replace: "attributes: { httpOnly: false, secure: true,",
    expect: ["cookie-flags"],
  },
  {
    id: "ba-cookie-not-secure", rule: "AUTH-2", app: BA_APP, file: BA_INSTANCE,
    find: "attributes: { httpOnly: true, secure: true,",
    replace: "attributes: { httpOnly: true, secure: false,",
    expect: [],
    gap: "better-call forces Secure on any cookie named __Host-, so the explicit attribute is shadowed over HTTP; only a unit test that builds the instance and reads its cookie attributes can kill it",
  },
  {
    id: "ba-cookie-loses-host-prefix", rule: "AUTH-2", app: BA_APP, file: BA_INSTANCE,
    find: 'export const SESSION_COOKIE = "__Host-bk_session";',
    replace: 'export const SESSION_COOKIE = "bk_session";',
    // The probes look for the cookie by its __Host- name, so with another name no login yields a session and nearly every probe fails: cookie-flags among them, but not alone.
    expect: ["aad-transplant-fails", "api-key-scope", "authority-matrix", "bootstrap-claims-once", "cookie-flags", "cross-tenant-session", "csrf-origin", "disabled-user-denied", "key-revocation", "key-role-ceiling", "key-wrong-secret-denied", "listings-hide-secrets", "logout-revokes", "no-default-role", "nonce-uniqueness-and-rotation", "role-change-authority", "role-change-revokes", "role-matrix", "secret-write-only-readback", "session-rotation", "shredding-makes-data-unreadable", "storage-canary-at-rest", "unknown-email-login-same-answer"],
  },
  {
    id: "ba-csrf-origin-ignored", rule: "AUTH-2", app: BA_APP, file: BA_AUTH,
    find: "return new URL(origin).host === new URL(req.url).host;",
    replace: "return true;",
    expect: ["csrf-origin"],
  },
  {
    id: "ba-csrf-no-header-allowed", rule: "AUTH-2", app: BA_APP, file: BA_AUTH,
    find: 'return site === "same-origin" || site === "none";',
    replace: 'return site === null || site === "same-origin" || site === "none";',
    expect: ["csrf-origin"],
  },
  {
    id: "ba-unknown-session-gets-default-role", rule: "AUTH-1", app: BA_APP, file: BA_AUTH,
    find: "if (!found) return null;",
    replace: 'if (!found) return { id: "anonymous", role: "member" };',
    expect: ["cross-tenant-session", "disabled-user-denied", "logout-revokes", "no-default-role", "role-change-revokes", "session-rotation"],
  },
  {
    id: "ba-user-created-with-default-role", rule: "AUTH-1", app: BA_APP, file: BA_INSTANCE,
    find: "const role = slot.next;",
    replace: 'const role = slot.next ?? "owner";',
    expect: [],
    gap: "no HTTP route creates a user without an explicit role, so the fallback is unreachable over HTTP; a unit test that creates a user with an empty slot must kill it",
  },
  {
    id: "ba-logout-keeps-session", rule: "AUTH-2", app: BA_APP, file: BA_ROUTES,
    find: "const res = await instance(c).api.signOut({ headers: c.req.headers, asResponse: true });",
    replace: "const res = new Response(null);",
    also: [{ file: BA_ROUTES, find: "    if (presented) {\n      await c.db.run('delete from \"session\" where token = ?', presented);\n      if (((await c.db.query<{ n: number }>('select count(*) as n from \"session\" where token = ?', presented))[0]?.n ?? 1) !== 0) throw new Error(\"session survived logout\");\n    }\n", replace: "" }],
    // Two independent defences (signOut, and the explicit delete that follows it) must both go.
    expect: ["logout-revokes"],
  },
  {
    id: "ba-logout-explicit-delete-removed", rule: "AUTH-2", app: BA_APP, file: BA_ROUTES,
    find: "    if (presented) {\n      await c.db.run('delete from \"session\" where token = ?', presented);\n      if (((await c.db.query<{ n: number }>('select count(*) as n from \"session\" where token = ?', presented))[0]?.n ?? 1) !== 0) throw new Error(\"session survived logout\");\n    }\n",
    replace: "",
    expect: [],
    gap: "Better Auth's signOut deletes the session itself, so the explicit delete and survival check are shadowed over HTTP; killed by gaps.test.ts 'logout is a 500, not a 200, when the session could not be removed'",
  },
  {
    id: "ba-logout-signout-skipped", rule: "AUTH-2", app: BA_APP, file: BA_ROUTES,
    find: "const res = await instance(c).api.signOut({ headers: c.req.headers, asResponse: true });",
    replace: "const res = new Response(null);",
    expect: [],
    gap: "the explicit delete still revokes the session, so only the cookie-clearing Set-Cookie from signOut is lost, which no probe checks; killed by gaps.test.ts 'ba-logout-keeps-session: logout clears the cookie in the response and removes the session row'",
  },
  {
    id: "ba-login-unknown-email-distinguishable", rule: "AUTH-2", app: BA_APP, file: BA_ROUTES,
    find: '      await c.db.run("insert into login_attempts (email, at) values (?, ?)", email, now);\n      return bad();\n    }\n    // Rotation',
    replace: '      await c.db.run("insert into login_attempts (email, at) values (?, ?)", email, now);\n      return c.json({ error: "no such user" }, 401);\n    }\n    // Rotation',
    expect: ["unknown-email-login-same-answer"],
  },
  {
    id: "ba-login-unknown-email-skips-dummy-hash", rule: "AUTH-2", app: BA_APP, file: BA_ROUTES,
    find: "      await verifyPassword(b.password, null); // the same work as a real check, so timing does not separate the cases\n",
    replace: "",
    expect: [],
    gap: "the dummy hash only equalises timing, which no black-box probe measures; a unit test must assert the unknown-email branch calls verifyPassword",
  },
  {
    id: "ba-login-lockout-removed", rule: "AUTH-2", app: BA_APP, file: BA_ROUTES,
    find: 'if (n >= MAX_FAILED_LOGINS) return c.json({ error: "too many attempts" }, 429);',
    replace: "",
    expect: [],
    gap: "no probe drives repeated failed logins; a unit test must assert the sixth attempt inside the window is refused",
  },
  {
    id: "ba-login-no-rotation", rule: "AUTH-2", app: BA_APP, file: BA_ROUTES,
    find: "    if (presented) await c.db.run('delete from \"session\" where token = ?', presented);\n    await c.db.run(\"delete from login_attempts",
    replace: "    await c.db.run(\"delete from login_attempts",
    expect: ["session-rotation"],
  },
  {
    id: "ba-adapter-where-dropped", rule: "TENANT-1", app: BA_APP, file: BA_ADAPTER,
    find: "return { sql: ` where ${groups.join(\" and \")}`, params: [...ands, ...ors].flatMap((p) => p.p) };",
    replace: "return { sql: \"\", params: [] };",
    // Every lookup by id or email then returns the first row of the table (writes are refused by writeWhere only when the list is empty, not when the SQL is), so identity-dependent probes fail broadly.
    expect: ["authority-matrix", "cross-tenant-session", "disabled-user-denied", "key-revocation", "key-role-ceiling", "listings-hide-secrets", "role-change-authority", "role-change-revokes", "role-matrix", "session-rotation"],
  },
  {
    id: "ba-adapter-handle-shared-across-requests", rule: "TENANT-1", app: BA_APP, file: BA_ADAPTER,
    find: "export function tenantDbAdapter(db: TenantDb) {\n  return createAdapterFactory({",
    replace: "let firstDb: TenantDb | undefined;\nexport function tenantDbAdapter(db: TenantDb) {\n  firstDb ??= db;\n  db = firstDb;\n  return createAdapterFactory({",
    // A module-level handle serves the first tenant's database to every later request; the Worker breaks wholesale, and cross-tenant-session is among the probes that notice.
    expect: ["aad-transplant-fails", "api-key-scope", "authority-matrix", "bootstrap-claims-once", "bootstrap-token-required", "cookie-flags", "cross-tenant-session", "csrf-origin", "disabled-user-denied", "key-revocation", "key-role-ceiling", "key-wrong-secret-denied", "listings-hide-secrets", "logout-revokes", "no-default-role", "nonce-uniqueness-and-rotation", "role-change-authority", "role-change-revokes", "role-matrix", "secret-write-only-readback", "session-rotation", "shredding-makes-data-unreadable", "storage-canary-at-rest", "unknown-email-login-same-answer"],
  },
  {
    id: "ba-bootstrap-guards-removed", rule: "AUTH-1", app: BA_APP, file: BA_ROUTES,
    find: "    if (((await c.db.query<{ n: number }>('select count(*) as n from \"user\"'))[0]?.n ?? 0) > 0) return c.json({ error: \"tenant already has users\" }, 409);\n",
    replace: "",
    also: [{ file: BA_ROUTES, find: " and (select count(*) from \"user\") = 1', id);", replace: "', id);" }],
    // Two overlapping defences: the pre-check on the user count and the count guard on the claiming update.
    expect: ["bootstrap-claims-once"],
  },
  {
    id: "ba-bootstrap-precheck-removed", rule: "AUTH-1", app: BA_APP, file: BA_ROUTES,
    find: "    if (((await c.db.query<{ n: number }>('select count(*) as n from \"user\"'))[0]?.n ?? 0) > 0) return c.json({ error: \"tenant already has users\" }, 409);\n",
    replace: "",
    expect: [],
    gap: "the guarded claiming update discards a second claimant again, so the pre-check is shadowed over HTTP; killed by gaps.test.ts 'ba-bootstrap-precheck-removed: a second claim is refused before any second user is written'",
  },
  {
    id: "ba-bootstrap-postcheck-removed", rule: "AUTH-1", app: BA_APP, file: BA_ROUTES,
    find: " and (select count(*) from \"user\") = 1', id);",
    replace: "', id);",
    expect: [],
    gap: "the pre-check refuses a sequential second claimant first; the count guard exists for races, which a sequential black-box probe cannot produce; killed by gaps.test.ts 'ba-bootstrap-postcheck-removed: two claims racing leave at most one user, never two owners'",
  },
  {
    id: "ba-bootstrap-token-unchecked", rule: "AUTH-1", app: BA_APP, file: BA_ROUTES,
    find: "|| !safeEqual(b.token, secret)) return c.json({ error: \"forbidden\" }, 403);",
    replace: ") return c.json({ error: \"forbidden\" }, 403);",
    expect: ["bootstrap-token-required"],
  },
  {
    id: "ba-role-patch-above-own-role", rule: "AUTH-3", app: BA_APP, file: BA_ROUTES,
    find: "    if (rank(b.role) > rank(c.user!.role)) return c.json({ error: \"cannot grant a role above your own\" }, 403);\n    const refused = await guardTarget(c, id, b.role !== \"owner\");",
    replace: "    const refused = await guardTarget(c, id, b.role !== \"owner\");",
    expect: ["role-change-authority"],
  },
  {
    id: "ba-guard-target-above-own-role", rule: "AUTH-3", app: BA_APP, file: BA_ROUTES,
    find: "if (rank(target.role) > rank(c.user!.role)) return c.json({ error: \"cannot modify a user above your own role\" }, 403);",
    replace: "",
    expect: ["role-change-authority"],
  },
  {
    id: "ba-grant-above-own-role", rule: "AUTH-3", app: BA_APP, file: BA_ROUTES,
    find: '    if (rank(b.role) > rank(c.user!.role)) return c.json({ error: "cannot grant a role above your own" }, 403);\n    const made = await createUser(',
    replace: "    const made = await createUser(",
    expect: ["authority-matrix"],
  },
  {
    id: "ba-key-minted-above-own-role", rule: "AUTH-4", app: BA_APP, file: BA_ROUTES,
    find: "if (rank(role) > rank(c.user!.role)) return c.json({ error: \"cannot mint a key above your own role\" }, 403);",
    replace: "",
    expect: ["key-role-ceiling"],
  },
  {
    id: "ba-key-delete-noop", rule: "AUTH-4", app: BA_APP, file: BA_ROUTES,
    find: '"update api_keys set revoked_at = ? where id = ? and revoked_at is null"',
    replace: '"update api_keys set revoked_at = revoked_at where id = ? and ? is not null and revoked_at is null"',
    expect: ["key-revocation"],
  },
  {
    id: "ba-key-list-leaks-secret-hash", rule: "AUTH-4", app: BA_APP, file: BA_ROUTES,
    find: 'select id, name, role, permissions, created_by, created_at, expires_at, revoked_at from api_keys',
    replace: 'select id, name, role, permissions, created_by, created_at, expires_at, revoked_at, secret_hash from api_keys',
    expect: ["listings-hide-secrets"],
  },
  {
    id: "ba-key-revoked-check-removed", rule: "AUTH-4", app: BA_APP, file: BA_AUTH,
    find: "where k.id = ? and k.revoked_at is null and (k.expires_at is null or k.expires_at > ?)",
    replace: "where k.id = ? and (k.expires_at is null or k.expires_at > ?)",
    expect: ["key-revocation"],
  },
  {
    id: "ba-key-expiry-check-removed", rule: "AUTH-4", app: BA_APP, file: BA_AUTH,
    find: "where k.id = ? and k.revoked_at is null and (k.expires_at is null or k.expires_at > ?)",
    replace: "where k.id = ? and k.revoked_at is null and ? is not null",
    expect: [],
    gap: "no probe mints an expiring key and waits it out; a unit test with a past expires_at must kill it",
  },
  {
    id: "ba-key-secret-not-compared", rule: "AUTH-4", app: BA_APP, file: BA_AUTH,
    find: "if (!row || !ok || row.user_disabled",
    replace: "if (!row || row.user_disabled",
    expect: ["key-wrong-secret-denied"],
  },
  {
    id: "ba-key-ignores-disabled", rule: "AUTH-4", app: BA_APP, file: BA_AUTH,
    find: "row.user_disabled !== 0 || ",
    replace: "",
    expect: [],
    gap: "disable revokes sessions and keys first, so over HTTP this check is shadowed by revocation (defence in depth); only a unit test of authenticate can kill it",
  },
  {
    id: "ba-key-role-not-capped-by-owner", rule: "AUTH-4", app: BA_APP, file: BA_AUTH,
    find: "const role = ROLE_VALUES.indexOf(row.role) <= ROLE_VALUES.indexOf(row.user_role) ? row.role : row.user_role;",
    replace: "const role = row.role;",
    expect: [],
    gap: "a role change revokes the user's keys, so a key outliving a demotion cannot be built over HTTP; only a unit test of authenticate can kill it",
  },
  {
    id: "ba-writes-without-condition-allowed", rule: "TENANT-1", app: BA_APP, file: BA_ADAPTER,
    find: "if (!where || where.length === 0) throw new Error(\"refusing a write with an empty where clause\");",
    replace: "",
    expect: [],
    gap: "Better Auth does not issue a write without a condition over HTTP; killed by gaps.test.ts 'the adapter refuses a write with no condition'",
  },
  {
    id: "ba-adapter-or-joined-into-and", rule: "TENANT-1", app: BA_APP, file: BA_ADAPTER,
    find: "  const ands = parts.filter((p) => !p.or);\n  const ors = parts.filter((p) => p.or);",
    replace: "  const ands = parts;\n  const ors: typeof parts = [];",
    expect: [],
    gap: "no route builds a query with OR clauses, so grouping is invisible over HTTP; killed by gaps.test.ts 'the adapter groups (every AND clause) AND (any OR clause), like Better Auth's own adapters'",
  },
  {
    id: "ba-signup-failure-keeps-partial-user", rule: "AUTH-1", app: BA_APP, file: BA_ROUTES,
    find: "      if (partial) await discardUser(c, partial.id);\n",
    replace: "",
    expect: [],
    gap: "a sign-up that fails halfway cannot be provoked over HTTP; killed by gaps.test.ts 'a sign-up that fails halfway leaves no partial user: bootstrap is a 500, then a retry succeeds'",
  },
  {
    id: "ba-signup-invalid-is-not-400", rule: "AUTH-1", app: BA_APP, file: BA_ROUTES,
    find: "      if ((e as { status?: unknown; statusCode?: unknown }).statusCode === 400) return { error: \"invalid\" };\n",
    replace: "",
    expect: [],
    gap: "the routes validate email and password before Better Auth, so Better Auth's own 400 is unreachable over HTTP; killed by gaps.test.ts 'an email Better Auth rejects is a 400, not a conflict'",
  },
  {
    id: "ba-token-decode-unguarded", rule: "AUTH-2", app: BA_APP, file: BA_ROUTES,
    find: "  try { return decodeURIComponent(cookie).split(\".\")[0] || null; } catch { return null; } // a malformed escape is no session, not a 500",
    replace: "  return decodeURIComponent(cookie).split(\".\")[0] || null;",
    expect: [],
    gap: "no probe sends a malformed percent-escape in the session cookie; killed by gaps.test.ts 'a malformed cookie escape on login is not a server error'",
  },
  {
    id: "ba-signup-existing-email-precheck-removed", rule: "AUTH-1", app: BA_APP, file: BA_ROUTES,
    find: "    if ((await c.db.query('select 1 from \"user\" where email = ?', email)).length > 0) return { error: \"exists\" };\n",
    replace: "",
    // provisional expect, set from the run
    expect: [],
    gap: "Better Auth answers a duplicate email with a made-up user and the row check afterwards still reports it as taken, so the pre-check is shadowed over HTTP; killed by gaps.test.ts 'ba-signup-existing-email-precheck-removed: a taken email is refused before Better Auth runs'",
  },
];
