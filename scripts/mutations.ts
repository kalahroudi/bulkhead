// Mutation catalog (DR-0007, VERIFY-4): each entry deliberately breaks one security-relevant line and names the
// probe ids that must then fail. `find` must occur exactly once in `file`, otherwise the runner errors instead of skipping.
// Every entry below was first proven by hand in Phases 2-3. New probes must arrive with at least one entry.
// The catalog lives here until DR-0007 is signed, which moves it next to the seeded-bug catalog in packages/verify/.
export interface Mutation {
  id: string;
  /** Rule the broken code upholds. */
  rule: string;
  /** Repo-relative path, edited only in the scratch copy. */
  file: string;
  find: string;
  replace: string;
  /** Probe ids that must fail, exactly. A missing one means a worthless scenario; an extra one means a mis-attributed scenario. */
  expect: string[];
  /**
   * Set only when no black-box probe can catch the mutation yet. `expect` must then be empty, and the unit tests of the
   * mutated package must fail instead, otherwise the line is unprotected and the gate fails. Naming the gap keeps it loud.
   */
  gap?: string;
}

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
    expect: [],
    gap: "no black-box probe disables a user and then retries; covered by auth unit tests only (DR-0006 known limits)",
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
];
