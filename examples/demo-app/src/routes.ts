// Demo routes. Kept free of `cloudflare:workers` imports so the manifest can be generated under Node.
import { createAuth } from "@kalahroudi/bulkhead-auth";
import { createApp } from "@kalahroudi/bulkhead-core/api";

const DEMO = { public: { reason: "demo route used by the verify probes; real apps declare roles" } } as const;

/** `bootstrapToken` is read per request from the Worker's env (see index.ts); undefined disables first-owner bootstrap. */
export function createDemoApp(bootstrapToken: () => string | undefined = () => undefined) {
  const auth = createAuth({ bootstrapToken });
  const app = createApp({
    schema: [...auth.schema, "create table notes (id integer primary key autoincrement, text text not null)"],
    authenticate: auth.authenticate,
  });
  auth.registerRoutes(app);

  app.route("POST", "/notes", DEMO, async (c) => {
    const body = (await c.req.json().catch(() => null)) as { text?: unknown } | null;
    if (!body || typeof body.text !== "string") return c.json({ error: "text required" }, 400);
    await c.db.run("insert into notes (text) values (?)", body.text);
    return c.json({ ok: true }, 201);
  });
  app.route("GET", "/notes", DEMO, async (c) => c.json({ notes: (await c.db.query<{ text: string }>("select text from notes order by id")).map((r) => r.text) }));
  app.route("GET", "/summary", DEMO, async (c) => c.json({ summary: (await c.db.query<{ text: string }>("select text from notes order by id")).map((r) => r.text).join(" | ") }));
  app.route("GET", "/whoami", DEMO, (c) => c.json({ tenant: c.tenant.slug }));

  // One protected route per role, so the role differential (AUTH-3) and key scoping (AUTH-4) have something to bite on.
  app.route("GET", "/private/member", { role: "member", permission: "private:read" }, (c) => c.json({ area: "member", who: c.user!.id }));
  app.route("GET", "/private/admin", { role: "admin", permission: "private:admin" }, (c) => c.json({ area: "admin", who: c.user!.id }));
  app.route("GET", "/private/owner", { role: "owner" }, (c) => c.json({ area: "owner", who: c.user!.id }));
  return app;
}
