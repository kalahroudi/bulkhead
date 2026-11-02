// Demo routes. Kept free of `cloudflare:workers` imports so the manifest can be generated under Node.
import { createAuth } from "@kalahroudi/bulkhead-auth";
import { createApp } from "@kalahroudi/bulkhead-core/api";
import { parseClassification, sealedCheck } from "@kalahroudi/bulkhead-core/crypto";
import classificationFile from "../bulkhead.classification.json" with { type: "json" };

const DEMO = { public: { reason: "demo route used by the verify probes; real apps declare roles" } } as const;

/** `bootstrapToken` is read per request from the Worker's env (see index.ts); undefined disables first-owner bootstrap. */
export function createDemoApp(bootstrapToken: () => string | undefined = () => undefined) {
  const auth = createAuth({ bootstrapToken });
  const app = createApp({
    classification: parseClassification(classificationFile),
    schema: [
      ...auth.schema,
      `create table notes (id integer primary key autoincrement, text text not null ${sealedCheck("text")})`,
      `create table tenant_secrets (id text primary key, name text not null, value text not null ${sealedCheck("value")}, created_at integer not null)`,
    ],
    authenticate: auth.authenticate,
  });
  auth.registerRoutes(app);

  app.route("POST", "/notes", DEMO, async (c) => {
    const body = (await c.req.json().catch(() => null)) as { text?: unknown } | null;
    if (!body || typeof body.text !== "string") return c.json({ error: "text required" }, 400);
    await c.db.run("insert into notes (text) values (?)", await c.db.seal("notes", "text", body.text)); // notes.text is sensitive: only sealed values are accepted
    return c.json({ ok: true }, 201);
  });
  const readNotes = async (c: { db: { query<T>(sql: string): Promise<T[]>; open(t: string, f: string, v: string): Promise<string> } }) =>
    Promise.all((await c.db.query<{ text: string }>("select text from notes order by id")).map((r) => c.db.open("notes", "text", r.text)));
  app.route("GET", "/notes", DEMO, async (c) => c.json({ notes: await readNotes(c) }));
  app.route("GET", "/summary", DEMO, async (c) => c.json({ summary: (await readNotes(c)).join(" | ") }));
  app.route("GET", "/whoami", DEMO, (c) => c.json({ tenant: c.tenant.slug }));

  // One protected route per role, so the role differential (AUTH-3) and key scoping (AUTH-4) have something to bite on.
  app.route("GET", "/private/member", { role: "member", permission: "private:read" }, (c) => c.json({ area: "member", who: c.user!.id }));
  app.route("GET", "/private/admin", { role: "admin", permission: "private:admin" }, (c) => c.json({ area: "admin", who: c.user!.id }));
  app.route("GET", "/private/owner", { role: "owner" }, (c) => c.json({ area: "owner", who: c.user!.id }));

  // CRYPTO-5: tenant secrets have a store route and a metadata listing, and no route that returns a value. The handle refuses to open a write-only field.
  app.route("POST", "/secrets", { role: "owner" }, async (c) => {
    const body = (await c.req.json().catch(() => null)) as { name?: unknown; value?: unknown } | null;
    if (!body || typeof body.name !== "string" || !body.name || typeof body.value !== "string" || !body.value) return c.json({ error: "name and value required" }, 400);
    const id = crypto.randomUUID();
    await c.db.run("insert into tenant_secrets (id, name, value, created_at) values (?, ?, ?, ?)", id, body.name, await c.db.seal("tenant_secrets", "value", body.value), Date.now());
    return c.json({ id, name: body.name }, 201);
  });
  app.route("GET", "/secrets", { role: "owner" }, async (c) => c.json({ secrets: await c.db.query("select id, name, created_at from tenant_secrets order by created_at") }));

  // Key lifecycle (CRYPTO-3/4). Owner only. Shredding is irreversible.
  app.route("POST", "/admin/rotate-key", { role: "owner" }, async (c) => c.json({ keyVersion: await c.keys.rotate() }));
  app.route("POST", "/admin/shred", { role: "owner" }, async (c) => (await c.keys.shred(), c.json({ shredded: true })));
  return app;
}
