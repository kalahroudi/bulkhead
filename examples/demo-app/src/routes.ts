// Demo routes. Kept free of `cloudflare:workers` imports so the manifest can be generated under Node.
import { createApp } from "@kalahroudi/bulkhead-core/api";

const DEMO = { public: { reason: "demo route used by the verify probes; real apps declare roles" } } as const;

export function createDemoApp() {
  const app = createApp({
    schema: ["create table notes (id integer primary key autoincrement, text text not null)"],
  });

  app.route("POST", "/notes", DEMO, async (c) => {
    const body = (await c.req.json().catch(() => null)) as { text?: unknown } | null;
    if (!body || typeof body.text !== "string") return c.json({ error: "text required" }, 400);
    await c.db.run("insert into notes (text) values (?)", body.text);
    return c.json({ ok: true }, 201);
  });
  app.route("GET", "/notes", DEMO, async (c) => c.json({ notes: (await c.db.query<{ text: string }>("select text from notes order by id")).map((r) => r.text) }));
  app.route("GET", "/summary", DEMO, async (c) => c.json({ summary: (await c.db.query<{ text: string }>("select text from notes order by id")).map((r) => r.text).join(" | ") }));
  app.route("GET", "/whoami", DEMO, (c) => c.json({ tenant: c.tenant.slug }));
  return app;
}
