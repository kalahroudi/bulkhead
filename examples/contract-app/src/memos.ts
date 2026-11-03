// The contract app keeps its text store under different names than the demo: /notes is backed by `memos.body`.
import type { createApp } from "@kalahroudi/bulkhead-core/api";

type App = ReturnType<typeof createApp>;
const OPEN = { public: { reason: "contract-app route used by the verify probes; real apps declare roles" } } as const;

export function memoRoutes(app: App) {
  const list = async (c: { db: { query<T>(sql: string): Promise<T[]>; open(t: string, f: string, v: string): Promise<string> } }) =>
    Promise.all((await c.db.query<{ body: string }>("select body from memos order by id asc")).map((r) => c.db.open("memos", "body", r.body)));
  app.route("POST", "/notes", OPEN, async (c) => {
    const input = (await c.req.json().catch(() => null)) as { text?: unknown } | null;
    if (!input || typeof input.text !== "string") return c.json({ error: "text required" }, 400);
    await c.db.run("insert into memos (body) values (?)", await c.db.seal("memos", "body", input.text));
    return c.json({ ok: true }, 201);
  });
  app.route("GET", "/notes", OPEN, async (c) => c.json({ notes: await list(c) }));
  app.route("GET", "/summary", OPEN, async (c) => c.json({ summary: (await list(c)).join(" | ") }));
}
