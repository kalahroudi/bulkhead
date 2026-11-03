// /secrets is backed by `vault_entries`: the stored value is `payload`, which is write-only. No route returns it.
import type { createApp } from "@kalahroudi/bulkhead-core/api";

type App = ReturnType<typeof createApp>;

export function vaultRoutes(app: App) {
  app.route("POST", "/secrets", { role: "owner" }, async (c) => {
    const input = (await c.req.json().catch(() => null)) as { name?: unknown; value?: unknown } | null;
    if (!input || typeof input.name !== "string" || !input.name || typeof input.value !== "string" || !input.value) return c.json({ error: "name and value required" }, 400);
    const id = crypto.randomUUID();
    await c.db.run("insert into vault_entries (id, label, payload, stored_at) values (?, ?, ?, ?)", id, input.name, await c.db.seal("vault_entries", "payload", input.value), Date.now());
    return c.json({ id, name: input.name }, 201);
  });
  app.route("GET", "/secrets", { role: "owner" }, async (c) => c.json({ secrets: await c.db.query("select id, label as name, stored_at as created_at from vault_entries order by stored_at") }));
  app.route("POST", "/admin/rotate-key", { role: "owner" }, async (c) => c.json({ keyVersion: await c.keys.rotate() }));
  app.route("POST", "/admin/shred", { role: "owner" }, async (c) => (await c.keys.shred(), c.json({ shredded: true })));
}
