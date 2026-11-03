// Role-gated areas and the tenant echo, declared from one table instead of one call each.
import type { createApp } from "@kalahroudi/bulkhead-core/api";

type App = ReturnType<typeof createApp>;

const AREAS = [
  { area: "member", policy: { role: "member", permission: "private:read" } },
  { area: "admin", policy: { role: "admin", permission: "private:admin" } },
  { area: "owner", policy: { role: "owner" } },
] as const;

export function areaRoutes(app: App) {
  for (const { area, policy } of AREAS) app.route("GET", `/private/${area}`, policy, (c) => c.json({ area, who: c.user!.id }));
  app.route("GET", "/whoami", { public: { reason: "contract-app route used by the verify probes; real apps declare roles" } }, (c) => c.json({ tenant: c.tenant.slug }));
}
