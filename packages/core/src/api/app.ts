import { Hono } from "hono";
import type { Classification } from "../crypto/classification.ts";
import { createSealer, KeyDestroyedError } from "../crypto/keys.ts";
import { getKeyRing } from "../crypto/ring.ts";
import { ConfigError, loadConfig } from "../tenant/config.ts";
import { resolveTenant } from "../tenant/directory.ts";
import { createTenantDb, type TenantDb } from "../tenant/handle.ts";
import type { Config, Tenant } from "../tenant/types.ts";
import { PolicyError, roleAtLeast, toManifestEntry, validatePolicy, type ManifestEntry, type Policy, type Role } from "./policy.ts";

export interface User {
  id: string;
  role: Role;
  /**
   * Set only for credentials that carry a declared permission set (API keys, AUTH-4). When present, the route
   * must declare a `permission` the user holds; routes that declare none are unreachable. Absent for sessions.
   */
  permissions?: readonly string[];
}

/** What a handler receives. Deliberately has no `env`: raw bindings are not reachable from route code. */
export interface RouteContext {
  readonly tenant: Tenant;
  readonly user: User | null;
  readonly db: TenantDb;
  /** Key lifecycle for this tenant only (CRYPTO-3/4). Gate it with an owner policy. Throws when the app declares no classified data. */
  readonly keys: { rotate(): Promise<number>; shred(): Promise<void> };
  readonly req: Request;
  readonly params: Readonly<Record<string, string>>;
  json(body: unknown, status?: number): Response;
  text(body: string, status?: number): Response;
}

export type Handler = (c: RouteContext) => Promise<Response> | Response;

export interface AppOptions {
  /** Per-tenant SQLite schema steps, applied in order. */
  schema?: readonly string[];
  /**
   * Resolves the signed-in user for this tenant. Default: nobody, so only public routes are reachable.
   * Receives the tenant-scoped handle so sessions and keys live in the tenant's own database (TENANT-3).
   * Runs inside the gate, so no handler has run and none receives the handle until it returns.
   */
  authenticate?: (req: Request, tenant: Tenant, db: TenantDb) => Promise<User | null>;
  /**
   * The parsed `bulkhead.classification.json`. Declaring it turns on sealing and requires master keys at boot (BOOT-1); every column of every
   * table must be classified, and sensitive/secret columns must carry `sealedCheck`, or the tenant refuses to initialise (CRYPTO-1).
   */
  classification?: Classification;
  /** Plan entitlements arrive in Phase 5. Default denies every feature (fail closed). */
  hasFeature?: (tenant: Tenant, feature: string) => Promise<boolean>;
}

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
type Method = (typeof METHODS)[number];

// One body for every "nothing here" outcome so an unknown host cannot be told apart from an unknown route.
const notFound = () => new Response(JSON.stringify({ error: "not found" }), { status: 404, headers: { "content-type": "application/json" } });
const reply = (status: number, error: string) => new Response(JSON.stringify({ error }), { status, headers: { "content-type": "application/json" } });

export function createApp(options: AppOptions = {}) {
  const hono = new Hono();
  const manifest: ManifestEntry[] = [];
  const schema = options.schema ?? [];
  const classification = options.classification;
  let config: Config | undefined;

  hono.notFound(notFound);
  hono.onError((err) => {
    console.error("request failed", err instanceof Error ? err.name : "error"); // no stack, no message to the client
    if (err instanceof KeyDestroyedError) return reply(410, "tenant data is unavailable");
    return reply(500, "internal error");
  });

  function route(method: Method, path: string, policy: Policy, handler: Handler) {
    const checked = validatePolicy(method, path, policy); // throws at startup, before the route exists
    if (manifest.some((m) => m.method === method && m.path === path)) throw new PolicyError(`${method} ${path}: registered twice`);
    manifest.push(toManifestEntry(method, path, checked));

    hono.on(method, path, async (c) => {
      const cfg = (config ??= loadConfig(c.env as Record<string, unknown>, { requireMasterKeys: !!classification }));
      // 1. The hostname picks the tenant. Nothing else is consulted.
      const tenant = await resolveTenant(new URL(c.req.url).hostname, cfg);
      if (!tenant) return notFound();
      // 2. Policy gate, before any handler runs. The scoped handle exists, but only authenticate sees it until the gate passes.
      const ring = cfg.masterKeys ? getKeyRing(cfg) : undefined;
      const db = createTenantDb(tenant, cfg.tenants, schema, classification, ring && classification ? (reserve) => createSealer(tenant.id, ring, classification, reserve) : undefined);
      const noKeys = () => Promise.reject(new Error("this app declares no classified data, so it has no tenant keys"));
      const user = checked.public ? null : ((await options.authenticate?.(c.req.raw, tenant, db)) ?? null);
      if (!checked.public) {
        if (!user) return reply(401, "authentication required");
        if (!roleAtLeast(user.role, checked.role!)) return reply(403, "forbidden");
        if (user.permissions && !(checked.permission && user.permissions.includes(checked.permission))) return reply(403, "forbidden");
        if (checked.feature && !(await options.hasFeature?.(tenant, checked.feature))) return reply(403, "forbidden");
      }
      // 3. Only now does the handler get a handle with the tenant fixed.
      return handler({
        tenant,
        user,
        db,
        keys: { rotate: () => (ring ? ring.rotate(tenant.id) : noKeys()), shred: () => (ring ? ring.shred(tenant.id) : noKeys()) },
        req: c.req.raw,
        params: Object.freeze({ ...c.req.param() }),
        json: (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }),
        text: (body, status = 200) => new Response(body, { status, headers: { "content-type": "text/plain; charset=utf-8" } }),
      });
    });
  }

  return {
    route,
    /** Sorted, stable description of every route and its policy (ROUTE-2). */
    manifest: (): ManifestEntry[] => [...manifest].sort((a, b) => (a.path + a.method).localeCompare(b.path + b.method)),
    fetch: async (req: Request, env: unknown): Promise<Response> => {
      try {
        config ??= loadConfig(env as Record<string, unknown>, { requireMasterKeys: !!classification });
      } catch (e) {
        if (e instanceof ConfigError) {
          console.error("misconfigured:", e.message);
          return reply(500, "service misconfigured"); // fail closed: serve nothing
        }
        throw e;
      }
      return hono.fetch(req, env as never);
    },
  };
}
