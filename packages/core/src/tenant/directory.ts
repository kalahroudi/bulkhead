// Control plane (D1): tenants only. Domains and billing state arrive in later phases (TENANT-3).
import type { Config, D1Like, Tenant } from "./types.ts";

const SLUG = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

const ready = new WeakMap<object, Promise<void>>();

export function ensureControlPlaneSchema(db: D1Like): Promise<void> {
  let p = ready.get(db);
  if (!p) {
    p = db
      .prepare("create table if not exists tenants (id text primary key, slug text not null unique, status text not null default 'active')")
      .run()
      .then(() => undefined);
    ready.set(db, p);
    p.catch(() => ready.delete(db));
  }
  return p;
}

/** The only place a tenant is derived: from the hostname. Headers, bodies and query strings never reach this. */
export function slugFromHostname(hostname: string, baseDomain: string): string | null {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const suffix = `.${baseDomain}`;
  if (!host.endsWith(suffix)) return null;
  const slug = host.slice(0, -suffix.length);
  return SLUG.test(slug) ? slug : null;
}

export async function resolveTenant(hostname: string, config: Config): Promise<Tenant | null> {
  const slug = slugFromHostname(hostname, config.baseDomain);
  if (!slug) return null;
  await ensureControlPlaneSchema(config.db);
  if (config.autoProvision)
    await config.db.prepare("insert or ignore into tenants (id, slug) values (?, ?)").bind(crypto.randomUUID(), slug).run();
  const row = await config.db.prepare("select id, slug from tenants where slug = ? and status = 'active'").bind(slug).first<{ id: string; slug: string }>();
  return row ? { id: row.id, slug: row.slug } : null;
}
