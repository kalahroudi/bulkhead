// Fakes built on real SQLite (node:sqlite) so SQL behaviour is genuine.
import { DatabaseSync } from "node:sqlite";
import { TenantStore } from "../src/tenant/store.ts";
import type { D1Like, TenantNamespaceLike, TenantStub } from "../src/tenant/types.ts";

export function fakeD1(): D1Like & { raw: DatabaseSync } {
  const raw = new DatabaseSync(":memory:");
  const stmt = (sql: string, values: unknown[] = []) => ({
    bind: (...v: unknown[]) => stmt(sql, v),
    first: async <T>() => (raw.prepare(sql).get(...(values as never[])) as T | undefined) ?? null,
    run: async () => raw.prepare(sql).run(...(values as never[])),
    all: async <T>() => ({ results: raw.prepare(sql).all(...(values as never[])) as T[] }),
  });
  return { raw, prepare: (sql: string) => stmt(sql) as never };
}

export function fakeNamespace(): TenantNamespaceLike & { databases: Map<string, DatabaseSync> } {
  const stores = new Map<string, TenantStore>();
  const databases = new Map<string, DatabaseSync>();
  const stubFor = (name: string): TenantStub => {
    if (!stores.has(name)) {
      const db = new DatabaseSync(":memory:");
      databases.set(name, db);
      stores.set(name, new TenantStore((sql, params) => {
        const s = db.prepare(sql);
        if (/^\s*(select|pragma)/i.test(sql)) return { rows: s.all(...(params as never[])) as Record<string, unknown>[], changes: 0 };
        return { rows: [], changes: Number(s.run(...(params as never[])).changes) };
      }));
    }
    return { exec: async (id, schema, sql, params) => stores.get(name)!.run(id, schema, sql, params) };
  };
  return { databases, idFromName: (n) => n, get: (id) => stubFor(String(id)) };
}

export function makeEnv(over: Record<string, unknown> = {}) {
  return { BULKHEAD_ENV: "development", BULKHEAD_BASE_DOMAIN: "demo.localhost", BULKHEAD_AUTO_PROVISION: "true", BULKHEAD_DB: fakeD1(), BULKHEAD_TENANT: fakeNamespace(), ...over };
}
