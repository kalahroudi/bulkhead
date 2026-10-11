import type { Tenant, TenantNamespaceLike } from "./types.ts";

/** The only database handle a route handler gets. The tenant is fixed at construction; there is no way to name another. */
export interface TenantDb {
  query<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T[]>;
  run(sql: string, ...params: unknown[]): Promise<{ changes: number }>;
}

export function createTenantDb(tenant: Tenant, ns: TenantNamespaceLike, schema: readonly string[]): TenantDb {
  const stub = ns.get(ns.idFromName(tenant.id));
  const id = tenant.id;
  return Object.freeze({
    async query<T>(sql: string, ...params: unknown[]) {
      return (await stub.exec(id, schema, sql, params)).rows as T[];
    },
    async run(sql: string, ...params: unknown[]) {
      return { changes: (await stub.exec(id, schema, sql, params)).changes };
    },
  });
}
