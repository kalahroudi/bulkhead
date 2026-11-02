import type { Classification } from "../crypto/classification.ts";
import type { Sealer } from "../crypto/keys.ts";
import type { Tenant, TenantNamespaceLike } from "./types.ts";

/** The only database handle a route handler gets. The tenant is fixed at construction; there is no way to name another. */
export interface TenantDb {
  query<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T[]>;
  run(sql: string, ...params: unknown[]): Promise<{ changes: number }>;
  /** Seals a value for a column classified sensitive or secret (CRYPTO-1). The result is the only thing such a column accepts. */
  seal(table: string, field: string, plaintext: string): Promise<string>;
  /** Opens a sealed value from this tenant's own column. Refuses write-only fields (CRYPTO-5) and anything sealed elsewhere (CRYPTO-2). */
  open(table: string, field: string, sealed: string): Promise<string>;
}

export function createTenantDb(tenant: Tenant, ns: TenantNamespaceLike, schema: readonly string[], classification?: Classification, sealer?: (reserve: (keyVersion: number) => Promise<number>) => Sealer): TenantDb {
  const stub = ns.get(ns.idFromName(tenant.id));
  const id = tenant.id;
  const s = sealer?.((v) => stub.nonce(id, schema, v, classification));
  const noSealer = () => Promise.reject(new Error("this app declares no classified data, so nothing can be sealed"));
  return Object.freeze({
    async query<T>(sql: string, ...params: unknown[]) {
      return (await stub.exec(id, schema, sql, params, classification)).rows as T[];
    },
    async run(sql: string, ...params: unknown[]) {
      return { changes: (await stub.exec(id, schema, sql, params, classification)).changes };
    },
    seal: (table: string, field: string, plaintext: string) => (s ? s.seal(table, field, plaintext) : noSealer()),
    open: (table: string, field: string, sealed: string) => (s ? s.open(table, field, sealed) : noSealer()),
  });
}
