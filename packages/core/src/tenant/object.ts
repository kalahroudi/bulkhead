import { TenantStore } from "./store.ts";

interface DOState {
  storage: { sql: { exec(sql: string, ...params: unknown[]): { toArray(): Record<string, unknown>[]; rowsWritten: number } } };
}

/**
 * Builds the per-tenant Durable Object class. Pass the runtime's `DurableObject` base:
 *   export class TenantObject extends makeTenantObject(DurableObject) {}
 * (The base is injected because `cloudflare:workers` only resolves inside workerd.)
 */
export function makeTenantObject<B extends abstract new (...args: any[]) => object>(Base: B) {
  abstract class TenantObject extends Base {
    #store: TenantStore;
    constructor(...args: any[]) {
      super(...args);
      const ctx = args[0] as DOState;
      this.#store = new TenantStore((sql, params) => {
        const cursor = ctx.storage.sql.exec(sql, ...params);
        const rows = cursor.toArray();
        return { rows, changes: cursor.rowsWritten };
      });
    }
    async exec(tenantId: string, schema: readonly string[], sql: string, params: unknown[]) {
      return this.#store.run(tenantId, schema, sql, params);
    }
  }
  return TenantObject;
}
