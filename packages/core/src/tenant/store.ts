import { enforceClassification, type Classification } from "../crypto/classification.ts";

// Logic behind each tenant's Durable Object. Pure over an injected SQL executor so it is unit-testable on node:sqlite.
export type SqlExec = (sql: string, params: unknown[]) => { rows: Record<string, unknown>[]; changes: number };

const RESERVED = /_bulkhead_/i;

/**
 * In an app with classified data, routes may only read and write rows. Schema changes belong in the schema steps, which are checked against the
 * classification when the tenant initialises; a route that could run DDL or `pragma ignore_check_constraints` would walk around that check.
 * One statement only: a `;` followed by anything is refused.
 */
function assertDataStatement(sql: string) {
  const text = sql.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/--[^\n]*/g, " ").trim().replace(/;\s*$/, "");
  if (!/^(select|insert|update|delete|replace|with)\b/i.test(text) || text.includes(";")) throw new Error("only single data statements are allowed");
  if (/\bpragma\b/i.test(text) && !/pragma_table_info/i.test(text)) throw new Error("only single data statements are allowed");
}

export class TenantStore {
  private exec: SqlExec;
  private ready = false;
  constructor(exec: SqlExec) {
    this.exec = exec;
  }

  /** Binds the database to one tenant on first use and applies schema steps in order. A different tenant ID is refused. */
  private init(tenantId: string, schema: readonly string[], classification?: Classification) {
    this.exec("create table if not exists _bulkhead_meta (key text primary key, value text not null)", []);
    const bound = this.exec("select value from _bulkhead_meta where key = 'tenant_id'", []).rows[0]?.value;
    if (bound === undefined) this.exec("insert into _bulkhead_meta (key, value) values ('tenant_id', ?)", [tenantId]);
    else if (bound !== tenantId) throw new Error("tenant mismatch");
    const applied = Number(this.exec("select value from _bulkhead_meta where key = 'schema_version'", []).rows[0]?.value ?? 0);
    for (let i = applied; i < schema.length; i++) {
      this.exec(schema[i] as string, []);
      this.exec("insert or replace into _bulkhead_meta (key, value) values ('schema_version', ?)", [String(i + 1)]);
    }
    if (classification) enforceClassification(this.exec, classification); // throws: the tenant refuses to initialise, and `ready` stays false
    this.ready = true;
  }

  private guard(tenantId: string, schema: readonly string[], classification?: Classification) {
    if (!this.ready) this.init(tenantId, schema, classification);
    else if (this.exec("select value from _bulkhead_meta where key = 'tenant_id'", []).rows[0]?.value !== tenantId) throw new Error("tenant mismatch");
  }

  run(tenantId: string, schema: readonly string[], sql: string, params: unknown[], classification?: Classification) {
    if (RESERVED.test(sql)) throw new Error("reserved table");
    if (classification) assertDataStatement(sql);
    this.guard(tenantId, schema, classification);
    return this.exec(sql, params);
  }

  /**
   * CRYPTO-4: reserves the next nonce counter for one key version. The counter lives in the tenant's own database and the bump is a single
   * statement followed by a read with no await between, so two reservations never return the same number. A failed write after a
   * reservation burns a number; gaps are harmless, reuse is not possible.
   */
  nonce(tenantId: string, schema: readonly string[], keyVersion: number, classification?: Classification): number {
    if (!Number.isSafeInteger(keyVersion) || keyVersion < 1) throw new Error("bad key version");
    this.guard(tenantId, schema, classification);
    const key = `nonce:${keyVersion}`;
    this.exec("insert into _bulkhead_meta (key, value) values (?, '1') on conflict (key) do update set value = cast(cast(value as integer) + 1 as text)", [key]);
    return Number(this.exec("select value from _bulkhead_meta where key = ?", [key]).rows[0]?.value);
  }
}
